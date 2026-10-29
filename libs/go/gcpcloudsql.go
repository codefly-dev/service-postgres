package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// gcpCloudSQLScope is the scope whose access token Cloud SQL accepts in place of
// a password for a CLOUD_IAM_SERVICE_ACCOUNT login. Deliberately not
// cloud-platform: the database credential is minted at the narrowest scope that
// can log in, so a token that leaves this process can do nothing but log in.
const gcpCloudSQLScope = "https://www.googleapis.com/auth/sqlservice.login"

// gcpImpersonationScope is the scope the IAM Credentials API requires of the
// CALLER asking for another principal's token. It authorizes the exchange and
// never the database: what comes back out carries gcpCloudSQLScope. Collapsing
// the two sources into one would send a cloud-platform token to Postgres as a
// password.
const gcpImpersonationScope = "https://www.googleapis.com/auth/cloud-platform"

// gcpServiceAccountSuffix is what Cloud SQL strips from a service account's
// email to form its SQL login — infra registers the login as
// trimsuffix(email, ".gserviceaccount.com"). Appending it to the DSN login
// reverses that derivation exactly, so the mapping from login to cloud
// principal is computed rather than declared a second time somewhere it can
// drift from the first.
const gcpServiceAccountSuffix = ".gserviceaccount.com"

const gcpIAMCredentialsEndpoint = "https://iamcredentials.googleapis.com"

// gcpTokenLifetime is the longest an impersonated token may be issued for
// without a project policy raising the ceiling; gcpTokenRefreshMargin retires it
// early so a connection opened at the edge of validity does not race expiry.
const (
	gcpTokenLifetime      = time.Hour
	gcpTokenRefreshMargin = 2 * time.Minute
	gcpExchangeTimeout    = 15 * time.Second
	gcpMaxResponseBytes   = 1 << 16
)

// gcpSQLLoginPattern is the exact shape of a Cloud SQL service-account login:
// a service account's account id, an "@", its project, and the ".iam" that
// remains once the email suffix is stripped. The login arrives from a
// connection string and becomes a path segment in an IAM request, so it is
// matched against that shape rather than escaped and hoped for.
var gcpSQLLoginPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z0-9][a-z0-9.:-]{4,28}[a-z0-9]\.iam$`)

// gcpIdentity mints Cloud SQL login credentials for the workload's own identity
// and, for any other login, by asking IAM for that principal's token.
//
// A pod has one Kubernetes ServiceAccount and therefore one primary cloud
// identity, while this library opens several logins deliberately kept distinct
// (a request login that reaches only the tenant role, and a control-plane login
// that reaches the cross-tenant roles). The reference deployment annotates the
// ServiceAccount with one of them and grants it
// roles/iam.serviceAccountTokenCreator on the others, so the login named by each
// connection decides whether the ambient credential is used directly or
// exchanged for that principal's.
type gcpIdentity struct {
	ownLogin string
	own      oauth2.TokenSource
	caller   oauth2.TokenSource
	endpoint string
	client   *http.Client

	mu       sync.Mutex
	borrowed map[string]oauth2.TokenSource
}

// gcpCloudSQLIAM resolves the pod's workload identity and returns the provider
// that authenticates each login with it. Every failure here is a deployment that
// is wrong — no federated credential, no metadata server — so it is returned at
// startup instead of per connection.
func gcpCloudSQLIAM(ctx context.Context) (AccessTokenProvider, error) {
	own, err := google.DefaultTokenSource(ctx, gcpCloudSQLScope)
	if err != nil {
		return nil, fmt.Errorf("resolve workload identity credentials: %w", err)
	}
	caller, err := google.DefaultTokenSource(ctx, gcpImpersonationScope)
	if err != nil {
		return nil, fmt.Errorf("resolve workload identity credentials for impersonation: %w", err)
	}
	email, err := metadata.EmailWithContext(ctx, "default")
	if err != nil {
		// Without the workload's own identity every login looks like another
		// principal's, and the provider would ask IAM to impersonate the account
		// it already is — a grant the reference deployment does not make,
		// failing every connection with a 403 that names the wrong cause.
		return nil, fmt.Errorf("resolve the workload's own service account: %w", err)
	}
	identity, err := newGCPIdentity(strings.TrimSuffix(strings.TrimSpace(email), gcpServiceAccountSuffix), own, caller, gcpIAMCredentialsEndpoint, nil)
	if err != nil {
		return nil, err
	}
	return identity.provider(), nil
}

func newGCPIdentity(ownLogin string, own, caller oauth2.TokenSource, endpoint string, client *http.Client) (*gcpIdentity, error) {
	if own == nil || caller == nil {
		return nil, errors.New("Cloud SQL IAM identity requires both its own and its impersonating token source")
	}
	if !gcpSQLLoginPattern.MatchString(ownLogin) {
		return nil, fmt.Errorf("the workload's own service account %q is not a Cloud SQL service-account login", elide(ownLogin))
	}
	if client == nil {
		client = &http.Client{Timeout: gcpExchangeTimeout}
	}
	return &gcpIdentity{
		ownLogin: ownLogin,
		own:      own,
		caller:   caller,
		endpoint: strings.TrimSuffix(endpoint, "/"),
		client:   client,
		borrowed: map[string]oauth2.TokenSource{},
	}, nil
}

func (g *gcpIdentity) provider() AccessTokenProvider {
	return func(_ context.Context, principal string) (string, error) {
		return g.token(principal)
	}
}

// token selects the credential for the login the connection names. The
// connection's context is deliberately not used to mint it: a credential shared
// by a pool must not inherit the deadline of whichever request happened to grow
// the pool, or one cancelled request would fail connections for every other.
func (g *gcpIdentity) token(principal string) (string, error) {
	login := strings.TrimSpace(principal)
	if login == "" {
		return "", errors.New("Cloud SQL IAM connection names no login, so there is no principal to authenticate as")
	}
	if login == g.ownLogin {
		return accessTokenFrom(g.own)
	}
	source, err := g.borrow(login)
	if err != nil {
		return "", err
	}
	return accessTokenFrom(source)
}

// borrow memoizes one reusable token source per impersonated login. Caching is
// the provider's own job: pgx asks for a credential on every physical
// connection, and a pool that grows under load would otherwise mint an IAM
// token per connection.
func (g *gcpIdentity) borrow(login string) (oauth2.TokenSource, error) {
	if !gcpSQLLoginPattern.MatchString(login) {
		return nil, errors.New("Cloud SQL IAM login is not a service-account login")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if source, cached := g.borrowed[login]; cached {
		return source, nil
	}
	source := oauth2.ReuseTokenSourceWithExpiry(nil, &gcpBorrowedTokens{
		identity:  g,
		principal: login + gcpServiceAccountSuffix,
	}, gcpTokenRefreshMargin)
	g.borrowed[login] = source
	return source, nil
}

// gcpBorrowedTokens exchanges the workload's own credential for one principal's.
type gcpBorrowedTokens struct {
	identity  *gcpIdentity
	principal string
}

func (b *gcpBorrowedTokens) Token() (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gcpExchangeTimeout)
	defer cancel()
	return b.identity.exchange(ctx, b.principal)
}

func (g *gcpIdentity) exchange(ctx context.Context, principal string) (*oauth2.Token, error) {
	caller, err := g.caller.Token()
	if err != nil {
		return nil, fmt.Errorf("acquire the impersonating workload's own token: %w", err)
	}
	body, err := json.Marshal(map[string]any{
		"scope":    []string{gcpCloudSQLScope},
		"lifetime": fmt.Sprintf("%ds", int(gcpTokenLifetime.Seconds())),
	})
	if err != nil {
		return nil, fmt.Errorf("encode the Cloud SQL token request: %w", err)
	}
	endpoint := g.endpoint + "/v1/projects/-/serviceAccounts/" + url.PathEscape(principal) + ":generateAccessToken"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build the Cloud SQL token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	caller.SetAuthHeader(request)
	response, err := g.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("ask IAM for a Cloud SQL token for %s: %w", principal, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, gcpMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read IAM's Cloud SQL token response for %s: %w", principal, err)
	}
	if response.StatusCode != http.StatusOK {
		// The principal, not the body: a refusal here is almost always the
		// missing roles/iam.serviceAccountTokenCreator grant on exactly this
		// account, which is the one fact worth logging, and the body is the
		// cloud's prose rather than ours.
		return nil, fmt.Errorf("IAM refused a Cloud SQL token for %s: HTTP %d", principal, response.StatusCode)
	}
	var minted struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	if err := json.Unmarshal(payload, &minted); err != nil {
		return nil, fmt.Errorf("decode IAM's Cloud SQL token response for %s: %w", principal, err)
	}
	if minted.AccessToken == "" {
		return nil, fmt.Errorf("IAM returned an empty Cloud SQL token for %s", principal)
	}
	// An unparseable or absent expiry would leave the zero time, which oauth2
	// reads as a token that never expires: it would be reused for the life of
	// the process and start failing silently an hour in, with no refresh.
	expiry, err := time.Parse(time.RFC3339, minted.ExpireTime)
	if err != nil {
		return nil, fmt.Errorf("IAM returned a Cloud SQL token for %s with no usable expiry: %w", principal, err)
	}
	return &oauth2.Token{AccessToken: minted.AccessToken, TokenType: "Bearer", Expiry: expiry}, nil
}

func accessTokenFrom(source oauth2.TokenSource) (string, error) {
	token, err := source.Token()
	if err != nil {
		return "", fmt.Errorf("acquire Cloud SQL IAM token: %w", err)
	}
	if token.AccessToken == "" {
		return "", errors.New("Cloud SQL IAM token source returned an empty token")
	}
	return token.AccessToken, nil
}
