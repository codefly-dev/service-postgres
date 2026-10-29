package postgres

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	testOwnLogin   = "cell-db-accounts-writer@example-project.iam"
	testOtherLogin = "cell-db-accounts-reader@example-project.iam"
)

type fixedTokenSource struct {
	token string
	err   error
	calls atomic.Int64
}

func (f *fixedTokenSource) Token() (*oauth2.Token, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return &oauth2.Token{AccessToken: f.token, TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}, nil
}

type exchangeRecord struct {
	path      string
	authorize string
	scopes    []string
	lifetime  string
}

// iamStub answers generateAccessToken, recording what was actually asked for.
func iamStub(t *testing.T, mint func(principal string) (int, string)) (*gcpIdentity, *[]exchangeRecord, func()) {
	t.Helper()
	var mu sync.Mutex
	records := []exchangeRecord{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var request struct {
			Scope    []string `json:"scope"`
			Lifetime string   `json:"lifetime"`
		}
		_ = json.Unmarshal(body, &request)
		mu.Lock()
		records = append(records, exchangeRecord{
			path:      r.URL.Path,
			authorize: r.Header.Get("Authorization"),
			scopes:    request.Scope,
			lifetime:  request.Lifetime,
		})
		mu.Unlock()
		principal := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/projects/-/serviceAccounts/"), ":generateAccessToken")
		status, payload := mint(principal)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(payload))
	}))
	identity, err := newGCPIdentity(
		testOwnLogin,
		&fixedTokenSource{token: "own-sqlservice-token"},
		&fixedTokenSource{token: "caller-cloud-platform-token"},
		server.URL,
		server.Client(),
	)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return identity, &records, server.Close
}

func mintedToken(token string, expiry time.Time) string {
	payload, _ := json.Marshal(map[string]string{"accessToken": token, "expireTime": expiry.Format(time.RFC3339)})
	return string(payload)
}

// The pod's own login must not go through IAM at all: the reference deployment
// grants it no token-creator role on itself, so an exchange here would 403.
func TestGCPOwnLoginUsesTheAmbientCredentialWithoutAnExchange(t *testing.T) {
	identity, records, close := iamStub(t, func(string) (int, string) {
		t.Error("the workload's own login was exchanged through IAM")
		return http.StatusForbidden, "{}"
	})
	defer close()
	token, err := identity.token(" " + testOwnLogin + " ")
	if err != nil {
		t.Fatal(err)
	}
	if token != "own-sqlservice-token" {
		t.Fatalf("token = %q, want the ambient sqlservice token", token)
	}
	if len(*records) != 0 {
		t.Fatalf("own login reached IAM: %+v", *records)
	}
}

func TestGCPOtherLoginIsExchangedForThatPrincipal(t *testing.T) {
	identity, records, close := iamStub(t, func(principal string) (int, string) {
		return http.StatusOK, mintedToken("borrowed-for-"+principal, time.Now().Add(time.Hour))
	})
	defer close()
	token, err := identity.token(testOtherLogin)
	if err != nil {
		t.Fatal(err)
	}
	want := "borrowed-for-" + testOtherLogin + gcpServiceAccountSuffix
	if token != want {
		t.Fatalf("token = %q, want %q", token, want)
	}
	if len(*records) != 1 {
		t.Fatalf("records = %+v, want exactly one exchange", *records)
	}
	record := (*records)[0]
	// The DSN login is reversed into the service-account email Cloud SQL
	// stripped it from, with no second declaration mapping the two.
	if wantPath := "/v1/projects/-/serviceAccounts/" + testOtherLogin + gcpServiceAccountSuffix + ":generateAccessToken"; record.path != wantPath {
		t.Fatalf("path = %q, want %q", record.path, wantPath)
	}
	// The exchange is authorized with cloud-platform; what it mints is scoped to
	// logging in and nothing else.
	if record.authorize != "Bearer caller-cloud-platform-token" {
		t.Fatalf("authorization = %q", record.authorize)
	}
	if len(record.scopes) != 1 || record.scopes[0] != gcpCloudSQLScope {
		t.Fatalf("scopes = %v, want only %q", record.scopes, gcpCloudSQLScope)
	}
	if record.lifetime != "3600s" {
		t.Fatalf("lifetime = %q", record.lifetime)
	}
}

// The failure the infra record names outright: one credential standing in for
// two logins, which would hand the request login the control plane's authority.
func TestGCPDistinctLoginsNeverShareACredential(t *testing.T) {
	identity, _, close := iamStub(t, func(principal string) (int, string) {
		return http.StatusOK, mintedToken("borrowed-for-"+principal, time.Now().Add(time.Hour))
	})
	defer close()
	third := "cell-db-accounts-control@example-project.iam"
	seen := map[string]string{}
	for _, login := range []string{testOwnLogin, testOtherLogin, third} {
		token, err := identity.token(login)
		if err != nil {
			t.Fatalf("login %q: %v", login, err)
		}
		if owner, duplicate := seen[token]; duplicate {
			t.Fatalf("logins %q and %q authenticate with the same token", owner, login)
		}
		seen[token] = login
	}
}

func TestGCPBorrowedTokensAreCachedUntilTheyNearExpiry(t *testing.T) {
	var exchanges atomic.Int64
	identity, _, close := iamStub(t, func(principal string) (int, string) {
		exchanges.Add(1)
		return http.StatusOK, mintedToken(fmt.Sprintf("borrowed-%d", exchanges.Load()), time.Now().Add(time.Hour))
	})
	defer close()
	for range 5 {
		if _, err := identity.token(testOtherLogin); err != nil {
			t.Fatal(err)
		}
	}
	if exchanges.Load() != 1 {
		t.Fatalf("exchanges = %d, want 1: pgx asks per physical connection, so an uncached provider mints one IAM token per connection", exchanges.Load())
	}
}

func TestGCPBorrowedTokenIsReExchangedOnceItIsInsideTheRefreshMargin(t *testing.T) {
	var exchanges atomic.Int64
	identity, _, close := iamStub(t, func(string) (int, string) {
		exchanges.Add(1)
		return http.StatusOK, mintedToken(fmt.Sprintf("borrowed-%d", exchanges.Load()), time.Now().Add(gcpTokenRefreshMargin/2))
	})
	defer close()
	first, err := identity.token(testOtherLogin)
	if err != nil {
		t.Fatal(err)
	}
	second, err := identity.token(testOtherLogin)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || exchanges.Load() != 2 {
		t.Fatalf("a token inside the refresh margin was reused: %q then %q over %d exchanges", first, second, exchanges.Load())
	}
}

func TestGCPRefusesALoginThatIsNotAServiceAccount(t *testing.T) {
	identity, records, close := iamStub(t, func(string) (int, string) {
		t.Error("a login that is not a service account reached IAM")
		return http.StatusOK, mintedToken("leaked", time.Now().Add(time.Hour))
	})
	defer close()
	for _, login := range []string{
		"",
		"   ",
		"app_tenant",
		"postgres",
		"../../projects/other/serviceAccounts/victim@example-project.iam",
		"writer@example-project.iam:generateAccessToken",
		"writer@example-project.iam.gserviceaccount.com",
		"writer@example-project.iam\nX-Injected: 1",
		"UPPER@example-project.iam",
	} {
		if _, err := identity.token(login); err == nil {
			t.Fatalf("login %q was accepted", login)
		}
	}
	if len(*records) != 0 {
		t.Fatalf("a refused login still reached IAM: %+v", *records)
	}
}

func TestGCPExchangeFailuresFailClosedWithoutEchoingTheResponse(t *testing.T) {
	secret := "ya29.super-secret-token-material"
	for name, answer := range map[string]func(string) (int, string){
		"refused": func(string) (int, string) { return http.StatusForbidden, `{"error":{"message":"` + secret + `"}}` },
		"empty token": func(string) (int, string) {
			return http.StatusOK, `{"accessToken":"","expireTime":"2030-01-01T00:00:00Z"}`
		},
		"no expiry": func(string) (int, string) { return http.StatusOK, `{"accessToken":"` + secret + `"}` },
		"unusable expiry": func(string) (int, string) {
			return http.StatusOK, `{"accessToken":"` + secret + `","expireTime":"soon"}`
		},
		"not json":         func(string) (int, string) { return http.StatusOK, "<html>" + secret + "</html>" },
		"server error":     func(string) (int, string) { return http.StatusInternalServerError, secret },
		"empty 200 body":   func(string) (int, string) { return http.StatusOK, "" },
		"token in a field": func(string) (int, string) { return http.StatusOK, `{"token":"` + secret + `"}` },
	} {
		t.Run(name, func(t *testing.T) {
			identity, _, close := iamStub(t, answer)
			defer close()
			token, err := identity.token(testOtherLogin)
			if err == nil {
				t.Fatalf("token = %q, want a refusal", token)
			}
			if token != "" {
				t.Fatalf("a failed exchange returned %q", token)
			}
			// A credential the exchange happened to carry must not reach a log
			// line through the error, and the principal must, because it names
			// the missing grant.
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error carries response material: %v", err)
			}
			if !strings.Contains(err.Error(), testOtherLogin) {
				t.Fatalf("error does not name the principal: %v", err)
			}
		})
	}
}

func TestGCPAmbientTokenFailureFailsClosed(t *testing.T) {
	identity, err := newGCPIdentity(testOwnLogin,
		&fixedTokenSource{err: fmt.Errorf("no federated credential")},
		&fixedTokenSource{token: "caller"},
		"https://iamcredentials.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token, err := identity.token(testOwnLogin); err == nil {
		t.Fatalf("token = %q, want a refusal", token)
	}
	if token, err := identity.token(testOwnLogin); err == nil || token != "" {
		t.Fatal("a failed ambient credential was cached as a usable one")
	}
}

func TestNewGCPIdentityRefusesAnIncompleteBinding(t *testing.T) {
	source := &fixedTokenSource{token: "t"}
	for name, build := range map[string]func() (*gcpIdentity, error){
		"no own source":    func() (*gcpIdentity, error) { return newGCPIdentity(testOwnLogin, nil, source, "", nil) },
		"no caller source": func() (*gcpIdentity, error) { return newGCPIdentity(testOwnLogin, source, nil, "", nil) },
		"no own login":     func() (*gcpIdentity, error) { return newGCPIdentity("", source, source, "", nil) },
		"own login is a database role": func() (*gcpIdentity, error) {
			return newGCPIdentity("app_tenant", source, source, "", nil)
		},
		"own login kept its email suffix": func() (*gcpIdentity, error) {
			return newGCPIdentity(testOwnLogin+gcpServiceAccountSuffix, source, source, "", nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); err == nil {
				t.Fatal("an incomplete binding was accepted")
			}
		})
	}
}

// The provider is handed to pgx's BeforeConnect, which supplies the login of the
// connection being opened. It must read that argument rather than any ambient
// notion of "the" identity.
func TestGCPProviderAuthenticatesTheLoginItIsGiven(t *testing.T) {
	identity, _, close := iamStub(t, func(principal string) (int, string) {
		return http.StatusOK, mintedToken("borrowed-for-"+principal, time.Now().Add(time.Hour))
	})
	defer close()
	provider := identity.provider()
	own, err := provider(t.Context(), testOwnLogin)
	if err != nil {
		t.Fatal(err)
	}
	other, err := provider(t.Context(), testOtherLogin)
	if err != nil {
		t.Fatal(err)
	}
	if own == other {
		t.Fatal("the provider ignored the login it was given")
	}
}

// The login shapes a cell actually registers, transcribed with placeholder
// names of identical length and character classes: infra derives a service
// account as <prefix>-<region>-db-<role> in a hyphenated project, and the
// pattern has to accept the whole family rather than the one example it was
// written against.
func TestGCPLoginPatternAcceptsTheShapesACellRegisters(t *testing.T) {
	for _, login := range []string{
		"acmex-use1-db-writer@acme-acmex-staging.iam",
		"acmex-use1-db-reader@acme-acmex-staging.iam",
		"acmex-use1-db-migrator@acme-acmex-staging.iam",
		"acmex-use1-db-control-plane@acme-acmex-staging.iam",
		// A GCP project id is 6-30 characters, so these are the
		// shortest account id and project a login can really carry.
		"a-cell-db-rw@acme-1.iam",
		"service-account@example.com:scoped-project.iam",
	} {
		if !gcpSQLLoginPattern.MatchString(login) {
			t.Fatalf("login shape %q was refused", login)
		}
	}
}
