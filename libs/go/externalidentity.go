package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// An external identity is a credential the cloud issues to the workload itself:
// the pod authenticates to managed Postgres as its own identity, and no password
// exists to be seeded, projected, rotated or leaked.
//
// WHICH cloud issues it is a property of the deployment, never of the
// application. A consuming service forwards the declaration it was handed and
// names no cloud, no cloud SDK and no identity endpoint; adding a cloud is a
// change to this file and the issuer beside it, and to nothing above the
// library. That boundary is the point: a service that reaches for one cloud's
// credential API has encoded its deployment into its source, and the next cloud
// becomes a second code path in every consumer instead of one entry here.
//
// The declaration is an exact enum with no default. An empty or unrecognized
// value is refused rather than treated as "no external identity", because the
// absence of a declaration and the declaration of absence are different states,
// and collapsing them is how a workload ends up on whatever credential happened
// to be reachable.
const (
	// IssuerAzureEntra: Azure Database for PostgreSQL Flexible Server, where the
	// login is an Entra principal and the password is an Entra access token.
	IssuerAzureEntra = "azure-entra"
	// IssuerGCPCloudSQL: Cloud SQL for PostgreSQL with
	// `cloudsql.iam_authentication` on, where the login is a service account and
	// the password is an IAM access token.
	IssuerGCPCloudSQL = "gcp-cloud-sql"
)

// ErrExternalIdentity reports a declaration this library cannot honour. It is
// returned before any pool exists, so a deployment that names a cloud this
// build does not implement fails at startup rather than on its first query.
var ErrExternalIdentity = errors.New("invalid Postgres external identity declaration")

// externalIdentityIssuers maps a declaration to the constructor that mints its
// credential. A table rather than a switch so a refusal can state what IS
// declarable, which is the one thing the operator who mis-typed it needs.
var externalIdentityIssuers = map[string]func(context.Context) (AccessTokenProvider, error){
	IssuerAzureEntra:  azureEntraWorkloadIdentity,
	IssuerGCPCloudSQL: gcpCloudSQLIAM,
}

// WithExternalIdentity authenticates every pooled connection as the workload's
// own cloud identity. declaration is the deployment's statement of where this
// workload runs; the caller forwards it verbatim from its configuration and does
// not interpret it.
//
// The read-only and read-write DSNs must then carry their login principal and no
// password. The credential is minted per physical connection, so rotation is
// picked up as the pool grows or reconnects, and nothing durable holds a secret.
//
// It is refused alongside WithAccessTokenProvider: both authenticate the same
// pools, and a deployment that declares two credentials for one login has not
// said which one is authoritative.
func WithExternalIdentity(declaration string) Option {
	return func(configuration *config) error {
		issuer := strings.TrimSpace(declaration)
		if _, known := externalIdentityIssuers[issuer]; !known {
			return fmt.Errorf("%w: %q is not one of %s", ErrExternalIdentity, elide(declaration), strings.Join(declarableIssuers(), ", "))
		}
		configuration.externalIdentity = issuer
		return nil
	}
}

// resolveExternalIdentity builds the declared provider. It runs where a
// connection is opened rather than where the option is applied, because minting
// the first credential reaches the cloud's identity endpoint — work that belongs
// to the caller's context and its timeout, not to the construction of a config
// value.
func resolveExternalIdentity(ctx context.Context, configuration *config) error {
	if configuration.externalIdentity == "" {
		return nil
	}
	if configuration.accessTokenProvider != nil {
		return fmt.Errorf("%w: an external identity and an explicit access-token provider both authenticate the same pools", ErrExternalIdentity)
	}
	issue, known := externalIdentityIssuers[configuration.externalIdentity]
	if !known {
		return fmt.Errorf("%w: %q is not one of %s", ErrExternalIdentity, configuration.externalIdentity, strings.Join(declarableIssuers(), ", "))
	}
	provider, err := issue(ctx)
	if err != nil {
		return fmt.Errorf("%s external identity: %w", configuration.externalIdentity, err)
	}
	configuration.accessTokenProvider = provider
	return nil
}

func declarableIssuers() []string {
	issuers := make([]string, 0, len(externalIdentityIssuers))
	for issuer := range externalIdentityIssuers {
		issuers = append(issuers, issuer)
	}
	sort.Strings(issuers)
	return issuers
}

// elide bounds a rejected declaration before it reaches a log line. The value is
// configuration rather than a credential, but an unbounded one is still an
// unbounded write driven by something outside this process.
func elide(value string) string {
	const limit = 64
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

// ExternalIdentityProvider resolves a declaration to the provider that mints
// its credential, for a caller that opens its own connection rather than going
// through Open — the managed bootstrap, which runs migrations as a subprocess
// and so cannot use a pool's connect hook for them.
//
// It is the same table WithExternalIdentity uses, exported so there is one
// vocabulary and one resolution for every path to the database rather than a
// second copy wherever a connection happens to be opened.
func ExternalIdentityProvider(ctx context.Context, declaration string) (AccessTokenProvider, error) {
	configuration := config{}
	if err := WithExternalIdentity(declaration)(&configuration); err != nil {
		return nil, err
	}
	if err := resolveExternalIdentity(ctx, &configuration); err != nil {
		return nil, err
	}
	return configuration.accessTokenProvider, nil
}
