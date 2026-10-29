package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// azureEntraScope is the OSS RDBMS resource for Azure Database for PostgreSQL
// Entra ID authentication. The access token issued for this scope is used as the
// connection password; the DSN user is the Entra principal name.
const azureEntraScope = "https://ossrdbms-aad.database.windows.net/.default"

// azureEntraWorkloadIdentity builds an AccessTokenProvider backed by the pod's
// federated workload identity (DefaultAzureCredential resolves the projected
// service-account token in-cluster), so a deployed workload authenticates to
// managed Azure Postgres with no stored password.
//
// Unexported on purpose: it is reached through WithExternalIdentity and the
// IssuerAzureEntra declaration, never by a consumer naming this cloud. The
// context is the caller's, carried for symmetry with the other issuers —
// DefaultAzureCredential resolves its chain without one.
func azureEntraWorkloadIdentity(_ context.Context) (AccessTokenProvider, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("initialize Azure workload identity credential: %w", err)
	}
	return accessTokenProviderFromCredential(credential), nil
}

// accessTokenProviderFromCredential adapts any azcore.TokenCredential to an
// AccessTokenProvider scoped to Azure Postgres. Kept separate from the
// DefaultAzureCredential constructor so the token flow is unit-testable without
// an Azure environment.
func accessTokenProviderFromCredential(credential azcore.TokenCredential) AccessTokenProvider {
	// principal is unused: DefaultAzureCredential always resolves the pod's own
	// federated identity, which must equal the DSN login role.
	return func(ctx context.Context, _ string) (string, error) {
		token, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureEntraScope}})
		if err != nil {
			return "", fmt.Errorf("acquire Azure Entra Postgres token: %w", err)
		}
		if token.Token == "" {
			return "", errors.New("Azure Entra returned an empty Postgres token")
		}
		return token.Token, nil
	}
}
