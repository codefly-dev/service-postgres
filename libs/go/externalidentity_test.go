package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestWithExternalIdentityRefusesAnUndeclaredIssuer(t *testing.T) {
	for _, declaration := range []string{"", "   ", "gcp", "GCP-CLOUD-SQL", "aws-rds", strings.Repeat("x", 512)} {
		var configuration config
		err := WithExternalIdentity(declaration)(&configuration)
		if !errors.Is(err, ErrExternalIdentity) {
			t.Fatalf("declaration %q: err = %v, want ErrExternalIdentity", declaration, err)
		}
		if configuration.externalIdentity != "" {
			t.Fatalf("declaration %q was recorded despite being refused", declaration)
		}
		// The operator who mistyped it needs the declarable set, and a rejected
		// value must not be echoed back unbounded.
		for _, issuer := range declarableIssuers() {
			if !strings.Contains(err.Error(), issuer) {
				t.Fatalf("declaration %q: refusal does not name %q: %v", declaration, issuer, err)
			}
		}
		if len(err.Error()) > 256 {
			t.Fatalf("declaration %q: refusal is %d bytes", declaration, len(err.Error()))
		}
	}
}

func TestWithExternalIdentityAcceptsEveryDeclarableIssuer(t *testing.T) {
	for _, issuer := range declarableIssuers() {
		var configuration config
		if err := WithExternalIdentity(" " + issuer + " ")(&configuration); err != nil {
			t.Fatalf("issuer %q: %v", issuer, err)
		}
		if configuration.externalIdentity != issuer {
			t.Fatalf("issuer %q recorded as %q", issuer, configuration.externalIdentity)
		}
	}
}

// Every issuer named by a published constant must be declarable, and every
// declarable issuer must be reachable: a constant with no entry is a value a
// deployment can write and no build can honour.
func TestPublishedIssuerConstantsAreDeclarable(t *testing.T) {
	for _, issuer := range []string{IssuerAzureEntra, IssuerGCPCloudSQL} {
		if _, known := externalIdentityIssuers[issuer]; !known {
			t.Fatalf("published issuer %q has no constructor", issuer)
		}
	}
	for issuer, construct := range externalIdentityIssuers {
		if construct == nil {
			t.Fatalf("declarable issuer %q has a nil constructor", issuer)
		}
	}
}

func TestResolveExternalIdentityRefusesTwoCredentialsForOnePool(t *testing.T) {
	configuration := config{
		externalIdentity:    IssuerGCPCloudSQL,
		accessTokenProvider: func(context.Context, string) (string, error) { return "token", nil },
	}
	err := resolveExternalIdentity(context.Background(), &configuration)
	if !errors.Is(err, ErrExternalIdentity) {
		t.Fatalf("err = %v, want ErrExternalIdentity", err)
	}
}

func TestResolveExternalIdentityLeavesAnUndeclaredConfigAlone(t *testing.T) {
	configuration := config{}
	if err := resolveExternalIdentity(context.Background(), &configuration); err != nil {
		t.Fatal(err)
	}
	if configuration.accessTokenProvider != nil {
		t.Fatal("an undeclared external identity installed a provider")
	}
}

// A declaration this build cannot honour must fail where the deployment is
// wrong. resolveExternalIdentity is also reached by callers that set the field
// directly, so it refuses rather than trusting WithExternalIdentity's check.
func TestResolveExternalIdentityRefusesAnUnknownIssuerItWasHandedDirectly(t *testing.T) {
	configuration := config{externalIdentity: "azure-managed-identity"}
	if err := resolveExternalIdentity(context.Background(), &configuration); !errors.Is(err, ErrExternalIdentity) {
		t.Fatalf("err = %v, want ErrExternalIdentity", err)
	}
}
