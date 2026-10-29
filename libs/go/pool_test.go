package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const poolTestHost = "store.identity.internal.example.com"

func TestOpenPoolRefusesAnIncompleteCall(t *testing.T) {
	cleanProfileEnvironment(t)
	dsn := "postgresql://writer@" + poolTestHost + "/records?sslmode=verify-full"
	//nolint:staticcheck // a nil context is exactly what this asserts is refused
	if _, _, err := OpenPool(nil, dsn, ConnectionProfile{Transport: VerifiedTLS}); err == nil {
		t.Fatal("a nil context was accepted")
	}
	if _, _, err := OpenPool(t.Context(), "", ConnectionProfile{Transport: VerifiedTLS}); err == nil {
		t.Fatal("an empty connection was accepted")
	}
}

// Every refusal the opinionated constructors make about a capability's
// transport and credential must hold here too: this is the same decision, not a
// relaxed version of it reached by a shorter route.
func TestOpenPoolKeepsEveryTransportAndCredentialRefusal(t *testing.T) {
	cleanProfileEnvironment(t)
	anchorPEM, _, _ := authority(t, "Cloud SQL Server CA", time.Now().Add(time.Hour))
	provider := func(context.Context, string) (string, error) { return "token", nil }

	for name, call := range map[string]func() error{
		"two credentials for one pool": func() error {
			_, _, err := OpenPool(t.Context(), "postgresql://writer@"+poolTestHost+"/records?sslmode=verify-ca",
				ConnectionProfile{Transport: PinnedAuthorityTLS, ServerTrustAnchorPEM: anchorPEM},
				WithExternalIdentity(IssuerGCPCloudSQL), WithAccessTokenProvider(provider))
			return err
		},
		"a password beside a credential provider": func() error {
			_, _, err := OpenPool(t.Context(), "postgresql://writer:seeded@"+poolTestHost+"/records?sslmode=verify-full",
				ConnectionProfile{Transport: VerifiedTLS}, WithAccessTokenProvider(provider))
			return err
		},
		"a pinned transport with no anchor": func() error {
			_, _, err := OpenPool(t.Context(), "postgresql://writer@"+poolTestHost+"/records?sslmode=verify-ca",
				ConnectionProfile{Transport: PinnedAuthorityTLS})
			return err
		},
		"an anchor on a transport that verifies nothing": func() error {
			_, _, err := OpenPool(t.Context(), "postgresql://writer@"+poolTestHost+"/records?sslmode=disable",
				ConnectionProfile{Transport: MeshProtected, ServerTrustAnchorPEM: anchorPEM})
			return err
		},
		"an undeclared external identity": func() error {
			_, _, err := OpenPool(t.Context(), "postgresql://writer@"+poolTestHost+"/records?sslmode=verify-full",
				ConnectionProfile{Transport: VerifiedTLS}, WithExternalIdentity(""))
			return err
		},
		"verify-full on a pinned transport": func() error {
			_, _, err := OpenPool(t.Context(), "postgresql://writer@"+poolTestHost+"/records?sslmode=verify-full",
				ConnectionProfile{Transport: PinnedAuthorityTLS, ServerTrustAnchorPEM: anchorPEM})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// pgxpool connects lazily. A pool handed back before its first connection
// succeeded moves a wrong credential, an unverifiable server or an unreachable
// address from boot to the first query, where it reads as a runtime fault.
func TestOpenPoolFailsAtBootRatherThanAtFirstQuery(t *testing.T) {
	cleanProfileEnvironment(t)
	pool, close, err := OpenPool(t.Context(),
		"postgresql://writer@unresolvable.invalid/records?sslmode=verify-full",
		ConnectionProfile{Transport: VerifiedTLS},
		WithOperationTimeout(3*time.Second))
	if err == nil {
		close()
		t.Fatal("a pool whose server does not resolve was returned as usable")
	}
	if pool != nil || close != nil {
		t.Fatal("a failed open returned a pool or a closer")
	}
	// An explicit profile reports the capability as unavailable rather than
	// handing back the driver's own text, which carries the binding.
	if !errors.Is(err, ErrConnectionUnavailable) && !strings.Contains(err.Error(), "ping") {
		t.Fatalf("unexpected error shape: %v", err)
	}
}

// The legacy zero profile stays available for a caller not yet declaring a
// transport, so adoption is one call rather than one call plus a posture change.
func TestOpenPoolAcceptsTheLegacyZeroProfile(t *testing.T) {
	cleanProfileEnvironment(t)
	_, _, err := OpenPool(t.Context(), "postgresql://writer:local@127.0.0.1:1/records?sslmode=disable",
		ConnectionProfile{}, WithOperationTimeout(3*time.Second))
	if err == nil {
		t.Fatal("a pool to a closed port was returned as usable")
	}
	if errors.Is(err, ErrConnectionProfile) {
		t.Fatalf("the zero profile was rejected as a profile error: %v", err)
	}
}
