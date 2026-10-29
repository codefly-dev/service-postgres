package postgres

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func encodeCertificate(t *testing.T, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// authority mints a self-signed CA in the shape Cloud SQL's default mode uses:
// subject equal to issuer, with a long life.
func authority(t *testing.T, name string, notAfter time.Time) (string, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return encodeCertificate(t, der), parsed, key
}

func serverCertificate(t *testing.T, host string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// The property the whole option exists for: the pool admits the instance's own
// authority and refuses every other one. Without this, pinning would be a
// comment rather than a control.
func TestServerTrustAnchorAdmitsOnlyTheDeclaredAuthority(t *testing.T) {
	ownPEM, own, ownKey := authority(t, "Cloud SQL Server CA own", time.Now().Add(10*365*24*time.Hour))
	otherPEM, _, _ := authority(t, "Cloud SQL Server CA other", time.Now().Add(10*365*24*time.Hour))
	server := serverCertificate(t, "store.identity.internal.example.com", own, ownKey)

	ownPool, err := serverTrustAnchor(ownPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Verify(x509.VerifyOptions{Roots: ownPool, DNSName: "store.identity.internal.example.com"}); err != nil {
		t.Fatalf("the instance's own authority did not verify its server: %v", err)
	}
	otherPool, err := serverTrustAnchor(otherPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Verify(x509.VerifyOptions{Roots: otherPool, DNSName: "store.identity.internal.example.com"}); err == nil {
		t.Fatal("a server verified against an authority that did not sign it")
	}
	// Pinning narrows the authority and leaves hostname verification alone.
	if _, err := server.Verify(x509.VerifyOptions{Roots: ownPool, DNSName: "attacker.example.com"}); err == nil {
		t.Fatal("pinning an authority suppressed hostname verification")
	}
}

func TestServerTrustAnchorAcceptsABundle(t *testing.T) {
	first, _, _ := authority(t, "CA one", time.Now().Add(time.Hour))
	second, _, _ := authority(t, "CA two", time.Now().Add(time.Hour))
	if _, err := serverTrustAnchor(first + second); err != nil {
		t.Fatalf("a two-authority bundle was refused: %v", err)
	}
}

func TestServerTrustAnchorRefusesWhatALenientParseWouldSwallow(t *testing.T) {
	_, leafIssuer, leafIssuerKey := authority(t, "CA", time.Now().Add(time.Hour))
	leaf := serverCertificate(t, "store.example.com", leafIssuer, leafIssuerKey)
	expired, _, _ := authority(t, "Expired CA", time.Now().Add(-time.Minute))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	for name, anchor := range map[string]string{
		"empty":                   "",
		"whitespace":              "   \n  ",
		"not pem":                 "-- this is a certificate, promise --",
		"escaped newlines":        "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----",
		"a private key":           privateKeyPEM,
		"a server leaf, not a CA": encodeCertificate(t, leaf.Raw),
		"an expired authority":    expired,
		"truncated body":          "-----BEGIN CERTIFICATE-----\nnotbase64!!\n-----END CERTIFICATE-----\n",
	} {
		t.Run(name, func(t *testing.T) {
			pool, err := serverTrustAnchor(anchor)
			if !errors.Is(err, ErrServerTrustAnchor) {
				t.Fatalf("err = %v, want ErrServerTrustAnchor", err)
			}
			if pool != nil {
				t.Fatal("a refused anchor returned a pool")
			}
		})
	}
}

func TestParseConnectionPinsTheDeclaredAuthorityWithoutWeakeningAnything(t *testing.T) {
	cleanProfileEnvironment(t)
	anchorPEM, _, _ := authority(t, "Cloud SQL Server CA", time.Now().Add(time.Hour))
	host := "store.identity.internal.example.com"
	dsn := "postgresql://writer@" + host + "/saas?sslmode=verify-full"
	profile := ConnectionProfile{Transport: VerifiedTLS, ServerTrustAnchorPEM: anchorPEM}

	parsed, err := ParseConnection(dsn, profile, true)
	if err != nil {
		t.Fatal(err)
	}
	tls := parsed.ConnConfig.TLSConfig
	if tls == nil || tls.RootCAs == nil {
		t.Fatal("the declared authority did not reach the driver configuration")
	}
	if tls.InsecureSkipVerify {
		t.Fatal("pinning an authority turned verification off")
	}
	if tls.ServerName != host {
		t.Fatalf("ServerName = %q, want %q", tls.ServerName, host)
	}
	if len(parsed.ConnConfig.Fallbacks) != 0 {
		t.Fatal("a pinned connection kept a fallback that is not pinned")
	}
}

// The file form and the declared value are two answers to one question, and the
// file is the one a deployment with no mount seam cannot deliver.
func TestParseConnectionRefusesAFileAnchorBesideADeclaredOne(t *testing.T) {
	cleanProfileEnvironment(t)
	anchorPEM, _, _ := authority(t, "Cloud SQL Server CA", time.Now().Add(time.Hour))
	host := "store.identity.internal.example.com"
	// pgx reads the named file while parsing, so the file form is only
	// exercisable against one that exists.
	onDisk := filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(onDisk, []byte(anchorPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	withFile := "postgresql://writer@" + host + "/saas?sslmode=verify-full&sslrootcert=" + onDisk
	if _, err := ParseConnection(withFile, ConnectionProfile{Transport: VerifiedTLS, ServerTrustAnchorPEM: anchorPEM}, false); !errors.Is(err, ErrConnectionProfile) {
		t.Fatalf("err = %v, want ErrConnectionProfile", err)
	}
	// Without a declared anchor the file form is still the supported spelling.
	if _, err := ParseConnection(withFile, ConnectionProfile{Transport: VerifiedTLS}, false); err != nil {
		t.Fatalf("a file anchor alone was refused: %v", err)
	}
}

func TestConnectionProfileRefusesAnAnchorOnATransportThatVerifiesNothing(t *testing.T) {
	anchorPEM, _, _ := authority(t, "Cloud SQL Server CA", time.Now().Add(time.Hour))
	for _, transport := range []ConnectionTransport{LocalIdentityProxy, MeshProtected, LocalLoopback} {
		profile := ConnectionProfile{Transport: transport, ServerTrustAnchorPEM: anchorPEM}
		if err := profile.validate(); !errors.Is(err, ErrServerTrustAnchor) {
			t.Fatalf("transport %q: err = %v, want ErrServerTrustAnchor", transport, err)
		}
	}
}

// The reason has to survive the option, or the operator who supplied a bad
// anchor is told only that a connection profile is invalid.
func TestWithConnectionProfilesReportsWhyAnAnchorWasRefused(t *testing.T) {
	var configuration config
	bad := ConnectionProfile{Transport: VerifiedTLS, ServerTrustAnchorPEM: "not a certificate"}
	good := ConnectionProfile{Transport: VerifiedTLS}
	if err := WithConnectionProfiles(bad, good)(&configuration); !errors.Is(err, ErrServerTrustAnchor) {
		t.Fatalf("reader anchor: err = %v, want ErrServerTrustAnchor", err)
	}
	if err := WithConnectionProfiles(good, bad)(&configuration); !errors.Is(err, ErrServerTrustAnchor) {
		t.Fatalf("writer anchor: err = %v, want ErrServerTrustAnchor", err)
	}
	if err := WithMaintenanceConnectionProfile(bad)(&configuration); !errors.Is(err, ErrServerTrustAnchor) {
		t.Fatalf("maintenance anchor: err = %v, want ErrServerTrustAnchor", err)
	}
	// An unsupported transport still collapses to the profile error it always did.
	if err := WithConnectionProfiles(ConnectionProfile{Transport: "carrier-pigeon"}, good)(&configuration); !errors.Is(err, ErrConnectionProfile) {
		t.Fatalf("err = %v, want ErrConnectionProfile", err)
	}
}
