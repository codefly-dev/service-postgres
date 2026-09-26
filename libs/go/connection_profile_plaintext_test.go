package postgres

import (
	"errors"
	"strings"
	"testing"
)

// The two plaintext profiles accept exactly the connection the Postgres agent
// renders — a named in-cluster host, or a loopback one, with sslmode=disable —
// and nothing that would widen it.
func TestPlaintextConnectionProfiles(t *testing.T) {
	cleanProfileEnvironment(t)
	mesh := "postgres://reader:secret@store.runtime.svc.cluster.local:80/catalog?sslmode=disable"
	loopback := "postgres://reader:secret@localhost:5432/catalog?sslmode=disable"
	for _, tc := range []struct {
		name, dsn string
		profile   ConnectionProfile
		host      string
		port      uint16
	}{
		{"mesh", mesh, ConnectionProfile{Transport: MeshProtected}, "store.runtime.svc.cluster.local", 80},
		{"mesh role", mesh + "&role=request_group", ConnectionProfile{Transport: MeshProtected, ApplicationRole: "request_group"}, "store.runtime.svc.cluster.local", 80},
		{"mesh exact binding", mesh, ConnectionProfile{Transport: MeshProtected, Host: "store.runtime.svc.cluster.local", Port: 80, Database: "catalog", User: "reader"}, "store.runtime.svc.cluster.local", 80},
		{"loopback name", loopback, ConnectionProfile{Transport: LocalLoopback}, "localhost", 5432},
		{"loopback IPv4", strings.Replace(loopback, "localhost", "127.0.0.1", 1), ConnectionProfile{Transport: LocalLoopback}, "127.0.0.1", 5432},
		{"loopback IPv6", strings.Replace(loopback, "localhost", "[::1]", 1), ConnectionProfile{Transport: LocalLoopback}, "::1", 5432},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := ParseConnection(tc.dsn, tc.profile, false)
			if err != nil {
				t.Fatal(err)
			}
			c := pc.ConnConfig
			if c.Host != tc.host || c.Port != tc.port || c.User != "reader" || c.Password != "secret" || c.Database != "catalog" || c.RuntimeParams["role"] != tc.profile.ApplicationRole || len(c.Fallbacks) != 0 || c.TLSConfig != nil {
				t.Fatal("effective binding changed")
			}
		})
	}
	for _, tc := range []struct {
		dsn     string
		profile ConnectionTransport
	}{
		// sslmode is exactly "disable": anything else is a TLS question these
		// profiles do not answer.
		{strings.Replace(mesh, "disable", "prefer", 1), MeshProtected},
		{strings.Replace(mesh, "disable", "require", 1), MeshProtected},
		{strings.Replace(mesh, "disable", "verify-full", 1), MeshProtected},
		{strings.Replace(mesh, "?sslmode=disable", "", 1), MeshProtected},
		{mesh + "&sslrootcert=/private/root", MeshProtected},
		{mesh + "&sslcert=/private/cert", MeshProtected},
		{mesh + "&passfile=/private/passfile", MeshProtected},
		{mesh + "&host=/tmp/socket", MeshProtected},
		{mesh + "&application_name=x", MeshProtected},
		{strings.Replace(mesh, "store.runtime.svc.cluster.local:80", "a:80,b:80", 1), MeshProtected},
		{strings.Replace(mesh, "store.runtime.svc.cluster.local:80", "", 1), MeshProtected},
		// Loopback means loopback.
		{strings.Replace(loopback, "localhost", "store.example", 1), LocalLoopback},
		{strings.Replace(loopback, "localhost", "10.0.0.1", 1), LocalLoopback},
		{strings.Replace(loopback, "localhost", "localhost.example", 1), LocalLoopback},
		{strings.Replace(loopback, "disable", "prefer", 1), LocalLoopback},
		// A verified-TLS binding is not a plaintext one.
		{"postgres://reader@db.example:5432/catalog?sslmode=verify-full", MeshProtected},
	} {
		_, err := ParseConnection(tc.dsn, ConnectionProfile{Transport: tc.profile}, false)
		if !errors.Is(err, ErrConnectionProfile) {
			t.Fatalf("unsafe %s binding accepted: %q", tc.profile, tc.dsn)
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "store") {
			t.Fatal("error disclosed binding")
		}
	}
	// A plaintext connection is never accepted under the verified profile.
	if _, err := ParseConnection(mesh, ConnectionProfile{Transport: VerifiedTLS}, false); !errors.Is(err, ErrConnectionProfile) {
		t.Fatal("plaintext accepted as verified TLS")
	}
}
