package postgres

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
)

func cleanProfileEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "PG") {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestConnectionProfileBindings(t *testing.T) {
	cleanProfileEnvironment(t)
	tls := "postgres://reader@db.example:5432/catalog?sslmode=verify-full"
	proxy := "postgres://reader@/catalog?host=/tmp/private-reader&port=5432&sslmode=disable&passfile=/dev/null"
	for _, tc := range []struct {
		name, dsn string
		profile   ConnectionProfile
		host      string
		role      string
	}{
		{"verified", tls, ConnectionProfile{Transport: VerifiedTLS}, "db.example", ""},
		{"verified role", tls + "&role=request_group", ConnectionProfile{Transport: VerifiedTLS, ApplicationRole: "request_group"}, "db.example", "request_group"},
		{"proxy", proxy, ConnectionProfile{Transport: LocalIdentityProxy}, "/tmp/private-reader", ""},
		{"proxy role", proxy + "&role=request_group", ConnectionProfile{Transport: LocalIdentityProxy, ApplicationRole: "request_group"}, "/tmp/private-reader", "request_group"},
		{"exact binding", tls, ConnectionProfile{Transport: VerifiedTLS, Host: "db.example", Port: 5432, Database: "catalog", User: "reader"}, "db.example", ""},
		{"IPv6", "postgres://reader@[::1]:5432/catalog?sslmode=verify-full", ConnectionProfile{Transport: VerifiedTLS}, "::1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := ParseConnection(tc.dsn, tc.profile, false)
			if err != nil {
				t.Fatal(err)
			}
			c := pc.ConnConfig
			if c.Host != tc.host || c.Port != 5432 || c.User != "reader" || c.Database != "catalog" || c.RuntimeParams["role"] != tc.role || len(c.Fallbacks) != 0 {
				t.Fatal("effective binding changed")
			}
			if tc.profile.Transport == VerifiedTLS && (c.TLSConfig == nil || c.TLSConfig.InsecureSkipVerify || c.TLSConfig.ServerName != tc.host || len(c.TLSConfig.Certificates) != 0) {
				t.Fatal("TLS identity changed")
			}
			if tc.profile.Transport == LocalIdentityProxy && (c.TLSConfig != nil || c.Password != "") {
				t.Fatal("proxy credentials changed")
			}
		})
	}
	for _, key := range []string{"ROLE", "Role", "role", "session_authorization", "SESSION_AUTHORIZATION", "options", "OPTIONS", "host", "HOST", "hostaddr", "port", "user", "password", "dbname", "database", "service", "servicefile", "target_session_attrs", "sslnegotiation", "unknown", "sslMode", "SSLMode"} {
		t.Run("reject key "+key, func(t *testing.T) {
			if _, err := ParseConnection(tls+"&"+key+"=private-value", ConnectionProfile{Transport: VerifiedTLS}, false); !errors.Is(err, ErrConnectionProfile) {
				t.Fatal("unreviewed option accepted", key, err)
			}
		})
	}
	for _, dsn := range []string{
		tls + "&sslmode=verify-full", tls + "&role=", tls + "&application_name=x&application_name=y", tls + "&application_name=%00",
		tls + "&passfile=/private/credential", tls + "&sslrootcert=/private/missing-root", strings.Replace(tls, "verify-full", "prefer", 1),
		strings.Replace(tls, "verify-full", "verify-ca", 1), strings.Replace(tls, "db.example:5432", "a:5432,b:5432", 1),
		strings.Replace(tls, "db.example:5432", "", 1), strings.Replace(tls, "/catalog", "/", 1), strings.Replace(tls, "/catalog", "/a/b", 1),
		strings.Replace(tls, "reader@", "@", 1), tls + "#fragment", "user=reader host=db.example dbname=catalog sslmode=verify-full",
	} {
		_, err := ParseConnection(dsn, ConnectionProfile{Transport: VerifiedTLS}, false)
		if !errors.Is(err, ErrConnectionProfile) {
			t.Fatalf("unsafe TLS binding accepted: %q", dsn)
		}
		if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "db.example") {
			t.Fatal("error disclosed binding")
		}
	}
	for _, dsn := range []string{proxy + "&role=", proxy + "&application_name=x", proxy + "&host=/tmp/other", proxy + "&user=other", strings.Replace(proxy, "reader@", "reader:@", 1), strings.Replace(proxy, "reader@", "reader:secret@", 1), strings.Replace(proxy, "@/catalog", "@localhost/catalog", 1), strings.Replace(proxy, "/tmp/private-reader", "/tmp/../private-reader", 1), strings.Replace(proxy, "/tmp/private-reader", "/tmp/a,/tmp/b", 1), strings.Replace(proxy, "port=5432", "port=05432", 1), strings.Replace(proxy, "/dev/null", "/private/passfile", 1)} {
		if _, err := ParseConnection(dsn, ConnectionProfile{Transport: LocalIdentityProxy}, false); !errors.Is(err, ErrConnectionProfile) {
			t.Fatalf("unsafe proxy accepted: %q", dsn)
		}
	}
	if _, err := ParseConnection(proxy, ConnectionProfile{Transport: LocalIdentityProxy}, true); !errors.Is(err, ErrConnectionProfile) {
		t.Fatal("proxy token hook accepted")
	}
	for _, p := range []ConnectionProfile{{Transport: "automatic"}, {ApplicationRole: "unexpected"}, {Transport: VerifiedTLS, ApplicationRole: "missing"}, {Transport: VerifiedTLS, Host: "other"}, {Transport: VerifiedTLS, Port: 9999}, {Transport: VerifiedTLS, Database: "other"}, {Transport: VerifiedTLS, User: "other"}} {
		if _, err := ParseConnection(tls, p, false); !errors.Is(err, ErrConnectionProfile) {
			t.Fatal("profile mismatch accepted")
		}
	}
}

func TestConnectionProfileAmbientAndLegacy(t *testing.T) {
	cleanProfileEnvironment(t)
	dsn := "postgres://reader@db.example/catalog?sslmode=verify-full"
	for _, key := range []string{"PGHOST", "PGPORT", "PGUSER", "PGDATABASE", "PGPASSWORD", "PGPASSFILE", "PGSERVICE", "PGSERVICEFILE", "PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY", "PGOPTIONS", "PGAPPNAME", "PGTARGETSESSIONATTRS", "PGCONNECT_TIMEOUT", "PGUNRECOGNIZED"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "")
			if _, err := ParseConnection(dsn, ConnectionProfile{Transport: VerifiedTLS}, false); !errors.Is(err, ErrConnectionProfile) {
				t.Fatal("ambient key accepted even when empty")
			}
		})
	}
	t.Setenv("PGPASSWORD", "legacy-password")
	c, err := ParseConnection("user=legacy host=localhost dbname=legacy sslmode=disable", ConnectionProfile{}, false)
	if err != nil || c.ConnConfig.Password != "legacy-password" || c.ConnConfig.TLSConfig != nil {
		t.Fatal("legacy driver behavior changed", err)
	}
}

func TestConnectionProfilesValidateBothBeforePoolOrToken(t *testing.T) {
	cleanProfileEnvironment(t)
	called := 0
	provider := func(context.Context, string) (string, error) {
		called++
		return "do-not-leak", errors.New("private-token-path")
	}
	_, close, err := Open(context.Background(), "postgres://reader@unresolvable.invalid/catalog?sslmode=verify-full", "postgres://writer@unresolvable.invalid/catalog?sslmode=verify-full&ROLE=administrator", nil, WithConnectionProfiles(ConnectionProfile{Transport: VerifiedTLS}, ConnectionProfile{Transport: VerifiedTLS}), WithAccessTokenProvider(provider))
	if close != nil || !errors.Is(err, ErrConnectionProfile) || called != 0 {
		t.Fatal("opened pool/provider before both bindings validated", err, called)
	}
	u := &url.URL{Scheme: "postgres", User: url.User("reader"), Path: "/catalog", RawQuery: "host=/tmp/reader&port=5432&sslmode=disable&passfile=/dev/null"}
	reader := u.String()
	u.User = url.User("writer")
	writer := u.String()
	c, err := configured(WithConnectionProfiles(ConnectionProfile{Transport: LocalIdentityProxy}, ConnectionProfile{Transport: LocalIdentityProxy}), WithDistinctProxySockets())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := capabilityConfigsWithProfiles(reader, writer, c); !errors.Is(err, ErrConnectionProfile) {
		t.Fatal("same private socket accepted")
	}
	c.distinctProxySockets = false
	if _, _, err := capabilityConfigsWithProfiles(reader, writer, c); err != nil {
		t.Fatal("service opt-in scope changed", err)
	}
}
