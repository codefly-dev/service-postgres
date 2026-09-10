package postgres

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRestrictedSessionOption(t *testing.T) {
	for _, roles := range [][]string{{""}, {" group"}, {"group", "group"}, {strings.Repeat("x", 64)}, {"bad\x00role"}} {
		if _, err := configured(WithRestrictedSession(roles...)); err == nil {
			t.Fatal("invalid denied roles accepted")
		}
	}
	roles := []string{"background_jobs"}
	option := WithRestrictedSession(roles...)
	roles[0] = "changed"
	c, err := configured(option)
	if err != nil || !c.restrictedSession || c.deniedRoles[0] != "background_jobs" {
		t.Fatal("option retained mutable caller data")
	}
	c.deniedRoles[0] = "changed again"
	c2, err := configured(option)
	if err != nil || c2.deniedRoles[0] != "background_jobs" {
		t.Fatal("configurations share mutable role data")
	}
	if _, err := configured(WithRestrictedSession()); err != nil {
		t.Fatal(err)
	}
}

// The DSN must name a disposable local database with a superuser fixture owner.
// CI supplies its own isolated container. No developer or hosted database is used.
func TestRestrictedSessionPostgres(t *testing.T) {
	dsn := os.Getenv("SESSION_POLICY_TEST_DSN")
	if dsn == "" {
		t.Skip("SESSION_POLICY_TEST_DSN is required for the real-database role regression")
	}
	endpoint, err := url.Parse(dsn)
	if err != nil || endpoint.Scheme != "postgres" || (endpoint.Hostname() != "127.0.0.1" && endpoint.Hostname() != "localhost" && endpoint.Hostname() != "::1") {
		t.Fatal("role regression requires a loopback PostgreSQL URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("cannot connect to isolated role fixture")
	}
	defer admin.Close(context.Background())
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	prefix := fmt.Sprintf("policy_%d_", time.Now().UnixNano())
	role := func(name string) string { return prefix + name }
	ident := func(name string) string { return pgx.Identifier{role(name)}.Sanitize() }
	names := []string{"reader", "writer", "jobs", "intermediate", "owner", "privileged"}
	for _, name := range names {
		attrs := "NOLOGIN"
		if name == "reader" || name == "writer" {
			attrs = "LOGIN NOINHERIT PASSWORD 'isolated-fixture-only'"
		}
		exec("CREATE ROLE " + ident(name) + " " + attrs)
	}
	originalOwner := ""
	if err := admin.QueryRow(ctx, "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()").Scan(&originalOwner); err != nil {
		t.Fatal(err)
	}
	db := ""
	if err := admin.QueryRow(ctx, "SELECT current_database()").Scan(&db); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "ALTER DATABASE "+pgx.Identifier{db}.Sanitize()+" OWNER TO "+pgx.Identifier{originalOwner}.Sanitize()); err != nil {
			t.Error(err)
		}
		for _, name := range names {
			if _, err := admin.Exec(cleanup, "DROP ROLE "+ident(name)); err != nil {
				t.Error(err)
			}
		}
	}()
	connection := func(name string) string {
		u := *endpoint
		u.User = url.UserPassword(role(name), "isolated-fixture-only")
		return u.String()
	}
	policy := WithRestrictedSession(role("jobs"))
	auth := fakeAuthenticator{principal: testPrincipal{tenant: "tenant", user: "user"}}
	open := func(option ...Option) (*Factory, func(), error) {
		return Open(ctx, connection("reader"), connection("writer"), auth, option...)
	}
	assertRejected := func() {
		t.Helper()
		_, close, err := open(policy)
		if close != nil {
			close()
		}
		if err == nil {
			t.Fatal("unsafe session accepted")
		}
		if strings.Contains(err.Error(), "isolated-fixture-only") || strings.Contains(err.Error(), role("writer")) {
			t.Fatal("role-policy error disclosed credentials or identity")
		}
	}
	t.Run("safe and missing role", func(t *testing.T) {
		_, close, err := open(policy)
		if err != nil {
			t.Fatal(err)
		}
		close()
		_, close, err = open(WithRestrictedSession(role("absent")))
		if close != nil {
			close()
		}
		if err == nil {
			t.Fatal("missing denied role accepted")
		}
	})
	t.Run("direct and transitive membership", func(t *testing.T) {
		exec("GRANT " + ident("jobs") + " TO " + ident("writer"))
		assertRejected()
		// Without the opt-in policy, existing consumers keep their prior behavior.
		_, close, err := open()
		if err != nil {
			t.Fatal(err)
		}
		close()
		exec("REVOKE " + ident("jobs") + " FROM " + ident("writer"))
		exec("GRANT " + ident("jobs") + " TO " + ident("intermediate"))
		exec("GRANT " + ident("intermediate") + " TO " + ident("reader"))
		assertRejected()
		exec("REVOKE " + ident("intermediate") + " FROM " + ident("reader"))
	})
	t.Run("privileged and owner membership", func(t *testing.T) {
		exec("ALTER ROLE " + ident("privileged") + " CREATEROLE")
		exec("GRANT " + ident("privileged") + " TO " + ident("writer"))
		assertRejected()
		exec("REVOKE " + ident("privileged") + " FROM " + ident("writer"))
		exec("ALTER ROLE " + ident("reader") + " BYPASSRLS")
		assertRejected()
		exec("ALTER ROLE " + ident("reader") + " NOBYPASSRLS")
		exec("ALTER DATABASE " + pgx.Identifier{db}.Sanitize() + " OWNER TO " + ident("owner"))
		exec("GRANT " + ident("owner") + " TO " + ident("writer"))
		assertRejected()
		exec("REVOKE " + ident("owner") + " FROM " + ident("writer"))
	})
	t.Run("permission change on pooled session", func(t *testing.T) {
		factory, close, err := open(policy)
		if err != nil {
			t.Fatal(err)
		}
		defer close()
		writer, err := factory.Writer(ctx)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		transaction := func(ctx context.Context, tx WriteTx) error { calls++; _, err := tx.Exec(ctx, "SELECT 1"); return err }
		if err := writer.InTransaction(ctx, transaction); err != nil {
			t.Fatal(err)
		}
		exec("GRANT " + ident("jobs") + " TO " + ident("writer"))
		if err := writer.InTransaction(ctx, transaction); err == nil {
			t.Fatal("existing pool accepted newly forbidden membership")
		}
		if calls != 1 {
			t.Fatal("application callback ran under forbidden authority")
		}
		exec("REVOKE " + ident("jobs") + " FROM " + ident("writer"))
		if err := writer.InTransaction(ctx, transaction); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("maintenance composes existing validation", func(t *testing.T) {
		exec("GRANT " + ident("jobs") + " TO " + ident("writer"))
		_, close, err := OpenMaintenance(ctx, connection("writer"), role("jobs"), WithRestrictedSession())
		if err != nil {
			t.Fatal(err)
		}
		close()
		_, close, err = OpenMaintenance(ctx, connection("writer"), role("jobs"), policy)
		if close != nil {
			close()
		}
		if err == nil {
			t.Fatal("maintenance ignored denied group")
		}
		exec("ALTER ROLE " + ident("jobs") + " LOGIN")
		_, close, err = OpenMaintenance(ctx, connection("writer"), role("jobs"), WithRestrictedSession())
		if close != nil {
			close()
		}
		if err == nil {
			t.Fatal("existing maintenance login-role check bypassed")
		}
	})
	t.Run("existing connection hooks preserved", func(t *testing.T) {
		pc, err := pgxpool.ParseConfig(connection("reader"))
		if err != nil {
			t.Fatal(err)
		}
		after, before := false, false
		pc.AfterConnect = func(context.Context, *pgx.Conn) error { after = true; return nil }
		pc.BeforeAcquire = func(context.Context, *pgx.Conn) bool { before = true; return true }
		c, _ := configured(policy)
		installRestrictedSession(pc, c)
		pool, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		if err := pool.Ping(ctx); err != nil {
			t.Fatal(err)
		}
		if !after || !before {
			t.Fatal("existing connection hooks were replaced")
		}
	})
}
