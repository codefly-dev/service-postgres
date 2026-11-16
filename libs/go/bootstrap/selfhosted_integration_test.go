//go:build controlplaneintegration

package bootstrap

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/codefly-dev/service-postgres/libs/go/controlplane"
)

// TestSelfHostedBootstrapProvisionsPasswordLogins runs the in-cluster path: the
// owner connects with its password, migrations run under the lock, and the
// read-only, read-write and declared logins are created with their passwords,
// delegated roles and defaults. A replay changes nothing and rotates passwords.
func TestSelfHostedBootstrapProvisionsPasswordLogins(t *testing.T) {
	admin := fixtureDB(t, "postgres", "postgres")
	statement(t, admin, "CREATE ROLE selfhosted_owner LOGIN CREATEROLE NOSUPERUSER PASSWORD 'owner-only'")
	statement(t, admin, "CREATE DATABASE selfhosted_proof OWNER selfhosted_owner")
	dir, p, b := packageFixture(t, "CREATE TABLE receipts(id serial PRIMARY KEY, value text); CREATE ROLE selfhosted_app NOLOGIN; GRANT INSERT, SELECT ON receipts TO selfhosted_app; GRANT USAGE ON SEQUENCE receipts_id_seq TO selfhosted_app;")
	p.Database = "selfhosted_proof"
	// Roles are cluster-wide: these must not be the managed test's groups.
	p.Access.ReadOnlyRole, p.Access.ReadWriteRole = "selfhosted_ro", "selfhosted_rw"
	p.Access.ReadWriteRoles = []string{"selfhosted_app"}
	b = Binding{OwnerRole: "selfhosted_owner"}
	writePlan(t, dir, p, &b)
	u, _ := url.Parse(os.Getenv("SERVICE_POSTGRES_CONTROLPLANE_TEST_DSN"))
	u.Path, u.User, u.RawQuery = "/selfhosted_proof", url.User(b.OwnerRole), "sslmode=disable"
	o := Options{Directory: dir, Binding: b, Connection: u.String(), MigrateExecutable: os.Getenv("SERVICE_POSTGRES_MIGRATE_EXECUTABLE"),
		Timeout: 30 * time.Second, LockTimeout: 3 * time.Second, StatementTimeout: 5 * time.Second, ReadinessTimeout: 5 * time.Second,
		Password: &Password{Owner: "owner-only", ReadOnly: "ro-secret", ReadWrite: "rw-secret",
			Logins: []controlplane.PasswordLogin{{Role: "selfhosted_maintenance", Password: "maintenance-secret", ReadWriteRoles: []string{"selfhosted_app"}}}}}
	for run := 0; run < 2; run++ {
		r, e := Run(context.Background(), o)
		if e != nil || !r.AccessCommitted || len(r.CompletedLineages) != 1 {
			t.Fatalf("run %d: %+v %v", run, r, e)
		}
	}
	for role, want := range map[string]string{
		"selfhosted_ro":          "t f f f f",
		"selfhosted_rw":          "t f f f f",
		"selfhosted_maintenance": "t f f f f",
	} {
		got := value(t, admin, "SELECT concat_ws(' ', rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole) FROM pg_roles WHERE rolname='"+role+"'")
		if got != want {
			t.Fatalf("%s attributes %q, want %q", role, got, want)
		}
		if value(t, admin, "SELECT (rolpassword IS NOT NULL)::text FROM pg_authid WHERE rolname='"+role+"'") != "true" {
			t.Fatalf("%s has no password", role)
		}
	}
	if value(t, admin, "SELECT string_agg(r.rolname, ',' ORDER BY r.rolname) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles l ON l.oid=m.member WHERE l.rolname IN ('selfhosted_rw','selfhosted_maintenance')") != "selfhosted_app,selfhosted_app" {
		t.Fatal("delegated memberships not reconciled")
	}
	if value(t, admin, "SELECT string_agg(array_to_string(setconfig, ' '), '|' ORDER BY setrole) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole WHERE r.rolname IN ('selfhosted_ro','selfhosted_rw','selfhosted_maintenance')") != "default_transaction_read_only=on|role=selfhosted_app|role=selfhosted_app" {
		t.Fatal("login defaults not set")
	}
	if value(t, admin, "SELECT count(*)::text FROM pg_roles WHERE rolname LIKE 'selfhosted_%' AND rolcanlogin") != "4" {
		t.Fatal("unexpected login set: want owner, ro, rw and maintenance")
	}
	owner := fixtureDB(t, "selfhosted_proof", "selfhosted_owner")
	if value(t, owner, "SELECT (version=1 AND NOT dirty)::text FROM schema_migrations_application") != "true" {
		t.Fatal("ledger mismatch")
	}
}
