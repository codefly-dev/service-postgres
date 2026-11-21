// Package rowscopefixture builds the principals a row-confinement test needs on
// an isolated loopback Postgres, the way a Codefly Postgres run hands them out:
// a migration owner that is not a superuser, a fixture principal that bypasses
// row security without being one either, and the two runtime logins. It is
// internal: a module's suite receives the same principals from its dependency
// stack (owner-connection, fixture-connection, the read-only and read-write
// connections) and never builds them.
package rowscopefixture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// DSNVariable names a disposable loopback database whose login is a superuser.
// scripts/qualify-controlplane.py supplies its own isolated container; no
// developer or hosted database is used.
const DSNVariable = "ROW_SCOPE_TEST_DSN"

// Sandbox is one isolated database and the principals of one test.
type Sandbox struct {
	// Admin is the superuser the fixture arrived with. Only a test that proves
	// what a superuser bypasses may use it.
	Admin string
	// Owner owns the database and runs migrations: CREATEROLE, and neither a
	// superuser nor BYPASSRLS, like the native run server's migration owner.
	Owner string
	// Fixture is the fixture principal as fixture.go provisions it where the
	// owner is not a superuser: BYPASSRLS, CREATEROLE, a member of the owner.
	Fixture string
	// ReadOnly and ReadWrite are the runtime logins. They are NOINHERIT and
	// hold no table privilege of their own.
	ReadOnly  string
	ReadWrite string

	prefix   string
	endpoint *url.URL
}

// Open creates the sandbox, or skips when no fixture database was supplied.
func Open(t testing.TB) *Sandbox {
	t.Helper()
	dsn := os.Getenv(DSNVariable)
	if dsn == "" {
		t.Skip(DSNVariable + " is required for the real-database row-confinement tests")
	}
	endpoint, err := url.Parse(dsn)
	if err != nil || endpoint.Scheme != "postgres" || (endpoint.Hostname() != "127.0.0.1" && endpoint.Hostname() != "localhost" && endpoint.Hostname() != "::1") {
		t.Fatal("row-confinement tests require a loopback PostgreSQL URL")
	}
	random := make([]byte, 5)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	sandbox := &Sandbox{Admin: dsn, prefix: "rs_" + hex.EncodeToString(random), endpoint: endpoint}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("cannot connect to the isolated row-confinement fixture")
	}
	defer admin.Close(context.Background())
	owner, fixture := sandbox.Role("owner"), sandbox.Role("fixture")
	database := sandbox.Role("db")
	t.Cleanup(sandbox.drop)
	for _, statement := range []string{
		`CREATE ROLE ` + owner + ` LOGIN CREATEROLE NOSUPERUSER NOBYPASSRLS PASSWORD 'isolated-fixture-only'`,
		`CREATE ROLE ` + fixture + ` LOGIN NOSUPERUSER INHERIT BYPASSRLS CREATEROLE CREATEDB NOREPLICATION PASSWORD 'isolated-fixture-only'`,
		`GRANT ` + owner + ` TO ` + fixture,
		`ALTER ROLE ` + fixture + ` SET createrole_self_grant TO 'set, inherit'`,
		`CREATE ROLE ` + sandbox.Role("ro") + ` LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS PASSWORD 'isolated-fixture-only'`,
		`CREATE ROLE ` + sandbox.Role("rw") + ` LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS PASSWORD 'isolated-fixture-only'`,
		`CREATE DATABASE ` + database + ` OWNER ` + owner,
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	sandbox.Admin = sandbox.connection(endpoint.User.Username(), passwordOf(endpoint))
	sandbox.Owner = sandbox.connection(owner, "isolated-fixture-only")
	sandbox.Fixture = sandbox.connection(fixture, "isolated-fixture-only")
	sandbox.ReadOnly = sandbox.connection(sandbox.Role("ro"), "isolated-fixture-only")
	sandbox.ReadWrite = sandbox.connection(sandbox.Role("rw"), "isolated-fixture-only")
	return sandbox
}

// Role returns the sandbox's own name for a role. Roles are cluster-wide, so
// every name a test creates goes through here and is dropped with the sandbox.
func (s *Sandbox) Role(name string) string { return s.prefix + "_" + name }

// Login creates one more NOINHERIT runtime login and returns its connection.
// The owner creates it, as a migration would.
func (s *Sandbox) Login(t testing.TB, name string) string {
	t.Helper()
	s.Exec(t, s.Owner, `CREATE ROLE `+s.Role(name)+` LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS PASSWORD 'isolated-fixture-only'`)
	return s.connection(s.Role(name), "isolated-fixture-only")
}

// Connect opens one connection that the test's cleanup closes.
func (s *Sandbox) Connect(t testing.TB, connection string) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, connection)
	if err != nil {
		t.Fatalf("connect to the row-confinement sandbox: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// Exec runs statements on a short-lived connection of the named principal.
func (s *Sandbox) Exec(t testing.TB, connection string, statements ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, connection)
	if err != nil {
		t.Fatalf("connect to the row-confinement sandbox: %v", err)
	}
	defer conn.Close(context.Background())
	for _, statement := range statements {
		if _, err := conn.Exec(ctx, statement); err != nil {
			t.Fatalf("%v\n%s", err, statement)
		}
	}
}

func (s *Sandbox) connection(user, password string) string {
	endpoint := *s.endpoint
	if password == "" {
		endpoint.User = url.User(user)
	} else {
		endpoint.User = url.UserPassword(user, password)
	}
	endpoint.Path = "/" + s.Role("db")
	return endpoint.String()
}

func passwordOf(endpoint *url.URL) string {
	password, _ := endpoint.User.Password()
	return password
}

// drop removes the database and every role this sandbox named. A failure is
// not hidden: a leaked role would collide with nothing, but it is still a leak.
func (s *Sandbox) drop() {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	endpoint := *s.endpoint
	admin, err := pgx.Connect(ctx, endpoint.String())
	if err != nil {
		return
	}
	defer admin.Close(context.Background())
	_, _ = admin.Exec(ctx, `DROP DATABASE IF EXISTS `+s.Role("db")+` WITH (FORCE)`)
	rows, err := admin.Query(ctx, `SELECT rolname FROM pg_roles WHERE starts_with(rolname, $1)`, s.prefix+"_")
	if err != nil {
		return
	}
	roles, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return
	}
	// Repeated: a role that granted a membership cannot go before its grantee.
	for range 3 {
		for _, role := range roles {
			_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS `+pgx.Identifier{role}.Sanitize())
		}
	}
}
