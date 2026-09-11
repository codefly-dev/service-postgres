//go:build controlplaneintegration

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixtureDB(t *testing.T, database, user string) *sql.DB {
	t.Helper()
	u, e := url.Parse(os.Getenv("SERVICE_POSTGRES_CONTROLPLANE_TEST_DSN"))
	if e != nil || u == nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.Port() == "" {
		t.Fatal("use scripts/qualify-controlplane.py with its disposable loopback fixture")
	}
	u.Path = "/" + database
	u.User = url.User(user)
	u.RawQuery = "sslmode=disable&connect_timeout=5"
	db, e := sql.Open("postgres", u.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
func statement(t *testing.T, db *sql.DB, sql string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, e := db.ExecContext(ctx, sql); e != nil {
		t.Fatal(e)
	}
}
func value(t *testing.T, db *sql.DB, sql string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var v string
	if e := db.QueryRowContext(ctx, sql).Scan(&v); e != nil {
		t.Fatal(e)
	}
	return v
}

func TestManagedBootstrapRestrictedPostgres(t *testing.T) {
	admin := fixtureDB(t, "postgres", "postgres")
	statement(t, admin, "CREATE ROLE bootstrap_owner LOGIN CREATEROLE NOSUPERUSER NOBYPASSRLS")
	statement(t, admin, "CREATE ROLE bootstrap_reader LOGIN INHERIT PASSWORD 'fixture-only'")
	statement(t, admin, "CREATE ROLE bootstrap_writer LOGIN INHERIT PASSWORD 'fixture-only'")
	statement(t, admin, "CREATE DATABASE bootstrap_proof OWNER bootstrap_owner")
	owner := fixtureDB(t, "bootstrap_proof", "bootstrap_owner")
	reader := fixtureDB(t, "bootstrap_proof", "bootstrap_reader")
	writer := fixtureDB(t, "bootstrap_proof", "bootstrap_writer")
	password := value(t, admin, "SELECT rolpassword FROM pg_authid WHERE rolname='bootstrap_writer'")
	// The deliberate delay overlaps concurrent bootstraps; the unguarded INSERT
	// exposes duplicate execution of the migration rather than hiding it.
	dir, p, b := packageFixture(t, "CREATE TABLE receipts(id serial PRIMARY KEY,value text); INSERT INTO receipts(value) VALUES ('once'); SELECT pg_sleep(0.3);")
	u, _ := url.Parse(os.Getenv("SERVICE_POSTGRES_CONTROLPLANE_TEST_DSN"))
	u.Path = "/bootstrap_proof"
	u.User = url.User(b.OwnerRole)
	u.RawQuery = "sslmode=disable"
	o := Options{Directory: dir, Binding: b, Connection: u.String(), MigrateExecutable: os.Getenv("SERVICE_POSTGRES_MIGRATE_EXECUTABLE"), Timeout: 10 * time.Second, LockTimeout: 3 * time.Second, StatementTimeout: 5 * time.Second}
	t.Run("missing principal rejects before migration", func(t *testing.T) {
		bad := o
		bad.Binding.ReadWritePrincipals = []string{"missing_external"}
		if _, e := Run(context.Background(), bad); e == nil {
			t.Fatal("accepted missing principal")
		}
		if value(t, owner, "SELECT (to_regclass('receipts') IS NULL)::text") != "true" {
			t.Fatal("provider work preceded principal validation")
		}
	})
	t.Run("login group rejects before migration", func(t *testing.T) {
		statement(t, admin, "CREATE ROLE bootstrap_ro LOGIN")
		if _, e := Run(context.Background(), o); e == nil {
			t.Fatal("would rewrite cloud login")
		}
		statement(t, admin, "DROP ROLE bootstrap_ro")
		if value(t, owner, "SELECT (to_regclass('receipts') IS NULL)::text") != "true" {
			t.Fatal("migration ran")
		}
	})
	t.Run("concurrent jobs and replay", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, e := Run(context.Background(), o)
				if e == nil && !r.AccessCommitted {
					t.Error("missing committed access")
				}
				errs <- e
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			if e != nil {
				t.Fatal(e)
			}
		}
		if value(t, owner, "SELECT count(*)::text FROM receipts") != "1" {
			t.Fatal("migration executed more than once")
		}
		if value(t, owner, "SELECT (version=1 AND NOT dirty)::text FROM schema_migrations_application") != "true" {
			t.Fatal("ledger mismatch")
		}
	})
	t.Run("principals unchanged and restricted", func(t *testing.T) {
		if value(t, admin, "SELECT rolpassword FROM pg_authid WHERE rolname='bootstrap_writer'") != password {
			t.Fatal("password changed")
		}
		statement(t, writer, "INSERT INTO receipts(value) VALUES ('writer')")
		if value(t, reader, "SELECT count(*)::text FROM receipts") != "2" {
			t.Fatal("reader cannot read")
		}
		for _, db := range []*sql.DB{reader, writer} {
			if _, e := db.Exec("CREATE TABLE forbidden(id integer)"); e == nil {
				t.Fatal("runtime DDL succeeded")
			}
		}
		if _, e := reader.Exec("INSERT INTO receipts(value) VALUES ('forbidden')"); e == nil {
			t.Fatal("reader DML succeeded")
		}
		statement(t, owner, "CREATE TABLE after_bootstrap(id serial,value text)")
		statement(t, writer, "INSERT INTO after_bootstrap(value) VALUES ('default privileges')")
		if value(t, reader, "SELECT value FROM after_bootstrap") != "default privileges" {
			t.Fatal("default privileges mismatch")
		}
	})
	t.Run("shared lock bounded and released", func(t *testing.T) {
		conn, e := owner.Conn(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		if _, e = conn.ExecContext(context.Background(), "SELECT pg_advisory_lock(hashtext('codefly-runtime-access:' || current_database()))"); e != nil {
			t.Fatal(e)
		}
		blocked := o
		blocked.LockTimeout = 100 * time.Millisecond
		start := time.Now()
		_, e = Run(context.Background(), blocked)
		if e == nil || time.Since(start) > 2*time.Second {
			t.Fatal("lock not bounded")
		}
		conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock_all()")
		if _, e = Run(context.Background(), o); e != nil {
			t.Fatal("failed job leaked lock:", e)
		}
	})
	t.Run("served command replay", func(t *testing.T) {
		binding := filepath.Join(t.TempDir(), "binding.json")
		data, _ := json.Marshal(b)
		os.WriteFile(binding, data, 0600)
		cmd := exec.Command(os.Getenv("SERVICE_POSTGRES_BOOTSTRAP_EXECUTABLE"), "-package", dir, "-binding", binding, "-migrate", o.MigrateExecutable, "-timeout", "10s", "-lock-timeout", "3s", "-statement-timeout", "5s")
		cmd.Env = []string{"CODEFLY_POSTGRES_MIGRATION_CONNECTION=" + o.Connection, "PGPASSWORD=fixture-should-not-be-used", "PGOPTIONS=-c role=bootstrap_reader"}
		output, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatal("command failed:", e, string(output))
		}
		var r Result
		if e = json.Unmarshal(output, &r); e != nil || !r.AccessCommitted || r.PlanDigest != p.Digest {
			t.Fatal("command receipt mismatch")
		}
	})
	t.Run("dirty failure and cancellation skip access", func(t *testing.T) {
		// Separate ledgers let this test exercise dirty recovery without forcing or
		// repairing the successful lineage. The sentinel must never appear in logs.
		for _, kind := range []string{"dirty", "cancel"} {
			t.Run(kind, func(t *testing.T) {
				statement(t, owner, "REVOKE bootstrap_rw FROM bootstrap_writer")
				sqlText := "SELECT 'private sentinel'::integer;"
				if kind == "cancel" {
					sqlText = "SELECT pg_sleep(20);"
				}
				d, plan, binding := packageFixture(t, sqlText)
				plan.Lineages[0].Ledger = "schema_migrations_" + kind
				plan.Lineages[0].Digest = plan.Lineages[0].ContentDigest()
				writePlan(t, d, plan, &binding)
				failed := o
				failed.Directory = d
				failed.Binding = binding
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if kind == "cancel" {
					time.AfterFunc(300*time.Millisecond, cancel)
				}
				start := time.Now()
				r, e := Run(ctx, failed)
				if e == nil || r.AccessCommitted || strings.Contains(e.Error(), "private sentinel") {
					t.Fatal("unsafe failure result")
				}
				if value(t, owner, "SELECT pg_has_role('bootstrap_writer','bootstrap_rw','MEMBER')::text") != "false" {
					t.Fatal("failed migration changed runtime access")
				}
				if value(t, owner, "SELECT count(*)::text FROM pg_stat_activity WHERE application_name LIKE 'codefly-bootstrap-%'") != "0" {
					t.Fatal("child database session survived lock release")
				}
				if kind == "cancel" && time.Since(start) > 3*time.Second {
					t.Fatal("cancellation did not stop child")
				}
				if kind == "dirty" {
					if value(t, owner, "SELECT dirty::text FROM schema_migrations_dirty") != "true" {
						t.Fatal("dirty state lost")
					}
					if r, e = Run(context.Background(), failed); e == nil || r.AccessCommitted {
						t.Fatal("dirty state silently repaired")
					}
				}
			})
		}
	})
}
