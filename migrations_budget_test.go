package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4/database"
)

// Both migration budgets are enforced by the server, because golang-migrate's
// postgres driver takes its advisory lock and runs every statement under
// context.Background(): no caller context reaches that SQL. Nothing but a real
// backend holding a real lock and running a real long statement can show that
// the budgets bite, so these tests run one.

func TestMigrationLockBudgetExpiresWhilePeerHoldsTheLock(t *testing.T) {
	const lockBudget = 3 * time.Second
	runtime, connection := budgetRuntime(t, Timeouts{
		MigrationLock:      int(lockBudget / time.Second),
		MigrationStatement: 30,
	})
	source := migrationSourceFrom(t, map[string]string{
		"1_create_table.up.sql": "CREATE TABLE IF NOT EXISTS thing (id integer primary key);",
	})

	// Bring the lineage into existence first, so the tracking table this test
	// inspects afterwards is the one golang-migrate itself created.
	if err := runtime.applySource(context.Background(), source); err != nil {
		t.Fatal(err)
	}

	release := holdMigrationLock(t, connection, runtime.Settings.DatabaseName, source)

	started := time.Now()
	err := runtime.applySource(context.Background(), source)
	elapsed := time.Since(started)
	release()

	if err == nil {
		t.Fatal("migration acquired a lock another session was holding")
	}
	// The retries share one lock budget: three attempts must not wait three
	// times as long as the budget allows.
	if elapsed > 3*lockBudget {
		t.Fatalf("lock wait took %s against a %s budget: %v", elapsed, lockBudget, err)
	}
	if !strings.Contains(err.Error(), "lock timeout") && !strings.Contains(err.Error(), "canceling statement") {
		t.Fatalf("failure does not report the lock budget: %v", err)
	}
	assertMigrationConnectionsReleased(t, connection, runtime.Settings.DatabaseName)
}

func TestMigrationStatementBudgetExpiresAndPreservesTheLedger(t *testing.T) {
	const statementBudget = 3 * time.Second
	runtime, connection := budgetRuntime(t, Timeouts{
		MigrationLock:      30,
		MigrationStatement: int(statementBudget / time.Second),
	})
	source := migrationSourceFrom(t, map[string]string{
		"1_slow.up.sql": "SELECT pg_sleep(120);",
	})

	started := time.Now()
	err := runtime.applySource(context.Background(), source)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("a migration statement ran past its budget without failing")
	}
	if elapsed > 4*statementBudget {
		t.Fatalf("statement took %s against a %s budget: %v", elapsed, statementBudget, err)
	}
	if !strings.Contains(err.Error(), "statement timeout") {
		t.Fatalf("failure does not report the statement budget: %v", err)
	}

	// The evidence of what went wrong must survive the failure: a budget
	// expiry does not license dropping the schema or rewriting the version
	// pointer. Recovering a dirty ledger is a separate, deliberate decision
	// (codefly-dev/service-postgres#76).
	version, dirty := migrationLedger(t, connection)
	if version != 1 || !dirty {
		t.Fatalf("ledger = version %d dirty %t, want the interrupted migration preserved as version 1 dirty", version, dirty)
	}
	assertMigrationConnectionsReleased(t, connection, runtime.Settings.DatabaseName)
}

// budgetRuntime wires the production agent to one isolated database on a
// disposable postgres, carrying the budgets under test, and returns the owner
// connection string alongside it.
func budgetRuntime(t *testing.T, timeouts Timeouts) (*Runtime, string) {
	t.Helper()
	server := startDisposablePostgres(t)
	isolated := disposableDatabase(t, server)
	// The control plane keeps a pool open on the database it creates, and the
	// assertions below count the backends a failed migration leaves behind.
	// Release it here: nothing in these tests goes through it, and cleanup
	// still drops the database.
	if err := isolated.Close(); err != nil {
		t.Fatal(err)
	}
	connection := server.dsn(isolated.Name)

	runtime := NewRuntime()
	runtime.Settings.DatabaseName = isolated.Name
	runtime.Settings.Timeouts = timeouts
	bounded, err := withConnectTimeout(connection, timeouts.connect())
	if err != nil {
		t.Fatal(err)
	}
	runtime.connection = bounded
	return runtime, connection
}

// migrationSourceFrom writes migration files to a fresh directory and returns
// the lineage pointing at it.
func migrationSourceFrom(t *testing.T, files map[string]string) migrationSource {
	t.Helper()
	directory := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return migrationSource{dir: directory}
}

// holdMigrationLock takes the same advisory lock golang-migrate takes for this
// lineage, from a session the runtime does not control.
func holdMigrationLock(t *testing.T, connection, databaseName string, src migrationSource) func() {
	t.Helper()
	table := src.table
	if table == "" {
		table = "schema_migrations"
	}
	lockID, err := database.GenerateAdvisoryLockId(databaseName, "public", table)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := sql.Open("postgres", connection)
	if err != nil {
		t.Fatal(err)
	}
	held, err := peer.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = held.ExecContext(context.Background(), "SELECT pg_advisory_lock($1)", lockID); err != nil {
		t.Fatal(err)
	}
	return func() {
		_ = held.Close()
		_ = peer.Close()
	}
}

func migrationLedger(t *testing.T, connection string) (int, bool) {
	t.Helper()
	db, err := sql.Open("postgres", connection)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	var dirty bool
	if err = db.QueryRowContext(context.Background(),
		"SELECT version, dirty FROM schema_migrations").Scan(&version, &dirty); err != nil {
		t.Fatal(err)
	}
	return version, dirty
}

// assertMigrationConnectionsReleased proves the failed attempt left no backend
// behind: a leaked migration connection keeps its advisory lock and blocks the
// next run.
func assertMigrationConnectionsReleased(t *testing.T, connection, databaseName string) {
	t.Helper()
	db, err := sql.Open("postgres", connection)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The pool backing this very query is one connection, and postgres reports
	// backends asynchronously, so allow a moment for the closed ones to go.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var backends int
		if err = db.QueryRowContext(context.Background(),
			"SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
			databaseName).Scan(&backends); err != nil {
			t.Fatal(err)
		}
		if backends == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d migration backend(s) survived the budget expiry", backends)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
