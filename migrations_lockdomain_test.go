package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// runtimeAccessLockSQL is spelled out literally here, on purpose. The
// production identifier is a Go constant shared with the SQL template; writing
// it out again means this test fails if that constant is ever changed to a key
// the rest of the system does not take.
const runtimeAccessLockSQL = `hashtext('codefly-runtime-access:' || current_database())`

// TestMigrationJoinsRuntimeAccessLockDomain pins the CROSS-PROCESS half of the
// collision. golang-migrate locks on its own key space, so before this the
// migration path and the grants path excluded each other only inside one Go
// process: a GRANT ... ON ALL TABLES from the bootstrap job — or from a second
// agent — could rewrite the tracking table's pg_class row while a migration
// TRUNCATEd it, aborting one side with "tuple concurrently updated" and leaving
// the lineage dirty. A process-local mutex cannot see that, so the migration
// path has to take the runtime-access advisory lock inside the database.
//
// The holder below stands in for that other process: while it holds the lock,
// no migration may proceed.
func TestMigrationJoinsRuntimeAccessLockDomain(t *testing.T) {
	server := startDisposablePostgres(t)
	ctx := context.Background()

	database := disposableDatabase(t, server)
	root := t.TempDir()
	own := newLineage(t, root, "store")
	own.write(t, 1, "base", `CREATE TABLE lock_domain (id int PRIMARY KEY);`, `DROP TABLE lock_domain;`)

	runtime := migrationRuntime(t, server, database.Name, root)

	// A dedicated session, not the pool: advisory locks are session-scoped.
	holder, err := database.DB.Conn(ctx)
	require.NoError(t, err)
	defer holder.Close()
	_, err = holder.ExecContext(ctx, `SELECT pg_advisory_lock(`+runtimeAccessLockSQL+`)`)
	require.NoError(t, err)

	sources, _, err := runtime.resolveMigrationSources()
	require.NoError(t, err, "the declared lineages must resolve before migrating")

	done := make(chan error, 1)
	go func() { done <- runtime.applyMigration(ctx, sources) }()

	select {
	case err := <-done:
		t.Fatalf("applyMigration ran while another process held the runtime-access lock (err=%v); "+
			"migrations are not in the same lock domain as the grants", err)
	case <-time.After(3 * time.Second):
		// Correctly blocked.
	}

	require.False(t, relationPresent(t, database.DB, "lock_domain"),
		"no migration may have landed while the lock was held")

	_, err = holder.ExecContext(ctx, `SELECT pg_advisory_unlock(`+runtimeAccessLockSQL+`)`)
	require.NoError(t, err)

	select {
	case err := <-done:
		require.NoError(t, err, "applyMigration must succeed once the lock is free")
	case <-time.After(90 * time.Second):
		t.Fatal("applyMigration never completed after the runtime-access lock was released")
	}
	require.True(t, relationPresent(t, database.DB, "lock_domain"))
}

// TestMigrationReleasesRuntimeAccessLock pins the release. The lock is taken on
// a POOLED connection, and sql.Conn.Close() only returns that connection to the
// pool — a session advisory lock outlives it. Leaking one would wedge every
// later control-plane mutation against this database, so a completed migration
// must leave the lock free for the next taker.
func TestMigrationReleasesRuntimeAccessLock(t *testing.T) {
	server := startDisposablePostgres(t)
	ctx := context.Background()

	database := disposableDatabase(t, server)
	root := t.TempDir()
	own := newLineage(t, root, "store")
	own.write(t, 1, "base", `CREATE TABLE lock_release (id int PRIMARY KEY);`, `DROP TABLE lock_release;`)

	runtime := migrationRuntime(t, server, database.Name, root)
	require.NoError(t, applyMigrations(t, ctx, runtime))

	probe, err := database.DB.Conn(ctx)
	require.NoError(t, err)
	defer probe.Close()

	var acquired bool
	require.NoError(t, probe.QueryRowContext(ctx,
		`SELECT pg_try_advisory_lock(`+runtimeAccessLockSQL+`)`).Scan(&acquired))
	require.True(t, acquired, "migration must not leave the runtime-access advisory lock held")
}
