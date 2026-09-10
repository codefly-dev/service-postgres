package main

import (
	"context"
	"sync"
	"testing"

	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/stretchr/testify/require"
)

// TestConcurrentControlPlaneStaysConsistent pins the serialization of this
// agent's database control-plane mutations. Migration application and
// runtime-access reconciliation reach the database from unrelated goroutines —
// the hot-reload watcher runs on its own goroutine while Init and Start drive
// the rest from RPC handlers — and Postgres does not serialize them for us:
// REVOKE/GRANT ON ALL TABLES rewrites the pg_class row of every table in the
// schema, each lineage's golang-migrate tracking table included, while taking
// no lock on the table itself. It therefore collides with the TRUNCATE
// golang-migrate uses to record a version, and one side aborts with "tuple
// concurrently updated".
//
// Everything here is the production path against a real, disposable database.
func TestConcurrentControlPlaneStaysConsistent(t *testing.T) {
	server := startDisposablePostgres(t)
	ctx := context.Background()

	database := disposableDatabase(t, server)
	root := t.TempDir()

	own := newLineage(t, root, "store")
	own.write(t, 1, "base", `CREATE TABLE control_base (id int PRIMARY KEY);`, `DROP TABLE control_base;`)
	own.write(t, 2, "second", `CREATE TABLE control_second (id int PRIMARY KEY);`, `DROP TABLE control_second;`)

	runtime := migrationRuntime(t, server, database.Name, root)
	runtime.postgresUser = "postgres"
	runtime.readOnlyPassword = deriveRuntimePassword(disposableOwnerPassword, database.Name, "read-only")
	runtime.readWritePassword = deriveRuntimePassword(disposableOwnerPassword, database.Name, "read-write")

	const rounds = 6
	applyErrors := make([]error, rounds)
	accessErrors := make([]error, rounds)

	// One barrier for every goroutine so the migrators and the reconcilers all
	// enter the database together.
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range rounds {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			applyErrors[i] = applyMigrations(t, ctx, runtime)
		}()
		go func() {
			defer wg.Done()
			<-start
			accessErrors[i] = runtime.ensureRuntimeAccess(ctx)
		}()
	}
	close(start)
	wg.Wait()

	for i := range rounds {
		require.NoError(t, applyErrors[i], "overlapping migration application %d must not corrupt the tracking table", i)
		require.NoError(t, accessErrors[i], "overlapping runtime-access reconciliation %d must not collide with a migration", i)
	}

	version, dirty := readLedger(t, database.DB, postgres.DefaultMigrationsTable)
	require.EqualValues(t, 2, version, "the ledger must end at the last applied version")
	require.False(t, dirty)
	require.True(t, relationPresent(t, database.DB, "control_base"))
	require.True(t, relationPresent(t, database.DB, "control_second"))
}
