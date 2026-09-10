package main

import (
	"context"
	"sync"
	"testing"

	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/stretchr/testify/require"
)

// TestConcurrentControlPlaneStaysConsistent pins the serialization of this
// agent's database control-plane mutations. The rationale — why Postgres does
// not serialize these for us — lives once, on Runtime.controlPlane; it is not
// repeated here.
//
// Migration application and runtime-access reconciliation are driven against
// one database together, which is what reproduces the collision: REVOKE/GRANT
// ON ALL TABLES rewrites the tracking table's pg_class row while golang-migrate
// TRUNCATEs it, and one side aborts with "tuple concurrently updated".
//
// What this does NOT pin is the in-process acquisition, and that was measured
// rather than assumed: deleting it leaves this green, because openMigration
// takes the runtime-access advisory lock inside the database and that alone
// serializes these two. The in-process lock earns its place elsewhere — it
// makes extensions, migrations and grants ONE transition (see migrateOnInit),
// which no single database lock spans.
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
