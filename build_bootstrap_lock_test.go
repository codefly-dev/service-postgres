package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// readRendered returns one file from a freshly built recipe tree.
func readRendered(t *testing.T, outputDirectory, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(outputDirectory, filepath.FromSlash(name)))
	require.NoError(t, err)
	return string(data)
}

// TestBootstrapRunsMigrationInsideRuntimeAccessLock pins the CONTAINER half of
// the cross-process collision. The bootstrap job used to run `migrate up` and
// then psql as two separate processes with nothing serializing them, and
// golang-migrate's advisory lock is on a different key from the grants'. With a
// Job that is restartPolicy: Never, Kubernetes does not guarantee a single
// running pod, so pod A's GRANT ... ON ALL TABLES could rewrite the tracking
// table's pg_class row while pod B's `migrate up` TRUNCATEd it — one side
// aborting, and an aborted migration leaves the lineage dirty.
//
// The fix is that migrate runs as a child of the psql session that already
// holds the runtime-access lock, so both steps are in one lock domain.
func TestBootstrapRunsMigrationInsideRuntimeAccessLock(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	outputDirectory := t.TempDir()

	_, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)

	bootstrap := readRendered(t, outputDirectory, "bootstrap.sql")
	dockerfile := readRendered(t, outputDirectory, "builder/Dockerfile")

	// The migration must be invoked from inside the locked psql session...
	lockAt := strings.Index(bootstrap, "pg_advisory_lock("+runtimeAccessLockSQL+")")
	migrateAt := strings.Index(bootstrap, `/usr/local/bin/migrate -path /app/bootstrap/sources/00-store`)
	includeAt := strings.Index(bootstrap, `\i /app/runtime-access.sql`)
	require.NotEqual(t, -1, lockAt, "bootstrap must take the runtime-access advisory lock")
	require.NotEqual(t, -1, migrateAt, "bootstrap must run the migration inside that session")
	require.NotEqual(t, -1, includeAt, "bootstrap must include the runtime-access script")
	require.Less(t, lockAt, migrateAt, "the lock must be held BEFORE the migration runs")
	require.Less(t, migrateAt, includeAt, "the grants must follow the migration in the same session")

	// ...and the lock must be session-scoped, since it spans a child process.
	require.NotContains(t, bootstrap, "pg_advisory_xact_lock",
		"a transaction-scoped lock cannot span the migrate child process")
	require.Contains(t, bootstrap, "pg_advisory_unlock("+runtimeAccessLockSQL+")")

	// A failing migration must not fall through into granting access over a
	// schema that was never migrated: ON_ERROR_STOP does not cover \!.
	require.Contains(t, bootstrap, `\if :SHELL_ERROR`)

	// lib/pq panics on the libpq settings it does not implement, and psql
	// exports PGSYSCONFDIR to its children, so running migrate as a psql child
	// crashes unless they are stripped.
	require.Contains(t, bootstrap, "-u PGSYSCONFDIR",
		"migrate must not inherit the libpq settings its driver panics on")
	require.Contains(t, bootstrap, "RAISE EXCEPTION 'schema migration failed")

	// runtime-access.sql stays purely about access. It is the file a consumer
	// may substitute, and a substituted copy must not be able to take the
	// migration down with it.
	access := readRendered(t, outputDirectory, "runtime-access.sql")
	require.NotContains(t, access, "/usr/local/bin/migrate",
		"runtime-access.sql must not run migrations")

	// The Dockerfile must no longer invoke migrate as its own process. It still
	// INSTALLS the binary, so the assertion is on the invocation form only.
	require.NotContains(t, dockerfile, "migrate -path",
		"migrate must not run outside the locked psql session")
	// The image's CMD runs the bootstrap program, which gates on readiness and
	// on verifying the staged sources before opening that one locked session.
	require.Contains(t, dockerfile, `CMD ["/bin/sh", "/app/bootstrap/bootstrap.sh"]`)
	require.Contains(t, readRendered(t, outputDirectory, "bootstrap/bootstrap.sh"),
		"--file=/app/bootstrap.sql")
}

// TestBootstrapOmitsMigrationWhenDisabled keeps the lock unconditional while the
// migration step stays gated: a service with no migrations still reconciles
// grants, and must still do so under the lock.
func TestBootstrapOmitsMigrationWhenDisabled(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	builder.Settings.NoMigration = true
	outputDirectory := t.TempDir()

	_, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)

	bootstrap := readRendered(t, outputDirectory, "bootstrap.sql")
	require.Contains(t, bootstrap, "pg_advisory_lock("+runtimeAccessLockSQL+")")
	require.Contains(t, bootstrap, `\i /app/runtime-access.sql`)
	require.NotContains(t, bootstrap, `/usr/local/bin/migrate`)
}
