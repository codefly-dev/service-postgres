package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/resources"
	dockerrun "github.com/codefly-dev/core/runners/dockerrun"
	migrationtest "github.com/codefly-dev/service-postgres/libs/go/migrationtest"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

const disposableOwnerPassword = "dirty-migration-owner"

// testRuntimeImageEnv names the postgres image the real-infrastructure tests run
// against. CI sets it to the image built from this repo's Dockerfile, so the
// regression needs no registry access. Setting it ALSO makes the prerequisite
// mandatory: a run that declares an image must never report success by skipping.
const testRuntimeImageEnv = "SERVICE_POSTGRES_TEST_IMAGE"

func testRuntimeImage(t *testing.T) *resources.DockerImage {
	t.Helper()
	override := strings.TrimSpace(os.Getenv(testRuntimeImageEnv))
	if override == "" {
		return image
	}
	parsed := resources.NewDockerImage(override)
	require.NotNil(t, parsed, "%s=%q is not a name:tag reference", testRuntimeImageEnv, override)
	return parsed
}

// dockerDaemonUnavailable reports whether err is the runner's "no usable docker
// daemon" diagnostic. Every other construction failure — a missing image, a
// registry rejection, a rate limit — is a real failure: reporting it as a missing
// prerequisite would silently stop enforcing this regression while CI stays green.
func dockerDaemonUnavailable(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "not reachable") ||
		strings.Contains(message, "cannot create docker client")
}

// disposableServer is a throwaway postgres instance shared by the dirty-state
// acceptance tests. Every test case runs against its own database created and
// dropped through the migration control plane, so no case can observe or damage
// another's tables — and none of them touches a developer database.
type disposableServer struct {
	address string
	control *migrationtest.ControlPlane
}

func (d *disposableServer) dsn(database string) string {
	return postgresConnectionString(d.address, database, "postgres", disposableOwnerPassword, false, false)
}

// startDisposablePostgres boots the pinned runtime image on a free port with no
// persistent mount, so the whole server dies with the test binary.
func startDisposablePostgres(t *testing.T) *disposableServer {
	t.Helper()
	ctx := context.Background()

	runtime := NewRuntime()
	ctx = runtime.Wool.Inject(ctx)

	port := freeTCPPort(t)
	runner, err := dockerrun.NewDockerHeadlessEnvironment(ctx, testRuntimeImage(t), fmt.Sprintf("dirty-migration-%d", time.Now().UnixNano()))
	if err != nil {
		mandatory := os.Getenv(testRuntimeImageEnv) != ""
		if mandatory || !dockerDaemonUnavailable(err) {
			require.NoError(t, err, "real postgres prerequisite must be available, not skipped")
		}
		t.Skipf("no docker daemon on this host: %v", err)
	}
	runner.WithEphemeral()
	runner.WithPortMapping(ctx, port, 5432)
	runner.WithEnvironmentVariables(ctx,
		resources.Env("POSTGRES_USER", "postgres"),
		resources.Env("POSTGRES_PASSWORD", disposableOwnerPassword),
		resources.Env("POSTGRES_DB", "postgres"))
	// Registered BEFORE Init: Init is what creates the container, so a failure
	// part-way through it would otherwise leave the container behind untracked.
	t.Cleanup(func() {
		// Removal uses a fixed client-side timeout that a loaded docker daemon can
		// exceed after the whole suite's containers. The environment is ephemeral,
		// so the startup sweep reaps anything a timeout leaves behind — reporting
		// beats failing an otherwise green acceptance run.
		if err := runner.Shutdown(context.Background()); err != nil {
			t.Logf("disposable postgres shutdown: %v", err)
		}
	})
	require.NoError(t, runner.Init(ctx))

	server := &disposableServer{address: fmt.Sprintf("localhost:%d", port)}
	control := waitForControlPlane(t, ctx, server.dsn("postgres"))
	t.Cleanup(func() { require.NoError(t, control.Close()) })
	server.control = control
	return server
}

func waitForControlPlane(t *testing.T, ctx context.Context, dsn string) *migrationtest.ControlPlane {
	t.Helper()
	var lastErr error
	for range 60 {
		control, err := migrationtest.OpenControlPlane(ctx, dsn)
		if err == nil {
			return control
		}
		lastErr = err
		time.Sleep(time.Second)
	}
	t.Fatalf("disposable postgres never accepted connections: %v", lastErr)
	return nil
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())
	return port
}

// lineage is a migration directory laid out the way a service ships one.
type lineage struct {
	dir string
}

func newLineage(t *testing.T, root, name string) lineage {
	t.Helper()
	dir := filepath.Join(root, name, "migrations")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	return lineage{dir: dir}
}

func (l lineage) write(t *testing.T, version int64, name, up, down string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(l.dir, fmt.Sprintf("%d_%s.up.sql", version, name)), []byte(up), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(l.dir, fmt.Sprintf("%d_%s.down.sql", version, name)), []byte(down), 0o600))
}

// migrationRuntime is the production agent wired to one disposable database:
// applyMigration, applySource, openMigration and runUp are the real code paths.
func migrationRuntime(t *testing.T, server *disposableServer, database, root string, sources ...MigrationSource) *Runtime {
	t.Helper()
	runtime := NewRuntime()
	runtime.Location = filepath.Join(root, "store")
	runtime.Settings.DatabaseName = database
	runtime.Settings.MigrationSources = sources
	runtime.connection = server.dsn(database)
	return runtime
}

// disposableDatabase creates a uniquely named database and drops it on cleanup.
func disposableDatabase(t *testing.T, server *disposableServer) *migrationtest.Database {
	t.Helper()
	database, err := server.control.Create(context.Background(), "dirty_migration")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Drop(context.Background())) })
	return database
}

func markLedgerDirty(t *testing.T, db *sql.DB, table string, version int64) {
	t.Helper()
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ` + pq.QuoteIdentifier(table) +
		` (version bigint not null primary key, dirty boolean not null)`)
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM ` + pq.QuoteIdentifier(table))
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO `+pq.QuoteIdentifier(table)+` (version, dirty) VALUES ($1, true)`, version)
	require.NoError(t, err)
}

func readLedger(t *testing.T, db *sql.DB, table string) (int64, bool) {
	t.Helper()
	var version int64
	var dirty bool
	require.NoError(t, db.QueryRow(`SELECT version, dirty FROM `+pq.QuoteIdentifier(table)).Scan(&version, &dirty))
	return version, dirty
}

func relationPresent(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var present bool
	require.NoError(t, db.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, "public."+name).Scan(&present))
	return present
}

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+pq.QuoteIdentifier(table)).Scan(&count))
	return count
}

// requireDirty asserts the failure is the fail-closed dirty report: it still
// classifies as migrate.ErrDirty for callers, names the lineage, its tracking
// table, the stuck version and the runbook, and never leaks the owner password.
func requireDirty(t *testing.T, err error, source, table string, version int) {
	t.Helper()
	require.Error(t, err)

	// The wrap must not cost callers their ability to classify the failure, and
	// the version it reports must be the version the ledger is actually stuck on.
	var dirty migrate.ErrDirty
	require.True(t, errors.As(err, &dirty), "dirty classification must survive wrapping: %v", err)
	require.Equal(t, version, dirty.Version)

	require.Contains(t, err.Error(), source)
	require.Contains(t, err.Error(), table)
	require.Contains(t, err.Error(), fmt.Sprintf("%d", version))
	require.Contains(t, err.Error(), dirtyRecoveryRunbook, "the error must point the operator at the runbook")
	require.NotContains(t, err.Error(), disposableOwnerPassword)
}

// TestDirtyMigrationFailsClosed is the F01 regression: a dirty lineage must stop
// startup instead of triggering golang-migrate's schema-wide Drop or a
// speculative Force(V-1). Every case runs the production migration path against
// a real, uniquely named, disposable database.
func TestDirtyMigrationFailsClosed(t *testing.T) {
	server := startDisposablePostgres(t)
	ctx := context.Background()

	// Two independent lineages plus a sentinel table owned by neither. golang-
	// migrate's Drop enumerates every base table in the schema, so the sentinel
	// and lineage A are exactly what the old recovery path destroyed.
	t.Run("dirty at first version preserves every other lineage", func(t *testing.T) {
		database := disposableDatabase(t, server)
		root := t.TempDir()

		own := newLineage(t, root, "store")
		own.write(t, 1, "a", `CREATE TABLE lineage_a (id int PRIMARY KEY); INSERT INTO lineage_a VALUES (1);`, `DROP TABLE lineage_a;`)
		other := newLineage(t, root, "other")
		other.write(t, 1, "b", `CREATE TABLE lineage_b (id int PRIMARY KEY);`, `DROP TABLE lineage_b;`)

		_, err := database.DB.ExecContext(ctx, `CREATE TABLE sentinel (id int PRIMARY KEY); INSERT INTO sentinel VALUES (42);`)
		require.NoError(t, err)

		runtime := migrationRuntime(t, server, database.Name, root)
		require.NoError(t, runtime.applyMigration(ctx), "lineage A must apply cleanly first")

		markLedgerDirty(t, database.DB, "schema_migrations_other", 1)

		runtime = migrationRuntime(t, server, database.Name, root, MigrationSource{Name: "other", Path: other.dir})
		requireDirty(t, runtime.applyMigration(ctx), "other", "schema_migrations_other", 1)

		require.True(t, relationPresent(t, database.DB, "sentinel"), "unrelated table must survive a dirty lineage")
		require.Equal(t, 1, countRows(t, database.DB, "sentinel"))
		require.True(t, relationPresent(t, database.DB, "lineage_a"))
		require.Equal(t, 1, countRows(t, database.DB, "lineage_a"))
		require.False(t, relationPresent(t, database.DB, "lineage_b"), "the dirty lineage must not be applied")

		version, dirty := readLedger(t, database.DB, postgres.DefaultMigrationsTable)
		require.Equal(t, int64(1), version)
		require.False(t, dirty, "the clean lineage's ledger must be untouched")

		version, dirty = readLedger(t, database.DB, "schema_migrations_other")
		require.Equal(t, int64(1), version)
		require.True(t, dirty, "the dirty marker must be left for manual reconciliation")
	})

	// Above version 1 the old path forced V-1 and re-ran Up, which assumes the
	// interrupted migration rolled back and that V-1 is a real version.
	t.Run("dirty at a later version is not rewound", func(t *testing.T) {
		database := disposableDatabase(t, server)
		root := t.TempDir()

		own := newLineage(t, root, "store")
		for version := int64(1); version <= 5; version++ {
			own.write(t, version,
				fmt.Sprintf("step%d", version),
				fmt.Sprintf(`CREATE TABLE step_%d (id int PRIMARY KEY);`, version),
				fmt.Sprintf(`DROP TABLE step_%d;`, version))
		}

		runtime := migrationRuntime(t, server, database.Name, root)
		require.NoError(t, runtime.applyMigration(ctx))

		markLedgerDirty(t, database.DB, postgres.DefaultMigrationsTable, 5)
		requireDirty(t, runtime.applyMigration(ctx), "store", postgres.DefaultMigrationsTable, 5)

		for version := 1; version <= 5; version++ {
			require.True(t, relationPresent(t, database.DB, fmt.Sprintf("step_%d", version)),
				"no already-applied migration may be dropped")
		}
		version, dirty := readLedger(t, database.DB, postgres.DefaultMigrationsTable)
		require.Equal(t, int64(5), version, "the version pointer must not be rewritten")
		require.True(t, dirty)
	})

	// Timestamp versions make V-1 arithmetic meaningless: 20260201090000-1 is
	// not a migration that exists in the lineage.
	t.Run("nonconsecutive timestamp versions are not rewound", func(t *testing.T) {
		database := disposableDatabase(t, server)
		root := t.TempDir()

		const first, second = int64(20260114093000), int64(20260201090000)
		own := newLineage(t, root, "store")
		own.write(t, first, "first", `CREATE TABLE stamped_first (id int PRIMARY KEY);`, `DROP TABLE stamped_first;`)
		own.write(t, second, "second", `CREATE TABLE stamped_second (id int PRIMARY KEY);`, `DROP TABLE stamped_second;`)

		runtime := migrationRuntime(t, server, database.Name, root)
		require.NoError(t, runtime.applyMigration(ctx))
		require.True(t, relationPresent(t, database.DB, "stamped_second"))

		markLedgerDirty(t, database.DB, postgres.DefaultMigrationsTable, second)
		requireDirty(t, runtime.applyMigration(ctx), "store", postgres.DefaultMigrationsTable, int(second))

		require.True(t, relationPresent(t, database.DB, "stamped_first"))
		require.True(t, relationPresent(t, database.DB, "stamped_second"))
		version, dirty := readLedger(t, database.DB, postgres.DefaultMigrationsTable)
		require.Equal(t, second, version)
		require.True(t, dirty)
	})

	// The marker is cleared in a statement of its own, so an interruption
	// between commit and marker leaves the schema fully applied but dirty.
	t.Run("dirty marker over already committed SQL is not reapplied", func(t *testing.T) {
		database := disposableDatabase(t, server)
		root := t.TempDir()

		own := newLineage(t, root, "store")
		own.write(t, 1, "committed",
			`CREATE TABLE committed_effect (id int PRIMARY KEY); INSERT INTO committed_effect VALUES (7);`,
			`DROP TABLE committed_effect;`)

		_, err := database.DB.ExecContext(ctx, `CREATE TABLE committed_effect (id int PRIMARY KEY); INSERT INTO committed_effect VALUES (7);`)
		require.NoError(t, err)
		markLedgerDirty(t, database.DB, postgres.DefaultMigrationsTable, 1)

		runtime := migrationRuntime(t, server, database.Name, root)
		requireDirty(t, runtime.applyMigration(ctx), "store", postgres.DefaultMigrationsTable, 1)

		require.True(t, relationPresent(t, database.DB, "committed_effect"))
		require.Equal(t, 1, countRows(t, database.DB, "committed_effect"), "the committed migration must not be replayed")
		version, dirty := readLedger(t, database.DB, postgres.DefaultMigrationsTable)
		require.Equal(t, int64(1), version)
		require.True(t, dirty)
	})

	// A failing migration leaves the lineage dirty. The NEXT startup is the
	// audited data-loss path: it used to Drop every table in the schema.
	t.Run("a failed migration wedges the lineage without destroying data", func(t *testing.T) {
		database := disposableDatabase(t, server)
		root := t.TempDir()

		own := newLineage(t, root, "store")
		own.write(t, 1, "good", `CREATE TABLE kept (id int PRIMARY KEY); INSERT INTO kept VALUES (1);`, `DROP TABLE kept;`)
		own.write(t, 2, "bad", `CREATE TABLE kept (id int PRIMARY KEY);`, `SELECT 1;`)

		runtime := migrationRuntime(t, server, database.Name, root)
		err := runtime.applyMigration(ctx)
		require.Error(t, err, "the broken migration must surface as an ordinary SQL failure")
		var dirty migrate.ErrDirty
		require.False(t, errors.As(err, &dirty), "an SQL error is not a dirty-state report: %v", err)

		requireDirty(t, runtime.applyMigration(ctx), "store", postgres.DefaultMigrationsTable, 2)

		require.True(t, relationPresent(t, database.DB, "kept"))
		require.Equal(t, 1, countRows(t, database.DB, "kept"))
		version, isDirty := readLedger(t, database.DB, postgres.DefaultMigrationsTable)
		require.Equal(t, int64(2), version)
		require.True(t, isDirty)
	})

	// A partially migrated database must never be reported ready: iteration
	// stops at the first failing lineage.
	t.Run("iteration stops at the first dirty lineage", func(t *testing.T) {
		database := disposableDatabase(t, server)
		root := t.TempDir()

		own := newLineage(t, root, "store")
		own.write(t, 1, "a", `CREATE TABLE first_lineage (id int PRIMARY KEY);`, `DROP TABLE first_lineage;`)
		second := newLineage(t, root, "second")
		second.write(t, 1, "b", `CREATE TABLE second_lineage (id int PRIMARY KEY);`, `DROP TABLE second_lineage;`)
		third := newLineage(t, root, "third")
		third.write(t, 1, "c", `CREATE TABLE third_lineage (id int PRIMARY KEY);`, `DROP TABLE third_lineage;`)

		markLedgerDirty(t, database.DB, "schema_migrations_second", 1)

		runtime := migrationRuntime(t, server, database.Name, root,
			MigrationSource{Name: "second", Path: second.dir},
			MigrationSource{Name: "third", Path: third.dir})
		requireDirty(t, runtime.applyMigration(ctx), "second", "schema_migrations_second", 1)

		require.True(t, relationPresent(t, database.DB, "first_lineage"))
		require.False(t, relationPresent(t, database.DB, "third_lineage"), "a lineage after the failure must not be applied")
		require.False(t, relationPresent(t, database.DB, "schema_migrations_third"), "a lineage after the failure must not be touched")
	})

	// The Init path is the one that gates readiness, so the dirty report has to
	// travel all the way out of it.
	t.Run("the init migration path fails closed", func(t *testing.T) {
		database := disposableDatabase(t, server)
		root := t.TempDir()

		own := newLineage(t, root, "store")
		own.write(t, 1, "a", `CREATE TABLE init_lineage (id int PRIMARY KEY);`, `DROP TABLE init_lineage;`)
		markLedgerDirty(t, database.DB, postgres.DefaultMigrationsTable, 1)

		runtime := migrationRuntime(t, server, database.Name, root)
		err := runtime.migrateOnInit(ctx)
		requireDirty(t, err, "store", postgres.DefaultMigrationsTable, 1)

		response, initErr := runtime.Runtime.InitError(err)
		require.NoError(t, initErr)
		require.Equal(t, runtimev0.InitStatus_ERROR, response.GetStatus().GetState())
		require.Contains(t, response.GetStatus().GetMessage(), "dirty")
		require.NotContains(t, response.GetStatus().GetMessage(), disposableOwnerPassword)
	})

	// Fail-closed must not make ordinary startup stricter.
	t.Run("clean lineages apply and stay idempotent", func(t *testing.T) {
		database := disposableDatabase(t, server)
		root := t.TempDir()

		own := newLineage(t, root, "store")
		own.write(t, 1, "a", `CREATE TABLE clean_a (id int PRIMARY KEY);`, `DROP TABLE clean_a;`)
		other := newLineage(t, root, "other")
		other.write(t, 1, "b", `CREATE TABLE clean_b (id int PRIMARY KEY);`, `DROP TABLE clean_b;`)

		runtime := migrationRuntime(t, server, database.Name, root, MigrationSource{Name: "other", Path: other.dir})
		require.NoError(t, runtime.applyMigration(ctx))
		require.True(t, relationPresent(t, database.DB, "clean_a"))
		require.True(t, relationPresent(t, database.DB, "clean_b"))

		require.NoError(t, runtime.applyMigration(ctx), "an already-current database must succeed")
		version, dirty := readLedger(t, database.DB, postgres.DefaultMigrationsTable)
		require.Equal(t, int64(1), version)
		require.False(t, dirty)
	})
}

// TestStartupPathHasNoAutomaticRecovery locks the source-level property the audit
// asked for. It scans the WHOLE of every file that migrates, so moving a Drop or
// Force into a helper cannot slip past it. There is no longer any carve-out:
// hot reload used to be the one place these calls were expected, and it is now
// forward-only, so no migration path may reach for them.
func TestStartupPathHasNoAutomaticRecovery(t *testing.T) {
	for _, file := range []string{"migrations.go", "hotreload.go"} {
		body, err := os.ReadFile(file)
		require.NoError(t, err)

		for _, forbidden := range []string{"m.Drop()", ".Force(", ".Steps(", "m.Down()"} {
			require.NotContains(t, string(body), forbidden,
				"%s must not recover automatically from a dirty lineage", file)
		}
	}
}

// TestDirtyRecoveryRunbookExists keeps the pointer in the dirty-lineage error and
// the document it names in step with each other.
func TestDirtyRecoveryRunbookExists(t *testing.T) {
	_, err := os.Stat(dirtyRecoveryRunbook)
	require.NoError(t, err, "the dirty-lineage error must point at a runbook that exists")

	body, err := os.ReadFile(dirtyRecoveryRunbook)
	require.NoError(t, err)
	runbook := string(body)

	// The audited case is a lineage dirty at its FIRST migration, where there is
	// no earlier version to reconcile against. The runbook must cover it.
	require.Contains(t, runbook, "DELETE FROM schema_migrations",
		"the runbook must tell the operator how to reconcile a lineage dirty at its first migration")
	require.Contains(t, runbook, "destroys every lineage in the database",
		"the reset recipe must warn that it takes every co-tenant lineage with it")
}
