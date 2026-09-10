package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	migrationtest "github.com/codefly-dev/service-postgres/libs/go/migrationtest"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// unreachableConnection points at a closed port so any database work fails
// immediately: a test that expects an event to be IGNORED proves it by getting
// no error at all.
const unreachableConnection = "postgresql://invalid:invalid@127.0.0.1:1/none?sslmode=disable"

func TestParseMigrationFileAcceptsOnlyMigrationSQL(t *testing.T) {
	for name, want := range map[string]migrationFile{
		"1_create.up.sql":                 {version: 1, forward: true},
		"1_create.down.sql":               {version: 1, forward: false},
		"0012_add_column.up.sql":          {version: 12, forward: true},
		"8_non_consecutive.step.down.sql": {version: 8, forward: false},
		// Any plain extension is a real migration — golang-migrate's own
		// `migrate create -ext` produces whatever it is told. The extension is
		// what separates these from the leftovers below, not the letters "sql".
		"1_create.up.pgsql": {version: 1, forward: true},
		"1_create.up.SQL":   {version: 1, forward: true},
	} {
		got, ok := parseMigrationFile(name)
		if !ok || got != want {
			t.Errorf("parseMigrationFile(%q) = %+v, %v; want %+v, true", name, got, ok, want)
		}
	}
	// Editor temporaries, backups and anything else are not migrations: an
	// allow-list is what keeps a half-written save from executing SQL.
	for _, name := range []string{
		"1_create.up.sql~",
		".1_create.up.sql.swp",
		"#1_create.up.sql#",
		".#1_create.up.sql",
		"1_create.up.sql.tmp",
		"1_create.up.sql.bak",
		"1_create.sql",
		"create.up.sql",
		"_1_create.up.sql",
		"README.md",
	} {
		if _, ok := parseMigrationFile(name); ok {
			t.Errorf("parseMigrationFile(%q) accepted a non-migration file", name)
		}
	}
}

func TestOwningMigrationSourceMatchesTheExactSourceDirectory(t *testing.T) {
	own := migrationSource{dir: filepath.Join("/w", "store", "migrations")}
	api := migrationSource{name: "api", dir: filepath.Join("/w", "api", "migrations"), table: "schema_migrations_api"}
	// A declared source can legitimately sit INSIDE another source's tree.
	nested := migrationSource{name: "nested", dir: filepath.Join("/w", "store", "migrations", "nested"), table: "schema_migrations_nested"}
	sources := []migrationSource{own, api, nested}

	for path, want := range map[string]string{
		filepath.Join(own.dir, "1_create.up.sql"):    own.name,
		filepath.Join(api.dir, "1_create.up.sql"):    api.name,
		filepath.Join(nested.dir, "1_create.up.sql"): nested.name,
	} {
		owner, err := owningMigrationSource(sources, path)
		require.NoError(t, err)
		require.NotNil(t, owner, path)
		require.Equal(t, want, owner.name, path)
	}

	// Outside every source, deeper than a source (golang-migrate reads a source
	// directory flat), and escaping through "..".
	for _, path := range []string{
		filepath.Join("/w", "other", "1_create.up.sql"),
		filepath.Join(api.dir, "sub", "1_create.up.sql"),
		filepath.Clean(filepath.Join(own.dir, "..", "..", "etc", "1_create.up.sql")),
	} {
		owner, err := owningMigrationSource(sources, path)
		require.NoError(t, err)
		require.Nil(t, owner, path)
	}

	shared := filepath.Join("/w", "shared", "migrations")
	_, err := owningMigrationSource([]migrationSource{
		{name: "first", dir: shared, table: "schema_migrations_first"},
		{name: "second", dir: shared, table: "schema_migrations_second"},
	}, filepath.Join(shared, "1_create.up.sql"))
	require.ErrorIs(t, err, errAmbiguousMigrationOwnership)
}

func TestMigrationWatchRequirementsCoverEveryDeclaredSource(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	location := filepath.Join(root, "store")
	mustMkdir(t, filepath.Join(location, "migrations"))
	mustMkdir(t, filepath.Join(root, "api", "migrations"))
	mustMkdir(t, filepath.Join(root, "billing", "db", "migrations"))

	fixed := len(requirements.Components)
	s := NewRuntime()
	s.Location = location
	s.Settings.DatabaseName = "app"
	s.Settings.MigrationSources = []MigrationSource{
		{Name: "api"},
		{Name: "billing", Path: "../billing/db/migrations"},
	}

	watch, err := s.migrationWatchRequirements(ctx)
	require.NoError(t, err)
	require.Len(t, requirements.Components, fixed, "the fixed build requirements must not be mutated")
	// The own migrations directory is already a fixed requirement, so only the
	// two declared sibling sources are added.
	require.Len(t, watch.Components, fixed+2)

	var declared []string
	for _, component := range watch.Components {
		declared = append(declared, component.Components()...)
	}
	require.Contains(t, declared, "service.codefly.yaml")
	require.Contains(t, declared, "migrations")
	require.Contains(t, declared, filepath.Join("..", "api", "migrations"))
	require.Contains(t, declared, filepath.Join("..", "billing", "db", "migrations"))

	for _, component := range watch.Components[fixed:] {
		require.True(t, component.Keep(filepath.Join(root, "api", "migrations", "1_create.up.sql")))
		require.False(t, component.Keep(filepath.Join(root, "api", "migrations", "notes.md")))
	}
}

// TestApplyMigrationChangeIgnoresEventsThatCannotBeApplied proves the event
// filter runs BEFORE any database work: the runtime points at a closed port, so
// an ignored event returns no error while an accepted one fails to connect.
func TestApplyMigrationChangeIgnoresEventsThatCannotBeApplied(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	location := filepath.Join(root, "store")
	migrations := filepath.Join(location, "migrations")
	mustMkdir(t, migrations)
	mustMkdir(t, filepath.Join(location, "outside"))
	// An undeclared sibling directory: watching or applying it is not this
	// service's business until it appears in migration-sources.
	mustMkdir(t, filepath.Join(root, "api", "migrations"))

	s := NewRuntime()
	s.Location = location
	s.Settings.DatabaseName = "app"
	s.connection = unreachableConnection

	destructive := "DROP TABLE sentinel;"
	for _, name := range []string{
		filepath.Join(migrations, "1_create.up.sql"),
		filepath.Join(migrations, "1_create.down.sql"),
		filepath.Join(migrations, "2_create.up.sql~"),
		filepath.Join(migrations, ".2_create.up.sql.swp"),
		filepath.Join(migrations, "README.md"),
		filepath.Join(location, "outside", "3_create.up.sql"),
		filepath.Join(root, "api", "migrations", "1_api.up.sql"),
	} {
		require.NoError(t, os.WriteFile(name, []byte(destructive), 0o600))
	}

	for _, event := range []string{
		"service.codefly.yaml",
		filepath.Join("migrations", "README.md"),
		filepath.Join("migrations", "2_create.up.sql~"),
		filepath.Join("migrations", ".2_create.up.sql.swp"),
		filepath.Join("migrations", "1_create.down.sql"),
		filepath.Join("migrations", "..", "outside", "3_create.up.sql"),
		filepath.Join("..", "api", "migrations", "1_api.up.sql"),
	} {
		applied, err := s.applyMigrationChange(ctx, event)
		require.NoError(t, err, event)
		require.False(t, applied, event)
	}

	// Control: a valid up file in the own source DOES reach the database.
	_, err := s.applyMigrationChange(ctx, filepath.Join("migrations", "1_create.up.sql"))
	require.Error(t, err)
}

// assertHotReloadPreservesAppliedHistory is the F02 acceptance suite. It runs
// against the real Postgres instance under test, giving every case its own
// disposable database and its own migration directories.
func assertHotReloadPreservesAppliedHistory(
	t *testing.T,
	ctx context.Context,
	control *migrationtest.ControlPlane,
	ownerConnection string,
) {
	t.Helper()

	t.Run("an edited applied migration is reported, never replayed", func(t *testing.T) {
		fixture := newHotReloadFixture(t, ctx, control, ownerConnection, "hot_reload_forward_only")
		fixture.writeMigration(t, 1, "sentinel",
			`CREATE TABLE sentinel (id int PRIMARY KEY);`, `DROP TABLE sentinel;`)
		for version := 2; version <= 5; version++ {
			fixture.writeMigration(t, version, fmt.Sprintf("step%d", version),
				fmt.Sprintf(`ALTER TABLE sentinel ADD COLUMN step%d int;`, version),
				fmt.Sprintf(`ALTER TABLE sentinel DROP COLUMN step%d;`, version))
		}
		require.NoError(t, fixture.runtime.applyMigration(ctx))
		fixture.requireLedger(t, ctx, "schema_migrations", 5, false)
		for id := 1; id <= 3; id++ {
			_, err := fixture.db.ExecContext(ctx, `INSERT INTO sentinel (id) VALUES ($1)`, id)
			require.NoError(t, err)
		}

		// Migration 2 is rewritten, down script included — exactly the edit that
		// used to force the ledger back to 2 and run this DROP.
		editedUp, _ := fixture.writeMigration(t, 2, "step2",
			`CREATE TABLE must_not_exist (id int);`, `DROP TABLE sentinel;`)
		applied, err := fixture.runtime.applyMigrationChange(ctx, editedUp)
		require.ErrorIs(t, err, errAppliedMigrationEdited)
		require.False(t, applied)
		fixture.requireLedger(t, ctx, "schema_migrations", 5, false)
		require.False(t, fixture.relationExists(t, ctx, "must_not_exist"), "the edited migration must not execute")
		require.True(t, fixture.relationExists(t, ctx, "sentinel"))
		require.Equal(t, 3, fixture.countRows(t, ctx, "sentinel"), "no row may be lost")

		// A new, non-consecutive forward migration applies once and stays
		// applied when the same event repeats.
		forwardUp, _ := fixture.writeMigration(t, 8, "forward",
			`CREATE TABLE forward_eight (id int);`, `DROP TABLE forward_eight;`)
		applied, err = fixture.runtime.applyMigrationChange(ctx, forwardUp)
		require.NoError(t, err)
		require.True(t, applied)
		fixture.requireLedger(t, ctx, "schema_migrations", 8, false)
		require.True(t, fixture.relationExists(t, ctx, "forward_eight"))
		require.False(t, fixture.relationExists(t, ctx, "must_not_exist"), "moving forward must not re-run migration 2")

		applied, err = fixture.runtime.applyMigrationChange(ctx, forwardUp)
		require.ErrorIs(t, err, errAppliedMigrationEdited)
		require.False(t, applied)
		fixture.requireLedger(t, ctx, "schema_migrations", 8, false)
		require.True(t, fixture.relationExists(t, ctx, "forward_eight"))
		require.Equal(t, 3, fixture.countRows(t, ctx, "sentinel"))
	})

	t.Run("only a new up file in its owning source applies SQL", func(t *testing.T) {
		fixture := newHotReloadFixture(t, ctx, control, ownerConnection, "hot_reload_event_filter")
		fixture.writeMigration(t, 1, "sentinel",
			`CREATE TABLE sentinel (id int PRIMARY KEY);`, `DROP TABLE sentinel;`)
		require.NoError(t, fixture.runtime.applyMigration(ctx))
		fixture.requireLedger(t, ctx, "schema_migrations", 1, false)

		// A sibling service declares its own lineage into this database after
		// startup, so its first migration is pending.
		external := filepath.Join(fixture.root, "api", "migrations")
		mustMkdir(t, external)
		fixture.runtime.Settings.MigrationSources = []MigrationSource{{Name: "api"}}
		require.NoError(t, os.WriteFile(filepath.Join(external, "1_api.up.sql"),
			[]byte(`CREATE TABLE api_one (id int);`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(external, "1_api.down.sql"),
			[]byte(`DROP TABLE api_one;`), 0o600))

		// A pending forward migration, plus the churn a save produces around it.
		pendingUp, pendingDown := fixture.writeMigration(t, 2, "pending",
			`CREATE TABLE pending_two (id int);`, `DROP TABLE pending_two;`)
		temporary := pendingUp + "~"
		require.NoError(t, os.WriteFile(temporary, []byte(`DROP TABLE sentinel;`), 0o600))
		unrelated := filepath.Join(fixture.location, "service.codefly.yaml")
		require.NoError(t, os.WriteFile(unrelated, []byte("name: store\n"), 0o600))

		for _, event := range []string{pendingDown, temporary, unrelated} {
			applied, err := fixture.runtime.applyMigrationChange(ctx, event)
			require.NoError(t, err, event)
			require.False(t, applied, event)
		}
		fixture.requireLedger(t, ctx, "schema_migrations", 1, false)
		require.False(t, fixture.relationExists(t, ctx, "pending_two"))

		// The declared external source applies against its OWN ledger.
		applied, err := fixture.runtime.applyMigrationChange(ctx, filepath.Join(external, "1_api.up.sql"))
		require.NoError(t, err)
		require.True(t, applied)
		fixture.requireLedger(t, ctx, "schema_migrations_api", 1, false)
		fixture.requireLedger(t, ctx, "schema_migrations", 1, false)
		require.True(t, fixture.relationExists(t, ctx, "api_one"))

		// The pending own migration then applies — with the editor backup STILL
		// on disk. openSource hides "2_pending.up.sql~" from the source driver,
		// which otherwise parses it as a second version-2 up file and refuses the
		// whole lineage, so the apply would fail before reaching any SQL. The
		// backup's own "DROP TABLE sentinel" never runs either: filtered out of
		// the source, it is not a migration this lineage contains.
		applied, err = fixture.runtime.applyMigrationChange(ctx, pendingUp)
		require.NoError(t, err)
		require.True(t, applied)
		fixture.requireLedger(t, ctx, "schema_migrations", 2, false)
		require.True(t, fixture.relationExists(t, ctx, "pending_two"))
		require.True(t, fixture.relationExists(t, ctx, "sentinel"),
			"the ignored backup's DROP TABLE must never have run")
		require.NoError(t, os.Remove(temporary))
	})

	t.Run("a dirty ledger fails closed without ending hot reload", func(t *testing.T) {
		fixture := newHotReloadFixture(t, ctx, control, ownerConnection, "hot_reload_dirty_ledger")
		fixture.writeMigration(t, 1, "sentinel",
			`CREATE TABLE sentinel (id int PRIMARY KEY);`, `DROP TABLE sentinel;`)
		require.NoError(t, fixture.runtime.applyMigration(ctx))
		_, err := fixture.db.ExecContext(ctx, `UPDATE schema_migrations SET dirty = true`)
		require.NoError(t, err)

		forwardUp, _ := fixture.writeMigration(t, 2, "forward",
			`CREATE TABLE forward_two (id int);`, `DROP TABLE forward_two;`)
		applied, err := fixture.runtime.applyMigrationChange(ctx, forwardUp)
		require.ErrorIs(t, err, errDirtyMigrationLedger)
		require.False(t, applied)
		fixture.requireLedger(t, ctx, "schema_migrations", 1, true)
		require.False(t, fixture.relationExists(t, ctx, "forward_two"))

		// Once the operator has reconciled the lineage, the same event applies.
		_, err = fixture.db.ExecContext(ctx, `UPDATE schema_migrations SET dirty = false`)
		require.NoError(t, err)
		applied, err = fixture.runtime.applyMigrationChange(ctx, forwardUp)
		require.NoError(t, err)
		require.True(t, applied)
		fixture.requireLedger(t, ctx, "schema_migrations", 2, false)
		require.True(t, fixture.relationExists(t, ctx, "forward_two"))
	})

	t.Run("a ledger dirtied at the nil version fails closed, not into a drop", func(t *testing.T) {
		fixture := newHotReloadFixture(t, ctx, control, ownerConnection, "hot_reload_nil_version_dirty")
		fixture.writeMigration(t, 1, "sentinel",
			`CREATE TABLE sentinel (id int PRIMARY KEY);`, `DROP TABLE sentinel;`)
		require.NoError(t, fixture.runtime.applyMigration(ctx))
		for id := 1; id <= 3; id++ {
			_, err := fixture.db.ExecContext(ctx, `INSERT INTO sentinel (id) VALUES ($1)`, id)
			require.NoError(t, err)
		}

		// An interrupted full down migration leaves the ledger dirty at the nil
		// version, where migrate.Version() reports "no migration" and drops the
		// dirty flag: the applied-version read cannot see this state, only the
		// forward call can.
		_, err := fixture.db.ExecContext(ctx, `UPDATE schema_migrations SET version = -1, dirty = true`)
		require.NoError(t, err)

		forwardUp, _ := fixture.writeMigration(t, 2, "forward",
			`CREATE TABLE forward_two (id int);`, `DROP TABLE forward_two;`)
		applied, err := fixture.runtime.applyMigrationChange(ctx, forwardUp)
		require.ErrorIs(t, err, errDirtyMigrationLedger)
		require.False(t, applied)
		fixture.requireLedger(t, ctx, "schema_migrations", -1, true)
		require.False(t, fixture.relationExists(t, ctx, "forward_two"))
		require.True(t, fixture.relationExists(t, ctx, "sentinel"), "recovering a dirty ledger must never drop the schema")
		require.Equal(t, 3, fixture.countRows(t, ctx, "sentinel"))
	})

	t.Run("simultaneous events apply a new migration exactly once", func(t *testing.T) {
		fixture := newHotReloadFixture(t, ctx, control, ownerConnection, "hot_reload_simultaneous")
		fixture.writeMigration(t, 1, "sentinel",
			`CREATE TABLE sentinel (id int PRIMARY KEY);`, `DROP TABLE sentinel;`)
		require.NoError(t, fixture.runtime.applyMigration(ctx))
		forwardUp, forwardDown := fixture.writeMigration(t, 2, "forward",
			`CREATE TABLE forward_two (id int);`, `DROP TABLE forward_two;`)

		const events = 8
		type outcome struct {
			applied bool
			err     error
		}
		outcomes := make([]outcome, events)
		var group sync.WaitGroup
		for index := range events {
			group.Add(1)
			go func(index int) {
				defer group.Done()
				event := forwardUp
				if index%2 == 1 {
					event = forwardDown
				}
				applied, err := fixture.runtime.applyMigrationChange(ctx, event)
				outcomes[index] = outcome{applied: applied, err: err}
			}(index)
		}
		group.Wait()

		applications := 0
		for index, result := range outcomes {
			if result.applied {
				applications++
				require.NoError(t, result.err, index)
				continue
			}
			if result.err != nil {
				require.ErrorIs(t, result.err, errAppliedMigrationEdited, index)
			}
		}
		require.Equal(t, 1, applications, "interleaved events must not apply the same migration twice")
		fixture.requireLedger(t, ctx, "schema_migrations", 2, false)
		require.True(t, fixture.relationExists(t, ctx, "forward_two"))
	})
}

// hotReloadFixture is one disposable database plus the service directory whose
// migrations are applied to it.
type hotReloadFixture struct {
	runtime  *Runtime
	root     string
	location string
	db       *sql.DB
}

func newHotReloadFixture(
	t *testing.T,
	ctx context.Context,
	control *migrationtest.ControlPlane,
	ownerConnection string,
	prefix string,
) *hotReloadFixture {
	t.Helper()
	database, err := control.Create(ctx, prefix)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Drop(context.Background())) })

	connection, err := url.Parse(ownerConnection)
	require.NoError(t, err)
	connection.Path = "/" + database.Name

	root := t.TempDir()
	location := filepath.Join(root, "store")
	mustMkdir(t, filepath.Join(location, "migrations"))

	runtime := NewRuntime()
	runtime.Location = location
	runtime.connection = connection.String()
	runtime.Settings.DatabaseName = database.Name
	return &hotReloadFixture{runtime: runtime, root: root, location: location, db: database.DB}
}

func (f *hotReloadFixture) writeMigration(t *testing.T, version int, name, up, down string) (string, string) {
	t.Helper()
	directory := filepath.Join(f.location, "migrations")
	upPath := filepath.Join(directory, fmt.Sprintf("%d_%s.up.sql", version, name))
	downPath := filepath.Join(directory, fmt.Sprintf("%d_%s.down.sql", version, name))
	require.NoError(t, os.WriteFile(upPath, []byte(up), 0o600))
	require.NoError(t, os.WriteFile(downPath, []byte(down), 0o600))
	return upPath, downPath
}

func (f *hotReloadFixture) requireLedger(t *testing.T, ctx context.Context, table string, version int64, dirty bool) {
	t.Helper()
	var gotVersion int64
	var gotDirty bool
	require.NoError(t, f.db.QueryRowContext(ctx,
		`SELECT version, dirty FROM `+pq.QuoteIdentifier(table)).Scan(&gotVersion, &gotDirty))
	require.Equal(t, version, gotVersion, table)
	require.Equal(t, dirty, gotDirty, table)
}

func (f *hotReloadFixture) relationExists(t *testing.T, ctx context.Context, relation string) bool {
	t.Helper()
	var exists bool
	require.NoError(t, f.db.QueryRowContext(ctx,
		`SELECT to_regclass($1) IS NOT NULL`, "public."+relation).Scan(&exists))
	return exists
}

func (f *hotReloadFixture) countRows(t *testing.T, ctx context.Context, relation string) int {
	t.Helper()
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx,
		`SELECT count(*) FROM `+pq.QuoteIdentifier(relation)).Scan(&count))
	return count
}
