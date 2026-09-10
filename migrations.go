package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codefly-dev/core/shared"
	"github.com/codefly-dev/core/wool"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// migrationSource is one independent migration lineage applied against the
// shared database. Each source owns its OWN golang-migrate tracking table
// (Table), so several services can contribute migrations to a SINGLE postgres
// database without colliding on the global integer version counter.
//
// The "own" source (this postgres service's ./migrations dir) keeps the
// default table name (schema_migrations) for backward compatibility — existing
// single-service setups are byte-for-byte unchanged. Additional sources, listed
// in Settings.MigrationSources, get schema_migrations_<name>.
type migrationSource struct {
	name string // "" for this service's own migrations
	dir  string // absolute filesystem path to the migration files
	// table is the golang-migrate tracking table for this lineage. Empty means
	// the driver default (schema_migrations) — used by the own source so legacy
	// databases keep their existing version table.
	table string
}

// label is a human-readable source name for logs.
func (m migrationSource) label() string {
	if m.name == "" {
		return "store"
	}
	return m.name
}

// migrationFileNamePattern is the ONE definition of a conventional
// golang-migrate filename: <version>_<name>.<up|down>.<ext>. It is POSIX ERE so
// the bootstrap image's shell prune matches it with grep -E over the same names
// this runtime applies; builder.go renders it into the Dockerfile.
//
// The extension is a single alphanumeric run, exactly what golang-migrate's own
// `migrate create -ext` produces. Its parser accepts ANY extension (a free-form
// group), which is why an editor backup left beside a migration —
// 2_add_index.up.sql~, .bak, .orig — parses as the SAME version and direction as
// the file it shadows and makes the source driver reject the entire lineage as a
// duplicate. Requiring a plain extension excludes the leftovers while keeping
// every real migration, whatever it is named (.sql, .pgsql, .psql).
const migrationFileNamePattern = `^([0-9]+)_.+\.(up|down)\.[A-Za-z0-9]+$`

var migrationFileName = regexp.MustCompile(migrationFileNamePattern)

// migrationFS serves golang-migrate ONE snapshot of the migration files, taken
// by openSource. Handing over a precomputed listing rather than re-reading the
// directory keeps the conflict check and the exposed set from disagreeing when a
// file lands between the two scans — hot reload runs while an editor is writing.
type migrationFS struct {
	fs.FS
	entries []fs.DirEntry
}

func (f migrationFS) ReadDir(string) ([]fs.DirEntry, error) {
	return f.entries, nil
}

// openSource builds the golang-migrate source driver for one lineage over the
// migration files in its directory, hiding everything that is not one.
func (m migrationSource) openSource() (source.Driver, error) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return nil, err
	}
	var migrations []fs.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() && migrationFileName.MatchString(entry.Name()) {
			migrations = append(migrations, entry)
		}
	}
	if err := checkConflicts(migrations); err != nil {
		return nil, err
	}
	return iofs.New(migrationFS{FS: os.DirFS(m.dir), entries: migrations}, ".")
}

// checkConflicts rejects two migration files claiming the same version and
// direction — a real authoring mistake, unlike the editor leftovers already
// filtered out. golang-migrate names only the file it read second, which does
// not say what it collides with.
func checkConflicts(migrations []fs.DirEntry) error {
	claimed := make(map[string]string)
	for _, entry := range migrations {
		match := migrationFileName.FindStringSubmatch(entry.Name())
		version, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			// golang-migrate skips a version it cannot parse; stay aligned with
			// what the source driver will actually see.
			continue
		}
		key := fmt.Sprintf("%d.%s", version, match[2])
		if first, taken := claimed[key]; taken {
			return fmt.Errorf("migration version %d has two %s files: %q and %q",
				version, match[2], first, entry.Name())
		}
		claimed[key] = entry.Name()
	}
	return nil
}

// dirtyRecoveryRunbook is the manual reconciliation procedure a dirty-lineage
// error points the operator at.
const dirtyRecoveryRunbook = "docs/dirty-migrations.md"

// trackingTable is the golang-migrate version table this lineage records into.
func (m migrationSource) trackingTable() string {
	if m.table == "" {
		return postgres.DefaultMigrationsTable
	}
	return m.table
}

// migrationSources resolves every migration lineage to apply to the shared
// database: this service's own ./migrations dir (when present) plus each entry
// in Settings.MigrationSources. A source whose directory does not exist is
// skipped with a warning — a service may legitimately declare a dependency on
// this database before it ships any migrations.
func (s *Runtime) migrationSources(ctx context.Context) ([]migrationSource, error) {
	var sources []migrationSource

	// Own migrations — default tracking table, backward compatible.
	own := s.Local("migrations")
	exists, err := shared.DirectoryExists(ctx, own)
	if err != nil {
		return nil, s.Wool.Wrapf(err, "cannot check migration directory")
	}
	if exists {
		sources = append(sources, migrationSource{dir: own})
	} else {
		s.Wool.Debug("no own migration folder found", wool.DirField(own))
	}

	// Additional per-service sources sharing this database.
	for _, src := range s.Settings.MigrationSources {
		name := strings.TrimSpace(src.Name)
		if name == "" {
			s.Wool.Warn("skipping migration source with empty name", wool.Field("path", src.Path))
			continue
		}
		if !validSourceName(name) {
			s.Wool.Warn("skipping migration source with unsafe name", wool.Field("name", name))
			continue
		}
		dir := src.Path
		if dir == "" {
			dir = filepath.Join("..", name, "migrations")
		}
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(s.Location, dir)
		}
		dir = filepath.Clean(dir)
		ok, errExists := shared.DirectoryExists(ctx, dir)
		if errExists != nil {
			return nil, s.Wool.Wrapf(errExists, "cannot check migration directory for source %q", name)
		}
		if !ok {
			s.Wool.Warn("migration source directory not found; skipping",
				wool.Field("source", name), wool.DirField(dir))
			continue
		}
		sources = append(sources, migrationSource{
			name:  name,
			dir:   dir,
			table: "schema_migrations_" + name,
		})
	}
	return sources, nil
}

// validSourceName restricts a source name to characters safe in a SQL
// identifier (the tracking table is schema_migrations_<name>). golang-migrate
// quotes the table, but we keep the name conservative regardless.
func validSourceName(name string) bool {
	for _, r := range name {
		ok := r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return name != ""
}

func (s *Runtime) applyMigration(ctx context.Context) error {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	sources, err := s.migrationSources(ctx)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return nil
	}

	s.Wool.Debug("migrations", wool.Field("sources", len(sources)))
	for _, src := range sources {
		if err := s.applySource(ctx, src); err != nil {
			return s.Wool.Wrapf(err, "cannot apply migrations for source %q", src.label())
		}
	}
	return nil
}

// applySource brings ONE migration lineage up to date against the shared db,
// using that source's dedicated tracking table. Retries the driver handshake a
// few times (the pool may still be warming up); a dirty lineage fails closed.
func (s *Runtime) applySource(ctx context.Context, src migrationSource) error {
	maxRetry := 3
	var lastErr error
	for range maxRetry {
		handle, err := s.openMigration(ctx, src)
		if err != nil {
			lastErr = err
			select {
			case <-ctx.Done():
				return errors.Join(lastErr, ctx.Err())
			case <-time.After(time.Second):
			}
			continue
		}
		return errors.Join(s.runUp(handle.migration, src), handle.Close())
	}
	return s.Wool.Wrapf(lastErr, "cannot prepare migration for source %q after %d attempts", src.label(), maxRetry)
}

// migrationHandle owns every resource golang-migrate opens for one migration
// lineage. The postgres driver reserves a dedicated *sql.Conn; closing only the
// parent pool leaves that connection alive and blocks native Postgres smart
// shutdown. Each lineage therefore receives its own pool and closes the
// migrate source, driver connection, and pool together.
type migrationHandle struct {
	migration *migrate.Migrate
	pool      *sql.DB
}

// Close releases the migration source, its dedicated database connection, and
// the parent pool, preserving every cleanup failure for the caller.
func (h *migrationHandle) Close() error {
	if h == nil || h.migration == nil || h.pool == nil {
		return errors.New("migration handle is incomplete")
	}
	sourceErr, databaseErr := h.migration.Close()
	poolErr := h.pool.Close()
	return errors.Join(
		wrapMigrationCloseError("source", sourceErr),
		wrapMigrationCloseError("database connection", databaseErr),
		wrapMigrationCloseError("SQL pool", poolErr),
	)
}

// wrapMigrationCloseError adds ownership context without manufacturing an
// error for a successful close.
func wrapMigrationCloseError(resource string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close migration %s: %w", resource, err)
}

// openMigration constructs one fully-owned real golang-migrate stack. It uses
// WithConnection rather than WithInstance so construction failures cannot hide
// a leased sql.Conn inside the library before ownership reaches a Migrate.
func (s *Runtime) openMigration(ctx context.Context, src migrationSource) (*migrationHandle, error) {
	pool, err := sql.Open("postgres", s.connection)
	if err != nil {
		return nil, s.Wool.Wrapf(err, "cannot open database")
	}
	conn, err := pool.Conn(ctx)
	if err != nil {
		return nil, errors.Join(
			s.Wool.Wrapf(err, "cannot reserve migration connection"),
			wrapMigrationCloseError("SQL pool after connection failure", pool.Close()),
		)
	}
	driver, err := postgres.WithConnection(ctx, conn, &postgres.Config{
		DatabaseName:    s.Settings.DatabaseName,
		MigrationsTable: src.table, // "" → schema_migrations (default)
	})
	if err != nil {
		return nil, errors.Join(
			s.Wool.Wrapf(err, "cannot initialize migration driver"),
			wrapMigrationCloseError("database connection after driver failure", conn.Close()),
			wrapMigrationCloseError("SQL pool after driver failure", pool.Close()),
		)
	}
	sourceDriver, err := src.openSource()
	if err != nil {
		return nil, errors.Join(
			s.Wool.Wrapf(err, "cannot read migrations for source %q", src.label()),
			wrapMigrationCloseError("database driver after source failure", driver.Close()),
			wrapMigrationCloseError("SQL pool after source failure", pool.Close()),
		)
	}
	migration, err := migrate.NewWithInstance(src.label(), sourceDriver, s.Settings.DatabaseName, driver)
	if err != nil {
		return nil, errors.Join(
			s.Wool.Wrapf(err, "cannot create migration"),
			wrapMigrationCloseError("database driver after migration failure", driver.Close()),
			wrapMigrationCloseError("SQL pool after migration failure", pool.Close()),
		)
	}
	return &migrationHandle{migration: migration, pool: pool}, nil
}

// runUp brings one lineage up to date. A dirty ledger fails closed: golang-migrate's
// Drop deletes every base table in the schema — including the other services sharing
// this database — and forcing version-1 assumes both that the interrupted migration
// rolled back and that versions are consecutive, neither of which a dirty marker
// establishes.
func (s *Runtime) runUp(m *migrate.Migrate, src migrationSource) error {
	err := m.Up()
	if err == nil || errors.Is(err, migrate.ErrNoChange) {
		return nil
	}

	var dirty migrate.ErrDirty
	if errors.As(err, &dirty) {
		s.Wool.Error("migration lineage is dirty; refusing to migrate",
			wool.Field("source", src.label()),
			wool.Field("tracking_table", src.trackingTable()),
			wool.Field("dirty_version", dirty.Version))
		// Wrap rather than replace: this keeps errors.As(err, &migrate.ErrDirty{})
		// working for callers that classify the failure. The ambiguity of a dirty
		// marker, and the reconciliation steps, live in the runbook.
		return s.Wool.Wrapf(err,
			"migration lineage %q is dirty at version %d (tracking table %s); an interrupted run left the schema "+
				"out of step with the ledger and automatic recovery cannot be done safely — reconcile it by hand, see %s",
			src.label(), dirty.Version, src.trackingTable(), dirtyRecoveryRunbook)
	}
	return s.Wool.Wrapf(err, "can't apply migration")
}

func (s *Runtime) updateMigration(ctx context.Context, migrationFile string) (runErr error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	// Find which source owns the changed file so we re-apply against the right
	// tracking table. A migration is hot-reloaded inside its own lineage only.
	sources, err := s.migrationSources(ctx)
	if err != nil {
		return err
	}
	changed := filepath.Clean(migrationFile)
	var owner *migrationSource
	for i := range sources {
		if strings.HasPrefix(changed, sources[i].dir+string(filepath.Separator)) {
			owner = &sources[i]
			break
		}
	}
	if owner == nil {
		s.Wool.Debug("changed migration file matched no source", wool.Field("file", changed))
		return nil
	}

	// A write to anything that is not a migration file must not touch the
	// schema: the replay below rolls the version down and back up, so acting on
	// an editor backup (2_x.up.sql~, .bak) would drop and rebuild the table that
	// file shadows, destroying its rows.
	base := filepath.Base(migrationFile)
	if !migrationFileName.MatchString(base) {
		s.Wool.Debug("changed file is not a migration", wool.Field("file", base))
		return nil
	}

	// Extract the migration number from the filename (NNN_name.up.sql).
	s.Wool.Info(fmt.Sprintf("applying migration: %v (source %s)", base, owner.label()))
	migrationNumber, err := strconv.Atoi(strings.Split(base, "_")[0])
	if err != nil {
		return s.Wool.Wrapf(err, "cannot parse migration number")
	}

	handle, err := s.openMigration(ctx, *owner)
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, handle.Close())
	}()
	m := handle.migration

	// Re-apply ONLY the changed migration (hot-reload during dev). Force sets
	// the version to N (clearing any dirty flag), then we step exactly one
	// migration down and back up — NOT m.Down()/m.Up(), which would roll the
	// WHOLE schema to 0 and back, destroying all data on every file save.
	if err := m.Force(migrationNumber); err != nil {
		return s.Wool.Wrapf(err, "cannot force migration to %d", migrationNumber)
	}
	if err := m.Steps(-1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return s.Wool.Wrapf(err, "cannot roll back migration %d", migrationNumber)
	}
	if err := m.Steps(1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return s.Wool.Wrapf(err, "cannot re-apply migration %d", migrationNumber)
	}
	s.Wool.Info(fmt.Sprintf("re-applied migration %d (source %s)", migrationNumber, owner.label()))
	return nil
}
