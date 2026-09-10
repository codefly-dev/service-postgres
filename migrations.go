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

// migrationFileName matches the conventional golang-migrate filename:
// <version>_<name>.up.sql or <version>_<name>.down.sql.
var migrationFileName = regexp.MustCompile(`^([0-9]+)_.+\.(up|down)\.sql$`)

// migrationFS hides every directory entry that is not a conventional migration
// filename. golang-migrate parses the extension as a free-form group, so an
// editor backup left beside a migration — 2_add_index.up.sql~, .bak, .orig —
// parses as the SAME version and direction as the file it shadows and makes the
// source driver reject the entire lineage as a duplicate.
type migrationFS struct {
	fs.FS
}

func (f migrationFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(f.FS, name)
	if err != nil {
		return nil, err
	}
	var migrations []fs.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() && migrationFileName.MatchString(entry.Name()) {
			migrations = append(migrations, entry)
		}
	}
	return migrations, nil
}

// openSource builds the golang-migrate source driver for one lineage over the
// filtered view of its directory.
func (m migrationSource) openSource() (source.Driver, error) {
	if err := m.checkConflicts(); err != nil {
		return nil, err
	}
	return iofs.New(migrationFS{os.DirFS(m.dir)}, ".")
}

// checkConflicts rejects two migration files claiming the same version and
// direction — a real authoring mistake, unlike the editor leftovers filtered
// above. golang-migrate names only the file it read second, which does not say
// what it collides with.
func (m migrationSource) checkConflicts() error {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return err
	}
	claimed := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		match := migrationFileName.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
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
// few times (the pool may still be warming up) and self-heals a dirty state
// left by an interrupted prior run.
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

// runUp runs m.Up with dirty-state self-healing for a single source.
func (s *Runtime) runUp(m *migrate.Migrate, src migrationSource) error {
	err := m.Up()
	if err == nil || errors.Is(err, migrate.ErrNoChange) {
		return nil
	}

	// Self-heal a dirty database left by an INTERRUPTED prior migration
	// (process killed mid-apply). golang-migrate runs each migration file
	// atomically, so a dirty version V means V fully rolled back and the schema
	// is clean at V-1. Force the version pointer back to V-1 (clearing the dirty
	// flag) and re-run Up to re-apply V onward. Without this, a single
	// interrupted run wedges the database forever ("Dirty database version N").
	var dirty migrate.ErrDirty
	if errors.As(err, &dirty) {
		s.Wool.Warn("recovering dirty migration",
			wool.Field("source", src.label()), wool.Field("dirty_version", dirty.Version))
		if dirty.Version <= 1 {
			// Dirty at the FIRST migration: there is no "version 0" to force back
			// to. The clean state is "nothing applied" — Drop and re-apply.
			if derr := m.Drop(); derr != nil {
				return s.Wool.Wrapf(derr, "cannot drop to recover dirty migration %d", dirty.Version)
			}
		} else if ferr := m.Force(dirty.Version - 1); ferr != nil {
			return s.Wool.Wrapf(ferr, "cannot force dirty migration %d to clean state", dirty.Version)
		}
		if uerr := m.Up(); uerr != nil && !errors.Is(uerr, migrate.ErrNoChange) {
			return s.Wool.Wrapf(uerr, "cannot re-apply migrations after dirty recovery")
		}
		return nil
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

	// Extract the migration number from the filename (NNN_name.up.sql).
	base := filepath.Base(migrationFile)
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
