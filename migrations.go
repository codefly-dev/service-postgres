package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/codefly-dev/core/shared"
	"github.com/codefly-dev/core/wool"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
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

// fileURL returns the file:// migration source URL golang-migrate expects.
func (m migrationSource) fileURL() string {
	u := url.URL{Scheme: "file", Path: m.dir}
	return u.String()
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
	// One pool for the whole function — sql.Open is lazy and the *sql.DB is
	// reused across every source and retry, so a single defer cleans it up on
	// EVERY return path.
	db, err := sql.Open("postgres", s.connection)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot open database")
	}
	defer db.Close()

	for _, src := range sources {
		if err := s.applySource(ctx, db, src); err != nil {
			return s.Wool.Wrapf(err, "cannot apply migrations for source %q", src.label())
		}
	}
	return nil
}

// applySource brings ONE migration lineage up to date against the shared db,
// using that source's dedicated tracking table. Retries the driver handshake a
// few times (the pool may still be warming up) and self-heals a dirty state
// left by an interrupted prior run.
func (s *Runtime) applySource(ctx context.Context, db *sql.DB, src migrationSource) error {
	maxRetry := 3
	for range maxRetry {
		driver, err := postgres.WithInstance(db, &postgres.Config{
			DatabaseName:    s.Settings.DatabaseName,
			MigrationsTable: src.table, // "" → schema_migrations (default)
		})
		if err != nil {
			time.Sleep(time.Second)
			continue
		}

		m, err := migrate.NewWithDatabaseInstance(src.fileURL(), s.Settings.DatabaseName, driver)
		if err != nil {
			return s.Wool.Wrapf(err, "cannot create migration")
		}
		return s.runUp(m, src)
	}
	return s.Wool.NewError("cannot apply migration for source %q: retries exceeded", src.label())
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

func (s *Runtime) updateMigration(ctx context.Context, migrationFile string) error {
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

	db, err := sql.Open("postgres", s.connection)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot open database")
	}
	defer db.Close()
	driver, err := postgres.WithInstance(db, &postgres.Config{
		DatabaseName:    s.Settings.DatabaseName,
		MigrationsTable: owner.table,
	})
	if err != nil {
		return s.Wool.Wrapf(err, "cannot create driver")
	}

	m, err := migrate.NewWithDatabaseInstance(owner.fileURL(), s.Settings.DatabaseName, driver)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot create migration")
	}

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
