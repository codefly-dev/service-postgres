package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"time"

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
	// optional lets a declared source that has not shipped any migration yet
	// report a skip instead of failing startup.
	optional bool
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

// migrationLikeName matches a file that carries a conventional direction AND a
// plain extension — it claims to be a migration — but that migrationFileName
// rejects, which leaves only one reason: no leading <version>_. Such a file is
// never applied and never reported, so it is an authoring mistake rather than a
// leftover. Editor leftovers cannot match: their extension is what disqualifies
// them (sql~, sql.bak, sql.orig, sql.swp), and this pattern requires a plain one
// too. Kept beside migrationFileName so the pair cannot drift apart.
var migrationLikeName = regexp.MustCompile(`\.(up|down)\.[A-Za-z0-9]+$`)

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

// applyMigration brings every resolved lineage up to date. The sources have
// already been validated against the declaration, so this only fails on a real
// migration failure.
//
// The caller MUST hold the control plane: this runs inside applySchema, which
// migrateOnInit and Start already take one acquisition around. controlPlaneLock
// is NOT reentrant, so acquiring here would deadlock the whole lifecycle
// against itself. Cross-process exclusion against a concurrent grants run does
// not depend on that acquisition anyway — openMigration takes the
// runtime-access advisory lock inside the database.
func (s *Runtime) applyMigration(ctx context.Context, sources []migrationSource) error {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Wool.Debug("migrations", wool.Field("sources", len(sources)))
	for _, src := range sources {
		if err := s.applySource(ctx, src); err != nil {
			return s.Wool.Wrapf(err, "cannot apply migrations for source %q", src.label())
		}
	}
	return nil
}

// applySource brings ONE migration lineage up to date against the shared db,
// using that source's dedicated tracking table. Retries the driver handshake
// (the pool may still be warming up); a dirty lineage fails closed.
//
// The handshake takes golang-migrate's advisory lock, so a peer already
// migrating this lineage is exactly the wait the lock budget bounds. The
// retries share that one budget rather than each getting their own: three
// attempts against a lock held by someone else would otherwise wait three
// times as long as the configured lock budget.
func (s *Runtime) applySource(ctx context.Context, src migrationSource) error {
	budget := s.Settings.Timeouts.migrationLock()
	deadline, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var lastErr error
	for {
		handle, err := s.openMigration(deadline, src)
		if err == nil {
			return errors.Join(s.runUp(handle.migration, src), handle.Close())
		}
		lastErr = err
		select {
		case <-deadline.Done():
			return s.Wool.Wrapf(errors.Join(lastErr, deadline.Err()),
				"cannot prepare migration for source %q within %s", src.label(), budget)
		case <-time.After(migrationOpenRetryInterval):
		}
	}
}

// migrationOpenRetryInterval paces the driver-handshake retries; how many of
// them happen is whatever the lock budget affords.
const migrationOpenRetryInterval = time.Second

// migrationHandle owns every resource golang-migrate opens for one migration
// lineage. The postgres driver reserves a dedicated *sql.Conn; closing only the
// parent pool leaves that connection alive and blocks native Postgres smart
// shutdown. Each lineage therefore receives its own pool and closes the
// migrate source, driver connection, and pool together.
type migrationHandle struct {
	migration *migrate.Migrate
	pool      *sql.DB
	// conn is the driver's dedicated connection, retained so the control-plane
	// advisory lock taken on it can be released before it goes back to the pool.
	conn *sql.Conn
}

// Close releases the migration source, its dedicated database connection, and
// the parent pool, preserving every cleanup failure for the caller.
func (h *migrationHandle) Close() error {
	if h == nil || h.migration == nil || h.pool == nil || h.conn == nil {
		return errors.New("migration handle is incomplete")
	}
	// Release the control-plane lock BEFORE the driver closes the connection: a
	// session advisory lock outlives sql.Conn.Close(), which only returns the
	// connection to the pool, so a later borrower would inherit the lock and
	// wedge every other control-plane mutation against this database.
	_, unlockErr := h.conn.ExecContext(context.Background(),
		`SELECT pg_advisory_unlock(`+runtimeAccessLockID+`)`)
	sourceErr, databaseErr := h.migration.Close()
	poolErr := h.pool.Close()
	return errors.Join(
		wrapMigrationCloseError("control-plane advisory lock", unlockErr),
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
	if err = s.boundMigrationSession(ctx, conn); err != nil {
		return nil, errors.Join(
			err,
			wrapMigrationCloseError("database connection after budget failure", conn.Close()),
			wrapMigrationCloseError("SQL pool after budget failure", pool.Close()),
		)
	}
	// Join the runtime-access lock domain BEFORE golang-migrate touches the
	// tracking table. golang-migrate's own lock is on a different key, so
	// without this a GRANT ... ON ALL TABLES from another process — the
	// bootstrap job's runtime-access.sql, or a second agent — rewrites the
	// tracking table's pg_class row while this connection TRUNCATEs it, and one
	// side aborts with "tuple concurrently updated". An aborted migration
	// leaves the lineage dirty, which runUp fails closed on.
	//
	// Taken AFTER boundMigrationSession so the wait inherits that session's
	// lock_timeout: a peer holding this lock makes the migration fail inside
	// its budget instead of blocking forever. Session-scoped, so it covers
	// every statement golang-migrate runs on this handle.
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(`+runtimeAccessLockID+`)`); err != nil {
		return nil, errors.Join(
			s.Wool.Wrapf(err, "cannot acquire control-plane lock for migration"),
			wrapMigrationCloseError("database connection after lock failure", conn.Close()),
			wrapMigrationCloseError("SQL pool after lock failure", pool.Close()),
		)
	}

	driver, err := postgres.WithConnection(ctx, conn, &postgres.Config{
		DatabaseName:    s.Settings.DatabaseName,
		MigrationsTable: src.table, // "" → schema_migrations (default)
		// The driver's own statement budget is a client-side deadline. Give it
		// a grace period over the server-side one so the backend wins the race
		// and reports "canceling statement due to statement timeout" instead of
		// a bare context deadline.
		StatementTimeout: s.Settings.Timeouts.migrationStatement() + migrationStatementGrace,
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
	return &migrationHandle{migration: migration, pool: pool, conn: conn}, nil
}

// boundMigrationSession puts the lock and statement budgets on the connection
// golang-migrate is about to take ownership of. They have to be server-side
// GUCs: the driver acquires its advisory lock, reads and writes the version
// row, and drops tables under context.Background(), so no caller context ever
// reaches those statements. lock_timeout bounds the advisory-lock wait, and
// statement_timeout bounds every statement including that wait.
func (s *Runtime) boundMigrationSession(ctx context.Context, conn *sql.Conn) error {
	budgets := []struct {
		setting string
		budget  time.Duration
	}{
		{setting: "lock_timeout", budget: s.Settings.Timeouts.migrationLock()},
		{setting: "statement_timeout", budget: s.Settings.Timeouts.migrationStatement()},
	}
	for _, b := range budgets {
		// Neither GUC can be parameterized; both values are whole seconds from
		// validated settings, rendered as integer milliseconds.
		statement := fmt.Sprintf("SET %s = %d", b.setting, b.budget.Milliseconds())
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return s.Wool.Wrapf(err, "cannot bound migration %s", b.setting)
		}
	}
	return nil
}

// migrationStatementGrace separates the driver's client-side statement deadline
// from the server-side statement_timeout carrying the same budget.
const migrationStatementGrace = 15 * time.Second

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
