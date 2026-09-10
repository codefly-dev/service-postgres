package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/codefly-dev/core/wool"
	"github.com/golang-migrate/migrate/v4/source"
)

// migrationTablePrefix names the golang-migrate tracking table of a declared
// lineage: schema_migrations_<name>.
const migrationTablePrefix = "schema_migrations_"

// maxIdentifierBytes is PostgreSQL's identifier limit (NAMEDATALEN-1 on every
// stock build). The server truncates anything longer, quoted or not, so two
// lineages whose tracking tables differ only past that boundary would silently
// share ONE version ledger. The limit is therefore enforced on the final table
// name, before a connection is opened.
const maxIdentifierBytes = 63

const (
	prerequisiteMigrationSource = "migration-source"
	prerequisiteExtension       = "extension"
)

// schemaPrerequisites is the resolved, validated set of schema declarations for
// one database: every migration lineage to apply, every extension to create,
// and every explicitly optional declaration that was resolved but not applied.
// It is computed without opening a database connection, so the builder and the
// runtime reject the same declaration.
type schemaPrerequisites struct {
	sources    []migrationSource
	extensions []extensionRequest
	skipped    []skippedPrerequisite
}

// extensionRequest is one CREATE EXTENSION to run before migrations. A required
// request fails readiness when the extension cannot be created; the convenience
// defaults and declarations marked optional report a skip instead.
type extensionRequest struct {
	name     string
	required bool
}

// skippedPrerequisite is the structured outcome of an explicitly optional
// declaration that this run did not apply.
type skippedPrerequisite struct {
	kind   string
	name   string
	reason string
}

// resolveSchemaPrerequisites validates every declared schema prerequisite and
// resolves it against the filesystem. It opens no database: a typo, a duplicate
// lineage, or an over-long name fails here, before any schema is touched.
func (s *Service) resolveSchemaPrerequisites() (*schemaPrerequisites, error) {
	sources, skipped, err := s.resolveMigrationSources()
	if err != nil {
		return nil, err
	}
	extensions, err := resolveExtensions(s.Settings.Extensions)
	if err != nil {
		return nil, err
	}
	return &schemaPrerequisites{sources: sources, extensions: extensions, skipped: skipped}, nil
}

// resolveMigrationSources returns every lineage to apply to the shared database:
// this service's own ./migrations dir when present, plus each declared source.
//
// An explicitly declared source is REQUIRED: a missing directory, an unreadable
// one, a layout golang-migrate would ignore, or a directory holding no migration
// is a configuration error. Declaring `optional: true` turns the absent and
// empty cases — and only those — into a reported skip.
//
// The own dir is declared by existence rather than by configuration, so its
// absence and its emptiness stay legal (the builder creates an empty one so the
// bootstrap image's COPY resolves). Its LAYOUT is held to the same standard as
// any other lineage: the migration engine drops a file it cannot parse without
// a trace, whichever lineage owns it.
func (s *Service) resolveMigrationSources() ([]migrationSource, []skippedPrerequisite, error) {
	declared, err := s.declaredMigrationSources()
	if err != nil {
		return nil, nil, err
	}
	lineages := append([]migrationSource{{dir: s.Local("migrations")}}, declared...)

	var sources []migrationSource
	var skipped []skippedPrerequisite

	for _, lineage := range lineages {
		own := lineage.name == ""
		if own {
			// Lstat, not a read: something present but unusable — a dangling
			// symlink, a regular file — must reach the checks below rather than
			// read as "this service authors no migrations".
			if _, err := os.Lstat(lineage.dir); errors.Is(err, fs.ErrNotExist) {
				s.Wool.Debug("no own migration folder found", wool.DirField(lineage.dir))
				continue
			}
		}
		count, err := countMigrations(lineage.dir)
		switch {
		case own && err != nil:
			return nil, nil, fmt.Errorf("migration source %q: %w", lineage.label(), err)
		case errors.Is(err, fs.ErrNotExist):
			if !lineage.optional {
				return nil, nil, fmt.Errorf(
					"migration source %q declares directory %s, which does not exist: fix the path, or declare the source optional if it may ship no migrations yet",
					lineage.name, lineage.dir)
			}
			skipped = append(skipped, skippedPrerequisite{
				kind:   prerequisiteMigrationSource,
				name:   lineage.name,
				reason: fmt.Sprintf("optional source directory %s does not exist", lineage.dir),
			})
		case err != nil:
			// A path that is a file, or a directory this process may not read, is
			// a misconfiguration even for an optional source.
			return nil, nil, fmt.Errorf("migration source %q: %w", lineage.name, err)
		case count == 0 && !own:
			if !lineage.optional {
				return nil, nil, fmt.Errorf(
					"migration source %q declares directory %s, which holds no migration: add a <version>_<title>.up.sql file, or declare the source optional",
					lineage.name, lineage.dir)
			}
			skipped = append(skipped, skippedPrerequisite{
				kind:   prerequisiteMigrationSource,
				name:   lineage.name,
				reason: fmt.Sprintf("optional source directory %s holds no migration", lineage.dir),
			})
		default:
			sources = append(sources, lineage)
		}
	}
	return sources, skipped, nil
}

// declaredMigrationSources validates each declared lineage and resolves its
// directory. It touches neither the filesystem nor a database, so the builder
// and the runtime reject a bad declaration identically.
func (s *Service) declaredMigrationSources() ([]migrationSource, error) {
	declaring := make(map[string]string, len(s.Settings.MigrationSources))
	sources := make([]migrationSource, 0, len(s.Settings.MigrationSources))
	for i, declaration := range s.Settings.MigrationSources {
		name := strings.TrimSpace(declaration.Name)
		if name == "" {
			return nil, fmt.Errorf("migration source #%d declares an empty name", i+1)
		}
		if !validSourceName(name) {
			return nil, fmt.Errorf(
				"migration source %q has an unsafe name: only letters, digits and underscore are allowed", name)
		}
		table := migrationTablePrefix + name
		if len(table) > maxIdentifierBytes {
			return nil, fmt.Errorf(
				"migration source %q is too long: its tracking table %q is %d bytes and PostgreSQL truncates identifiers at %d, so a source name may be at most %d characters",
				name, table, len(table), maxIdentifierBytes, maxIdentifierBytes-len(migrationTablePrefix))
		}
		// golang-migrate quotes the tracking table, so the ledger identity is
		// the exact (case-sensitive) table name.
		if other, taken := declaring[table]; taken {
			return nil, fmt.Errorf(
				"migration sources %q and %q both track their versions in %q: give each lineage a distinct name",
				other, name, table)
		}
		declaring[table] = name
		sources = append(sources, migrationSource{
			name:     name,
			dir:      s.migrationDirectory(name, declaration.Path),
			table:    table,
			optional: declaration.Optional,
		})
	}
	return sources, nil
}

// migrationDirectory resolves a declared path against this service's directory,
// defaulting to the sibling-service layout when the declaration omits one.
func (s *Service) migrationDirectory(name, path string) string {
	if path == "" {
		path = filepath.Join("..", name, "migrations")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(s.Location, path)
	}
	return filepath.Clean(path)
}

// countMigrations reports how many forward migrations a directory holds and
// rejects a layout golang-migrate would silently ignore: its source driver skips
// every file that does not parse as <version>_<title>.<up|down>.sql, so one typo
// in a filename drops a migration without a trace. Non-SQL files (the scaffolded
// README) are not migrations and are left alone.
func countMigrations(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("cannot read migration directory %s: %w", dir, err)
	}
	up := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		migration, err := source.Parse(entry.Name())
		if err != nil {
			return 0, fmt.Errorf(
				"migration file %s is ignored by the migration engine: name it <version>_<title>.up.sql or <version>_<title>.down.sql",
				filepath.Join(dir, entry.Name()))
		}
		if migration.Direction == source.Up {
			up++
		}
	}
	return up, nil
}

// resolveExtensions merges the always-on convenience defaults with the
// explicitly declared extensions. A declaration is REQUIRED unless it says
// otherwise: an image that does not ship the shared library, or a migration
// owner that may not install it, must fail readiness rather than leave the
// service running against a schema it cannot use. Declaring the same extension
// as a default upgrades that default to required.
func resolveExtensions(declared []Extension) ([]extensionRequest, error) {
	position := make(map[string]int, len(defaultExtensions)+len(declared))
	requests := make([]extensionRequest, 0, len(defaultExtensions)+len(declared))
	for _, name := range defaultExtensions {
		position[name] = len(requests)
		requests = append(requests, extensionRequest{name: name})
	}
	for i, declaration := range declared {
		name := strings.TrimSpace(declaration.Name)
		if name == "" {
			return nil, fmt.Errorf("extension #%d declares an empty name", i+1)
		}
		if !validExtName(name) {
			return nil, fmt.Errorf(
				"extension %q has an unsafe name: only letters, digits, underscore and dash are allowed", name)
		}
		request := extensionRequest{name: name, required: !declaration.Optional}
		if at, seen := position[name]; seen {
			requests[at] = request
			continue
		}
		position[name] = len(requests)
		requests = append(requests, request)
	}
	return requests, nil
}

// reportSchemaPrerequisites records what this run resolved: the lineages and
// extensions it applied, and every optional declaration it skipped.
func (s *Service) reportSchemaPrerequisites(prerequisites *schemaPrerequisites) {
	labels := make([]string, 0, len(prerequisites.sources))
	for _, src := range prerequisites.sources {
		labels = append(labels, src.label())
	}
	s.Wool.Debug("schema prerequisites resolved",
		wool.Field("migration_sources", strings.Join(labels, ",")),
		wool.Field("extensions", len(prerequisites.extensions)))
	for _, skipped := range prerequisites.skipped {
		s.Wool.Warn("schema prerequisite skipped",
			wool.Field("kind", skipped.kind),
			wool.Field("name", skipped.name),
			wool.Field("reason", skipped.reason))
	}
}
