package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/codefly-dev/core/builders"
	"github.com/codefly-dev/core/shared"
	"github.com/codefly-dev/core/wool"
	"github.com/golang-migrate/migrate/v4"
)

// Hot reload is FORWARD-ONLY. A migration the lineage has already applied is
// immutable: re-running it would rewrite the version ledger to an older
// version while the effects of the migrations after it remain in the schema,
// re-apply SQL whose effects are already present, and — through the down
// script golang-migrate must execute to replay it — delete live rows. Saving
// an applied migration is therefore REPORTED, never executed; only a migration
// above the applied version is applied, through the same forward path used at
// startup.

var (
	// errAppliedMigrationEdited reports an edit to a migration at or below the
	// lineage's applied version. The schema can only move forward, so the
	// change belongs in a new migration.
	errAppliedMigrationEdited = errors.New("migration is already applied")

	// errDirtyMigrationLedger reports an interrupted migration. Hot reload
	// never repairs it: a dirty marker does not establish whether the
	// interrupted migration committed, rolled back, or was a downgrade.
	errDirtyMigrationLedger = errors.New("migration ledger is dirty")

	// errAmbiguousMigrationOwnership reports one file claimed by two lineages.
	// Each lineage keeps its own version ledger, so applying the file against
	// either one is a guess.
	errAmbiguousMigrationOwnership = errors.New("ambiguous migration source ownership")
)

// migrationFile is a parsed migration filename.
type migrationFile struct {
	version uint64
	forward bool
}

// parseMigrationFile is an ALLOW-LIST over one filename: an editor temporary
// ("2_x.up.sql~", ".2_x.up.sql.swp", "#2_x.up.sql#"), a README, or any other
// name does not match, so it can never trigger SQL.
//
// It deliberately reuses migrationFileName, the SAME pattern openSource uses to
// decide what the lineage contains. A file hot reload recognised but the source
// hid could never be applied, and one the source exposed but hot reload ignored
// would apply on the next restart and never on save — so the two must agree by
// construction, not by two patterns kept in step by hand.
func parseMigrationFile(name string) (migrationFile, bool) {
	matches := migrationFileName.FindStringSubmatch(name)
	if matches == nil {
		return migrationFile{}, false
	}
	version, err := strconv.ParseUint(matches[1], 10, 64)
	if err != nil {
		return migrationFile{}, false
	}
	return migrationFile{version: version, forward: matches[2] == "up"}, true
}

// resolveMigrationPath makes a changed path absolute. The watcher reports a
// path relative to the service location — including for a declared sibling
// source, as "../<name>/migrations/...".
func (s *Runtime) resolveMigrationPath(changed string) string {
	if filepath.IsAbs(changed) {
		return filepath.Clean(changed)
	}
	return filepath.Clean(filepath.Join(s.Location, changed))
}

// owningMigrationSource resolves which lineage owns changed. golang-migrate's
// file driver reads a source directory flat, so a migration belongs to the
// source whose directory is exactly its parent: overlapping roots keep their
// own files instead of the first arbitrary prefix match, and a path that
// escapes every declared source (through "..", or by naming an unrelated
// directory) belongs to none. Two sources resolving to one directory cannot be
// told apart, so they are rejected rather than picked between.
func owningMigrationSource(sources []migrationSource, changed string) (*migrationSource, error) {
	parent := filepath.Dir(changed)
	var owner *migrationSource
	for i := range sources {
		if filepath.Clean(sources[i].dir) != parent {
			continue
		}
		if owner != nil {
			return nil, fmt.Errorf("%w: %q is claimed by sources %q and %q",
				errAmbiguousMigrationOwnership, changed, owner.label(), sources[i].label())
		}
		owner = &sources[i]
	}
	return owner, nil
}

// applyMigrationChange handles ONE filesystem event for a migration file and
// reports whether it applied SQL. Only a valid up-file inside a declared
// source, carrying a version above what its lineage has applied, results in
// any database work.
func (s *Runtime) applyMigrationChange(ctx context.Context, changed string) (applied bool, runErr error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	// One save fires a burst of events — the up file, its paired down file,
	// editor churn — and the watcher can deliver the next one while a migration
	// is still running. Two golang-migrate operations interleaving over one
	// ledger write each other's version, so hot-reload work against this
	// database is serialized.
	s.migrationReload.Lock()
	defer s.migrationReload.Unlock()

	file := s.resolveMigrationPath(changed)
	sources, err := s.migrationSources(ctx)
	if err != nil {
		return false, err
	}
	owner, err := owningMigrationSource(sources, file)
	if err != nil {
		return false, err
	}
	if owner == nil {
		s.Wool.Debug("ignoring change outside every migration source", wool.Field("file", file))
		return false, nil
	}
	migration, ok := parseMigrationFile(filepath.Base(file))
	if !ok {
		s.Wool.Debug("ignoring change that is not a migration file", wool.Field("file", file))
		return false, nil
	}
	if !migration.forward {
		s.Wool.Debug("ignoring down migration change",
			wool.Field("file", file), wool.Field("source", owner.label()))
		return false, nil
	}

	handle, err := s.openMigration(ctx, *owner)
	if err != nil {
		return false, err
	}
	defer func() {
		runErr = errors.Join(runErr, handle.Close())
	}()

	current, dirty, err := handle.migration.Version()
	hasCurrent := true
	switch {
	case errors.Is(err, migrate.ErrNilVersion):
		hasCurrent = false
	case err != nil:
		return false, s.Wool.Wrapf(err, "cannot read the applied version of source %q", owner.label())
	case dirty:
		return false, fmt.Errorf(
			"%w: source %q is dirty at version %d. An interrupted migration may or may not have committed, so hot reload will not repair it: inspect the schema and the %s table, reconcile them by hand, and clear the dirty flag",
			errDirtyMigrationLedger, owner.label(), current, owner.trackingTable())
	case uint64(current) >= migration.version:
		return false, fmt.Errorf(
			"%w: source %q is at version %d, so editing migration %d cannot change the schema — add a new forward migration instead",
			errAppliedMigrationEdited, owner.label(), current, migration.version)
	}

	s.Wool.Info(fmt.Sprintf("applying migrations for source %s (saw version %d)", owner.label(), migration.version))
	if err := s.runUp(handle.migration, *owner); err != nil {
		return false, err
	}
	updated, _, err := handle.migration.Version()
	if err != nil {
		return false, s.Wool.Wrapf(err, "cannot confirm the applied version of source %q", owner.label())
	}
	if hasCurrent && updated == current {
		s.Wool.Debug("no migration to apply",
			wool.Field("source", owner.label()), wool.Field("version", current))
		return false, nil
	}
	s.Wool.Info(fmt.Sprintf("applied migrations for source %s up to version %d", owner.label(), updated))
	return true, nil
}

// migrationWatchRequirements builds the hot-reload watch set from the RESOLVED
// migration sources, so a sibling service's declared directory is watched too.
// The fixed build requirements only ever name this service's own ./migrations,
// which left every additional source's files unwatched.
func (s *Runtime) migrationWatchRequirements(ctx context.Context) (*builders.Dependencies, error) {
	sources, err := s.migrationSources(ctx)
	if err != nil {
		return nil, err
	}
	components := append([]*builders.Dependency{}, requirements.Components...)
	watched := make(map[string]bool, len(components)+len(sources))
	for _, component := range requirements.Components {
		for _, declared := range component.Components() {
			watched[s.resolveMigrationPath(declared)] = true
		}
	}
	for _, src := range sources {
		dir := filepath.Clean(src.dir)
		if watched[dir] {
			continue
		}
		watched[dir] = true
		// The watcher joins every component against the service location, so a
		// source outside the service is declared relative to it.
		relative, err := filepath.Rel(s.Location, dir)
		if err != nil {
			return nil, s.Wool.Wrapf(err, "cannot locate migration source %q relative to the service", src.label())
		}
		components = append(components, builders.NewDependency(relative).WithPathSelect(shared.NewSelect("*.sql")))
	}
	return builders.NewDependencies(requirements.Name, components...), nil
}
