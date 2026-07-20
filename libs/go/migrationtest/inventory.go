// Package migrationtest provides privileged, test-only migration controls for
// applications backed by the Codefly Postgres service.
//
// The production plugin remains the migration authority. This package exists
// so consuming services can qualify their own migration lineage against an
// isolated real database without copying owner-level database mechanics into
// application repositories. It must never be used by request-time code; the
// sibling postgres package intentionally exposes only authenticated read-only
// and read-write application capabilities.
package migrationtest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var migrationFilename = regexp.MustCompile(`^([0-9]+)_(.+)\.(up|down)\.sql$`)

// Migration is one reversible, numbered SQL migration. UpSQL and DownSQL are
// deliberately kept together so inventory validation cannot silently accept a
// one-way migration.
type Migration struct {
	Version int
	Name    string
	UpSQL   string
	DownSQL string
}

// LoadDirectory reads and validates a conventional golang-migrate directory.
// Versions must be contiguous from one, each version must have exactly one up
// and one down file, and the two directions must use the same descriptive name.
func LoadDirectory(directory string) ([]Migration, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return nil, errors.New("migration directory is required")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read migration directory %q: %w", directory, err)
	}
	type partial struct {
		migration Migration
		upFile    string
		downFile  string
	}
	byVersion := make(map[int]*partial)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		matches := migrationFilename.FindStringSubmatch(entry.Name())
		if matches == nil {
			return nil, fmt.Errorf("invalid migration filename %q", entry.Name())
		}
		version, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("parse migration version in %q: %w", entry.Name(), err)
		}
		if version < 1 {
			return nil, fmt.Errorf("migration version in %q must be positive", entry.Name())
		}
		candidate := byVersion[version]
		if candidate == nil {
			candidate = &partial{migration: Migration{Version: version, Name: matches[2]}}
			byVersion[version] = candidate
		} else if candidate.migration.Name != matches[2] {
			return nil, fmt.Errorf(
				"migration %d direction names differ: %q and %q",
				version, candidate.migration.Name, matches[2],
			)
		}
		body, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", entry.Name(), err)
		}
		if strings.TrimSpace(string(body)) == "" {
			return nil, fmt.Errorf("migration %q is empty", entry.Name())
		}
		switch matches[3] {
		case "up":
			if candidate.upFile != "" {
				return nil, fmt.Errorf("migration %d has duplicate up files %q and %q", version, candidate.upFile, entry.Name())
			}
			candidate.upFile = entry.Name()
			candidate.migration.UpSQL = string(body)
		case "down":
			if candidate.downFile != "" {
				return nil, fmt.Errorf("migration %d has duplicate down files %q and %q", version, candidate.downFile, entry.Name())
			}
			candidate.downFile = entry.Name()
			candidate.migration.DownSQL = string(body)
		}
	}
	if len(byVersion) == 0 {
		return nil, fmt.Errorf("migration directory %q contains no migrations", directory)
	}
	versions := make([]int, 0, len(byVersion))
	for version := range byVersion {
		versions = append(versions, version)
	}
	sort.Ints(versions)
	result := make([]Migration, 0, len(versions))
	for index, version := range versions {
		want := index + 1
		if version != want {
			return nil, fmt.Errorf("migration inventory is not contiguous: found version %d, want %d", version, want)
		}
		candidate := byVersion[version]
		if candidate.upFile == "" || candidate.downFile == "" {
			return nil, fmt.Errorf("migration %d %q requires both up and down files", version, candidate.migration.Name)
		}
		result = append(result, candidate.migration)
	}
	return result, nil
}

// ApplySQL executes one migration body in its own transaction. Transactional
// application matches the Postgres plugin's migration contract and makes a
// failed DDL body observable without leaving a partially applied schema.
func ApplySQL(ctx context.Context, db *sql.DB, body, label string) error {
	if ctx == nil {
		return errors.New("migration context is required")
	}
	if db == nil {
		return errors.New("migration database is required")
	}
	if strings.TrimSpace(body) == "" {
		return fmt.Errorf("migration %q body is empty", label)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migration %s begin: %w", label, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, body); err != nil {
		return fmt.Errorf("migration %s execute: %w", label, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %s commit: %w", label, err)
	}
	return nil
}

// ApplyUp installs every migration in ascending order.
func ApplyUp(ctx context.Context, db *sql.DB, migrations []Migration) error {
	for _, migration := range migrations {
		if err := ApplySQL(ctx, db, migration.UpSQL, fmt.Sprintf("up %d (%s)", migration.Version, migration.Name)); err != nil {
			return err
		}
	}
	return nil
}

// ApplyDown removes every migration in descending order.
func ApplyDown(ctx context.Context, db *sql.DB, migrations []Migration) error {
	for index := len(migrations) - 1; index >= 0; index-- {
		migration := migrations[index]
		if err := ApplySQL(ctx, db, migration.DownSQL, fmt.Sprintf("down %d (%s)", migration.Version, migration.Name)); err != nil {
			return err
		}
	}
	return nil
}
