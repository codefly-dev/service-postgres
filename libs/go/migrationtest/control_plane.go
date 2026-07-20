package migrationtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	pgcontrol "github.com/codefly-dev/service-postgres/libs/go/controlplane"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lib/pq"
)

// ControlPlane owns a migration-only Postgres connection. It is intentionally
// a separate test package rather than part of the authenticated Store API, so
// application code cannot accidentally obtain CREATEDB or schema-owner power.
type ControlPlane struct {
	ownerConnection string
	owner           *sql.DB
	closeOnce       sync.Once
}

// OpenControlPlane verifies a migration-owner connection supplied privately by
// a Codefly Postgres test composition.
func OpenControlPlane(ctx context.Context, ownerConnection string) (*ControlPlane, error) {
	if ctx == nil {
		return nil, errors.New("migration control-plane context is required")
	}
	if strings.TrimSpace(ownerConnection) == "" {
		return nil, errors.New("migration-owner connection is required")
	}
	owner, err := sql.Open("pgx", ownerConnection)
	if err != nil {
		return nil, fmt.Errorf("open migration-owner connection: %w", err)
	}
	if err := owner.PingContext(ctx); err != nil {
		_ = owner.Close()
		return nil, fmt.Errorf("ping migration-owner connection: %w", err)
	}
	return &ControlPlane{ownerConnection: ownerConnection, owner: owner}, nil
}

// Close releases the owner connection. Databases created by this control plane
// must be dropped separately; this avoids hiding failed cleanup.
func (control *ControlPlane) Close() error {
	if control == nil || control.owner == nil {
		return nil
	}
	var err error
	control.closeOnce.Do(func() { err = control.owner.Close() })
	return err
}

// Database is an isolated real Postgres database owned by a ControlPlane.
// Close releases client connections; Drop closes and forcibly removes it.
type Database struct {
	Name      string
	DB        *sql.DB
	control   *ControlPlane
	closeOnce sync.Once
	closeErr  error
	dropOnce  sync.Once
	dropErr   error
}

// Create creates and opens an isolated database with an unpredictable,
// identifier-safe name derived from prefix.
func (control *ControlPlane) Create(ctx context.Context, prefix string) (*Database, error) {
	name, err := uniqueDatabaseName(prefix)
	if err != nil {
		return nil, err
	}
	if err := control.create(ctx, name, ""); err != nil {
		return nil, err
	}
	database, err := control.open(ctx, name)
	if err != nil {
		_ = control.drop(context.Background(), name)
		return nil, err
	}
	return database, nil
}

// Clone creates a physical clone of source and opens it. The caller must close
// every source connection first because Postgres template cloning requires the
// source database to be idle.
func (control *ControlPlane) Clone(ctx context.Context, source, prefix string) (*Database, error) {
	if err := validateDatabaseName(source); err != nil {
		return nil, fmt.Errorf("source database: %w", err)
	}
	name, err := uniqueDatabaseName(prefix)
	if err != nil {
		return nil, err
	}
	if err := control.create(ctx, name, source); err != nil {
		return nil, err
	}
	database, err := control.open(ctx, name)
	if err != nil {
		_ = control.drop(context.Background(), name)
		return nil, err
	}
	return database, nil
}

func (control *ControlPlane) create(ctx context.Context, name, template string) error {
	if control == nil || control.owner == nil {
		return errors.New("migration control plane is not open")
	}
	statement := "CREATE DATABASE " + pq.QuoteIdentifier(name)
	if template != "" {
		statement += " WITH TEMPLATE " + pq.QuoteIdentifier(template)
	}
	if _, err := control.owner.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("create isolated database %q: %w", name, err)
	}
	return nil
}

func (control *ControlPlane) open(ctx context.Context, name string) (*Database, error) {
	config, err := pgx.ParseConfig(control.ownerConnection)
	if err != nil {
		return nil, fmt.Errorf("parse migration-owner connection: %w", err)
	}
	config.Database = name
	// pgx ConnConfig.ConnString returns the original DSN, so use a stdlib
	// connector built from the modified configuration.
	db := stdlib.OpenDB(*config)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open isolated database %q: %w", name, err)
	}
	return &Database{Name: name, DB: db, control: control}, nil
}

// Close releases all client connections to the isolated database without
// dropping it. This is required before Clone.
func (database *Database) Close() error {
	if database == nil || database.DB == nil {
		return nil
	}
	database.closeOnce.Do(func() { database.closeErr = database.DB.Close() })
	return database.closeErr
}

// ReconcileRuntimeAccess applies the same least-privilege grant/default-
// privilege contract used by the running Postgres plugin to this isolated
// database. Only role identities are read from the supplied runtime DSNs;
// owner authority remains inside the ControlPlane.
func (database *Database) ReconcileRuntimeAccess(
	ctx context.Context,
	readOnlyConnection string,
	readWriteConnection string,
	schemas ...string,
) error {
	if database == nil || database.DB == nil || database.control == nil {
		return errors.New("isolated database is not open")
	}
	ownerConfig, err := pgx.ParseConfig(database.control.ownerConnection)
	if err != nil {
		return fmt.Errorf("parse migration-owner connection: %w", err)
	}
	readOnlyConfig, err := pgx.ParseConfig(readOnlyConnection)
	if err != nil {
		return fmt.Errorf("parse read-only runtime connection: %w", err)
	}
	readWriteConfig, err := pgx.ParseConfig(readWriteConnection)
	if err != nil {
		return fmt.Errorf("parse read-write runtime connection: %w", err)
	}
	if len(schemas) == 0 {
		schemas = []string{"public"}
	}
	tx, err := database.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin isolated runtime-access reconciliation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := pgcontrol.ReconcileRuntimeAccess(ctx, tx, pgcontrol.RuntimeAccess{
		Database:      database.Name,
		OwnerRole:     ownerConfig.User,
		ReadOnlyRole:  readOnlyConfig.User,
		ReadWriteRole: readWriteConfig.User,
		Schemas:       schemas,
	}); err != nil {
		return fmt.Errorf("reconcile isolated runtime access: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit isolated runtime-access reconciliation: %w", err)
	}
	return nil
}

// Drop closes all client connections and forcibly removes the isolated
// database. It is idempotent and suitable for test cleanup.
func (database *Database) Drop(ctx context.Context) error {
	if database == nil {
		return nil
	}
	database.dropOnce.Do(func() {
		closeErr := database.Close()
		if database.control == nil {
			database.dropErr = errors.Join(closeErr, errors.New("isolated database has no control plane"))
			return
		}
		database.dropErr = errors.Join(closeErr, database.control.drop(ctx, database.Name))
	})
	return database.dropErr
}

func (control *ControlPlane) drop(ctx context.Context, name string) error {
	if control == nil || control.owner == nil {
		return errors.New("migration control plane is not open")
	}
	if err := validateDatabaseName(name); err != nil {
		return err
	}
	if _, err := control.owner.ExecContext(ctx, "DROP DATABASE IF EXISTS "+pq.QuoteIdentifier(name)+" WITH (FORCE)"); err != nil {
		return fmt.Errorf("drop isolated database %q: %w", name, err)
	}
	return nil
}

func uniqueDatabaseName(prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if err := validateDatabaseName(prefix); err != nil {
		return "", fmt.Errorf("database prefix: %w", err)
	}
	// Postgres identifiers are at most 63 bytes. Sixteen random hex characters
	// plus the separator leaves 46 bytes for a recognizable test prefix.
	if len(prefix) > 46 {
		prefix = prefix[:46]
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generate isolated database suffix: %w", err)
	}
	return fmt.Sprintf("%s_%x", prefix, suffix), nil
}

func validateDatabaseName(name string) error {
	if name == "" {
		return errors.New("database name is required")
	}
	if len(name) > 63 {
		return fmt.Errorf("database name exceeds 63 bytes")
	}
	for index, character := range name {
		valid := character == '_' ||
			(character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(index > 0 && character >= '0' && character <= '9')
		if !valid {
			return fmt.Errorf("database name %q contains unsafe characters", name)
		}
	}
	return nil
}
