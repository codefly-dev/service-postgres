package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	pgcontrol "github.com/codefly-dev/service-postgres/libs/go/controlplane"
	"github.com/lib/pq"
)

const (
	ownerConnectionKey     = "owner-connection"
	readOnlyConnectionKey  = "read-only-connection"
	readWriteConnectionKey = "read-write-connection"

	// migrationConnectionEnvironmentKey is an internal bootstrap-job secret.
	// It is never part of the service's exported Configuration contract.
	migrationConnectionEnvironmentKey = "CODEFLY_POSTGRES_MIGRATION_CONNECTION"
)

type runtimeAccess struct {
	readOnlyRole   string
	readWriteRole  string
	schemas        []string
	readWriteRoles []string
}

// deriveRuntimePassword deterministically upgrades legacy owner-only service
// configurations to the scoped runtime-credential contract. HMAC makes this a
// one-way derivation: possession of an exported reader or writer password does
// not reveal the migration-owner secret or the sibling capability password.
func deriveRuntimePassword(ownerPassword, database, capability string) string {
	if strings.TrimSpace(ownerPassword) == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(ownerPassword))
	_, _ = mac.Write([]byte("codefly/service-postgres/runtime-password/v1\x00"))
	_, _ = mac.Write([]byte(database))
	_, _ = mac.Write([]byte("\x00"))
	_, _ = mac.Write([]byte(capability))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) validateCredentials() error {
	if strings.TrimSpace(s.DatabaseName) == "" {
		return fmt.Errorf("database name is required")
	}
	if strings.TrimSpace(s.postgresUser) == "" {
		return fmt.Errorf("postgres owner user is required")
	}
	credentials := []struct {
		name  string
		value string
	}{
		{name: "POSTGRES_PASSWORD", value: s.postgresPassword},
		{name: "POSTGRES_READ_ONLY_PASSWORD", value: s.readOnlyPassword},
		{name: "POSTGRES_READ_WRITE_PASSWORD", value: s.readWritePassword},
	}
	for _, credential := range credentials {
		if strings.TrimSpace(credential.value) == "" {
			return fmt.Errorf("%s must not be empty", credential.name)
		}
	}
	if s.postgresPassword == s.readOnlyPassword ||
		s.postgresPassword == s.readWritePassword ||
		s.readOnlyPassword == s.readWritePassword {
		return fmt.Errorf("owner, read-only, and read-write passwords must be distinct")
	}
	_, _, err := s.runtimeAccess()
	return err
}

func (s *Service) runtimeAccess() (readOnlyRole, readWriteRole string, err error) {
	readOnlyRole, readWriteRole = runtimeRoleNames(s.DatabaseName)
	if s.postgresUser == readOnlyRole || s.postgresUser == readWriteRole {
		return "", "", fmt.Errorf("postgres owner user conflicts with a managed runtime role")
	}
	_, err = normalizedRuntimeSchemas(s.RuntimeSchemas)
	if err != nil {
		return "", "", err
	}
	if _, err = normalizedRuntimeReadWriteRoles(s.RuntimeReadWriteRoles, readOnlyRole, readWriteRole); err != nil {
		return "", "", err
	}
	return readOnlyRole, readWriteRole, nil
}

func runtimeRoleNames(database string) (readOnly, readWrite string) {
	var slug strings.Builder
	for _, r := range strings.ToLower(database) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if r <= unicode.MaxASCII {
				slug.WriteRune(r)
			}
			continue
		}
		if slug.Len() > 0 && !strings.HasSuffix(slug.String(), "_") {
			slug.WriteByte('_')
		}
	}
	base := strings.Trim(slug.String(), "_")
	if base == "" {
		base = "database"
	}
	if len(base) > 24 {
		base = base[:24]
	}
	sum := sha256.Sum256([]byte(database))
	digest := hex.EncodeToString(sum[:4])
	prefix := "codefly_" + base + "_" + digest
	return prefix + "_ro", prefix + "_rw"
}

func normalizedRuntimeSchemas(configured []string) ([]string, error) {
	if len(configured) == 0 {
		return []string{"public"}, nil
	}
	seen := make(map[string]struct{}, len(configured))
	schemas := make([]string, 0, len(configured))
	for _, raw := range configured {
		schema := strings.TrimSpace(raw)
		if !validSQLIdentifier(schema) {
			return nil, fmt.Errorf("runtime schema %q is not a safe SQL identifier", raw)
		}
		if _, ok := seen[schema]; ok {
			continue
		}
		seen[schema] = struct{}{}
		schemas = append(schemas, schema)
	}
	if len(schemas) == 0 {
		return nil, fmt.Errorf("at least one runtime schema is required")
	}
	return schemas, nil
}

func normalizedRuntimeReadWriteRoles(configured []string, managedRoles ...string) ([]string, error) {
	managed := make(map[string]struct{}, len(managedRoles))
	for _, role := range managedRoles {
		managed[role] = struct{}{}
	}
	seen := make(map[string]struct{}, len(configured))
	roles := make([]string, 0, len(configured))
	for _, raw := range configured {
		role := strings.TrimSpace(raw)
		if !validSQLIdentifier(role) {
			return nil, fmt.Errorf("runtime read-write role %q is not a safe SQL identifier", raw)
		}
		if _, reserved := managed[role]; reserved {
			return nil, fmt.Errorf("runtime read-write role %q conflicts with a managed login role", role)
		}
		if _, ok := seen[role]; ok {
			continue
		}
		seen[role] = struct{}{}
		roles = append(roles, role)
	}
	return roles, nil
}

func validSQLIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// ensureRuntimeAccess reconciles the least-privilege runtime credentials
// exported to dependent services. Both roles are non-owner, non-superuser,
// NOBYPASSRLS principals.
// The read-only role has SELECT grants only; the read-write role has DML grants
// but no schema CREATE or role-management authority.
func (s *Runtime) ensureRuntimeAccess(ctx context.Context) error {
	schemas, err := normalizedRuntimeSchemas(s.Settings.RuntimeSchemas)
	if err != nil {
		return err
	}
	readOnlyRole, readWriteRole := runtimeRoleNames(s.DatabaseName)
	readWriteRoles, err := normalizedRuntimeReadWriteRoles(
		s.Settings.RuntimeReadWriteRoles,
		readOnlyRole,
		readWriteRole,
	)
	if err != nil {
		return err
	}
	access := runtimeAccess{
		readOnlyRole:   readOnlyRole,
		readWriteRole:  readWriteRole,
		schemas:        schemas,
		readWriteRoles: readWriteRoles,
	}

	db, err := sql.Open("postgres", s.connection)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot open database to provision runtime access")
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot begin runtime access transaction")
	}
	defer tx.Rollback()

	// Serializes concurrent reconcilers for the same database while still
	// allowing unrelated Codefly Postgres services to initialize in parallel.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "codefly-runtime-access:"+s.DatabaseName); err != nil {
		return s.Wool.Wrapf(err, "cannot lock runtime access reconciliation")
	}
	if err := ensureLoginRole(ctx, tx, access.readOnlyRole, s.readOnlyPassword, true); err != nil {
		return s.Wool.Wrapf(err, "cannot provision read-only runtime role")
	}
	if err := ensureLoginRole(ctx, tx, access.readWriteRole, s.readWritePassword, false); err != nil {
		return s.Wool.Wrapf(err, "cannot provision read-write runtime role")
	}
	if err := pgcontrol.ReconcileRuntimeAccess(ctx, tx, pgcontrol.RuntimeAccess{
		Database:                          s.DatabaseName,
		OwnerRole:                         s.postgresUser,
		ReadOnlyRole:                      access.readOnlyRole,
		ReadWriteRole:                     access.readWriteRole,
		Schemas:                           access.schemas,
		ReadWriteRoles:                    access.readWriteRoles,
		ReconcileReadWriteRoleMemberships: true,
	}); err != nil {
		return s.Wool.Wrapf(err, "cannot reconcile runtime grants")
	}
	if err := tx.Commit(); err != nil {
		return s.Wool.Wrapf(err, "cannot commit runtime access transaction")
	}
	return nil
}

func ensureLoginRole(ctx context.Context, tx *sql.Tx, role, password string, readOnly bool) error {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
		return err
	}
	quotedRole := pq.QuoteIdentifier(role)
	if !exists {
		if _, err := tx.ExecContext(ctx, `CREATE ROLE `+quotedRole); err != nil {
			return err
		}
	}
	attributes := ` WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD ` + pq.QuoteLiteral(password)
	if _, err := tx.ExecContext(ctx, `ALTER ROLE `+quotedRole+attributes); err != nil {
		return err
	}
	if readOnly {
		_, err := tx.ExecContext(ctx, `ALTER ROLE `+quotedRole+` SET default_transaction_read_only = on`)
		return err
	}
	_, err := tx.ExecContext(ctx, `ALTER ROLE `+quotedRole+` RESET default_transaction_read_only`)
	return err
}
