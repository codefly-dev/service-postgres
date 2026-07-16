package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

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
	if err := reconcileRuntimeGrants(ctx, tx, s.DatabaseName, s.postgresUser, access); err != nil {
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

func reconcileRuntimeGrants(ctx context.Context, tx *sql.Tx, database, owner string, access runtimeAccess) error {
	db := pq.QuoteIdentifier(database)
	ownerRole := pq.QuoteIdentifier(owner)
	ro := pq.QuoteIdentifier(access.readOnlyRole)
	rw := pq.QuoteIdentifier(access.readWriteRole)

	databaseStatements := []string{
		`REVOKE ALL PRIVILEGES ON DATABASE ` + db + ` FROM ` + ro,
		`REVOKE ALL PRIVILEGES ON DATABASE ` + db + ` FROM ` + rw,
		`GRANT CONNECT ON DATABASE ` + db + ` TO ` + ro,
		`GRANT CONNECT ON DATABASE ` + db + ` TO ` + rw,
	}
	for _, statement := range databaseStatements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}

	for _, schemaName := range access.schemas {
		schema := pq.QuoteIdentifier(schemaName)
		statements := []string{
			`REVOKE CREATE ON SCHEMA ` + schema + ` FROM PUBLIC`,
			`REVOKE ALL PRIVILEGES ON SCHEMA ` + schema + ` FROM ` + ro,
			`REVOKE ALL PRIVILEGES ON SCHEMA ` + schema + ` FROM ` + rw,
			`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + ro,
			`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + rw,
			`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ` + schema + ` FROM ` + ro,
			`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ` + schema + ` FROM ` + rw,
			`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ` + schema + ` FROM ` + ro,
			`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ` + schema + ` FROM ` + rw,
			`GRANT SELECT ON ALL TABLES IN SCHEMA ` + schema + ` TO ` + ro,
			`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ` + schema + ` TO ` + rw,
			`GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA ` + schema + ` TO ` + rw,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + ownerRole + ` IN SCHEMA ` + schema + ` REVOKE ALL ON TABLES FROM ` + ro,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + ownerRole + ` IN SCHEMA ` + schema + ` REVOKE ALL ON TABLES FROM ` + rw,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + ownerRole + ` IN SCHEMA ` + schema + ` REVOKE ALL ON SEQUENCES FROM ` + ro,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + ownerRole + ` IN SCHEMA ` + schema + ` REVOKE ALL ON SEQUENCES FROM ` + rw,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + ownerRole + ` IN SCHEMA ` + schema + ` GRANT SELECT ON TABLES TO ` + ro,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + ownerRole + ` IN SCHEMA ` + schema + ` GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ` + rw,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + ownerRole + ` IN SCHEMA ` + schema + ` GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO ` + rw,
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
	}
	return reconcileRuntimeRoleMemberships(ctx, tx, access.readWriteRole, access.readWriteRoles)
}

func reconcileRuntimeRoleMemberships(ctx context.Context, tx *sql.Tx, member string, configured []string) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT granted.rolname
		FROM pg_auth_members membership
		JOIN pg_roles granted ON granted.oid = membership.roleid
		JOIN pg_roles principal ON principal.oid = membership.member
		WHERE principal.rolname = $1`, member)
	if err != nil {
		return err
	}
	var current []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			rows.Close()
			return err
		}
		current = append(current, role)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, role := range current {
		if _, err := tx.ExecContext(ctx, `REVOKE `+pq.QuoteIdentifier(role)+` FROM `+pq.QuoteIdentifier(member)); err != nil {
			return err
		}
	}

	for _, role := range configured {
		var canLogin, superuser, createDB, createRole bool
		err := tx.QueryRowContext(ctx, `
			SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole
			FROM pg_roles
			WHERE rolname = $1`, role).Scan(&canLogin, &superuser, &createDB, &createRole)
		if err == sql.ErrNoRows {
			return fmt.Errorf("configured runtime read-write role %q does not exist; create it in a migration", role)
		}
		if err != nil {
			return err
		}
		if canLogin || superuser || createDB || createRole {
			return fmt.Errorf("configured runtime read-write role %q must be NOLOGIN, NOSUPERUSER, NOCREATEDB, and NOCREATEROLE", role)
		}
		if _, err := tx.ExecContext(ctx, `GRANT `+pq.QuoteIdentifier(role)+` TO `+pq.QuoteIdentifier(member)); err != nil {
			return err
		}
	}
	return nil
}
