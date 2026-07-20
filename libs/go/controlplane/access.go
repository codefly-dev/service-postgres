// Package controlplane contains Postgres-owner operations used by the
// service-postgres runtime and explicit migration/test compositions.
//
// It is intentionally separate from the authenticated application Store. A
// request handler should never import this package or receive its credentials.
package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

// SQLExecutor is the transaction surface required to reconcile runtime roles.
// *sql.Tx satisfies it; callers retain ownership of commit and rollback.
type SQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// RuntimeAccess describes the least-privilege application roles for one
// database. Roles must already exist; login-role creation and password rotation
// remain service-runtime responsibilities.
type RuntimeAccess struct {
	Database       string
	OwnerRole      string
	ReadOnlyRole   string
	ReadWriteRole  string
	Schemas        []string
	ReadWriteRoles []string
	// ReconcileReadWriteRoleMemberships controls cluster-wide membership
	// reconciliation. The service runtime enables it; isolated database drills
	// leave it disabled because memberships are not database-local.
	ReconcileReadWriteRoleMemberships bool
}

// ReconcileRuntimeAccess grants only CONNECT/USAGE/query/DML capabilities,
// revokes schema creation, installs matching default privileges, and reconciles
// explicitly configured NOLOGIN roles assumed by the read-write principal.
func ReconcileRuntimeAccess(ctx context.Context, executor SQLExecutor, access RuntimeAccess) error {
	if ctx == nil {
		return errors.New("runtime-access context is required")
	}
	if executor == nil {
		return errors.New("runtime-access SQL executor is required")
	}
	if err := validateRuntimeAccess(access); err != nil {
		return err
	}
	database := pq.QuoteIdentifier(access.Database)
	owner := pq.QuoteIdentifier(access.OwnerRole)
	readOnly := pq.QuoteIdentifier(access.ReadOnlyRole)
	readWrite := pq.QuoteIdentifier(access.ReadWriteRole)

	databaseStatements := []string{
		`REVOKE ALL PRIVILEGES ON DATABASE ` + database + ` FROM ` + readOnly,
		`REVOKE ALL PRIVILEGES ON DATABASE ` + database + ` FROM ` + readWrite,
		`GRANT CONNECT ON DATABASE ` + database + ` TO ` + readOnly,
		`GRANT CONNECT ON DATABASE ` + database + ` TO ` + readWrite,
	}
	for _, statement := range databaseStatements {
		if _, err := executor.ExecContext(ctx, statement); err != nil {
			return err
		}
	}

	for _, schemaName := range access.Schemas {
		schema := pq.QuoteIdentifier(schemaName)
		statements := []string{
			`REVOKE CREATE ON SCHEMA ` + schema + ` FROM PUBLIC`,
			`REVOKE ALL PRIVILEGES ON SCHEMA ` + schema + ` FROM ` + readOnly,
			`REVOKE ALL PRIVILEGES ON SCHEMA ` + schema + ` FROM ` + readWrite,
			`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + readOnly,
			`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + readWrite,
			`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ` + schema + ` FROM ` + readOnly,
			`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ` + schema + ` FROM ` + readWrite,
			`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ` + schema + ` FROM ` + readOnly,
			`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ` + schema + ` FROM ` + readWrite,
			`GRANT SELECT ON ALL TABLES IN SCHEMA ` + schema + ` TO ` + readOnly,
			`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ` + schema + ` TO ` + readWrite,
			`GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA ` + schema + ` TO ` + readWrite,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` REVOKE ALL ON TABLES FROM ` + readOnly,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` REVOKE ALL ON TABLES FROM ` + readWrite,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` REVOKE ALL ON SEQUENCES FROM ` + readOnly,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` REVOKE ALL ON SEQUENCES FROM ` + readWrite,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` GRANT SELECT ON TABLES TO ` + readOnly,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ` + readWrite,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO ` + readWrite,
		}
		for _, statement := range statements {
			if _, err := executor.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
	}
	if !access.ReconcileReadWriteRoleMemberships {
		return nil
	}
	return reconcileRuntimeRoleMemberships(ctx, executor, access.ReadWriteRole, access.ReadWriteRoles)
}

func validateRuntimeAccess(access RuntimeAccess) error {
	for label, identifier := range map[string]string{
		"database":        access.Database,
		"owner role":      access.OwnerRole,
		"read-only role":  access.ReadOnlyRole,
		"read-write role": access.ReadWriteRole,
	} {
		if strings.TrimSpace(identifier) == "" {
			return fmt.Errorf("runtime-access %s is required", label)
		}
	}
	if access.ReadOnlyRole == access.ReadWriteRole {
		return errors.New("runtime-access read-only and read-write roles must differ")
	}
	if len(access.Schemas) == 0 {
		return errors.New("runtime-access schema is required")
	}
	if len(access.ReadWriteRoles) > 0 && !access.ReconcileReadWriteRoleMemberships {
		return errors.New("runtime-access read-write roles require membership reconciliation")
	}
	for _, schema := range access.Schemas {
		if strings.TrimSpace(schema) == "" {
			return errors.New("runtime-access schema cannot be empty")
		}
	}
	return nil
}

func reconcileRuntimeRoleMemberships(ctx context.Context, executor SQLExecutor, member string, configured []string) error {
	rows, err := executor.QueryContext(ctx, `
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
			_ = rows.Close()
			return err
		}
		current = append(current, role)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, role := range current {
		if _, err := executor.ExecContext(ctx, `REVOKE `+pq.QuoteIdentifier(role)+` FROM `+pq.QuoteIdentifier(member)); err != nil {
			return err
		}
	}

	for _, role := range configured {
		var canLogin, superuser, createDatabase, createRole bool
		err := executor.QueryRowContext(ctx, `
			SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole
			FROM pg_roles
			WHERE rolname = $1`, role).Scan(&canLogin, &superuser, &createDatabase, &createRole)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("configured runtime read-write role %q does not exist; create it in a migration", role)
		}
		if err != nil {
			return err
		}
		if canLogin || superuser || createDatabase || createRole {
			return fmt.Errorf("configured runtime read-write role %q must be NOLOGIN, NOSUPERUSER, NOCREATEDB, and NOCREATEROLE", role)
		}
		if _, err := executor.ExecContext(ctx, `GRANT `+pq.QuoteIdentifier(role)+` TO `+pq.QuoteIdentifier(member)); err != nil {
			return err
		}
	}
	return nil
}
