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

// AuthMode selects how the login principals for the runtime roles are managed.
type AuthMode string

const (
	// AuthModePassword is the default. The service runtime owns login-role
	// creation and password rotation; this reconciler only grants privileges to
	// the already-existing _ro/_rw login roles. Local nix/docker development.
	AuthModePassword AuthMode = "password"
	// AuthModeExternalIdentity is for managed cloud Postgres with password auth
	// off. The login principals are created out-of-band by the cloud identity
	// provider (Entra ID / Cloud SQL IAM); this reconciler creates only the
	// _ro/_rw NOLOGIN group roles, grants them the same privileges, and
	// reconciles the external principals into them. No password is ever set.
	AuthModeExternalIdentity AuthMode = "external-identity"
)

// RuntimeAccess describes the least-privilege application roles for one
// database. In password mode the _ro/_rw login roles must already exist;
// login-role creation and password rotation remain service-runtime
// responsibilities. In external-identity mode this reconciler creates the
// _ro/_rw NOLOGIN group roles itself.
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
	// AuthMode selects login-principal management. Empty is AuthModePassword.
	AuthMode AuthMode
	// ReadOnlyPrincipals and ReadWritePrincipals are the externally-created
	// login principals reconciled into exactly the read-only / read-write group
	// role. Consulted only in AuthModeExternalIdentity; this reconciler never
	// creates them.
	ReadOnlyPrincipals  []string
	ReadWritePrincipals []string
}

// ReconcileRuntimeAccess grants only CONNECT/USAGE/query capabilities, revokes
// schema creation, and installs matching default privileges. The read-write
// principal receives direct DML only when no delegated roles are configured;
// otherwise its exclusive write authority is the reconciled NOLOGIN role set.
// The caller owns the transaction and must roll it back on any returned error.
//
// Membership reconciliation revokes then re-grants, so the caller must also
// serialize concurrent reconciliations of the same database: the service
// runtime holds a per-database advisory lock for the transaction's duration,
// and external-identity callers must do the same.
func ReconcileRuntimeAccess(ctx context.Context, tx *sql.Tx, access RuntimeAccess) error {
	if ctx == nil {
		return errors.New("runtime-access context is required")
	}
	if tx == nil {
		return errors.New("runtime-access SQL transaction is required")
	}
	if err := validateRuntimeAccess(access); err != nil {
		return err
	}
	database := pq.QuoteIdentifier(access.Database)
	owner := pq.QuoteIdentifier(access.OwnerRole)
	readOnly := pq.QuoteIdentifier(access.ReadOnlyRole)
	readWrite := pq.QuoteIdentifier(access.ReadWriteRole)

	if access.AuthMode == AuthModeExternalIdentity {
		if err := ensureGroupRole(ctx, tx, access.ReadOnlyRole); err != nil {
			return err
		}
		if err := ensureGroupRole(ctx, tx, access.ReadWriteRole); err != nil {
			return err
		}
	}

	databaseStatements := []string{
		`REVOKE ALL PRIVILEGES ON DATABASE ` + database + ` FROM ` + readOnly,
		`REVOKE ALL PRIVILEGES ON DATABASE ` + database + ` FROM ` + readWrite,
		`GRANT CONNECT ON DATABASE ` + database + ` TO ` + readOnly,
		`GRANT CONNECT ON DATABASE ` + database + ` TO ` + readWrite,
	}
	for _, statement := range databaseStatements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
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
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` REVOKE ALL ON TABLES FROM ` + readOnly,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` REVOKE ALL ON TABLES FROM ` + readWrite,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` REVOKE ALL ON SEQUENCES FROM ` + readOnly,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` REVOKE ALL ON SEQUENCES FROM ` + readWrite,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + owner + ` IN SCHEMA ` + schema + ` GRANT SELECT ON TABLES TO ` + readOnly,
		}
		if len(access.ReadWriteRoles) == 0 {
			statements = append(statements,
				`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA `+schema+` TO `+readWrite,
				`GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA `+schema+` TO `+readWrite,
				`ALTER DEFAULT PRIVILEGES FOR ROLE `+owner+` IN SCHEMA `+schema+` GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO `+readWrite,
				`ALTER DEFAULT PRIVILEGES FOR ROLE `+owner+` IN SCHEMA `+schema+` GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO `+readWrite,
			)
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
	}
	if access.ReconcileReadWriteRoleMemberships {
		if err := reconcileRuntimeRoleMemberships(ctx, tx, access.ReadWriteRole, access.ReadWriteRoles); err != nil {
			return err
		}
	}
	if access.AuthMode == AuthModeExternalIdentity {
		if err := reconcileExternalPrincipals(ctx, tx, access.ReadOnlyRole, access.ReadOnlyPrincipals); err != nil {
			return err
		}
		return reconcileExternalPrincipals(ctx, tx, access.ReadWriteRole, access.ReadWritePrincipals)
	}
	return nil
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
	switch access.AuthMode {
	case "", AuthModePassword:
		if len(access.ReadOnlyPrincipals) > 0 || len(access.ReadWritePrincipals) > 0 {
			return errors.New("runtime-access external principals require external-identity auth mode")
		}
	case AuthModeExternalIdentity:
		for _, principals := range [][]string{access.ReadOnlyPrincipals, access.ReadWritePrincipals} {
			for _, principal := range principals {
				if strings.TrimSpace(principal) == "" {
					return errors.New("runtime-access external principal cannot be empty")
				}
			}
		}
	default:
		return fmt.Errorf("runtime-access auth mode %q is not supported", access.AuthMode)
	}
	return nil
}

// ensureGroupRole creates role as a NOLOGIN group role if absent and enforces
// the guard attributes on it. It never sets a password: external-identity mode
// leaves login-principal authentication to the cloud identity provider.
func ensureGroupRole(ctx context.Context, tx *sql.Tx, role string) error {
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
	// Reasserting NOSUPERUSER (even when already false) requires a superuser.
	// Managed administrators must not need protected attributes just to reconcile
	// already-safe groups. Only change attributes which actually differ; an
	// elevated existing group still requires authority to remove those privileges.
	var login, superuser, createDB, createRole, inherit, replication, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `
		SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolreplication, rolbypassrls
		FROM pg_roles WHERE rolname = $1`, role).Scan(&login, &superuser, &createDB, &createRole, &inherit, &replication, &bypassRLS); err != nil {
		return err
	}
	var changes []string
	for _, attribute := range []struct {
		set   bool
		clear string
	}{{login, "NOLOGIN"}, {superuser, "NOSUPERUSER"}, {createDB, "NOCREATEDB"}, {createRole, "NOCREATEROLE"}, {inherit, "NOINHERIT"}, {replication, "NOREPLICATION"}, {bypassRLS, "NOBYPASSRLS"}} {
		if attribute.set {
			changes = append(changes, attribute.clear)
		}
	}
	if len(changes) == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `ALTER ROLE `+quotedRole+` WITH `+strings.Join(changes, " "))
	return err
}

// reconcileExternalPrincipals makes the group role's members exactly the
// configured external principals: members no longer configured are revoked, and
// newly configured principals are granted. It reconciles the group's membership
// only — a principal's memberships outside this group are the cloud identity
// provider's concern and are left untouched. The provider owns the principals,
// so a configured principal that does not exist fails loud rather than being
// created (mirroring the delegated read-write role existence check).
func reconcileExternalPrincipals(ctx context.Context, tx *sql.Tx, group string, principals []string) error {
	desired := make(map[string]struct{}, len(principals))
	for _, principal := range principals {
		desired[principal] = struct{}{}
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT member.rolname
		FROM pg_auth_members membership
		JOIN pg_roles granted ON granted.oid = membership.roleid
		JOIN pg_roles member ON member.oid = membership.member
		WHERE granted.rolname = $1`, group)
	if err != nil {
		return err
	}
	current := make(map[string]struct{})
	for rows.Next() {
		var member string
		if err := rows.Scan(&member); err != nil {
			_ = rows.Close()
			return err
		}
		current[member] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	quotedGroup := pq.QuoteIdentifier(group)
	for member := range current {
		if _, keep := desired[member]; keep {
			continue
		}
		if _, err := tx.ExecContext(ctx, `REVOKE `+quotedGroup+` FROM `+pq.QuoteIdentifier(member)); err != nil {
			return err
		}
	}

	for _, principal := range principals {
		if _, member := current[principal]; member {
			continue
		}
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, principal).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("external identity principal %q does not exist; create it out-of-band", principal)
		}
		if _, err := tx.ExecContext(ctx, `GRANT `+quotedGroup+` TO `+pq.QuoteIdentifier(principal)); err != nil {
			return err
		}
		current[principal] = struct{}{}
	}
	return nil
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
		if _, err := tx.ExecContext(ctx, `REVOKE `+pq.QuoteIdentifier(role)+` FROM `+pq.QuoteIdentifier(member)); err != nil {
			return err
		}
	}

	for _, role := range configured {
		var canLogin, superuser, createDatabase, createRole bool
		err := tx.QueryRowContext(ctx, `
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
		if _, err := tx.ExecContext(ctx, `GRANT `+pq.QuoteIdentifier(role)+` TO `+pq.QuoteIdentifier(member)); err != nil {
			return err
		}
	}
	return nil
}
