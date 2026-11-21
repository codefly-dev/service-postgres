package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

// PasswordLogin is one declared password-authenticated LOGIN principal beside
// the read-write login: its own role, its password, and the delegated NOLOGIN
// application roles it may assume (it defaults to the first of them).
type PasswordLogin struct {
	Role           string
	Password       string
	ReadWriteRoles []string
}

// PasswordAccess is runtime access on a self-hosted server, where the owner
// creates the login principals and sets their passwords: a read-only login, the
// read-write login, and every declared login. The local runtime and the
// in-cluster bootstrap both reconcile it through ReconcilePasswordAccess, so the
// two cannot drift apart.
type PasswordAccess struct {
	Database          string
	OwnerRole         string
	ReadOnlyRole      string
	ReadOnlyPassword  string
	ReadWriteRole     string
	ReadWritePassword string
	Schemas           []string
	// ReconcileReadOnlyRoleMemberships opts into exclusive reader delegation.
	// An empty list in this mode revokes every reader membership.
	ReconcileReadOnlyRoleMemberships bool
	ReadOnlyRoles                    []string
	// ReadWriteRoles are the read-write login's delegated application roles.
	ReadWriteRoles []string
	Logins         []PasswordLogin
}

// DefaultReadWriteRole is the application role a delegated login starts its
// sessions in: the first configured one, so appending a second role never
// changes where existing consumers write. Empty means generic mode.
func DefaultReadWriteRole(roles []string) string {
	if len(roles) == 0 {
		return ""
	}
	return roles[0]
}

// ReconcilePasswordAccess provisions every password login (LOGIN NOINHERIT, no
// elevated attribute, the given password), reconciles each one's grants and
// delegated memberships with ReconcileRuntimeAccess, and sets its default role.
// The caller owns the transaction, rolls it back on any error, and serializes
// concurrent reconcilers of the same database (the runtime-access advisory lock).
func ReconcilePasswordAccess(ctx context.Context, tx *sql.Tx, access PasswordAccess) error {
	if err := validatePasswordAccess(access); err != nil {
		return err
	}
	if err := ensureLoginRole(ctx, tx, access.ReadOnlyRole, access.ReadOnlyPassword, true); err != nil {
		return fmt.Errorf("cannot provision the read-only runtime login: %w", err)
	}
	if err := ensureLoginRole(ctx, tx, access.ReadWriteRole, access.ReadWritePassword, false); err != nil {
		return fmt.Errorf("cannot provision the read-write runtime login: %w", err)
	}
	logins := append([]PasswordLogin{{Role: access.ReadWriteRole, ReadWriteRoles: access.ReadWriteRoles}}, access.Logins...)
	for i, login := range logins {
		if i > 0 {
			if err := ensureLoginRole(ctx, tx, login.Role, login.Password, false); err != nil {
				return fmt.Errorf("cannot provision the %s runtime login: %w", login.Role, err)
			}
		}
		// Each login's memberships are its own: reconciling one never touches another's.
		if err := ReconcileRuntimeAccess(ctx, tx, RuntimeAccess{
			Database:                          access.Database,
			OwnerRole:                         access.OwnerRole,
			ReadOnlyRole:                      access.ReadOnlyRole,
			ReadOnlyRoles:                     access.ReadOnlyRoles,
			ReconcileReadOnlyRoleMemberships:  access.ReconcileReadOnlyRoleMemberships,
			ReadWriteRole:                     login.Role,
			Schemas:                           access.Schemas,
			ReadWriteRoles:                    login.ReadWriteRoles,
			ReconcileReadWriteRoleMemberships: true,
		}); err != nil {
			return fmt.Errorf("cannot reconcile the %s login's grants: %w", login.Role, err)
		}
		// After the reconciliation, in its transaction: the membership the default
		// depends on has just been granted, and a failure rolls the default back too.
		if err := ensureDefaultRole(ctx, tx, login.Role, DefaultReadWriteRole(login.ReadWriteRoles)); err != nil {
			return fmt.Errorf("cannot set the %s login's default role: %w", login.Role, err)
		}
	}
	return nil
}

func validatePasswordAccess(access PasswordAccess) error {
	if access.ReadOnlyPassword == "" || access.ReadWritePassword == "" {
		return errors.New("password access requires the read-only and read-write passwords")
	}
	seen := map[string]bool{access.OwnerRole: true, access.ReadOnlyRole: true, access.ReadWriteRole: true}
	for _, login := range access.Logins {
		if strings.TrimSpace(login.Role) != login.Role || login.Role == "" || len(login.Role) > 63 || seen[login.Role] {
			return errors.New("password access logins must be distinct roles")
		}
		if login.Password == "" {
			return fmt.Errorf("password access login %s has no password", login.Role)
		}
		seen[login.Role] = true
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
	// Only a superuser may even restate SUPERUSER, REPLICATION or BYPASSRLS, so
	// a migration owner that is not one clears only the elevated attributes the
	// role actually holds. A role holding one it cannot clear still fails, as it must.
	var superuser, createDB, createRole, replication, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `
		SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
		FROM pg_roles WHERE rolname = $1`, role).Scan(&superuser, &createDB, &createRole, &replication, &bypassRLS); err != nil {
		return err
	}
	attributes := []string{"LOGIN", "NOINHERIT"}
	for _, attribute := range []struct {
		set   bool
		clear string
	}{{superuser, "NOSUPERUSER"}, {createDB, "NOCREATEDB"}, {createRole, "NOCREATEROLE"}, {replication, "NOREPLICATION"}, {bypassRLS, "NOBYPASSRLS"}} {
		if attribute.set {
			attributes = append(attributes, attribute.clear)
		}
	}
	if _, err := tx.ExecContext(ctx, `ALTER ROLE `+quotedRole+` WITH `+strings.Join(attributes, " ")+` PASSWORD `+pq.QuoteLiteral(password)); err != nil {
		return err
	}
	if readOnly {
		_, err := tx.ExecContext(ctx, `ALTER ROLE `+quotedRole+` SET default_transaction_read_only = on`)
		return err
	}
	_, err := tx.ExecContext(ctx, `ALTER ROLE `+quotedRole+` RESET default_transaction_read_only`)
	return err
}

// ensureDefaultRole makes role the session default of a login principal, or
// clears it when role is empty. A delegated principal is NOINHERIT and holds no
// table privileges of its own, so its write authority is reachable only by
// selecting the application role; a server-side default reaches every consumer
// of the credential whatever driver it uses, and a role it cannot yet assume
// only warns at login instead of refusing the connection the way a `role`
// startup parameter would.
func ensureDefaultRole(ctx context.Context, tx *sql.Tx, principal, role string) error {
	quotedPrincipal := pq.QuoteIdentifier(principal)
	if role == "" {
		// Generic mode: clearing matters on the delegated -> generic transition,
		// where a stale default would name a role the principal no longer holds.
		_, err := tx.ExecContext(ctx, `ALTER ROLE `+quotedPrincipal+` RESET role`)
		return err
	}
	_, err := tx.ExecContext(ctx, `ALTER ROLE `+quotedPrincipal+` SET role = `+pq.QuoteLiteral(role))
	return err
}
