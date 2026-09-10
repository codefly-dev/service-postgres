package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithRestrictedSession makes Open and OpenMaintenance reject privileged or
// database-owner sessions and membership in any denied role, including transitive
// membership. Missing denied roles fail closed. Checks run for every new physical
// connection and every pool checkout; this is not a fence against a concurrent
// GRANT after checkout. Role changes must also follow an operator drain policy.
//
// This option grants nothing and changes no role or transaction settings. It is
// opt-in for compatibility. Caller-owned pools supplied to NewFactory or
// NewMaintenance remain the caller's qualification responsibility.
func WithRestrictedSession(deniedRoles ...string) Option {
	roles := append([]string(nil), deniedRoles...)
	return func(c *config) error {
		seen := map[string]bool{}
		for _, role := range roles {
			if strings.TrimSpace(role) != role || role == "" || len(role) > 63 || strings.ContainsRune(role, '\x00') || seen[role] {
				return errors.New("restricted-session roles must be distinct nonempty PostgreSQL identifiers")
			}
			seen[role] = true
		}
		c.restrictedSession = true
		c.deniedRoles = append([]string{}, roles...)
		return nil
	}
}

func checkRestrictedSession(ctx context.Context, conn *pgx.Conn, denied []string) error {
	var allowed bool
	err := conn.QueryRow(ctx, `
 SELECT
 NOT EXISTS (
  SELECT 1 FROM pg_roles r
  WHERE (r.rolname=session_user OR r.rolname=current_user
         OR pg_has_role(session_user,r.oid,'MEMBER')
         OR pg_has_role(current_user,r.oid,'MEMBER'))
    AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
 )
 AND NOT EXISTS (
  SELECT 1 FROM pg_database d WHERE d.datname=current_database()
  AND (pg_has_role(session_user,d.datdba,'MEMBER') OR pg_has_role(current_user,d.datdba,'MEMBER'))
 )
 AND NOT EXISTS (
  SELECT 1 FROM unnest($1::text[]) denied(name)
  LEFT JOIN pg_roles r ON r.rolname=denied.name
  WHERE r.oid IS NULL OR pg_has_role(session_user,r.oid,'MEMBER')
     OR pg_has_role(current_user,r.oid,'MEMBER')
 )`, denied).Scan(&allowed)
	if err != nil || !allowed {
		return errors.New("Postgres session does not satisfy its restricted role policy")
	}
	return nil
}

func installRestrictedSession(pc *pgxpool.Config, c config) {
	if !c.restrictedSession {
		return
	}
	after, before := pc.AfterConnect, pc.BeforeAcquire
	pc.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if after != nil {
			if err := after(ctx, conn); err != nil {
				return err
			}
		}
		return checkRestrictedSession(ctx, conn, c.deniedRoles)
	}
	pc.BeforeAcquire = func(ctx context.Context, conn *pgx.Conn) bool {
		if before != nil && !before(ctx, conn) {
			return false
		}
		return checkRestrictedSession(ctx, conn, c.deniedRoles) == nil
	}
}
