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

	// authModePassword and authModeExternalIdentity are the supported values of
	// Settings.AuthMode. Empty is treated as authModePassword.
	authModePassword         = "password"
	authModeExternalIdentity = "external-identity"
)

// externalIdentity reports whether login principals authenticate through a
// cloud identity provider instead of service-managed passwords. In this mode no
// password is generated, required, or embedded in connection strings or Secrets.
func (s *Service) externalIdentity() bool {
	return s.AuthMode == authModeExternalIdentity
}

// validateAuthMode rejects any Settings.AuthMode outside the supported set.
// Empty is treated as authModePassword. It is enforced on every path that
// branches on the mode — including the restricted deploy build, which never
// loads runtime credentials — so a mistyped mode fails loud instead of silently
// falling back to password behavior.
func (s *Service) validateAuthMode() error {
	switch s.AuthMode {
	case "", authModePassword, authModeExternalIdentity:
		return nil
	default:
		return fmt.Errorf("unsupported postgres auth mode %q", s.AuthMode)
	}
}

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
	if err := s.validateAuthMode(); err != nil {
		return err
	}
	// External-identity login principals authenticate through the cloud identity
	// provider; the service holds no passwords to validate.
	if !s.externalIdentity() {
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

// defaultRuntimeReadWriteRole is the application role the managed read-write
// principal selects on login: the FIRST configured runtime read-write role,
// whatever else is configured alongside it. Keying it to the first entry rather
// than to "there is exactly one" keeps the exported credential's behavior stable
// when a second role is appended — otherwise adding `app_worker` next to
// `app_documents` would silently drop every consumer back to "permission denied"
// on its first write with no change on the consumer's side. Consumers that need
// one of the other roles still SET ROLE; the default only decides where a
// session starts.
func defaultRuntimeReadWriteRole(roles []string) string {
	if len(roles) == 0 {
		return ""
	}
	return roles[0]
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
// The read-only role has SELECT grants only. The read-write role has direct DML
// only in generic mode; delegated mode grants it only explicit SET ROLE
// memberships. Neither role has schema CREATE or role-management authority.
func (s *Runtime) ensureRuntimeAccess(ctx context.Context) error {
	// The self-hosted runtime provisions password-authenticated LOGIN roles
	// (ensureLoginRole). External-identity login principals are created
	// out-of-band by the cloud identity provider, so running this path would
	// issue empty-password LOGIN roles; fail closed instead.
	if s.externalIdentity() {
		return s.Wool.NewError("self-hosted runtime cannot reconcile runtime access in external-identity mode: login principals are provisioned by the cloud identity provider")
	}

	s.controlPlane.Lock()
	defer s.controlPlane.Unlock()

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
	// Runs after ReconcileRuntimeAccess, in its transaction: the membership the
	// default role depends on has just been proven and granted there, and a
	// reconciliation that failed rolls this back with it, leaving the principal's
	// prior default — and so its prior authority — untouched.
	if err := ensureDefaultRole(ctx, tx, access.readWriteRole, defaultRuntimeReadWriteRole(access.readWriteRoles)); err != nil {
		return s.Wool.Wrapf(err, "cannot set the read-write default role")
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

// ensureDefaultRole makes role the session default of a login principal, or
// clears it when role is empty.
//
// With runtime-read-write-roles configured the principal is NOINHERIT and holds
// no table privileges of its own — ReconcileRuntimeAccess revokes them and grants
// only membership of the application role — so its write authority is reachable
// only by selecting that role. Setting it as the login default is the same
// server-side mechanism ensureLoginRole already uses for the read-only role's
// default_transaction_read_only, and it reaches every consumer of the exported
// credential whatever driver or DSN it uses, including the restricted deploy
// profile whose connection strings this agent never authors (#94).
//
// It also degrades the way the DSN `options=-c role=<role>` form cannot: a role
// the principal cannot assume — not yet granted, or dropped by a later migration
// — logs `WARNING: permission denied to set role` and leaves the session as the
// principal, so the connection still opens and only writes fail. The startup
// parameter makes that same state a FATAL that refuses the connection, taking
// reads and health checks down with it.
//
// The value is a GUC string, not an identifier, so it is quoted as a literal;
// role has already passed validSQLIdentifier.
func ensureDefaultRole(ctx context.Context, tx *sql.Tx, principal, role string) error {
	quotedPrincipal := pq.QuoteIdentifier(principal)
	if role == "" {
		// Generic mode: the principal holds its DML grants directly. Clearing the
		// default matters on the delegated -> generic transition, where a stale
		// default would name a role the principal is no longer a member of.
		_, err := tx.ExecContext(ctx, `ALTER ROLE `+quotedPrincipal+` RESET role`)
		return err
	}
	_, err := tx.ExecContext(ctx, `ALTER ROLE `+quotedPrincipal+` SET role = `+pq.QuoteLiteral(role))
	return err
}
