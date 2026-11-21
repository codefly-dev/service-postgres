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

// runtimeLogin is a declared read-write login principal resolved against the
// database: its role, the keys its password and connection travel under, and
// its exclusive delegated role set (see Settings.RuntimeLogins).
type runtimeLogin struct {
	name           string
	role           string
	passwordKey    string
	connectionKey  string
	readWriteRoles []string
}

// maxRuntimeLoginNameLength keeps every derived role name inside PostgreSQL's
// 63-byte identifier limit: the managed prefix is at most 41 bytes.
const maxRuntimeLoginNameLength = 16

// reservedRuntimeLoginNames would collide with a managed key: the exported
// owner-, read-only-, read-write- and fixture-connection, and their passwords.
var reservedRuntimeLoginNames = map[string]bool{"owner": true, "read-only": true, "read-write": true, "fixture": true}

// resolveRuntimeLogins validates the declared logins and derives each one's
// role and keys. Resolution fails on anything a render could not carry
// faithfully, so a bad declaration is refused before any database or render
// sees it.
func resolveRuntimeLogins(settings *Settings) ([]runtimeLogin, error) {
	if settings == nil || len(settings.RuntimeLogins) == 0 {
		return nil, nil
	}
	if settings.AuthMode == authModeExternalIdentity {
		return nil, fmt.Errorf("runtime-logins are password principals; external-identity mode provisions its logins outside this service")
	}
	readOnlyRole, readWriteRole := runtimeRoleNames(settings.DatabaseName)
	prefix := strings.TrimSuffix(readWriteRole, "_rw")
	seen := make(map[string]bool, len(settings.RuntimeLogins))
	logins := make([]runtimeLogin, 0, len(settings.RuntimeLogins))
	for _, declared := range settings.RuntimeLogins {
		name := declared.Name
		if !validRuntimeLoginName(name) {
			return nil, fmt.Errorf("runtime login name %q must be 1-%d lower-case letters, digits and dashes, starting with a letter", name, maxRuntimeLoginNameLength)
		}
		if reservedRuntimeLoginNames[name] {
			return nil, fmt.Errorf("runtime login name %q is reserved for a managed credential", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("runtime login %q is declared twice", name)
		}
		seen[name] = true
		slug := strings.ReplaceAll(name, "-", "_")
		role := prefix + "_" + slug
		if role == readOnlyRole || role == readWriteRole {
			return nil, fmt.Errorf("runtime login %q collides with a managed login role", name)
		}
		roles, err := normalizedRuntimeReadWriteRoles(declared.ReadWriteRoles, readOnlyRole, readWriteRole, role)
		if err != nil {
			return nil, fmt.Errorf("runtime login %q: %w", name, err)
		}
		if len(roles) == 0 {
			return nil, fmt.Errorf("runtime login %q must declare at least one read-write role: a login's only write authority is delegated", name)
		}
		logins = append(logins, runtimeLogin{
			name:           name,
			role:           role,
			passwordKey:    "POSTGRES_" + strings.ToUpper(slug) + "_PASSWORD",
			connectionKey:  name + "-connection",
			readWriteRoles: roles,
		})
	}
	return logins, nil
}

func validRuntimeLoginName(name string) bool {
	if name == "" || len(name) > maxRuntimeLoginNameLength || name[0] < 'a' || name[0] > 'z' || strings.HasSuffix(name, "-") {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

func (s *Service) runtimeLogins() ([]runtimeLogin, error) {
	return resolveRuntimeLogins(s.Settings)
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
	if _, _, err := s.runtimeAccess(); err != nil {
		return err
	}
	logins, err := s.runtimeLogins()
	if err != nil {
		return err
	}
	used := map[string]string{s.postgresPassword: "owner", s.readOnlyPassword: "read-only", s.readWritePassword: "read-write"}
	if s.fixturePassword != "" {
		if s.externalIdentity() {
			return fmt.Errorf("the fixture principal is a password login; external-identity mode provisions its logins outside this service: remove %s", fixturePasswordKey)
		}
		if other, taken := used[s.fixturePassword]; taken {
			return fmt.Errorf("the fixture principal password must be distinct from the %s password", other)
		}
		used[s.fixturePassword] = "fixture principal"
	}
	for _, login := range logins {
		password := s.loginPasswords[login.name]
		if strings.TrimSpace(password) == "" {
			return fmt.Errorf("%s must not be empty", login.passwordKey)
		}
		if other, taken := used[password]; taken {
			return fmt.Errorf("the %s login password must be distinct from the %s password", login.name, other)
		}
		used[password] = login.name
	}
	return nil
}

func (s *Service) runtimeAccess() (readOnlyRole, readWriteRole string, err error) {
	readOnlyRole, readWriteRole = runtimeRoleNames(s.DatabaseName)
	if s.postgresUser == readOnlyRole || s.postgresUser == readWriteRole {
		return "", "", fmt.Errorf("postgres owner user conflicts with a managed runtime role")
	}
	if _, err := resolveSchemaAccess(s.Settings); err != nil {
		return "", "", err
	}
	return readOnlyRole, readWriteRole, nil
}

func runtimeRoleNames(database string) (readOnly, readWrite string) {
	prefix := runtimeRolePrefix(database)
	return prefix + "_ro", prefix + "_rw"
}

// runtimeRolePrefix is the server-wide name stem of a database's roles.
func runtimeRolePrefix(database string) string {
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
	return "codefly_" + base + "_" + digest
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

// runtimeAccessLockID is THE advisory-lock identifier every database
// control-plane mutation takes: this agent's migrations and grants, and the
// bootstrap job's runtime-access.sql alike. golang-migrate takes its OWN
// advisory lock in a DIFFERENT key space, which is precisely why a migration's
// TRUNCATE of the tracking table and a GRANT ... ON ALL TABLES rewriting that
// table's pg_class row could run concurrently and abort each other with "tuple
// concurrently updated". Putting both sides on this one key closes that across
// processes, which a Go mutex cannot do.
//
// It is computed from current_database() inside the database rather than from a
// Go-side name, so the agent and the SQL script cannot drift onto different
// keys and silently stop excluding each other.
const runtimeAccessLockID = `hashtext('codefly-runtime-access:' || current_database())`

// ensureRuntimeAccess reconciles the least-privilege runtime credentials
// exported to dependent services. Both roles are non-owner, non-superuser,
// NOBYPASSRLS principals.
// The read-only role has SELECT grants only. The read-write role has direct DML
// only in generic mode; delegated mode grants it only explicit SET ROLE
// memberships. Neither role has schema CREATE or role-management authority.
func (s *Runtime) ensureRuntimeAccess(ctx context.Context) error {
	release, err := s.controlPlane.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()

	return s.ensureRuntimeAccessLocked(ctx)
}

// ensureRuntimeAccessLocked is ensureRuntimeAccess's body. The caller MUST hold
// the control plane.
func (s *Runtime) ensureRuntimeAccessLocked(ctx context.Context) error {
	// The self-hosted runtime provisions password-authenticated LOGIN roles
	// (ensureLoginRole). External-identity login principals are created
	// out-of-band by the cloud identity provider, so running this path would
	// issue empty-password LOGIN roles; fail closed instead.
	if s.externalIdentity() {
		return s.Wool.NewError("self-hosted runtime cannot reconcile runtime access in external-identity mode: login principals are provisioned by the cloud identity provider")
	}

	access, err := resolveSchemaAccess(s.Settings)
	if err != nil {
		return err
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
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(`+runtimeAccessLockID+`)`); err != nil {
		return s.Wool.Wrapf(err, "cannot lock runtime access reconciliation")
	}
	logins, err := s.runtimeLogins()
	if err != nil {
		return err
	}
	declared := make([]pgcontrol.PasswordLogin, 0, len(logins))
	for _, login := range logins {
		declared = append(declared, pgcontrol.PasswordLogin{Role: login.role, Password: s.loginPasswords[login.name], ReadWriteRoles: login.readWriteRoles})
	}
	// The same reconciliation the in-cluster bootstrap Job runs, so a local store
	// and a deployed one grant exactly the same access.
	if err := pgcontrol.ReconcilePasswordAccess(ctx, tx, pgcontrol.PasswordAccess{
		Database:                         s.DatabaseName,
		OwnerRole:                        s.postgresUser,
		ReadOnlyRole:                     access.readOnlyRole,
		ReadOnlyPassword:                 s.readOnlyPassword,
		ReadOnlyRoles:                    access.readOnlyRoles,
		ReconcileReadOnlyRoleMemberships: access.readOnlyRoles != nil,
		ReadWriteRole:                    access.readWriteRole,
		ReadWritePassword:                s.readWritePassword,
		Schemas:                          access.schemas,
		ReadWriteRoles:                   access.readWriteRoles,
		Logins:                           declared,
	}); err != nil {
		return s.Wool.Wrapf(err, "cannot reconcile runtime access")
	}
	if err := tx.Commit(); err != nil {
		return s.Wool.Wrapf(err, "cannot commit runtime access transaction")
	}
	return nil
}
