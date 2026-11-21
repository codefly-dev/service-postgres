// Package rowscope emits the SQL that makes one table row-confined, so that an
// application's migrations state which table and which columns and never
// hand-write a policy: the roles of each mode and access, the grants, ENABLE
// and FORCE ROW LEVEL SECURITY, and the strict and privileged policies a
// postgres.Store's Binding is read by.
//
// It emits text and runs nothing. A migration embeds the output (or a
// generator writes it to a numbered migration file), and the migration owner
// runs it; migrationtest.CheckRowScope then checks the catalog the migrations
// left, whatever wrote them.
//
// The shape is proved in ../rowscope_spike_integration_test.go and
// ../rowscope_access_spike_integration_test.go. Four things it relies on are
// easy to get wrong by hand, which is why it is emitted:
//
//   - a read role holds SELECT and nothing else, so a write on it is refused
//     with permission denied in any transaction, READ ONLY or not.
//   - every policy names the roles it applies to, read and write, one by one.
//     No role is a member of another: what a role reaches is what the catalog
//     says about that role, and SET ROLE has no chain to walk.
//   - a row's partition, scope and principal are immutable after insert
//     because no mode role holds UPDATE on those columns. No policy stops a
//     privileged transaction re-stamping a principal; the column privilege does.
//   - every setting is read as (SELECT NULLIF(current_setting(name, true), ”)),
//     so that it is one InitPlan per statement and an unbound transaction
//     compares against NULL.
package rowscope

import (
	"errors"
	"fmt"
	"strings"

	postgres "github.com/codefly-dev/service-postgres/libs/go"
	"github.com/jackc/pgx/v5"
)

// Settings names the transaction-local settings the policies read. They must
// be the names the Store installs: WithScopeSettings' first name for the
// partition, WithBindingSettings' first two for the reach and the principal,
// and WithWriteReachSetting's for the write reach.
type Settings struct {
	Partition string
	Reach     string
	Principal string
	// WriteReach is the scopes a write transaction may write, a subset of the
	// reach. It is empty in a read transaction.
	WriteReach string
}

// DefaultSettings are the Store's defaults.
func DefaultSettings() Settings {
	return Settings{
		Partition:  "codefly.current_tenant_id",
		Reach:      "codefly.current_scopes",
		Principal:  "codefly.current_principal",
		WriteReach: "codefly.current_write_scopes",
	}
}

// Table describes one row-confined table by its column names. This package
// does not know what a partition or a scope is to the application; it needs to
// know where each is stored.
type Table struct {
	// Schema defaults to "public".
	Schema string
	Name   string
	// Partition, Scope, Principal and Shared default to "tenant", "scope",
	// "principal" and "shared". Columns shows the definitions they must have.
	Partition string
	Scope     string
	Principal string
	Shared    string
	// Mutable lists every column a transaction may UPDATE. The partition,
	// scope and principal columns are refused here: they never change.
	Mutable []string
}

func (table Table) defaulted() Table {
	if table.Schema == "" {
		table.Schema = "public"
	}
	if table.Partition == "" {
		table.Partition = "tenant"
	}
	if table.Scope == "" {
		table.Scope = "scope"
	}
	if table.Principal == "" {
		table.Principal = "principal"
	}
	if table.Shared == "" {
		table.Shared = "shared"
	}
	return table
}

func (table Table) validate() error {
	for name, identifier := range map[string]string{
		"schema": table.Schema, "table": table.Name, "partition column": table.Partition,
		"scope column": table.Scope, "principal column": table.Principal, "shared column": table.Shared,
	} {
		if err := validateIdentifier(identifier); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	fixed := map[string]bool{table.Partition: true, table.Scope: true, table.Principal: true}
	if len(fixed) != 3 || fixed[table.Shared] {
		return errors.New("the partition, scope, principal and shared columns must be four distinct columns")
	}
	for _, column := range table.Mutable {
		if err := validateIdentifier(column); err != nil {
			return fmt.Errorf("mutable column: %w", err)
		}
		if fixed[column] {
			return fmt.Errorf("column %q is the partition, scope or principal of its row and cannot be mutable", column)
		}
	}
	return nil
}

// Qualified returns the table's quoted, schema-qualified name.
func (table Table) Qualified() string {
	table = table.defaulted()
	return pgx.Identifier{table.Schema, table.Name}.Sanitize()
}

// Columns returns the four column definitions a row-confined table carries,
// for a CREATE TABLE or an ALTER TABLE ... ADD COLUMN. shared has no default
// on purpose: a row is shared because something said so, never because a
// writer forgot. An existing table backfills before it adds the constraints.
func Columns(table Table) ([]string, error) {
	table = table.defaulted()
	if err := table.validate(); err != nil {
		return nil, err
	}
	partition, scope, principal, shared := quote(table.Partition), quote(table.Scope), quote(table.Principal), quote(table.Shared)
	return []string{
		partition + ` text NOT NULL CHECK (` + partition + ` <> '')`,
		// The reach is a comma-separated list, and "" is what an empty entry of
		// it would match.
		scope + ` text NOT NULL CHECK (` + scope + ` <> '' AND position(',' in ` + scope + `) = 0)`,
		principal + ` text NOT NULL CHECK (` + principal + ` ~ '^[a-z]+:.+')`,
		shared + ` boolean NOT NULL`,
	}, nil
}

// Logins names the runtime logins that may assume each role. Membership is
// the only fence Postgres has on the mode and on the access: SET ROLE is
// checked against the session's login, so SQL sent on a connection can assume
// exactly the roles its login was granted, and no others.
//
//   - A login listed under read roles alone can never write a confined table,
//     in any transaction. That is the reader pool's login.
//   - A login listed under the strict roles alone can never run privileged.
//
// A login is refused under both a read role and a role that can write. Listing
// one under both modes is allowed, and gives up the second fence for it.
type Logins struct {
	// Strict and Privileged are the logins of the two-role form's roles.
	Strict     []string
	Privileged []string

	StrictRead      []string
	StrictWrite     []string
	PrivilegedRead  []string
	PrivilegedWrite []string
}

// access is one role of a store, with what Protect and Bootstrap need of it.
type access struct {
	role       string
	logins     []string
	privileged bool
	// reads and writes: a two-role form's role does both.
	reads, writes bool
}

func accesses(roles postgres.Roles, logins Logins) []access {
	all := []access{
		{roles.Strict, logins.Strict, false, true, true},
		{roles.StrictRead, logins.StrictRead, false, true, false},
		{roles.StrictWrite, logins.StrictWrite, false, false, true},
		{roles.Privileged, logins.Privileged, true, true, true},
		{roles.PrivilegedRead, logins.PrivilegedRead, true, true, false},
		{roles.PrivilegedWrite, logins.PrivilegedWrite, true, false, true},
	}
	return all
}

func named(all []access) ([]access, error) {
	var kept []access
	for _, one := range all {
		if one.role == "" {
			if len(one.logins) > 0 {
				return nil, errors.New("logins were named for a mode that has no role")
			}
			continue
		}
		if err := validateIdentifier(one.role); err != nil {
			return nil, fmt.Errorf("mode role: %w", err)
		}
		for _, other := range kept {
			if other.role == one.role {
				return nil, fmt.Errorf("role %q is named twice: distinct mode roles are required", one.role)
			}
		}
		kept = append(kept, one)
	}
	if len(kept) == 0 {
		return nil, errors.New("the role of at least one mode is required")
	}
	return kept, nil
}

// Bootstrap returns the statements that create the roles, idempotently, and
// grant them to the named logins. Each role is NOLOGIN and holds nothing but
// what Protect grants it. Each membership is INHERIT FALSE, SET TRUE: the
// login gains nothing by connecting, and assumes the role per transaction.
//
// Leave Logins empty where the Postgres agent reconciles memberships from the
// service's runtime-read-write-roles, and let the migration create the roles
// alone. PostgreSQL 16 or later.
func Bootstrap(roles postgres.Roles, logins Logins) ([]string, error) {
	all, err := named(accesses(roles, logins))
	if err != nil {
		return nil, err
	}
	var statements []string
	reader, writer := map[string]string{}, map[string]string{}
	for _, one := range all {
		role := quote(one.role)
		// A role an earlier migration left wider is not adopted: a migration
		// owner without the attribute could not narrow it, so this one fails.
		statements = append(statements, `DO $rowscope$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = `+literal(one.role)+`) THEN
    CREATE ROLE `+role+` NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  ELSIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = `+literal(one.role)+`
      AND (rolcanlogin OR rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'role % exists and is wider than a mode role may be', `+literal(one.role)+`;
  END IF;
END $rowscope$`)
		for _, login := range one.logins {
			if err := validateIdentifier(login); err != nil {
				return nil, fmt.Errorf("runtime login: %w", err)
			}
			for _, other := range all {
				if login == other.role {
					return nil, errors.New("a mode role cannot be granted to a mode role")
				}
			}
			// A read role proper is the access fence; a login that also holds
			// a role that writes can step over it from a read transaction.
			if one.writes {
				writer[login] = one.role
			} else {
				reader[login] = one.role
			}
			if reader[login] != "" && writer[login] != "" {
				return nil, fmt.Errorf("login %q would hold read role %q and %q, which writes: SQL on its read transactions could assume the second", login, reader[login], writer[login])
			}
			statements = append(statements, `GRANT `+role+` TO `+quote(login)+` WITH INHERIT FALSE, SET TRUE`)
		}
	}
	return statements, nil
}

// Protect returns the statements that confine one table: the grants to the
// roles, ENABLE and FORCE ROW LEVEL SECURITY, the restrictive policies that
// bind every role to the partition and the reach and every write to the write
// reach, the strict policies, the privileged ones, and the index the policies
// are served by.
//
// A read role is granted SELECT and nothing else. A write role is granted
// SELECT, INSERT, DELETE and UPDATE of the mutable columns, and is named in
// its mode's read policy itself: no role inherits from another.
//
// It is idempotent and complete: every grant a named role held on the table is
// revoked first and every policy it names is replaced, so a later migration
// that adds a mutable column, or the read and write roles to a store that had
// one role per mode, runs Protect again. It never touches a policy or a grant
// of any other role, so a maintenance role keeps its own.
func Protect(table Table, roles postgres.Roles, settings Settings) ([]string, error) {
	table = table.defaulted()
	if err := table.validate(); err != nil {
		return nil, err
	}
	for name, setting := range map[string]string{"partition": settings.Partition, "reach": settings.Reach, "principal": settings.Principal, "write reach": settings.WriteReach} {
		if err := validateSetting(setting); err != nil {
			return nil, fmt.Errorf("%s setting: %w", name, err)
		}
	}
	if settings.WriteReach == settings.Reach {
		return nil, errors.New("the reach and the write reach are two settings")
	}
	all, err := named(accesses(roles, Logins{}))
	if err != nil {
		return nil, err
	}
	list := func(keep func(access) bool) string {
		var kept []string
		for _, one := range all {
			if keep(one) {
				kept = append(kept, quote(one.role))
			}
		}
		return strings.Join(kept, ", ")
	}
	every := list(func(access) bool { return true })
	readers := list(func(one access) bool { return !one.writes })
	writers := list(func(one access) bool { return one.writes })
	strict := list(func(one access) bool { return !one.privileged })
	strictWriters := list(func(one access) bool { return !one.privileged && one.writes })
	privilegedReaders := list(func(one access) bool { return one.privileged && !one.writes })
	privilegedWriters := list(func(one access) bool { return one.privileged && one.writes })

	name := table.Qualified()
	partition, scope, principal, shared := quote(table.Partition), quote(table.Scope), quote(table.Principal), quote(table.Shared)
	read := func(setting string) string {
		return `(SELECT NULLIF(current_setting(` + literal(setting) + `, true), ''))`
	}
	within := func(setting string) string {
		return scope + ` = ANY ((SELECT string_to_array(NULLIF(current_setting(` + literal(setting) + `, true), ''), ','))::text[])`
	}
	inPartition := partition + ` = ` + read(settings.Partition)
	inReach, inWriteReach := within(settings.Reach), within(settings.WriteReach)
	own := principal + ` = ` + read(settings.Principal)

	statements := []string{
		`GRANT USAGE ON SCHEMA ` + quote(table.Schema) + ` TO ` + every,
		`REVOKE ALL ON TABLE ` + name + ` FROM ` + every,
	}
	if writers != "" {
		statements = append(statements, `GRANT SELECT, INSERT, DELETE ON TABLE `+name+` TO `+writers)
		if len(table.Mutable) > 0 {
			columns := make([]string, len(table.Mutable))
			for index, column := range table.Mutable {
				columns[index] = quote(column)
			}
			statements = append(statements, `GRANT UPDATE (`+strings.Join(columns, ", ")+`) ON TABLE `+name+` TO `+writers)
		}
	}
	if readers != "" {
		// SELECT, and that is all: the refusal of a write is the grant's.
		statements = append(statements, `GRANT SELECT ON TABLE `+name+` TO `+readers)
	}
	statements = append(statements,
		`ALTER TABLE `+name+` ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE `+name+` FORCE ROW LEVEL SECURITY`,
	)
	policy := func(suffix, roles, definition string) {
		if roles == "" {
			return
		}
		statements = append(statements,
			`DROP POLICY IF EXISTS `+quote("rowscope_"+suffix)+` ON `+name,
			`CREATE POLICY `+quote("rowscope_"+suffix)+` ON `+name+` `+strings.Replace(definition, "TO ROLES", "TO "+roles, 1),
		)
	}
	// The wall and the reach bind every role. RESTRICTIVE: ANDed with whatever
	// else is ever written for these roles.
	policy("partition", every, `AS RESTRICTIVE FOR ALL TO ROLES USING (`+inPartition+`) WITH CHECK (`+inPartition+`)`)
	policy("reach", every, `AS RESTRICTIVE FOR ALL TO ROLES USING (`+inReach+`) WITH CHECK (`+inReach+`)`)
	// The write reach binds every write, verb by verb: a policy is for one
	// command or for all of them, and SELECT must not read this setting.
	policy("reach_insert", writers, `AS RESTRICTIVE FOR INSERT TO ROLES WITH CHECK (`+inWriteReach+`)`)
	policy("reach_modify", writers, `AS RESTRICTIVE FOR UPDATE TO ROLES USING (`+inWriteReach+`) WITH CHECK (`+inWriteReach+`)`)
	policy("reach_delete", writers, `AS RESTRICTIVE FOR DELETE TO ROLES USING (`+inWriteReach+`)`)
	// Strict: mine, or shared, to read; mine to write.
	policy("strict_read", strict, `FOR SELECT TO ROLES USING (`+shared+` OR `+own+`)`)
	policy("strict_insert", strictWriters, `FOR INSERT TO ROLES WITH CHECK (`+own+`)`)
	policy("strict_modify", strictWriters, `FOR UPDATE TO ROLES USING (`+own+`) WITH CHECK (`+own+`)`)
	policy("strict_delete", strictWriters, `FOR DELETE TO ROLES USING (`+own+`)`)
	// Privileged: bounded only by the restrictive policies above.
	policy("privileged", privilegedWriters, `FOR ALL TO ROLES USING (true) WITH CHECK (true)`)
	policy("privileged_read", privilegedReaders, `FOR SELECT TO ROLES USING (true)`)
	statements = append(statements,
		`CREATE INDEX IF NOT EXISTS `+quote(indexName(table.Name))+` ON `+name+` (`+partition+`, `+scope+`, `+principal+`)`)
	return statements, nil
}

// Script joins statements into one migration body.
func Script(statements []string) string {
	return strings.Join(statements, ";\n") + ";\n"
}

func indexName(table string) string {
	const suffix = "_rowscope_idx"
	if len(table)+len(suffix) > 63 {
		table = table[:63-len(suffix)]
	}
	return table + suffix
}

func quote(identifier string) string { return pgx.Identifier{identifier}.Sanitize() }

func literal(value string) string { return `'` + strings.ReplaceAll(value, `'`, `''`) + `'` }

func validateIdentifier(identifier string) error {
	if identifier == "" || identifier != strings.TrimSpace(identifier) || len(identifier) > 63 || strings.ContainsRune(identifier, 0) {
		return fmt.Errorf("%q is not a Postgres identifier", identifier)
	}
	return nil
}

func validateSetting(setting string) error {
	segments := strings.Split(setting, ".")
	if len(segments) < 2 {
		return fmt.Errorf("setting %q must contain a namespace", setting)
	}
	for _, segment := range segments {
		if segment == "" {
			return fmt.Errorf("setting %q contains an empty namespace segment", setting)
		}
		for _, character := range segment {
			if character == '_' || (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') {
				continue
			}
			return fmt.Errorf("setting %q contains an unsafe character", setting)
		}
	}
	return nil
}
