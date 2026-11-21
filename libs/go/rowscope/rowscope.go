// Package rowscope emits the SQL that makes one table row-confined, so that an
// application's migrations state which table and which columns and never
// hand-write a policy: the two mode roles, the grants, ENABLE and FORCE ROW
// LEVEL SECURITY, and the strict and privileged policies a postgres.Store's
// Binding is read by.
//
// It emits text and runs nothing. A migration embeds the output (or a
// generator writes it to a numbered migration file), and the migration owner
// runs it; migrationtest.CheckRowScope then checks the catalog the migrations
// left, whatever wrote them.
//
// The shape is proved in ../rowscope_spike_integration_test.go. Two things it
// relies on are easy to get wrong by hand, which is why it is emitted:
//
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
// partition and WithBindingSettings' first two for the reach and the principal.
type Settings struct {
	Partition string
	Reach     string
	Principal string
}

// DefaultSettings are the Store's defaults.
func DefaultSettings() Settings {
	return Settings{
		Partition: "codefly.current_tenant_id",
		Reach:     "codefly.current_scopes",
		Principal: "codefly.current_principal",
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

// Logins names the runtime logins that may assume each mode's role. A login
// listed under Strict alone can never run a privileged transaction, whatever
// SQL it sends: that membership is the only fence on the mode Postgres has.
// List a login under both only when one process must serve both.
type Logins struct {
	Strict     []string
	Privileged []string
}

// Bootstrap returns the statements that create the mode roles, idempotently, and
// grant them to the named logins. Each role is NOLOGIN and holds nothing but
// what Protect grants it. Each membership is INHERIT FALSE, SET TRUE: the
// login gains nothing by connecting, and assumes the role per transaction.
//
// Leave Logins empty where the Postgres agent reconciles memberships from the
// service's runtime-read-write-roles, and let the migration create the roles
// alone. PostgreSQL 16 or later.
func Bootstrap(roles postgres.Roles, logins Logins) ([]string, error) {
	var statements []string
	for _, mode := range []struct {
		role   string
		logins []string
	}{{roles.Strict, logins.Strict}, {roles.Privileged, logins.Privileged}} {
		if mode.role == "" {
			if len(mode.logins) > 0 {
				return nil, errors.New("logins were named for a mode that has no role")
			}
			continue
		}
		if err := validateIdentifier(mode.role); err != nil {
			return nil, fmt.Errorf("mode role: %w", err)
		}
		role := quote(mode.role)
		// A role an earlier migration left wider is not adopted: a migration
		// owner without the attribute could not narrow it, so this one fails.
		statements = append(statements, `DO $rowscope$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = `+literal(mode.role)+`) THEN
    CREATE ROLE `+role+` NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  ELSIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = `+literal(mode.role)+`
      AND (rolcanlogin OR rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'role % exists and is wider than a mode role may be', `+literal(mode.role)+`;
  END IF;
END $rowscope$`)
		for _, login := range mode.logins {
			if err := validateIdentifier(login); err != nil {
				return nil, fmt.Errorf("runtime login: %w", err)
			}
			if login == roles.Strict || login == roles.Privileged {
				return nil, errors.New("a mode role cannot be granted to a mode role")
			}
			statements = append(statements, `GRANT `+role+` TO `+quote(login)+` WITH INHERIT FALSE, SET TRUE`)
		}
	}
	if len(statements) == 0 {
		return nil, errors.New("the role of at least one mode is required")
	}
	return statements, nil
}

// Protect returns the statements that confine one table: the grants to the
// mode roles, ENABLE and FORCE ROW LEVEL SECURITY, the two restrictive
// policies that bind both modes to the partition and the reach, the strict
// policies, the privileged policy, and the index the policies are served by.
//
// It is idempotent and complete: every grant a mode role held on the table is
// revoked first and every policy it names is replaced, so a later migration
// that adds a mutable column runs Protect again. It never touches a policy or
// a grant of any other role, so a maintenance role keeps its own.
func Protect(table Table, roles postgres.Roles, settings Settings) ([]string, error) {
	table = table.defaulted()
	if err := table.validate(); err != nil {
		return nil, err
	}
	for name, setting := range map[string]string{"partition": settings.Partition, "reach": settings.Reach, "principal": settings.Principal} {
		if err := validateSetting(setting); err != nil {
			return nil, fmt.Errorf("%s setting: %w", name, err)
		}
	}
	var modes []string
	for _, role := range []string{roles.Strict, roles.Privileged} {
		if role == "" {
			continue
		}
		if err := validateIdentifier(role); err != nil {
			return nil, fmt.Errorf("mode role: %w", err)
		}
		modes = append(modes, quote(role))
	}
	if len(modes) == 0 || roles.Strict == roles.Privileged {
		return nil, errors.New("distinct mode roles are required, at least one")
	}
	both := strings.Join(modes, ", ")
	name := table.Qualified()
	partition, scope, principal, shared := quote(table.Partition), quote(table.Scope), quote(table.Principal), quote(table.Shared)
	read := func(setting string) string {
		return `(SELECT NULLIF(current_setting(` + literal(setting) + `, true), ''))`
	}
	inPartition := partition + ` = ` + read(settings.Partition)
	inReach := scope + ` = ANY ((SELECT string_to_array(NULLIF(current_setting(` + literal(settings.Reach) + `, true), ''), ','))::text[])`
	own := principal + ` = ` + read(settings.Principal)

	statements := []string{
		`GRANT USAGE ON SCHEMA ` + quote(table.Schema) + ` TO ` + both,
		`REVOKE ALL ON TABLE ` + name + ` FROM ` + both,
		`GRANT SELECT, INSERT, DELETE ON TABLE ` + name + ` TO ` + both,
	}
	if len(table.Mutable) > 0 {
		columns := make([]string, len(table.Mutable))
		for index, column := range table.Mutable {
			columns[index] = quote(column)
		}
		statements = append(statements, `GRANT UPDATE (`+strings.Join(columns, ", ")+`) ON TABLE `+name+` TO `+both)
	}
	statements = append(statements,
		`ALTER TABLE `+name+` ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE `+name+` FORCE ROW LEVEL SECURITY`,
	)
	policy := func(suffix, definition string) {
		statements = append(statements,
			`DROP POLICY IF EXISTS `+quote("rowscope_"+suffix)+` ON `+name,
			`CREATE POLICY `+quote("rowscope_"+suffix)+` ON `+name+` `+definition,
		)
	}
	// The wall and the reach bind both modes. RESTRICTIVE: ANDed with whatever
	// else is ever written for these roles.
	policy("partition", `AS RESTRICTIVE FOR ALL TO `+both+` USING (`+inPartition+`) WITH CHECK (`+inPartition+`)`)
	policy("reach", `AS RESTRICTIVE FOR ALL TO `+both+` USING (`+inReach+`) WITH CHECK (`+inReach+`)`)
	if roles.Strict != "" {
		strict := quote(roles.Strict)
		// Mine, or shared, to read; mine to write.
		policy("strict_read", `FOR SELECT TO `+strict+` USING (`+shared+` OR `+own+`)`)
		policy("strict_insert", `FOR INSERT TO `+strict+` WITH CHECK (`+own+`)`)
		policy("strict_modify", `FOR UPDATE TO `+strict+` USING (`+own+`) WITH CHECK (`+own+`)`)
		policy("strict_delete", `FOR DELETE TO `+strict+` USING (`+own+`)`)
	}
	if roles.Privileged != "" {
		// Bounded only by the two restrictive policies above.
		policy("privileged", `FOR ALL TO `+quote(roles.Privileged)+` USING (true) WITH CHECK (true)`)
	}
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
