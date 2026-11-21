package migrationtest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	postgres "github.com/codefly-dev/service-postgres/libs/go"
	"github.com/codefly-dev/service-postgres/libs/go/rowscope"
	"github.com/jackc/pgx/v5"
)

// RowScopeGate describes what a migrated store must look like for a
// postgres.Store to confine it. CheckRowScope reads the catalog, not the
// migration files: whatever a migration did on the way, the end state is what
// is checked, and a store written in another language is checked the same way.
type RowScopeGate struct {
	// Schemas are the store's schemas. Empty means "public".
	Schemas []string
	// Roles are the mode roles. Name the ones the store has.
	Roles postgres.Roles
	// Logins are further runtime logins to check, beside the one the gate's
	// own connection arrived as (which is always checked).
	Logins []string
	// Settings are the names the policies must read. Zero means the defaults.
	Settings rowscope.Settings
	// Columns names the partition, scope and principal columns of every table
	// that does not appear in Tables. Zero means rowscope's defaults.
	Columns rowscope.Table
	// Tables lists the tables whose columns are named differently.
	Tables []rowscope.Table
	// Exempt lists the relations that are legitimately not row-scoped. Each is
	// named, with the reason, and a name that matches nothing fails the gate.
	Exempt []RowScopeExemption
}

// RowScopeExemption takes one table, view or materialized view out of the
// row-confinement checks. It never takes it out of the rule that a runtime
// login holds no privilege of its own.
type RowScopeExemption struct {
	// Relation is "schema.name".
	Relation string
	// Reason says why its rows belong to nobody. Required.
	Reason string
}

// RowScopeFinding is one way the catalog falls short.
type RowScopeFinding struct {
	// Relation is "schema.name", or empty for a finding about a role.
	Relation string
	Problem  string
}

func (finding RowScopeFinding) String() string {
	if finding.Relation == "" {
		return finding.Problem
	}
	return finding.Relation + ": " + finding.Problem
}

// CatalogQuerier is what the gate needs of a connection: *pgx.Conn,
// *pgxpool.Pool, pgx.Tx and postgres.ReadTx all satisfy it.
type CatalogQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// RowScopeReporter is the part of testing.TB RequireRowScope uses.
type RowScopeReporter interface {
	Helper()
	Fatalf(format string, arguments ...any)
}

// RequireRowScope fails the test with every finding of CheckRowScope.
func RequireRowScope(t RowScopeReporter, ctx context.Context, db CatalogQuerier, gate RowScopeGate) {
	t.Helper()
	findings, err := CheckRowScope(ctx, db, gate)
	if err != nil {
		t.Fatalf("row-scope gate: %v", err)
	}
	if len(findings) > 0 {
		lines := make([]string, len(findings))
		for index, finding := range findings {
			lines[index] = "  " + finding.String()
		}
		t.Fatalf("row-scope gate: %d finding(s)\n%s", len(findings), strings.Join(lines, "\n"))
	}
}

// CheckRowScope must run on a connection of the production runtime login, not
// the owner's and not the fixture principal's: what it asks is what that login
// can reach, and a gate that passes as a superuser proves nothing. It reports:
//
//   - a table without row security, or without FORCE;
//   - a mode role with a privilege on a table and no restrictive partition and
//     reach policies, or no permissive policy for a verb it holds, or no WITH
//     CHECK for a verb that writes;
//   - a mode role that may UPDATE a row's partition, scope or principal, or
//     holds TRUNCATE, REFERENCES or TRIGGER;
//   - a policy granted to PUBLIC, or one that reads a setting without NULLIF;
//   - any table privilege held by a runtime login itself, exempt table or not;
//   - a view that is not security_invoker, and any materialized view;
//   - a role that is a superuser, BYPASSRLS, CREATEROLE or an owner.
//
// It does not check index shape, unique-key or foreign-key side channels, or
// SECURITY DEFINER functions.
func CheckRowScope(ctx context.Context, db CatalogQuerier, gate RowScopeGate) ([]RowScopeFinding, error) {
	if ctx == nil || db == nil {
		return nil, errors.New("row-scope gate requires a context and a connection")
	}
	if gate.Roles.Strict == "" && gate.Roles.Privileged == "" {
		return nil, errors.New("row-scope gate requires the role of at least one mode")
	}
	if len(gate.Schemas) == 0 {
		gate.Schemas = []string{"public"}
	}
	if gate.Settings == (rowscope.Settings{}) {
		gate.Settings = rowscope.DefaultSettings()
	}
	var findings []RowScopeFinding
	report := func(relation, format string, arguments ...any) {
		findings = append(findings, RowScopeFinding{Relation: relation, Problem: fmt.Sprintf(format, arguments...)})
	}

	exempt := map[string]bool{}
	for _, exemption := range gate.Exempt {
		switch {
		case strings.TrimSpace(exemption.Reason) == "":
			report(exemption.Relation, "exempted without a reason")
		case exempt[exemption.Relation]:
			report(exemption.Relation, "exempted twice")
		}
		exempt[exemption.Relation] = true
	}
	columns := map[string]rowscope.Table{}
	for _, table := range gate.Tables {
		schema := table.Schema
		if schema == "" {
			schema = "public"
		}
		columns[schema+"."+table.Name] = table
	}

	var modes []string
	for _, role := range []string{gate.Roles.Strict, gate.Roles.Privileged} {
		if role != "" {
			modes = append(modes, role)
		}
	}

	// Who is asking, and what the roles are.
	type role struct {
		name                                       string
		login, super, bypass, createRole, createDB bool
		session, current                           bool
	}
	roles, err := collect(ctx, db, `
		SELECT r.rolname::text, r.rolcanlogin, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb,
		       r.rolname = session_user, r.rolname = current_user
		FROM pg_roles r
		WHERE r.rolname = session_user OR r.rolname = current_user OR r.rolname = ANY($1::text[])`,
		func(row pgx.Rows) (role, error) {
			var found role
			return found, row.Scan(&found.name, &found.login, &found.super, &found.bypass, &found.createRole, &found.createDB, &found.session, &found.current)
		}, append(slices.Clone(modes), gate.Logins...))
	if err != nil {
		return nil, fmt.Errorf("read roles: %w", err)
	}
	known := map[string]role{}
	logins := []string{}
	for _, found := range roles {
		known[found.name] = found
		if found.super || found.bypass || found.createRole || found.createDB {
			report("", "role %q is a superuser, BYPASSRLS, CREATEROLE or CREATEDB: nothing it is checked against binds it", found.name)
		}
		if !slices.Contains(modes, found.name) {
			logins = append(logins, found.name)
		}
	}
	for _, mode := range modes {
		found, exists := known[mode]
		switch {
		case !exists:
			report("", "mode role %q does not exist", mode)
		case found.login:
			report("", "mode role %q can log in", mode)
		case found.session:
			report("", "the gate is connected as mode role %q; connect as the runtime login", mode)
		case found.current:
			// ALTER ROLE ... SET role, or a startup role in the connection.
			report("", "the runtime login's connection arrives as mode role %q: a connection that skips the Store then holds that role's privileges with nothing bound, and RESET ROLE returns to it", mode)
		}
	}
	for _, login := range gate.Logins {
		if _, exists := known[login]; !exists {
			report("", "runtime login %q does not exist", login)
		}
	}
	sort.Strings(logins)

	type relation struct {
		oid                   uint32
		name, kind, owner     string
		secured, forced, part bool
		options, columns      []string
	}
	relations, err := collect(ctx, db, `
		SELECT c.oid, n.nspname || '.' || c.relname, c.relkind::text, pg_get_userbyid(c.relowner)::text,
		       c.relrowsecurity, c.relforcerowsecurity, c.relispartition,
		       coalesce(c.reloptions, '{}')::text[],
		       ARRAY(SELECT a.attname::text FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = ANY($1::text[]) AND c.relkind IN ('r', 'p', 'v', 'm')
		ORDER BY 2`,
		func(row pgx.Rows) (relation, error) {
			var found relation
			return found, row.Scan(&found.oid, &found.name, &found.kind, &found.owner, &found.secured, &found.forced, &found.part, &found.options, &found.columns)
		}, gate.Schemas)
	if err != nil {
		return nil, fmt.Errorf("read relations: %w", err)
	}

	type privilege struct {
		oid                                    uint32
		role                                   string
		read, insert, update, remove, truncate bool
		references, trigger, anyColumn         bool
		updatable                              []string
	}
	privileges, err := collect(ctx, db, `
		SELECT c.oid, r.rolname::text,
		       has_table_privilege(r.oid, c.oid, 'SELECT'), has_table_privilege(r.oid, c.oid, 'INSERT'),
		       has_table_privilege(r.oid, c.oid, 'UPDATE'), has_table_privilege(r.oid, c.oid, 'DELETE'),
		       has_table_privilege(r.oid, c.oid, 'TRUNCATE'), has_table_privilege(r.oid, c.oid, 'REFERENCES'),
		       has_table_privilege(r.oid, c.oid, 'TRIGGER'),
		       has_any_column_privilege(r.oid, c.oid, 'SELECT, INSERT, UPDATE, REFERENCES'),
		       ARRAY(SELECT a.attname::text FROM pg_attribute a
		             WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		               AND has_column_privilege(r.oid, c.oid, a.attnum, 'UPDATE'))
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, pg_roles r
		WHERE n.nspname = ANY($1::text[]) AND c.relkind IN ('r', 'p', 'v', 'm') AND r.rolname = ANY($2::text[])`,
		func(row pgx.Rows) (privilege, error) {
			var found privilege
			return found, row.Scan(&found.oid, &found.role, &found.read, &found.insert, &found.update, &found.remove,
				&found.truncate, &found.references, &found.trigger, &found.anyColumn, &found.updatable)
		}, gate.Schemas, append(slices.Clone(modes), logins...))
	if err != nil {
		return nil, fmt.Errorf("read privileges: %w", err)
	}
	held := map[uint32]map[string]privilege{}
	for _, found := range privileges {
		if held[found.oid] == nil {
			held[found.oid] = map[string]privilege{}
		}
		held[found.oid][found.role] = found
	}

	type policy struct {
		oid                 uint32
		name, command       string
		permissive, checked bool
		roles               []string
		using, withCheck    string
	}
	policies, err := collect(ctx, db, `
		SELECT p.polrelid, p.polname::text, p.polcmd::text, p.polpermissive, p.polwithcheck IS NOT NULL,
		       ARRAY(SELECT CASE WHEN member = 0 THEN '' ELSE pg_get_userbyid(member)::text END FROM unnest(p.polroles) AS member),
		       coalesce(pg_get_expr(p.polqual, p.polrelid), ''), coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')
		FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = ANY($1::text[])`,
		func(row pgx.Rows) (policy, error) {
			var found policy
			return found, row.Scan(&found.oid, &found.name, &found.command, &found.permissive, &found.checked, &found.roles, &found.using, &found.withCheck)
		}, gate.Schemas)
	if err != nil {
		return nil, fmt.Errorf("read policies: %w", err)
	}
	written := map[uint32][]policy{}
	for _, found := range policies {
		written[found.oid] = append(written[found.oid], found)
	}

	seen := map[string]bool{}
	for _, found := range relations {
		seen[found.name] = true
		grants := held[found.oid]

		// A runtime login holds nothing itself, on any relation, exempt or not.
		for _, login := range logins {
			if found.owner == login {
				report(found.name, "is owned by runtime login %q", login)
			}
			if own := grants[login]; own.read || own.insert || own.update || own.remove || own.truncate || own.references || own.trigger || own.anyColumn {
				report(found.name, "runtime login %q holds a privilege on it directly or by inheritance; every privilege belongs to a mode role", login)
			}
		}
		for _, mode := range modes {
			if found.owner == mode {
				report(found.name, "is owned by mode role %q", mode)
			}
		}
		if exempt[found.name] {
			continue
		}
		switch found.kind {
		case "v":
			if !slices.Contains(found.options, "security_invoker=true") && !slices.Contains(found.options, "security_invoker=on") {
				report(found.name, "is a view that is not security_invoker: it reads as its owner, around every row policy")
			}
			continue
		case "m":
			report(found.name, "is a materialized view: a copy of rows with no row policy; exempt it by name with the reason")
			continue
		}
		reachable := false
		for _, mode := range modes {
			own := grants[mode]
			reachable = reachable || own.read || own.insert || own.update || own.remove || own.truncate || own.anyColumn
		}
		// A partition nobody can address directly is confined by its parent.
		if found.part && !reachable {
			continue
		}
		if !found.secured {
			report(found.name, "row security is not enabled")
		}
		if !found.forced {
			report(found.name, "row security is not forced: its owner is not bound")
		}
		named := gate.Columns
		if override, ok := columns[found.name]; ok {
			named = override
		}
		fixed := []string{orDefault(named.Partition, "tenant"), orDefault(named.Scope, "scope"), orDefault(named.Principal, "principal")}
		for _, column := range fixed {
			if !slices.Contains(found.columns, column) {
				report(found.name, "has no %q column: it is not row-scoped; add the column or exempt the table by name with the reason", column)
			}
		}
		for _, written := range written[found.oid] {
			if slices.Contains(written.roles, "") {
				report(found.name, "policy %q is granted to PUBLIC", written.name)
			}
			for _, expression := range []string{written.using, written.withCheck} {
				if strings.Count(expression, "current_setting(") != strings.Count(expression, "NULLIF(current_setting(") {
					report(found.name, "policy %q reads a setting without NULLIF(current_setting(name, true), ''): after one use an unset setting is the empty string, not NULL", written.name)
					break
				}
			}
		}
		for _, mode := range modes {
			own := grants[mode]
			applies := func(command string, permissive bool) []policy {
				var matching []policy
				for _, written := range written[found.oid] {
					if written.permissive == permissive && slices.Contains(written.roles, mode) && (written.command == "*" || written.command == command) {
						matching = append(matching, written)
					}
				}
				return matching
			}
			if !slices.ContainsFunc(written[found.oid], func(written policy) bool { return written.permissive && slices.Contains(written.roles, mode) }) {
				report(found.name, "no permissive policy names mode role %q: it reads nothing here; protect the table or exempt it by name with the reason", mode)
			}
			for label, setting := range map[string]string{"partition": gate.Settings.Partition, "reach": gate.Settings.Reach} {
				bound := false
				for _, restrictive := range applies("*", false) {
					reads := "current_setting('" + setting + "'"
					bound = bound || (restrictive.command == "*" && strings.Contains(restrictive.using, reads) && strings.Contains(restrictive.withCheck, reads))
				}
				if !bound {
					report(found.name, "no RESTRICTIVE FOR ALL policy binds mode role %q to the %s (USING and WITH CHECK reading %s)", mode, label, setting)
				}
			}
			for _, verb := range []struct {
				name, command string
				held, writes  bool
			}{
				{"SELECT", "r", own.read, false},
				{"INSERT", "a", own.insert, true},
				{"UPDATE", "w", own.update || len(own.updatable) > 0, true},
				{"DELETE", "d", own.remove, false},
			} {
				if !verb.held {
					continue
				}
				permissive := applies(verb.command, true)
				if len(permissive) == 0 {
					report(found.name, "mode role %q has no permissive policy for %s", mode, verb.name)
					continue
				}
				if verb.writes && !slices.ContainsFunc(permissive, func(written policy) bool { return written.checked }) {
					report(found.name, "mode role %q may %s with no WITH CHECK policy", mode, verb.name)
				}
			}
			for _, column := range fixed {
				if slices.Contains(own.updatable, column) {
					report(found.name, "mode role %q may UPDATE %q: a row's partition, scope and principal never change, and no policy stops it", mode, column)
				}
			}
			if own.truncate || own.references || own.trigger {
				report(found.name, "mode role %q holds TRUNCATE, REFERENCES or TRIGGER", mode)
			}
		}
	}
	for _, exemption := range gate.Exempt {
		if !seen[exemption.Relation] {
			report(exemption.Relation, "is exempted and does not exist in %s", strings.Join(gate.Schemas, ", "))
		}
	}
	return findings, nil
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func collect[T any](ctx context.Context, db CatalogQuerier, statement string, scan func(pgx.Rows) (T, error), arguments ...any) ([]T, error) {
	rows, err := db.Query(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (T, error) { return scan(rows) })
}
