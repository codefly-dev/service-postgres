package rowscopefixture

import (
	"strings"
	"testing"

	postgres "github.com/codefly-dev/service-postgres/libs/go"
	"github.com/codefly-dev/service-postgres/libs/go/rowscope"
)

// Roles are the sandbox's roles, one per mode and access, whether or not they
// exist yet.
func (s *Sandbox) Roles() postgres.Roles {
	return postgres.Roles{
		StrictRead: s.Role("strict_read"), StrictWrite: s.Role("strict_write"),
		PrivilegedRead: s.Role("privileged_read"), PrivilegedWrite: s.Role("privileged_write"),
	}
}

// TwoRoles are the sandbox's roles in the two-role form: one per mode.
func (s *Sandbox) TwoRoles() postgres.Roles {
	return postgres.Roles{Strict: s.Role("strict"), Privileged: s.Role("privileged")}
}

// Migrate runs, as the owner, the migration a module would write with package
// rowscope: the four roles, the read ones granted to the read-only login and
// the write ones to the read-write login, then one table per name carrying the
// four columns, an identity key and a body, protected. Each login serves both
// modes, as one process that does would have them.
func (s *Sandbox) Migrate(t testing.TB, tables ...string) []rowscope.Table {
	t.Helper()
	return s.migrate(t, s.Roles(), rowscope.Logins{
		StrictRead: []string{s.Role("ro")}, PrivilegedRead: []string{s.Role("ro")},
		StrictWrite: []string{s.Role("rw")}, PrivilegedWrite: []string{s.Role("rw")},
	}, nil, tables)
}

// MigrateTwoRoles leaves the catalog a store has that was migrated before the
// read and write roles existed: one role per mode, granted to both runtime
// logins, and no policy that reads the write reach.
func (s *Sandbox) MigrateTwoRoles(t testing.TB, tables ...string) []rowscope.Table {
	t.Helper()
	return s.migrate(t, s.TwoRoles(), rowscope.Logins{
		Strict:     []string{s.Role("ro"), s.Role("rw")},
		Privileged: []string{s.Role("ro"), s.Role("rw")},
	}, []string{"rowscope_reach_insert", "rowscope_reach_modify", "rowscope_reach_delete"}, tables)
}

func (s *Sandbox) migrate(t testing.TB, roles postgres.Roles, logins rowscope.Logins, without []string, tables []string) []rowscope.Table {
	t.Helper()
	statements, err := rowscope.Bootstrap(roles, logins)
	if err != nil {
		t.Fatal(err)
	}
	var protected []rowscope.Table
	for _, name := range tables {
		table := rowscope.Table{Name: name, Mutable: []string{"shared", "body"}}
		columns, err := rowscope.Columns(table)
		if err != nil {
			t.Fatal(err)
		}
		statements = append(statements, `CREATE TABLE `+table.Qualified()+` (
			id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, `+strings.Join(columns, ", ")+`, body text NOT NULL DEFAULT '')`)
		protect, err := rowscope.Protect(table, roles, rowscope.DefaultSettings())
		if err != nil {
			t.Fatal(err)
		}
		statements = append(statements, protect...)
		for _, policy := range without {
			statements = append(statements, `DROP POLICY `+policy+` ON `+table.Qualified())
		}
		protected = append(protected, table)
	}
	s.Exec(t, s.Owner, rowscope.Script(statements))
	return protected
}
