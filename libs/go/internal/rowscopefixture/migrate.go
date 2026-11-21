package rowscopefixture

import (
	"strings"
	"testing"

	postgres "github.com/codefly-dev/service-postgres/libs/go"
	"github.com/codefly-dev/service-postgres/libs/go/rowscope"
)

// Roles are the sandbox's mode roles, whether or not they exist yet.
func (s *Sandbox) Roles() postgres.Roles {
	return postgres.Roles{Strict: s.Role("strict"), Privileged: s.Role("privileged")}
}

// Migrate runs, as the owner, the migration a module would write with package
// rowscope: the mode roles granted to both runtime logins, then one table per
// name carrying the four columns, an identity key and a body, protected.
func (s *Sandbox) Migrate(t testing.TB, tables ...string) []rowscope.Table {
	t.Helper()
	roles := s.Roles()
	statements, err := rowscope.Bootstrap(roles, rowscope.Logins{
		Strict:     []string{s.Role("ro"), s.Role("rw")},
		Privileged: []string{s.Role("ro"), s.Role("rw")},
	})
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
		protected = append(protected, table)
	}
	s.Exec(t, s.Owner, rowscope.Script(statements))
	return protected
}
