//go:build controlplaneintegration

package rowscopetest_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/codefly-dev/service-postgres/libs/go/internal/rowscopefixture"
	"github.com/codefly-dev/service-postgres/libs/go/rowscope"
	"github.com/codefly-dev/service-postgres/libs/go/rowscopetest"
)

func proofOf(sandbox *rowscopefixture.Sandbox, table rowscope.Table) rowscopetest.Proof {
	return rowscopetest.Proof{
		Fixture: sandbox.Fixture, ReadOnly: sandbox.ReadOnly, ReadWrite: sandbox.ReadWrite,
		Roles: sandbox.Roles(), Table: table, Body: "body",
	}
}

// The property the library ships: over random rows and random bindings, a
// table protected by package rowscope returns and changes exactly what the
// model allows. Arranged by a fixture principal that is not a superuser,
// asserted on the runtime logins.
func TestRowScopeProveHoldsOnAProtectedTable(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	table := sandbox.Migrate(t, "item")[0]
	proof := proofOf(sandbox, table)
	proof.Rows, proof.Rounds = 600, 600
	rowscopetest.Prove(t, proof)
}

// A proof that cannot fail proves nothing. Each case breaks the table one way
// a hand-written migration plausibly would, and the proof must notice.
func TestRowScopeProveCatchesABrokenTable(t *testing.T) {
	for name, damage := range map[string]func(sandbox *rowscopefixture.Sandbox) []string{
		"strict reads every principal": func(s *rowscopefixture.Sandbox) []string {
			return []string{`DROP POLICY rowscope_strict_read ON item`,
				`CREATE POLICY rowscope_strict_read ON item FOR SELECT TO ` + s.Role("strict_read") + `, ` + s.Role("strict_write") + ` USING (true)`}
		},
		"no reach policy": func(*rowscopefixture.Sandbox) []string {
			return []string{`DROP POLICY rowscope_reach ON item`}
		},
		"no partition policy": func(*rowscopefixture.Sandbox) []string {
			return []string{`DROP POLICY rowscope_partition ON item`}
		},
		"strict writes shared rows": func(s *rowscopefixture.Sandbox) []string {
			return []string{`CREATE POLICY loose ON item FOR UPDATE TO ` + s.Role("strict_write") + ` USING (shared) WITH CHECK (true)`}
		},
		"strict deletes others' rows": func(s *rowscopefixture.Sandbox) []string {
			return []string{`CREATE POLICY loose ON item FOR DELETE TO ` + s.Role("strict_write") + ` USING (true)`}
		},
		"strict inserts for anyone": func(s *rowscopefixture.Sandbox) []string {
			return []string{`CREATE POLICY loose ON item FOR INSERT TO ` + s.Role("strict_write") + ` WITH CHECK (true)`}
		},
		"the scope is mutable": func(s *rowscopefixture.Sandbox) []string {
			return []string{`GRANT UPDATE (scope) ON item TO ` + s.Role("privileged_write")}
		},
		"the principal is mutable": func(s *rowscopefixture.Sandbox) []string {
			return []string{`GRANT UPDATE (principal) ON item TO ` + s.Role("strict_write")}
		},
		"the login holds a grant itself": func(s *rowscopefixture.Sandbox) []string {
			return []string{`GRANT SELECT ON item TO ` + s.Role("rw")}
		},
		// The access. Each of these leaves every read and every ReadWrite
		// binding exactly right: only a Read binding that tries tells.
		"a read role was granted DELETE": func(s *rowscopefixture.Sandbox) []string {
			return []string{`GRANT DELETE ON item TO ` + s.Role("strict_read")}
		},
		"the privileged read role is a copy of the write role": func(s *rowscopefixture.Sandbox) []string {
			return []string{`GRANT INSERT, DELETE, UPDATE (body) ON item TO ` + s.Role("privileged_read"),
				`DROP POLICY rowscope_privileged_read ON item`,
				`CREATE POLICY rowscope_privileged_read ON item FOR ALL TO ` + s.Role("privileged_read") + ` USING (true) WITH CHECK (true)`}
		},
		"a read role may update the body": func(s *rowscopefixture.Sandbox) []string {
			return []string{`GRANT UPDATE (body) ON item TO ` + s.Role("strict_read")}
		},
		"a read role inherits the write role": func(s *rowscopefixture.Sandbox) []string {
			return []string{`GRANT ` + s.Role("strict_write") + ` TO ` + s.Role("strict_read") + ` WITH INHERIT TRUE, SET FALSE`}
		},
		"the reader's login may assume a write role": func(s *rowscopefixture.Sandbox) []string {
			return []string{`GRANT ` + s.Role("strict_write") + ` TO ` + s.Role("ro") + ` WITH INHERIT FALSE, SET TRUE`}
		},
		// The write mode and the write reach.
		"deletes are not bound to the write reach": func(*rowscopefixture.Sandbox) []string {
			return []string{`DROP POLICY rowscope_reach_delete ON item`}
		},
		"inserts are bound to the reach, not the write reach": func(s *rowscopefixture.Sandbox) []string {
			return []string{`DROP POLICY rowscope_reach_insert ON item`,
				`CREATE POLICY rowscope_reach_insert ON item AS RESTRICTIVE FOR INSERT TO ` + s.Role("strict_write") + `, ` + s.Role("privileged_write") + `
					WITH CHECK (scope = ANY (string_to_array(NULLIF(current_setting('codefly.current_scopes', true), ''), ',')))`}
		},
		"updates are not bound to the write reach": func(*rowscopefixture.Sandbox) []string {
			return []string{`DROP POLICY rowscope_reach_modify ON item`}
		},
		"the strict write role reads as privileged": func(s *rowscopefixture.Sandbox) []string {
			return []string{`CREATE POLICY loose ON item FOR SELECT TO ` + s.Role("strict_write") + ` USING (true)`}
		},
		"the write role is not in its mode's read policy": func(s *rowscopefixture.Sandbox) []string {
			return []string{`ALTER POLICY rowscope_strict_read ON item TO ` + s.Role("strict_read")}
		},
		"privileged is partition-only": func(s *rowscopefixture.Sandbox) []string {
			return []string{`DROP POLICY rowscope_reach ON item`,
				`CREATE POLICY rowscope_reach ON item AS RESTRICTIVE FOR ALL TO ` + s.Role("strict_read") + `, ` + s.Role("strict_write") + ` USING (scope = ANY (string_to_array(NULLIF(current_setting('codefly.current_scopes', true), ''), ',')))`}
		},
	} {
		t.Run(name, func(t *testing.T) {
			sandbox := rowscopefixture.Open(t)
			table := sandbox.Migrate(t, "item")[0]
			sandbox.Exec(t, sandbox.Owner, damage(sandbox)...)
			proof := proofOf(sandbox, table)
			proof.Rounds = 400
			recorder := &recorder{TB: t}
			func() {
				defer func() {
					if recovered := recover(); recovered != nil && recovered != recorder {
						panic(recovered)
					}
				}()
				rowscopetest.Prove(recorder, proof)
			}()
			if recorder.failure == "" {
				t.Fatal("the proof passed on a table that does not hold the model")
			}
			// A proof that could not start has caught nothing.
			if strings.Contains(recorder.failure, "required") || strings.Contains(recorder.failure, "connect as") || strings.Contains(recorder.failure, "open the store") {
				t.Fatalf("the proof did not run: %s", recorder.failure)
			}
			t.Log(strings.SplitN(recorder.failure, "\n", 2)[0])
		})
	}
}

// recorder turns the proof's failure into a value, and stops it where a test
// would have stopped.
type recorder struct {
	testing.TB
	failure string
}

func (r *recorder) Fatalf(format string, arguments ...any) {
	r.failure = fmt.Sprintf(format, arguments...)
	panic(r)
}

// The proof is of the four roles. A store with one role per mode does not hold
// the model, and is told so before a row is seeded.
func TestRowScopeProveRefusesTheTwoRoleForm(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	table := sandbox.MigrateTwoRoles(t, "item")[0]
	proof := proofOf(sandbox, table)
	proof.Roles = sandbox.TwoRoles()
	recorder := &recorder{TB: t}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil && recovered != recorder {
				panic(recovered)
			}
		}()
		rowscopetest.Prove(recorder, proof)
	}()
	if !strings.Contains(recorder.failure, "the read and the write role of both modes are required") {
		t.Fatalf("the proof of a two-role store: %q", recorder.failure)
	}
}
