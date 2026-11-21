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
				`CREATE POLICY rowscope_strict_read ON item FOR SELECT TO ` + s.Role("strict") + ` USING (true)`}
		},
		"no reach policy": func(*rowscopefixture.Sandbox) []string {
			return []string{`DROP POLICY rowscope_reach ON item`}
		},
		"no partition policy": func(*rowscopefixture.Sandbox) []string {
			return []string{`DROP POLICY rowscope_partition ON item`}
		},
		"strict writes shared rows": func(s *rowscopefixture.Sandbox) []string {
			return []string{`CREATE POLICY loose ON item FOR UPDATE TO ` + s.Role("strict") + ` USING (shared) WITH CHECK (true)`}
		},
		"strict deletes others' rows": func(s *rowscopefixture.Sandbox) []string {
			return []string{`CREATE POLICY loose ON item FOR DELETE TO ` + s.Role("strict") + ` USING (true)`}
		},
		"strict inserts for anyone": func(s *rowscopefixture.Sandbox) []string {
			return []string{`CREATE POLICY loose ON item FOR INSERT TO ` + s.Role("strict") + ` WITH CHECK (true)`}
		},
		"the scope is mutable": func(s *rowscopefixture.Sandbox) []string {
			return []string{`GRANT UPDATE (scope) ON item TO ` + s.Role("privileged")}
		},
		"the principal is mutable": func(s *rowscopefixture.Sandbox) []string {
			return []string{`GRANT UPDATE (principal) ON item TO ` + s.Role("strict")}
		},
		"the login holds a grant itself": func(s *rowscopefixture.Sandbox) []string {
			return []string{`GRANT SELECT ON item TO ` + s.Role("rw")}
		},
		"privileged is partition-only": func(s *rowscopefixture.Sandbox) []string {
			return []string{`DROP POLICY rowscope_reach ON item`,
				`CREATE POLICY rowscope_reach ON item AS RESTRICTIVE FOR ALL TO ` + s.Role("strict") + ` USING (scope = ANY (string_to_array(NULLIF(current_setting('codefly.current_scopes', true), ''), ',')))`}
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
