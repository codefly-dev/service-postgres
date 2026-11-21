//go:build controlplaneintegration

package migrationtest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/service-postgres/libs/go/internal/rowscopefixture"
	"github.com/codefly-dev/service-postgres/libs/go/migrationtest"
)

func gateFindings(t *testing.T, sandbox *rowscopefixture.Sandbox, connection string, gate migrationtest.RowScopeGate) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gate.Roles = sandbox.Roles()
	findings, err := migrationtest.CheckRowScope(ctx, sandbox.Connect(t, connection), gate)
	if err != nil {
		t.Fatal(err)
	}
	lines := make([]string, len(findings))
	for index, finding := range findings {
		lines[index] = finding.String()
	}
	return strings.Join(lines, "\n")
}

// A store migrated with package rowscope passes, checked as each runtime login.
func TestRowScopeGatePassesOnAProtectedStore(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	sandbox.Migrate(t, "item", "note")
	// What a real store also has: a ledger nobody reads at run time, and
	// reference data every caller reads, each exempted by name with its reason.
	sandbox.Exec(t, sandbox.Owner,
		`CREATE TABLE schema_migrations (version bigint PRIMARY KEY, dirty boolean NOT NULL)`,
		`CREATE TABLE unit (code text PRIMARY KEY)`,
		`GRANT SELECT ON unit TO `+sandbox.Role("strict")+`, `+sandbox.Role("privileged"),
		`CREATE VIEW item_bodies WITH (security_invoker = true) AS SELECT id, body FROM item`,
		`GRANT SELECT ON item_bodies TO `+sandbox.Role("strict"))
	gate := migrationtest.RowScopeGate{
		Logins: []string{sandbox.Role("ro"), sandbox.Role("rw")},
		Exempt: []migrationtest.RowScopeExemption{
			{Relation: "public.schema_migrations", Reason: "the migration ledger: owner-only, no runtime grant"},
			{Relation: "public.unit", Reason: "reference data, the same for every partition"},
		},
	}
	for _, connection := range []string{sandbox.ReadWrite, sandbox.ReadOnly} {
		if findings := gateFindings(t, sandbox, connection, gate); findings != "" {
			t.Fatalf("a protected store has findings:\n%s", findings)
		}
	}
	migrationtest.RequireRowScope(t, context.Background(), sandbox.Connect(t, sandbox.ReadWrite), func() migrationtest.RowScopeGate {
		gate.Roles = sandbox.Roles()
		return gate
	}())
}

// Each defect a migration can leave is found, by name, from the catalog alone.
func TestRowScopeGateFindsEachDefect(t *testing.T) {
	type defect struct {
		damage func(*rowscopefixture.Sandbox) []string
		gate   func(*rowscopefixture.Sandbox) migrationtest.RowScopeGate
		as     func(*rowscopefixture.Sandbox) string
		// superuser runs the damage as the fixture's superuser: an attribute
		// of a login the migration owner did not create.
		superuser bool
		want      []string
	}
	strict := func(s *rowscopefixture.Sandbox) string { return s.Role("strict") }
	for name, test := range map[string]defect{
		"row security never enabled": {
			damage: func(*rowscopefixture.Sandbox) []string {
				return []string{`ALTER TABLE item DISABLE ROW LEVEL SECURITY`}
			},
			want: []string{"public.item: row security is not enabled"},
		},
		"a migration lifted FORCE and did not restore it": {
			damage: func(*rowscopefixture.Sandbox) []string {
				return []string{`ALTER TABLE item NO FORCE ROW LEVEL SECURITY`}
			},
			want: []string{"public.item: row security is not forced"},
		},
		"a table nobody protected": {
			damage: func(s *rowscopefixture.Sandbox) []string {
				return []string{`CREATE TABLE loose (id bigint PRIMARY KEY, tenant text)`, `GRANT SELECT, INSERT ON loose TO ` + strict(s)}
			},
			want: []string{"public.loose: row security is not enabled", "public.loose: row security is not forced",
				`public.loose: has no "scope" column`, `no RESTRICTIVE FOR ALL policy binds mode role`, `no permissive policy names mode role`},
		},
		"an unlisted table with no grant at all": {
			damage: func(*rowscopefixture.Sandbox) []string {
				return []string{`CREATE TABLE ledger (version bigint PRIMARY KEY)`}
			},
			want: []string{"public.ledger: row security is not enabled", "exempt the table by name with the reason"},
		},
		"no policy for the privileged role": {
			damage: func(*rowscopefixture.Sandbox) []string { return []string{`DROP POLICY rowscope_privileged ON item`} },
			want:   []string{`public.item: no permissive policy names mode role`, `has no permissive policy for SELECT`},
		},
		"the reach policy is gone": {
			damage: func(*rowscopefixture.Sandbox) []string { return []string{`DROP POLICY rowscope_reach ON item`} },
			want:   []string{`to the reach (USING and WITH CHECK reading codefly.current_scopes)`},
		},
		"the partition policy is permissive": {
			damage: func(s *rowscopefixture.Sandbox) []string {
				return []string{`DROP POLICY rowscope_partition ON item`,
					`CREATE POLICY rowscope_partition ON item FOR ALL TO ` + strict(s) + `, ` + s.Role("privileged") + `
						USING (tenant = NULLIF(current_setting('codefly.current_tenant_id', true), ''))`}
			},
			want: []string{`to the partition (USING and WITH CHECK reading codefly.current_tenant_id)`},
		},
		"the runtime login holds a table grant": {
			damage: func(s *rowscopefixture.Sandbox) []string { return []string{`GRANT SELECT ON item TO ` + s.Role("rw")} },
			want:   []string{`public.item: runtime login "`, `holds a privilege on it directly or by inheritance`},
		},
		"the runtime login holds a column grant on an exempt table": {
			damage: func(s *rowscopefixture.Sandbox) []string {
				return []string{`CREATE TABLE unit (code text PRIMARY KEY)`, `GRANT SELECT (code) ON unit TO ` + s.Role("ro")}
			},
			gate: func(s *rowscopefixture.Sandbox) migrationtest.RowScopeGate {
				return migrationtest.RowScopeGate{
					Logins: []string{s.Role("ro")},
					Exempt: []migrationtest.RowScopeExemption{{Relation: "public.unit", Reason: "reference data"}},
				}
			},
			want: []string{`public.unit: runtime login "`},
		},
		"a grant to PUBLIC reaches the login": {
			damage: func(*rowscopefixture.Sandbox) []string { return []string{`GRANT SELECT ON item TO PUBLIC`} },
			want:   []string{`holds a privilege on it directly or by inheritance`},
		},
		"the login inherits a mode role": {
			damage: func(s *rowscopefixture.Sandbox) []string {
				return []string{`GRANT ` + strict(s) + ` TO ` + s.Role("rw") + ` WITH INHERIT TRUE`}
			},
			want: []string{`holds a privilege on it directly or by inheritance`},
		},
		// What the Postgres agent's session-default role does when a mode role
		// is the first of runtime-read-write-roles.
		"the login's session starts as a mode role": {
			superuser: true,
			damage: func(s *rowscopefixture.Sandbox) []string {
				return []string{`ALTER ROLE ` + s.Role("rw") + ` SET role = ` + strict(s)}
			},
			want: []string{`connection arrives as mode role`},
		},
		"the scope column is mutable": {
			damage: func(s *rowscopefixture.Sandbox) []string {
				return []string{`GRANT UPDATE (scope) ON item TO ` + s.Role("privileged")}
			},
			want: []string{`may UPDATE "scope"`},
		},
		"a whole-row UPDATE grant": {
			damage: func(s *rowscopefixture.Sandbox) []string { return []string{`GRANT UPDATE ON item TO ` + strict(s)} },
			want:   []string{`may UPDATE "tenant"`, `may UPDATE "scope"`, `may UPDATE "principal"`},
		},
		"a mode role may TRUNCATE": {
			damage: func(s *rowscopefixture.Sandbox) []string { return []string{`GRANT TRUNCATE ON item TO ` + strict(s)} },
			want:   []string{`holds TRUNCATE, REFERENCES or TRIGGER`},
		},
		"a policy for PUBLIC": {
			damage: func(*rowscopefixture.Sandbox) []string {
				return []string{`CREATE POLICY everyone ON item FOR SELECT USING (shared)`}
			},
			want: []string{`policy "everyone" is granted to PUBLIC`},
		},
		"a policy reads a setting bare": {
			damage: func(s *rowscopefixture.Sandbox) []string {
				return []string{`CREATE POLICY widen ON item FOR SELECT TO ` + strict(s) + ` USING (current_setting('app.read_scope', true) = 'organization')`}
			},
			want: []string{`policy "widen" reads a setting without NULLIF`},
		},
		"an insert grant with no policy": {
			damage: func(s *rowscopefixture.Sandbox) []string {
				return []string{`DROP POLICY rowscope_strict_insert ON item`}
			},
			want: []string{`has no permissive policy for INSERT`},
		},
		"an insert policy with no WITH CHECK": {
			damage: func(s *rowscopefixture.Sandbox) []string {
				return []string{`DROP POLICY rowscope_strict_insert ON item`, `CREATE POLICY rowscope_strict_insert ON item FOR INSERT TO ` + strict(s)}
			},
			want: []string{`may INSERT with no WITH CHECK policy`},
		},
		"a view that reads as its owner": {
			damage: func(*rowscopefixture.Sandbox) []string {
				return []string{`CREATE VIEW item_bodies AS SELECT id, body FROM item`}
			},
			want: []string{`public.item_bodies: is a view that is not security_invoker`},
		},
		"a materialized view": {
			damage: func(*rowscopefixture.Sandbox) []string {
				return []string{`CREATE MATERIALIZED VIEW item_counts AS SELECT tenant, count(*) FROM item GROUP BY tenant`}
			},
			want: []string{`public.item_counts: is a materialized view`},
		},
		"an exemption with no reason": {
			gate: func(*rowscopefixture.Sandbox) migrationtest.RowScopeGate {
				return migrationtest.RowScopeGate{Exempt: []migrationtest.RowScopeExemption{{Relation: "public.item", Reason: " "}}}
			},
			want: []string{`public.item: exempted without a reason`},
		},
		"an exemption for a table that is gone": {
			gate: func(*rowscopefixture.Sandbox) migrationtest.RowScopeGate {
				return migrationtest.RowScopeGate{Exempt: []migrationtest.RowScopeExemption{{Relation: "public.retired", Reason: "was reference data"}}}
			},
			want: []string{`public.retired: is exempted and does not exist`},
		},
		"a mode role that does not exist": {
			gate: func(*rowscopefixture.Sandbox) migrationtest.RowScopeGate { return migrationtest.RowScopeGate{} },
			damage: func(s *rowscopefixture.Sandbox) []string {
				return []string{`ALTER ROLE ` + s.Role("privileged") + ` RENAME TO ` + s.Role("renamed")}
			},
			want: []string{`mode role "`, `does not exist`},
		},
		"a mode role that can log in": {
			damage: func(s *rowscopefixture.Sandbox) []string { return []string{`ALTER ROLE ` + strict(s) + ` LOGIN`} },
			want:   []string{`can log in`},
		},
		// The gate asks what the production login can reach. Run as a login
		// that bypasses row security it would pass on anything, so it says so.
		"run as the fixture principal": {
			as:   func(s *rowscopefixture.Sandbox) string { return s.Fixture },
			want: []string{`is a superuser, BYPASSRLS, CREATEROLE or CREATEDB`, `holds a privilege on it directly or by inheritance`},
		},
		"run as the owner": {
			as:   func(s *rowscopefixture.Sandbox) string { return s.Owner },
			want: []string{`is owned by runtime login`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			sandbox := rowscopefixture.Open(t)
			sandbox.Migrate(t, "item")
			if test.damage != nil {
				by := sandbox.Owner
				if test.superuser {
					by = sandbox.Admin
				}
				sandbox.Exec(t, by, test.damage(sandbox)...)
			}
			gate, connection := migrationtest.RowScopeGate{}, sandbox.ReadWrite
			if test.gate != nil {
				gate = test.gate(sandbox)
			}
			if test.as != nil {
				connection = test.as(sandbox)
			}
			findings := gateFindings(t, sandbox, connection, gate)
			for _, want := range test.want {
				if !strings.Contains(findings, want) {
					t.Fatalf("missing finding %q in:\n%s", want, findings)
				}
			}
			t.Log("\n" + findings)
		})
	}
}
