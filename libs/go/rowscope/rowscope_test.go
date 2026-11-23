package rowscope

import (
	"strings"
	"testing"

	postgres "github.com/codefly-dev/service-postgres/libs/go"
)

var testRoles = postgres.Roles{Strict: "app_x_strict", Privileged: "app_x_privileged"}

func TestProtectEmitsTheWholeShape(t *testing.T) {
	statements, err := Protect(Table{Name: "record", Mutable: []string{"payload", "shared"}}, testRoles, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	script := Script(statements)
	for _, want := range []string{
		`REVOKE ALL ON TABLE "public"."record" FROM "app_x_strict", "app_x_privileged";`,
		`GRANT SELECT, INSERT, DELETE ON TABLE "public"."record" TO "app_x_strict", "app_x_privileged";`,
		`GRANT UPDATE ("payload", "shared") ON TABLE "public"."record" TO "app_x_strict", "app_x_privileged";`,
		`ALTER TABLE "public"."record" ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE "public"."record" FORCE ROW LEVEL SECURITY;`,
		`CREATE POLICY "rowscope_partition" ON "public"."record" AS RESTRICTIVE FOR ALL TO "app_x_strict", "app_x_privileged" USING ("tenant" = (SELECT NULLIF(current_setting('codefly.current_tenant_id', true), ''))) WITH CHECK (`,
		`CREATE POLICY "rowscope_reach" ON "public"."record" AS RESTRICTIVE FOR ALL TO "app_x_strict", "app_x_privileged" USING ("scope" = ANY ((SELECT string_to_array(NULLIF(current_setting('codefly.current_scopes', true), ''), ','))::text[])) WITH CHECK (`,
		`CREATE POLICY "rowscope_strict_read" ON "public"."record" FOR SELECT TO "app_x_strict" USING ("shared" OR "principal" = (SELECT NULLIF(current_setting('codefly.current_principal', true), '')));`,
		`CREATE POLICY "rowscope_strict_insert" ON "public"."record" FOR INSERT TO "app_x_strict" WITH CHECK ("principal" = `,
		`CREATE POLICY "rowscope_strict_modify" ON "public"."record" FOR UPDATE TO "app_x_strict" USING ("principal" = `,
		`CREATE POLICY "rowscope_strict_delete" ON "public"."record" FOR DELETE TO "app_x_strict" USING ("principal" = `,
		`CREATE POLICY "rowscope_privileged" ON "public"."record" FOR ALL TO "app_x_privileged" USING (true) WITH CHECK (true);`,
		`CREATE INDEX IF NOT EXISTS "record_rowscope_idx" ON "public"."record" ("tenant", "scope", "principal");`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %s in:\n%s", want, script)
		}
	}
	// Every setting read is the fail-closed, evaluate-once form.
	if strings.Count(script, "current_setting(") != strings.Count(script, "(SELECT NULLIF(current_setting(")+strings.Count(script, "(SELECT string_to_array(NULLIF(current_setting(") {
		t.Fatalf("a setting is read outside (SELECT NULLIF(...)):\n%s", script)
	}
	// No UPDATE that is not a column list, ever.
	if strings.Contains(script, "GRANT UPDATE ON") || strings.Contains(script, "TRUNCATE") {
		t.Fatalf("a whole-row UPDATE or TRUNCATE grant was emitted:\n%s", script)
	}
}

func TestProtectHonoursNamesAndRefusesAMutableIdentity(t *testing.T) {
	table := Table{Schema: "runtime", Name: `odd"name`, Partition: "org", Scope: "installation", Principal: "on_behalf_of", Shared: "is_shared"}
	statements, err := Protect(table, postgres.Roles{Strict: "people"}, Settings{Partition: "app.org", Reach: "app.reach", Principal: "app.who", WriteReach: "app.write_reach"})
	if err != nil {
		t.Fatal(err)
	}
	script := Script(statements)
	if !strings.Contains(script, `"runtime"."odd""name"`) || !strings.Contains(script, `"installation" = ANY`) || !strings.Contains(script, `'app.who'`) || strings.Contains(script, "rowscope_privileged") || strings.Contains(script, "GRANT UPDATE") {
		t.Fatalf("names not honoured:\n%s", script)
	}
	for name, broken := range map[string]Table{
		"no table":          {},
		"mutable scope":     {Name: "t", Mutable: []string{"body", "scope"}},
		"mutable principal": {Name: "t", Principal: "who", Mutable: []string{"who"}},
		"mutable partition": {Name: "t", Mutable: []string{"tenant"}},
		"shared is scope":   {Name: "t", Shared: "scope"},
		"padded column":     {Name: "t", Mutable: []string{" body"}},
	} {
		if _, err := Protect(broken, testRoles, DefaultSettings()); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	for name, settings := range map[string]Settings{
		"zero":           {},
		"injection":      {Partition: "a.b'); DROP TABLE t; --", Reach: "a.c", Principal: "a.d", WriteReach: "a.e"},
		"bare name":      {Partition: "tenant", Reach: "a.c", Principal: "a.d", WriteReach: "a.e"},
		"no write reach": {Partition: "a.b", Reach: "a.c", Principal: "a.d"},
		"one reach":      {Partition: "a.b", Reach: "a.c", Principal: "a.d", WriteReach: "a.c"},
	} {
		if _, err := Protect(Table{Name: "t"}, testRoles, settings); err == nil {
			t.Fatalf("%s settings: accepted", name)
		}
	}
	for _, roles := range []postgres.Roles{{}, {Strict: "one", Privileged: "one"}} {
		if _, err := Protect(Table{Name: "t"}, roles, DefaultSettings()); err == nil {
			t.Fatalf("roles %#v: accepted", roles)
		}
	}
}

func TestBootstrapCreatesPowerlessRolesAndNonInheritingMemberships(t *testing.T) {
	statements, err := Bootstrap(testRoles, Logins{Strict: []string{"svc_ro", "svc_rw"}, Privileged: []string{"svc_jobs"}})
	if err != nil {
		t.Fatal(err)
	}
	script := Script(statements)
	for _, want := range []string{
		`CREATE ROLE "app_x_strict" NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;`,
		`RAISE EXCEPTION 'role % exists and is wider than a mode role may be', 'app_x_privileged';`,
		`GRANT "app_x_strict" TO "svc_ro" WITH INHERIT FALSE, SET TRUE;`,
		`GRANT "app_x_strict" TO "svc_rw" WITH INHERIT FALSE, SET TRUE;`,
		`GRANT "app_x_privileged" TO "svc_jobs" WITH INHERIT FALSE, SET TRUE;`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %s in:\n%s", want, script)
		}
	}
	// The people-serving logins were not given the privileged role.
	if strings.Contains(script, `"app_x_privileged" TO "svc_r`) {
		t.Fatalf("a strict login was granted the privileged role:\n%s", script)
	}
	if _, err := Bootstrap(postgres.Roles{}, Logins{}); err == nil {
		t.Fatal("no roles accepted")
	}
	if _, err := Bootstrap(postgres.Roles{Strict: "s"}, Logins{Privileged: []string{"svc"}}); err == nil {
		t.Fatal("logins for a mode with no role accepted")
	}
	if _, err := Bootstrap(testRoles, Logins{Strict: []string{"app_x_privileged"}}); err == nil {
		t.Fatal("a mode role granted to a mode role accepted")
	}
}

func TestColumnsRefuseWhatTheReachCannotCarry(t *testing.T) {
	columns, err := Columns(Table{Name: "t"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(columns, "\n")
	for _, want := range []string{`"scope" <> ''`, `position(',' in "scope") = 0`, `"principal" ~ '^[a-z]+:.+'`, `"shared" boolean NOT NULL`, `"tenant" <> ''`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "DEFAULT") {
		t.Fatal("a row-scope column has a default: absence would mean something")
	}
}

var accessRoles = postgres.AccessRoles("app_x")

// The four-role shape: SELECT alone for the read roles, every policy naming
// its roles one by one, and each write bound to the write reach by verb.
func TestProtectEmitsReadRolesThatHoldSelectAlone(t *testing.T) {
	statements, err := Protect(Table{Name: "record", Mutable: []string{"payload"}}, accessRoles, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	script := Script(statements)
	const (
		every   = `"app_x_strict_read", "app_x_strict_write", "app_x_privileged_read", "app_x_privileged_write"`
		writers = `"app_x_strict_write", "app_x_privileged_write"`
		readers = `"app_x_strict_read", "app_x_privileged_read"`
		within  = `("scope" = ANY ((SELECT string_to_array(NULLIF(current_setting('codefly.current_write_scopes', true), ''), ','))::text[]))`
	)
	for _, want := range []string{
		`REVOKE ALL ON TABLE "public"."record" FROM ` + every + `;`,
		`GRANT SELECT, INSERT, DELETE ON TABLE "public"."record" TO ` + writers + `;`,
		`GRANT UPDATE ("payload") ON TABLE "public"."record" TO ` + writers + `;`,
		`GRANT SELECT ON TABLE "public"."record" TO ` + readers + `;`,
		`CREATE POLICY "rowscope_partition" ON "public"."record" AS RESTRICTIVE FOR ALL TO ` + every + ` USING (`,
		`CREATE POLICY "rowscope_reach" ON "public"."record" AS RESTRICTIVE FOR ALL TO ` + every + ` USING ("scope" = ANY ((SELECT string_to_array(NULLIF(current_setting('codefly.current_scopes', true), ''), ','))::text[])) WITH CHECK (`,
		`CREATE POLICY "rowscope_reach_insert" ON "public"."record" AS RESTRICTIVE FOR INSERT TO ` + writers + ` WITH CHECK ` + within + `;`,
		`CREATE POLICY "rowscope_reach_modify" ON "public"."record" AS RESTRICTIVE FOR UPDATE TO ` + writers + ` USING ` + within + ` WITH CHECK ` + within + `;`,
		`CREATE POLICY "rowscope_reach_delete" ON "public"."record" AS RESTRICTIVE FOR DELETE TO ` + writers + ` USING ` + within + `;`,
		`CREATE POLICY "rowscope_strict_read" ON "public"."record" FOR SELECT TO "app_x_strict_read", "app_x_strict_write" USING ("shared" OR `,
		`CREATE POLICY "rowscope_strict_insert" ON "public"."record" FOR INSERT TO "app_x_strict_write" WITH CHECK (`,
		`CREATE POLICY "rowscope_strict_modify" ON "public"."record" FOR UPDATE TO "app_x_strict_write" USING (`,
		`CREATE POLICY "rowscope_strict_delete" ON "public"."record" FOR DELETE TO "app_x_strict_write" USING (`,
		`CREATE POLICY "rowscope_privileged" ON "public"."record" FOR ALL TO "app_x_privileged_write" USING (true) WITH CHECK (true);`,
		`CREATE POLICY "rowscope_privileged_read" ON "public"."record" FOR SELECT TO "app_x_privileged_read" USING (true);`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %s in:\n%s", want, script)
		}
	}
	// A read role is named by no grant but SELECT and by no policy that writes.
	for _, line := range strings.Split(script, ";\n") {
		writes := strings.Contains(line, "INSERT") || strings.Contains(line, "UPDATE") || strings.Contains(line, "DELETE") || strings.Contains(line, "FOR ALL TO") && !strings.Contains(line, "RESTRICTIVE")
		if writes && !strings.HasPrefix(line, "REVOKE") && strings.Contains(line, `_read"`) && !strings.Contains(line, `"rowscope_privileged_read"`) {
			t.Fatalf("a read role is named by a statement that writes:\n%s", line)
		}
	}
	// A store of readers alone gets no write policy and no write grant.
	readOnly, err := Protect(Table{Name: "record", Mutable: []string{"payload"}}, postgres.Roles{StrictRead: "r", PrivilegedRead: "p"}, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	if script := Script(readOnly); strings.Contains(script, "INSERT") || strings.Contains(script, "GRANT UPDATE") || strings.Contains(script, "current_write_scopes") {
		t.Fatalf("a store of read roles was given something that writes:\n%s", script)
	}
	if _, err := Protect(Table{Name: "t"}, postgres.Roles{StrictRead: "one", StrictWrite: "one"}, DefaultSettings()); err == nil {
		t.Fatal("one role for read and write accepted")
	}
}

// The two-role form is still emitted, and its roles are bound to the write
// reach like any role that writes.
func TestProtectBindsTheTwoRoleFormToTheWriteReach(t *testing.T) {
	statements, err := Protect(Table{Name: "record"}, testRoles, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	script := Script(statements)
	if !strings.Contains(script, `CREATE POLICY "rowscope_reach_delete" ON "public"."record" AS RESTRICTIVE FOR DELETE TO "app_x_strict", "app_x_privileged" USING (`) || strings.Contains(script, "rowscope_privileged_read") || strings.Contains(script, `GRANT SELECT ON TABLE`) {
		t.Fatalf("two-role shape:\n%s", script)
	}
}

func TestBootstrapKeepsReadAndWriteLoginsApart(t *testing.T) {
	statements, err := Bootstrap(accessRoles, Logins{
		StrictRead: []string{"people_ro"}, StrictWrite: []string{"people_rw"},
		PrivilegedRead: []string{"jobs_ro", "people_ro"}, PrivilegedWrite: []string{"jobs_rw"},
	})
	if err != nil {
		t.Fatal(err)
	}
	script := Script(statements)
	for _, want := range []string{
		`CREATE ROLE "app_x_strict_read" NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;`,
		`CREATE ROLE "app_x_privileged_write" NOLOGIN NOINHERIT`,
		`GRANT "app_x_strict_read" TO "people_ro" WITH INHERIT FALSE, SET TRUE;`,
		`GRANT "app_x_strict_write" TO "people_rw" WITH INHERIT FALSE, SET TRUE;`,
		`GRANT "app_x_privileged_read" TO "people_ro" WITH INHERIT FALSE, SET TRUE;`,
		`GRANT "app_x_privileged_write" TO "jobs_rw" WITH INHERIT FALSE, SET TRUE;`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %s in:\n%s", want, script)
		}
	}
	// No role is granted to a role: there is no chain for SET ROLE to walk.
	if strings.Contains(script, `TO "app_x_`) {
		t.Fatalf("a mode role was granted to a mode role:\n%s", script)
	}
	for name, logins := range map[string]Logins{
		"read and write of one mode":  {StrictRead: []string{"svc"}, StrictWrite: []string{"svc"}},
		"read and write across modes": {PrivilegedRead: []string{"svc"}, StrictWrite: []string{"svc"}},
		"write listed first":          {StrictWrite: []string{"svc"}, PrivilegedRead: []string{"svc"}},
		"a role as a login":           {StrictWrite: []string{"app_x_strict_read"}},
	} {
		if _, err := Bootstrap(accessRoles, logins); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// A two-role form's role writes, so its login cannot also be a reader's.
	if _, err := Bootstrap(postgres.Roles{Strict: "both", StrictRead: "r"}, Logins{Strict: []string{"svc"}, StrictRead: []string{"svc"}}); err == nil {
		t.Fatal("a login under a read role and the two-role form's role accepted")
	}
}
