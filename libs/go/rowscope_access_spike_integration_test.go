//go:build controlplaneintegration

package postgres_test

// The access spike: the Postgres behaviours that make READ and READ-WRITE a
// dimension the database enforces, beside the mode. One named test per claim,
// statements written by hand, as in rowscope_spike_integration_test.go: this
// file proves the mechanism, rowscope_integration_test.go the library that
// emits it. A test named "...Can..." or "...Lets..." pins a behaviour the
// design has to live with.
//
// The matrix is four NOLOGIN roles, mode x access, and four logins, each
// granted exactly one of them WITH INHERIT FALSE, SET TRUE.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/codefly-dev/service-postgres/libs/go/internal/rowscopefixture"
	"github.com/jackc/pgx/v5"
)

type accessSpike struct {
	*rowscopefixture.Sandbox
	strictRead, strictWrite, privilegedRead, privilegedWrite string
	// One login per role, by the role's short name.
	logins map[string]string
}

func (s accessSpike) roles() []string {
	return []string{s.strictRead, s.strictWrite, s.privilegedRead, s.privilegedWrite}
}

// accessBind is spikeBind with the write reach: six settings and the role.
const accessBind = `SELECT set_config('codefly.current_tenant_id',   $1, true),
       set_config('codefly.current_scopes',       $2, true),
       set_config('codefly.current_write_scopes', $3, true),
       set_config('codefly.current_principal',    $4, true),
       set_config('role',                         $5, true)`

// tableSQL is the four-role shape for one table. Every policy names its roles
// one by one, and the read roles are granted SELECT alone.
func (s accessSpike) tableSQL(table string) []string {
	every := strings.Join(s.roles(), ", ")
	writers := s.strictWrite + ", " + s.privilegedWrite
	setting := func(name string) string {
		return `(SELECT NULLIF(current_setting('codefly.` + name + `', true), ''))`
	}
	within := func(name string) string {
		return `scope = ANY ((SELECT string_to_array(NULLIF(current_setting('codefly.` + name + `', true), ''), ','))::text[])`
	}
	own := `principal = ` + setting("current_principal")
	return []string{
		`CREATE TABLE ` + table + ` (
			id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			tenant text NOT NULL, scope text NOT NULL,
			principal text NOT NULL CHECK (principal ~ '^[a-z]+:.+'),
			shared boolean NOT NULL, body text NOT NULL DEFAULT '')`,
		`ALTER TABLE ` + table + ` ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE ` + table + ` FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY ` + table + `_partition ON ` + table + ` AS RESTRICTIVE FOR ALL TO ` + every + `
			USING (tenant = ` + setting("current_tenant_id") + `) WITH CHECK (tenant = ` + setting("current_tenant_id") + `)`,
		`CREATE POLICY ` + table + `_reach ON ` + table + ` AS RESTRICTIVE FOR ALL TO ` + every + `
			USING (` + within("current_scopes") + `) WITH CHECK (` + within("current_scopes") + `)`,
		`CREATE POLICY ` + table + `_reach_insert ON ` + table + ` AS RESTRICTIVE FOR INSERT TO ` + writers + `
			WITH CHECK (` + within("current_write_scopes") + `)`,
		`CREATE POLICY ` + table + `_reach_modify ON ` + table + ` AS RESTRICTIVE FOR UPDATE TO ` + writers + `
			USING (` + within("current_write_scopes") + `) WITH CHECK (` + within("current_write_scopes") + `)`,
		`CREATE POLICY ` + table + `_reach_delete ON ` + table + ` AS RESTRICTIVE FOR DELETE TO ` + writers + `
			USING (` + within("current_write_scopes") + `)`,
		`CREATE POLICY ` + table + `_strict_read ON ` + table + ` FOR SELECT TO ` + s.strictRead + `, ` + s.strictWrite + ` USING (shared OR ` + own + `)`,
		`CREATE POLICY ` + table + `_strict_insert ON ` + table + ` FOR INSERT TO ` + s.strictWrite + ` WITH CHECK (` + own + `)`,
		`CREATE POLICY ` + table + `_strict_modify ON ` + table + ` FOR UPDATE TO ` + s.strictWrite + ` USING (` + own + `) WITH CHECK (` + own + `)`,
		`CREATE POLICY ` + table + `_strict_delete ON ` + table + ` FOR DELETE TO ` + s.strictWrite + ` USING (` + own + `)`,
		`CREATE POLICY ` + table + `_privileged ON ` + table + ` FOR ALL TO ` + s.privilegedWrite + ` USING (true) WITH CHECK (true)`,
		`CREATE POLICY ` + table + `_privileged_read ON ` + table + ` FOR SELECT TO ` + s.privilegedRead + ` USING (true)`,
		`GRANT SELECT ON ` + table + ` TO ` + s.strictRead + `, ` + s.privilegedRead,
		`GRANT SELECT, INSERT, DELETE ON ` + table + ` TO ` + writers,
		`GRANT UPDATE (shared, body) ON ` + table + ` TO ` + writers,
	}
}

func openAccessSpike(t *testing.T) accessSpike {
	t.Helper()
	sandbox := rowscopefixture.Open(t)
	s := accessSpike{
		Sandbox:    sandbox,
		strictRead: sandbox.Role("strict_read"), strictWrite: sandbox.Role("strict_write"),
		privilegedRead: sandbox.Role("privileged_read"), privilegedWrite: sandbox.Role("privileged_write"),
		logins: map[string]string{},
	}
	var migration []string
	for _, role := range s.roles() {
		migration = append(migration, `CREATE ROLE `+role+` NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS`)
	}
	migration = append(migration, s.tableSQL("item")...)
	s.Exec(t, s.Owner, migration...)
	for _, name := range []string{"strict_read", "strict_write", "privileged_read", "privileged_write"} {
		s.logins[name] = s.Login(t, "login_"+name)
		s.Exec(t, s.Owner, `GRANT `+s.Role(name)+` TO `+s.Role("login_"+name)+` WITH INHERIT FALSE, SET TRUE`)
	}
	s.Exec(t, s.Fixture, fmt.Sprintf(spikeSeed, "item"))
	return s
}

// as runs fn in one READ WRITE transaction of the named login, bound to the
// role, and rolls back. READ WRITE on purpose: nothing in these tests may be
// refused by the transaction's access mode when the claim is about a grant.
func (s accessSpike) as(t *testing.T, ctx context.Context, conn *pgx.Conn, role, readScopes, writeScopes, principal string, fn func(pgx.Tx)) {
	t.Helper()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadWrite})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, accessBind, "t1", readScopes, writeScopes, principal, role); err != nil {
		t.Fatalf("bind %s: %v", role, err)
	}
	fn(tx)
}

// The statements that change a table or lock its rows. Every one needs a
// privilege SELECT does not carry.
var writeAttempts = []string{
	`INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:a',false)`,
	`UPDATE item SET body = 'x'`,
	`UPDATE item SET body = 'x' WHERE principal = 'human:a'`,
	`DELETE FROM item`,
	`DELETE FROM item WHERE principal = 'human:a'`,
	`TRUNCATE item`,
	`SELECT * FROM item FOR UPDATE`,
	`SELECT * FROM item FOR SHARE`,
	`INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:a',false) ON CONFLICT (id) DO UPDATE SET body = 'x'`,
	`MERGE INTO item USING (SELECT 1) AS one ON false WHEN NOT MATCHED THEN INSERT (tenant, scope, principal, shared) VALUES ('t1','s1','human:a',false)`,
	`WITH gone AS (DELETE FROM item RETURNING id) SELECT count(*) FROM gone`,
	`COPY item (tenant, scope, principal, shared) FROM STDIN`,
	`LOCK TABLE item IN SHARE ROW EXCLUSIVE MODE`,
}

// Claim 21: a role granted SELECT alone is refused every write with
// permission denied in a READ WRITE transaction, in both modes, with every
// setting bound as a writer's would be. It is the grant that refuses: nothing
// here is READ ONLY, and the write reach is bound.
func TestSpikeReadRoleIsRefusedEveryWriteOutsideReadOnly(t *testing.T) {
	s, ctx := openAccessSpike(t), spikeContext(t)
	for name, test := range map[string]struct{ role, principal, reads string }{
		"strict_read":     {s.strictRead, "human:a", "a-private,b-shared"},
		"privileged_read": {s.privilegedRead, "agent:s1", "a-private,b-private,b-shared"},
	} {
		conn := s.Connect(t, s.logins[name])
		s.as(t, ctx, conn, test.role, "s1", "s1", test.principal, func(tx pgx.Tx) {
			if scalar[string](t, ctx, tx, `SHOW transaction_read_only`) != "off" {
				t.Fatal("the transaction is READ ONLY; this test would prove nothing")
			}
			if got := bodies(t, ctx, tx, "item"); got != test.reads {
				t.Fatalf("%s read %q, want %q", name, got, test.reads)
			}
			for _, statement := range writeAttempts {
				wantProbe(t, ctx, tx, insufficientPrivilege, 0, statement)
			}
			if got := bodies(t, ctx, tx, "item"); got != test.reads {
				t.Fatalf("%s then read %q", name, got)
			}
		})
	}
	if got := bodies(t, ctx, s.Connect(t, s.Fixture), "item"); got != "a-in-s2,a-in-t2,a-private,b-private,b-shared" {
		t.Fatalf("the table holds %q", got)
	}
}

// Claim 22: READ ONLY is checked before privileges. In a READ ONLY transaction
// a role that holds every write grant and a role that holds none get the same
// refusal, 25006, for a row lock as for a write. So a test that attempts a
// write in a READ ONLY transaction cannot tell whether the grants are right,
// and READ ONLY on the reader pool hides a read role that was granted too much.
func TestSpikeReadOnlyRefusalHidesWhatTheRoleHolds(t *testing.T) {
	s, ctx := openAccessSpike(t), spikeContext(t)
	for name, role := range map[string]string{"strict_read": s.strictRead, "strict_write": s.strictWrite} {
		tx, err := s.Connect(t, s.logins[name]).BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, accessBind, "t1", "s1", "s1", "human:a", role); err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{
			`INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:a',false)`,
			`UPDATE item SET body = 'x'`, `DELETE FROM item`, `TRUNCATE item`, `SELECT * FROM item FOR UPDATE`,
		} {
			if state, _ := probe(t, ctx, tx, statement); state != readOnlyTransaction {
				t.Fatalf("%s in READ ONLY: %s => %q, want 25006 whatever the role holds", name, statement, state)
			}
		}
		_ = tx.Rollback(ctx)
	}
}

// Claim 23: a login granted a read role alone cannot reach a write role, by
// any spelling, from inside a read transaction or outside one. And the
// counter-case the design has to live with: a login granted both steps from
// the read role to the write role in the middle of a transaction and writes.
func TestSpikeReaderLoginCannotAssumeAWriteRole(t *testing.T) {
	s, ctx := openAccessSpike(t), spikeContext(t)
	reader := s.Connect(t, s.logins["strict_read"])
	for _, statement := range []string{`SET ROLE ` + s.strictWrite, `SET ROLE ` + s.privilegedWrite, `SET SESSION AUTHORIZATION ` + s.strictWrite} {
		if _, err := reader.Exec(ctx, statement); sqlState(err) != insufficientPrivilege {
			t.Fatalf("%s => SQLSTATE %q", statement, sqlState(err))
		}
	}
	s.as(t, ctx, reader, s.strictRead, "s1", "s1", "human:a", func(tx pgx.Tx) {
		for _, write := range []string{s.strictWrite, s.privilegedWrite} {
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE `+write)
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SELECT set_config('role', $1, true)`, write)
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, `RESET ROLE; SET ROLE `+write)
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, `GRANT `+write+` TO `+s.strictRead)
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, `GRANT `+write+` TO CURRENT_USER`)
		}
		// Nor can the role give itself the privilege it lacks: a GRANT by a
		// role with nothing to grant is a warning and changes nothing.
		if _, err := tx.Exec(ctx, `GRANT INSERT, DELETE ON item TO `+s.strictRead); err != nil {
			t.Fatal(err)
		}
		if scalar[bool](t, ctx, tx, `SELECT has_table_privilege(current_user, 'item', 'INSERT') OR has_table_privilege(current_user, 'item', 'DELETE')`) {
			t.Fatal("a read role granted itself a write privilege")
		}
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `ALTER TABLE item DISABLE ROW LEVEL SECURITY`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `DELETE FROM item`)
	})

	// One login holding the read and the write role of a mode.
	both := s.Login(t, "login_both")
	s.Exec(t, s.Owner, `GRANT `+s.strictRead+`, `+s.strictWrite+` TO `+s.Role("login_both")+` WITH INHERIT FALSE, SET TRUE`)
	s.as(t, ctx, s.Connect(t, both), s.strictRead, "s1", "s1", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `DELETE FROM item`)
		wantProbe(t, ctx, tx, "", 1, `SET LOCAL ROLE `+s.strictWrite+`; DELETE FROM item`)
	})
	// On that login, READ ONLY is again the only thing in the way.
	tx, err := s.Connect(t, both).BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, accessBind, "t1", "s1", "s1", "human:a", s.strictRead); err != nil {
		t.Fatal(err)
	}
	wantProbe(t, ctx, tx, readOnlyTransaction, 0, `SET LOCAL ROLE `+s.strictWrite+`; DELETE FROM item`)
}

// Claim 24: the escape matrix. From a transaction bound to any role, the roles
// SQL text can reach are exactly the ones the session's login holds SET on:
// its own, and nothing else, for each of four single-role logins. A login
// granted the two read roles reaches both modes and still no write.
func TestSpikeEscapeMatrixIsTheLoginsMemberships(t *testing.T) {
	s, ctx := openAccessSpike(t), spikeContext(t)
	reachable := func(conn *pgx.Conn, from string) string {
		var reached []string
		s.as(t, ctx, conn, from, "s1", "s1", "human:a", func(tx pgx.Tx) {
			for _, role := range s.roles() {
				// From the bound role, and again after RESET ROLE.
				first, _ := probe(t, ctx, tx, `SET LOCAL ROLE `+role)
				second, _ := probe(t, ctx, tx, `RESET ROLE; SELECT set_config('role', '`+role+`', true)`)
				if first != second || (first != "" && first != insufficientPrivilege) {
					t.Fatalf("from %s to %s: SET LOCAL ROLE => %q, after RESET => %q", from, role, first, second)
				}
				if first == "" {
					reached = append(reached, strings.TrimPrefix(role, s.Role("")))
				}
			}
			// Nothing outside the matrix either.
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE `+s.Role("owner"))
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE `+s.Role("fixture"))
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE pg_write_all_data`)
		})
		return strings.Join(reached, ",")
	}
	for _, name := range []string{"strict_read", "strict_write", "privileged_read", "privileged_write"} {
		if got := reachable(s.Connect(t, s.logins[name]), s.Role(name)); got != name {
			t.Fatalf("a login granted %s alone reaches %q", name, got)
		}
		// The catalog says the same without trying: this is what the gate reads.
		login := s.Role("login_" + name)
		for _, role := range s.roles() {
			if got, want := scalar[bool](t, ctx, s.Connect(t, s.logins[name]), `SELECT pg_has_role($1, $2, 'SET')`, login, role), role == s.Role(name); got != want {
				t.Fatalf("pg_has_role(%s, %s, 'SET') = %v", login, role, got)
			}
		}
	}
	// A reader login for a process that serves both modes.
	readers := s.Login(t, "login_readers")
	s.Exec(t, s.Owner, `GRANT `+s.strictRead+`, `+s.privilegedRead+` TO `+s.Role("login_readers")+` WITH INHERIT FALSE, SET TRUE`)
	conn := s.Connect(t, readers)
	if got := reachable(conn, s.strictRead); got != "strict_read,privileged_read" {
		t.Fatalf("a login granted both read roles reaches %q", got)
	}
	// The mode is not fenced on it, the access is.
	s.as(t, ctx, conn, s.strictRead, "s1", "s1", "human:a", func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+s.privilegedRead); err != nil {
			t.Fatal(err)
		}
		if got := bodies(t, ctx, tx, "item"); got != "a-private,b-private,b-shared" {
			t.Fatalf("after SET ROLE privileged_read, read %q", got)
		}
		for _, statement := range writeAttempts {
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, statement)
		}
	})
}

// Claim 25: a policy written TO a read role is not a policy of the write role.
// A write role its mode's read policy does not name holds SELECT and reads
// nothing, and its UPDATE ... WHERE and DELETE ... WHERE find no row. Making
// the write role a member of the read role applies the read policy to it on
// one server version and not on another — and, with the default membership
// options, hands every login of the write role a SET ROLE path to the read
// role. So each policy names both roles.
func TestSpikeWriteRoleNeedsItsOwnReadPolicy(t *testing.T) {
	s, ctx := openAccessSpike(t), spikeContext(t)
	s.Exec(t, s.Owner, `ALTER POLICY item_strict_read ON item TO `+s.strictRead)
	writer := s.Connect(t, s.logins["strict_write"])
	s.as(t, ctx, writer, s.strictWrite, "s1", "s1", "human:a", func(tx pgx.Tx) {
		if got := bodies(t, ctx, tx, "item"); got != "" {
			t.Fatalf("a write role with no read policy read %q", got)
		}
		wantProbe(t, ctx, tx, "", 0, `UPDATE item SET body = 'x' WHERE principal = 'human:a'`)
		wantProbe(t, ctx, tx, "", 0, `DELETE FROM item WHERE principal = 'human:a'`)
		// A statement that reads no column of the row needs no SELECT policy:
		// the row is changed by a role that cannot see it.
		wantProbe(t, ctx, tx, "", 1, `UPDATE item SET body = 'x'`)
		wantProbe(t, ctx, tx, "", 1, `DELETE FROM item`)
	})

	// Inheriting the policy instead of being named in it.
	s.Exec(t, s.Owner, `GRANT `+s.strictRead+` TO `+s.strictWrite+` WITH INHERIT TRUE, SET FALSE`)
	s.as(t, ctx, writer, s.strictWrite, "s1", "s1", "human:a", func(tx pgx.Tx) {
		// Whether a policy is inherited at all depends on the server: 17 applies
		// the read role's policy to its member, the 16.14 this suite also runs
		// on does not. A shape that leans on it reads rows on one and nothing
		// on the other.
		switch got := bodies(t, ctx, tx, "item"); got {
		case "a-private,b-shared":
			t.Logf("%s: the read role's policy applies to a role that inherits it", scalar[string](t, ctx, tx, `SHOW server_version`))
		case "":
			t.Logf("%s: the read role's policy does NOT apply to a role that inherits it", scalar[string](t, ctx, tx, `SHOW server_version`))
		default:
			t.Fatalf("a write role inheriting the read role read %q", got)
		}
		// SET FALSE on the second edge: no path for the login.
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE `+s.strictRead)
	})
	// The same membership as a plain GRANT writes it: SET is on by default.
	s.Exec(t, s.Owner, `GRANT `+s.strictRead+` TO `+s.strictWrite+` WITH INHERIT TRUE, SET TRUE`)
	s.as(t, ctx, writer, s.strictWrite, "s1", "s1", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, "", 0, `SET LOCAL ROLE `+s.strictRead)
	})
	// And the other direction is the dangerous one: a read role that is a
	// member of the write role holds its grants, whatever it was granted.
	s.Exec(t, s.Owner, `REVOKE `+s.strictRead+` FROM `+s.strictWrite, `GRANT `+s.strictWrite+` TO `+s.strictRead+` WITH INHERIT TRUE, SET FALSE`)
	s.as(t, ctx, s.Connect(t, s.logins["strict_read"]), s.strictRead, "s1", "s1", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, "", 1, `DELETE FROM item WHERE principal = 'human:a'`)
	})
}

// Claim 26: the write reach is a second setting that binds each write verb by
// its own restrictive policy, while SELECT is bound by the reach alone. A
// transaction that reads two scopes and may write one reads both and changes
// only the one; with no write reach it changes nothing, in either mode.
func TestSpikeWriteReachBindsEachWriteVerb(t *testing.T) {
	s, ctx := openAccessSpike(t), spikeContext(t)
	for name, test := range map[string]struct {
		role, principal, reads string
		writable               int64
	}{
		"strict_write":     {s.strictWrite, "human:a", "a-in-s2,a-private,b-shared", 1},
		"privileged_write": {s.privilegedWrite, "agent:s1", "a-in-s2,a-private,b-private,b-shared", 3},
	} {
		conn := s.Connect(t, s.logins[name])
		insert := `INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1', $1, '` + test.principal + `', false)`
		s.as(t, ctx, conn, test.role, "s1,s2", "s1", test.principal, func(tx pgx.Tx) {
			if got := bodies(t, ctx, tx, "item"); got != test.reads {
				t.Fatalf("%s read %q, want %q", name, got, test.reads)
			}
			wantProbe(t, ctx, tx, "", test.writable, `UPDATE item SET body = body || '!'`)
			wantProbe(t, ctx, tx, "", test.writable, `DELETE FROM item`)
			// The row in s2 is in sight and out of the write reach.
			wantProbe(t, ctx, tx, "", 0, `UPDATE item SET body = 'x' WHERE scope = 's2'`)
			wantProbe(t, ctx, tx, "", 0, `DELETE FROM item WHERE scope = 's2' RETURNING id`)
			wantProbe(t, ctx, tx, "", 1, insert, "s1")
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, insert, "s2")
		})
		// A write reach that names a scope outside the reach writes nothing
		// there: every write is still bound by the reach.
		s.as(t, ctx, conn, test.role, "s1", "s1,s2", test.principal, func(tx pgx.Tx) {
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, insert, "s2")
			wantProbe(t, ctx, tx, "", 0, `DELETE FROM item WHERE scope = 's2'`)
		})
		// No write reach: the role holds every grant and changes nothing.
		for _, unset := range []string{"", ","} {
			s.as(t, ctx, conn, test.role, "s1,s2", unset, test.principal, func(tx pgx.Tx) {
				if got := bodies(t, ctx, tx, "item"); got != test.reads {
					t.Fatalf("%s with no write reach read %q", name, got)
				}
				wantProbe(t, ctx, tx, "", 0, `UPDATE item SET body = 'x'`)
				wantProbe(t, ctx, tx, "", 0, `DELETE FROM item`)
				wantProbe(t, ctx, tx, insufficientPrivilege, 0, insert, "s1")
			})
		}
	}
}

// Claim 27, unwanted and pinned: the write reach is a setting, so SQL inside a
// write transaction can widen it to the whole reach — and, like the reach
// itself, beyond. It is a floor under statements sent as written, not a fence.
// What cannot be widened this way is a transaction on a read role: there is
// no grant for a rebound setting to unlock.
func TestSpikeWriteReachCanBeReboundBySQL(t *testing.T) {
	s, ctx := openAccessSpike(t), spikeContext(t)
	s.as(t, ctx, s.Connect(t, s.logins["strict_write"]), s.strictWrite, "s1,s2", "s1", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, "", 0, `DELETE FROM item WHERE scope = 's2'`)
		wantProbe(t, ctx, tx, "", 1, `SELECT set_config('codefly.current_write_scopes', 's1,s2', true); DELETE FROM item WHERE scope = 's2'`)
	})
	s.as(t, ctx, s.Connect(t, s.logins["strict_read"]), s.strictRead, "s1,s2", "", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SELECT set_config('codefly.current_write_scopes', 's1,s2', true); DELETE FROM item WHERE scope = 's2'`)
	})
}

// Claim 28: "privileged read, strict write" is two roles on two logins. The
// reader's login assumes privileged_read and sees every principal's rows; the
// writer's login assumes strict_write, where it writes its own rows and reads
// as strict. From the writer's connection no SQL reaches the privileged read,
// and from the reader's no SQL writes.
func TestSpikePrivilegedReadStrictWriteIsTwoRolesOnTwoLogins(t *testing.T) {
	s, ctx := openAccessSpike(t), spikeContext(t)
	s.as(t, ctx, s.Connect(t, s.logins["privileged_read"]), s.privilegedRead, "s1", "", "human:a", func(tx pgx.Tx) {
		if got := bodies(t, ctx, tx, "item"); got != "a-private,b-private,b-shared" {
			t.Fatalf("privileged_read read %q", got)
		}
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `DELETE FROM item`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE `+s.strictWrite)
	})
	s.as(t, ctx, s.Connect(t, s.logins["strict_write"]), s.strictWrite, "s1", "s1", "human:a", func(tx pgx.Tx) {
		// Inside the write transaction, reads are the write role's.
		if got := bodies(t, ctx, tx, "item"); got != "a-private,b-shared" {
			t.Fatalf("strict_write read %q", got)
		}
		wantProbe(t, ctx, tx, "", 1, `UPDATE item SET body = 'x'`)
		wantProbe(t, ctx, tx, "", 0, `UPDATE item SET body = 'x' WHERE principal = 'human:b'`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:b',false)`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE `+s.privilegedRead)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE `+s.privilegedWrite)
	})
}

// Claim 29, unwanted and pinned: a sequence is not a row. A read role granted
// USAGE on one advances it outside READ ONLY, no row policy applies, and the
// change survives the rollback. Without the grant it is refused; in a READ
// ONLY transaction nextval is refused whatever the role holds.
func TestSpikeSequenceUsageLetsAReadRoleChangeState(t *testing.T) {
	s, ctx := openAccessSpike(t), spikeContext(t)
	s.Exec(t, s.Owner, `CREATE SEQUENCE ticket`)
	reader := s.Connect(t, s.logins["strict_read"])
	s.as(t, ctx, reader, s.strictRead, "s1", "", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SELECT nextval('ticket')`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SELECT setval('ticket', 100)`)
	})
	s.Exec(t, s.Owner, `GRANT USAGE ON SEQUENCE ticket TO `+s.strictRead)
	s.as(t, ctx, reader, s.strictRead, "s1", "", "human:a", func(tx pgx.Tx) {
		if got := scalar[int64](t, ctx, tx, `SELECT nextval('ticket')`); got != 1 {
			t.Fatalf("nextval = %d", got)
		}
		// USAGE is nextval and currval; setval needs UPDATE.
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SELECT setval('ticket', 100)`)
	})
	if got := scalar[int64](t, ctx, s.Connect(t, s.Owner), `SELECT last_value FROM ticket`); got != 1 {
		t.Fatalf("after the rollback the sequence is at %d: the read role's nextval was undone", got)
	}
	tx, err := reader.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, accessBind, "t1", "s1", "", "human:a", s.strictRead); err != nil {
		t.Fatal(err)
	}
	wantProbe(t, ctx, tx, readOnlyTransaction, 0, `SELECT nextval('ticket')`)
}
