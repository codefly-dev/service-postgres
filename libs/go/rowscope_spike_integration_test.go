//go:build controlplaneintegration

package postgres_test

// The row-confinement spike: every Postgres behaviour the Binding leans on,
// proved or disproved against a real server, one named test per claim. The
// statements here are written by hand on purpose — this file proves the
// mechanism, and rowscope_integration_test.go then proves the library that
// emits it. A test named "...Can..." or "...Leaks..." pins a behaviour the
// design has to live with, not one it wants.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/service-postgres/libs/go/internal/rowscopefixture"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	insufficientPrivilege = "42501" // permission denied, and a row policy's refusal
	uniqueViolation       = "23505"
	foreignKeyViolation   = "23503"
	invalidParameterValue = "22023"
	readOnlyTransaction   = "25006"
	activeTransaction     = "25001"
)

type spike struct {
	*rowscopefixture.Sandbox
	strict, privileged string
}

// spikeBind is the statement the design proposes, verbatim: four settings and
// the role, all transaction-local, in one round trip.
const spikeBind = `SELECT set_config('codefly.current_tenant_id', $1, true),
       set_config('codefly.current_scopes',    $2, true),
       set_config('codefly.current_principal', $3, true),
       set_config('codefly.current_actor',     $4, true),
       set_config('role',                      $5, true)`

// spikeTableSQL is §4.2 of the design for one table. wholeRowUpdate grants
// UPDATE on every column, so a test can see what the policies alone refuse.
func (s spike) tableSQL(table string, wholeRowUpdate bool) []string {
	roles := s.strict + ", " + s.privileged
	setting := func(name string) string {
		return `(SELECT NULLIF(current_setting('codefly.` + name + `', true), ''))`
	}
	reach := `(SELECT string_to_array(NULLIF(current_setting('codefly.current_scopes', true), ''), ','))::text[]`
	update := `GRANT UPDATE (shared, body) ON ` + table + ` TO ` + roles
	if wholeRowUpdate {
		update = `GRANT UPDATE ON ` + table + ` TO ` + roles
	}
	return []string{
		`CREATE TABLE ` + table + ` (
			id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			tenant text NOT NULL, scope text NOT NULL,
			principal text NOT NULL CHECK (principal ~ '^[a-z]+:.+'),
			shared boolean NOT NULL, body text NOT NULL DEFAULT '')`,
		`ALTER TABLE ` + table + ` ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE ` + table + ` FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY ` + table + `_partition ON ` + table + ` AS RESTRICTIVE FOR ALL TO ` + roles + `
			USING (tenant = ` + setting("current_tenant_id") + `) WITH CHECK (tenant = ` + setting("current_tenant_id") + `)`,
		`CREATE POLICY ` + table + `_reach ON ` + table + ` AS RESTRICTIVE FOR ALL TO ` + roles + `
			USING (scope = ANY (` + reach + `)) WITH CHECK (scope = ANY (` + reach + `))`,
		`CREATE POLICY ` + table + `_strict_read ON ` + table + ` FOR SELECT TO ` + s.strict + `
			USING (shared OR principal = ` + setting("current_principal") + `)`,
		`CREATE POLICY ` + table + `_strict_insert ON ` + table + ` FOR INSERT TO ` + s.strict + `
			WITH CHECK (principal = ` + setting("current_principal") + `)`,
		`CREATE POLICY ` + table + `_strict_modify ON ` + table + ` FOR UPDATE TO ` + s.strict + `
			USING (principal = ` + setting("current_principal") + `) WITH CHECK (principal = ` + setting("current_principal") + `)`,
		`CREATE POLICY ` + table + `_strict_delete ON ` + table + ` FOR DELETE TO ` + s.strict + `
			USING (principal = ` + setting("current_principal") + `)`,
		`CREATE POLICY ` + table + `_privileged ON ` + table + ` FOR ALL TO ` + s.privileged + ` USING (true) WITH CHECK (true)`,
		`GRANT SELECT, INSERT, DELETE ON ` + table + ` TO ` + roles,
		update,
		`CREATE INDEX ON ` + table + ` (tenant, scope, principal)`,
	}
}

// The seed every spike test reads: two partitions, two scopes, two people.
const spikeSeed = `INSERT INTO %s (tenant, scope, principal, shared, body) VALUES
	('t1','s1','human:a',false,'a-private'),
	('t1','s1','human:b',false,'b-private'),
	('t1','s1','human:b',true ,'b-shared'),
	('t1','s2','human:a',false,'a-in-s2'),
	('t2','s1','human:a',false,'a-in-t2')`

// openSpike migrates as the owner and seeds through the fixture principal,
// which is not a superuser: the arrangement a module's suite has.
func openSpike(t *testing.T) spike {
	t.Helper()
	sandbox := rowscopefixture.Open(t)
	s := spike{Sandbox: sandbox, strict: sandbox.Role("strict"), privileged: sandbox.Role("privileged")}
	migration := []string{
		`CREATE ROLE ` + s.strict + ` NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS`,
		`CREATE ROLE ` + s.privileged + ` NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS`,
		`GRANT ` + s.strict + `, ` + s.privileged + ` TO ` + s.Role("rw") + ` WITH INHERIT FALSE, SET TRUE`,
	}
	migration = append(migration, s.tableSQL("item", false)...)
	migration = append(migration, s.tableSQL("item_open", true)...)
	s.Exec(t, s.Owner, migration...)
	s.Exec(t, s.Fixture, fmt.Sprintf(spikeSeed, "item"), fmt.Sprintf(spikeSeed, "item_open"))
	return s
}

func spikeContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// bound runs fn inside one transaction bound the way the design binds it, and
// rolls back.
func bound(t *testing.T, ctx context.Context, conn *pgx.Conn, role, tenant, scopes, principal string, fn func(pgx.Tx)) {
	t.Helper()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, spikeBind, tenant, scopes, principal, "service:spike", role); err != nil {
		t.Fatalf("bind: %v", err)
	}
	fn(tx)
}

func bodies(t *testing.T, ctx context.Context, db interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, table string) string {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT body FROM `+table+` ORDER BY body`)
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	found, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	return strings.Join(found, ",")
}

func sqlState(err error) string {
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		return postgres.Code
	}
	if err == nil {
		return ""
	}
	return "not-a-postgres-error: " + err.Error()
}

// probe runs one statement in a savepoint that is always rolled back, so a
// refusal does not abort the surrounding transaction and a success changes
// nothing. It returns the SQLSTATE ("" for success) and the affected rows.
func probe(t *testing.T, ctx context.Context, tx pgx.Tx, statement string, arguments ...any) (string, int64) {
	t.Helper()
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer savepoint.Rollback(context.Background())
	tag, err := savepoint.Exec(ctx, statement, arguments...)
	return sqlState(err), tag.RowsAffected()
}

func wantProbe(t *testing.T, ctx context.Context, tx pgx.Tx, wantState string, wantRows int64, statement string, arguments ...any) {
	t.Helper()
	state, rows := probe(t, ctx, tx, statement, arguments...)
	if state != wantState || (wantState == "" && rows != wantRows) {
		t.Fatalf("%s\n got SQLSTATE %q, %d rows; want %q, %d rows", statement, state, rows, wantState, wantRows)
	}
}

func scalar[T any](t *testing.T, ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, statement string, arguments ...any) T {
	t.Helper()
	var value T
	if err := db.QueryRow(ctx, statement, arguments...).Scan(&value); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
	return value
}

// Claim: SET LOCAL ROLE and set_config(..., true) end with the transaction,
// committed or rolled back, and `role` is an ordinary parameter of set_config.
func TestSpikeRoleAndSettingsResetAtCommitAndRollback(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	conn := s.Connect(t, s.ReadWrite)
	login := s.Role("rw")

	// Before any use the setting does not exist: missing_ok yields NULL.
	if !scalar[bool](t, ctx, conn, `SELECT current_setting('codefly.current_principal', true) IS NULL`) {
		t.Fatal("a never-set custom setting is not NULL")
	}
	for _, end := range []string{"COMMIT", "ROLLBACK"} {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, spikeBind, "t1", "s1", "human:a", "service:spike", s.strict); err != nil {
			t.Fatal(err)
		}
		if got := scalar[string](t, ctx, tx, `SELECT current_user::text`); got != s.strict {
			t.Fatalf("current_user inside the transaction = %q, want %q", got, s.strict)
		}
		if got := scalar[string](t, ctx, tx, `SELECT session_user::text`); got != login {
			t.Fatalf("session_user inside the transaction = %q, want the login", got)
		}
		if got := bodies(t, ctx, tx, "item"); got != "a-private,b-shared" {
			t.Fatalf("strict rows = %q", got)
		}
		if end == "COMMIT" {
			err = tx.Commit(ctx)
		} else {
			err = tx.Rollback(ctx)
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := scalar[string](t, ctx, conn, `SELECT current_user::text`); got != login {
			t.Fatalf("after %s current_user = %q: the role outlived its transaction", end, got)
		}
		// The pitfall the design names: after one local use the setting reads
		// as the empty string for the life of the connection, not NULL.
		for _, setting := range []string{"codefly.current_tenant_id", "codefly.current_scopes", "codefly.current_principal", "codefly.current_actor"} {
			if got := scalar[*string](t, ctx, conn, `SELECT current_setting($1, true)`, setting); got == nil || *got != "" {
				t.Fatalf("after %s %s = %v, want the empty string", end, setting, got)
			}
		}
		if state, _ := func() (string, int64) {
			_, err := conn.Exec(ctx, `SELECT 1 FROM item`)
			return sqlState(err), 0
		}(); state != insufficientPrivilege {
			t.Fatalf("after %s the bare login read the table: SQLSTATE %q", end, state)
		}
	}
}

// Claim: nothing bound in one transaction is visible to the next borrower of
// the same physical connection, under concurrency, through pgxpool.
func TestSpikeBindingDoesNotLeakAcrossPooledConnections(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	config, err := pgxpool.ParseConfig(s.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	// Two physical connections for sixteen workers: every transaction reuses a
	// connection another binding just left.
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	type identity struct{ role, tenant, scopes, principal, want string }
	identities := []identity{
		{s.strict, "t1", "s1", "human:a", "a-private,b-shared"},
		{s.strict, "t1", "s1", "human:b", "b-private,b-shared"},
		{s.strict, "t1", "s1,s2", "human:a", "a-in-s2,a-private,b-shared"},
		{s.privileged, "t1", "s1", "agent:s1", "a-private,b-private,b-shared"},
		{s.privileged, "t2", "s1", "agent:s1", "a-in-t2"},
		{s.strict, "t2", "s1", "human:b", ""},
	}
	failures := make(chan string, 64)
	var workers sync.WaitGroup
	for worker := range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for round := range 60 {
				// Every third transaction binds nothing at all and must find
				// nothing left behind: no role, no setting, no row.
				if (worker+round)%3 == 0 {
					err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
						var user, tenant, principal string
						if err := tx.QueryRow(ctx, `SELECT current_user::text, coalesce(current_setting('codefly.current_tenant_id', true), ''),
							coalesce(current_setting('codefly.current_principal', true), '')`).Scan(&user, &tenant, &principal); err != nil {
							return err
						}
						if user != s.Role("rw") || tenant != "" || principal != "" {
							return fmt.Errorf("unbound transaction inherited %q/%q/%q", user, tenant, principal)
						}
						return nil
					})
					if err != nil {
						failures <- err.Error()
						return
					}
					continue
				}
				who := identities[(worker*7+round)%len(identities)]
				err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, spikeBind, who.tenant, who.scopes, who.principal, "service:spike", who.role); err != nil {
						return err
					}
					rows, err := tx.Query(ctx, `SELECT body FROM item ORDER BY body`)
					if err != nil {
						return err
					}
					found, err := pgx.CollectRows(rows, pgx.RowTo[string])
					if err != nil {
						return err
					}
					if got := strings.Join(found, ","); got != who.want {
						return fmt.Errorf("%+v read %q", who, got)
					}
					if round%2 == 0 {
						return errors.New("roll back on purpose")
					}
					return nil
				})
				if err != nil && err.Error() != "roll back on purpose" {
					failures <- err.Error()
					return
				}
			}
		}()
	}
	workers.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

// Claim: a login whose memberships do not inherit, and which holds no table
// privilege of its own, is refused every table until it assumes a mode role.
// Both spellings are covered: the role attribute NOINHERIT and the PostgreSQL
// 16 membership option INHERIT FALSE on a login that would otherwise inherit.
func TestSpikeLoginWithoutSetRoleIsDenied(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	inheriting := s.Role("inheriting")
	s.Exec(t, s.Owner,
		`CREATE ROLE `+inheriting+` LOGIN INHERIT NOSUPERUSER NOBYPASSRLS PASSWORD 'isolated-fixture-only'`,
		`GRANT `+s.strict+`, `+s.privileged+` TO `+inheriting+` WITH INHERIT FALSE, SET TRUE`)
	for name, connection := range map[string]string{
		"NOINHERIT login":          s.ReadWrite,
		"INHERIT FALSE membership": strings.Replace(s.ReadWrite, s.Role("rw"), inheriting, 1),
	} {
		conn := s.Connect(t, connection)
		for _, statement := range []string{
			`SELECT * FROM item`,
			`INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:a',false)`,
			`UPDATE item SET body = 'x'`,
			`DELETE FROM item`,
			`TRUNCATE item`,
			`SELECT * FROM item FOR UPDATE`,
			`COPY item TO STDOUT`,
		} {
			if _, err := conn.Exec(ctx, statement); sqlState(err) != insufficientPrivilege {
				t.Fatalf("%s: %s => SQLSTATE %q, want permission denied", name, statement, sqlState(err))
			}
		}
		// And it does reach the table once it assumes the role.
		bound(t, ctx, conn, s.strict, "t1", "s1", "human:a", func(tx pgx.Tx) {
			if got := bodies(t, ctx, tx, "item"); got != "a-private,b-shared" {
				t.Fatalf("%s as strict read %q", name, got)
			}
		})
	}
	// A login that was never granted a mode role cannot assume it.
	stranger := s.Connect(t, s.Login(t, "stranger"))
	tx, err := stranger.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	_, err = tx.Exec(ctx, spikeBind, "t1", "s1", "human:a", "", s.strict)
	if sqlState(err) != insufficientPrivilege {
		t.Fatalf("a login without the membership assumed the role: SQLSTATE %q", sqlState(err))
	}
	t.Logf("set_config('role') without membership: %v", err)
}

// Claim: a policy written TO a role binds that role only, and a role with a
// table privilege but no policy reads nothing (default deny).
func TestSpikePoliciesApplyOnlyUnderTheirRole(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	other := s.Role("maintenance")
	s.Exec(t, s.Owner,
		`CREATE ROLE `+other+` NOLOGIN NOINHERIT`,
		`GRANT `+other+` TO `+s.Role("rw")+` WITH INHERIT FALSE, SET TRUE`,
		`GRANT SELECT, INSERT ON item TO `+other)
	conn := s.Connect(t, s.ReadWrite)
	bound(t, ctx, conn, s.strict, "t1", "s1", "human:a", func(tx pgx.Tx) {
		if got := bodies(t, ctx, tx, "item"); got != "a-private,b-shared" {
			t.Fatalf("strict read %q", got)
		}
	})
	bound(t, ctx, conn, s.privileged, "t1", "s1", "human:a", func(tx pgx.Tx) {
		// The strict policies do not narrow the privileged role.
		if got := bodies(t, ctx, tx, "item"); got != "a-private,b-private,b-shared" {
			t.Fatalf("privileged read %q", got)
		}
	})
	bound(t, ctx, conn, other, "t1", "s1", "human:a", func(tx pgx.Tx) {
		// Granted SELECT, bound to a real partition, named in no policy.
		if got := bodies(t, ctx, tx, "item"); got != "" {
			t.Fatalf("a role with no policy read %q", got)
		}
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:a',false)`)
	})
}

// Claim: without FORCE the table owner is not bound by its own policies; with
// FORCE it is, and since no policy names it, it reads nothing.
func TestSpikeForceBindsTheTableOwner(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	owner := s.Connect(t, s.Owner)
	if got := bodies(t, ctx, owner, "item"); got != "" {
		t.Fatalf("the owner read %q through FORCE", got)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:a',false)`); sqlState(err) != insufficientPrivilege {
		t.Fatalf("the owner wrote through FORCE: SQLSTATE %q", sqlState(err))
	}
	if _, err := owner.Exec(ctx, `ALTER TABLE item NO FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if got := bodies(t, ctx, owner, "item"); got != "a-in-s2,a-in-t2,a-private,b-private,b-shared" {
		t.Fatalf("without FORCE the owner read %q, want every row", got)
	}
	// The owner can always lift FORCE again: FORCE binds its queries, not its DDL.
}

// Claim: an unset or empty setting is NULL in the policy, NULL is not true,
// and so a transaction that assumed a role and bound nothing reads no row and
// may insert none.
func TestSpikeUnsetSettingFailsClosed(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	for _, role := range []string{s.strict, s.privileged} {
		// A fresh connection: the settings have never existed on it.
		conn := s.Connect(t, s.ReadWrite)
		for _, pass := range []string{"never set", "set once then empty"} {
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('role', $1, true)`, role); err != nil {
				t.Fatal(err)
			}
			if got := bodies(t, ctx, tx, "item"); got != "" {
				t.Fatalf("%s, %s: an unbound transaction read %q", role, pass, got)
			}
			wantProbe(t, ctx, tx, insufficientPrivilege, 0, `INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:a',false)`)
			wantProbe(t, ctx, tx, "", 0, `UPDATE item SET body = 'x'`)
			wantProbe(t, ctx, tx, "", 0, `DELETE FROM item`)
			_ = tx.Rollback(ctx)
			// Use the settings once so the second pass sees '' instead of NULL.
			bound(t, ctx, conn, role, "t1", "s1", "human:a", func(pgx.Tx) {})
		}
		// Each value missing on its own is enough to close the table.
		for _, partial := range [][3]string{{"", "s1", "human:a"}, {"t1", "", "human:a"}} {
			bound(t, ctx, conn, role, partial[0], partial[1], partial[2], func(tx pgx.Tx) {
				if got := bodies(t, ctx, tx, "item"); got != "" {
					t.Fatalf("%s with %v read %q", role, partial, got)
				}
			})
		}
	}
	// Strict with no principal still reads shared rows: shared means shared
	// with the scope, and the wall and the reach are bound.
	conn := s.Connect(t, s.ReadWrite)
	bound(t, ctx, conn, s.strict, "t1", "s1", "", func(tx pgx.Tx) {
		if got := bodies(t, ctx, tx, "item"); got != "b-shared" {
			t.Fatalf("strict with no principal read %q", got)
		}
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:a',false)`)
		wantProbe(t, ctx, tx, "", 0, `UPDATE item SET body = 'x'`)
	})
}

// Claim: under strict, WITH CHECK refuses a row stamped with another
// principal, another scope or another partition, on insert and on update.
// item_open grants UPDATE on every column, so the policies are what refuses.
func TestSpikeStrictWithCheckRefusesForeignRows(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	conn := s.Connect(t, s.ReadWrite)
	bound(t, ctx, conn, s.strict, "t1", "s1", "human:a", func(tx pgx.Tx) {
		insert := `INSERT INTO item_open (tenant, scope, principal, shared) VALUES ($1,$2,$3,false)`
		wantProbe(t, ctx, tx, "", 1, insert, "t1", "s1", "human:a")
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, insert, "t1", "s1", "human:b") // another principal
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, insert, "t1", "s2", "human:a") // a scope out of reach
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, insert, "t2", "s1", "human:a") // another partition
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, insert, "t1", "s1", "")        // the CHECK constraint is never reached

		// Update: only its own row is a candidate at all, and it may not leave.
		wantProbe(t, ctx, tx, "", 1, `UPDATE item_open SET body = 'mine'`)
		wantProbe(t, ctx, tx, "", 0, `UPDATE item_open SET body = 'x' WHERE body = 'b-shared'`) // readable, not writable
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `UPDATE item_open SET principal = 'human:b'`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `UPDATE item_open SET scope = 's2'`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `UPDATE item_open SET tenant = 't2'`)
		wantProbe(t, ctx, tx, "", 1, `DELETE FROM item_open`)

		// On the real shape the column grant refuses first, whatever the value.
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `UPDATE item SET principal = 'human:a'`)
	})
}

// Claim: under privileged, the policies stop a row leaving the partition or
// the reach — and that is all they stop. Moving a row between two scopes that
// are both in reach, or re-stamping its principal, passes every policy; what
// refuses it is the missing column privilege.
func TestSpikePrivilegedCannotMoveScopeOrPrincipal(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	conn := s.Connect(t, s.ReadWrite)
	bound(t, ctx, conn, s.privileged, "t1", "s1", "agent:s1", func(tx pgx.Tx) {
		// Policy alone, one scope in reach.
		wantProbe(t, ctx, tx, "", 3, `UPDATE item_open SET body = 'seen'`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `UPDATE item_open SET scope = 's2'`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `UPDATE item_open SET tenant = 't2'`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `INSERT INTO item_open (tenant, scope, principal, shared) VALUES ('t1','s2','human:a',false)`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `INSERT INTO item_open (tenant, scope, principal, shared) VALUES ('t2','s1','human:a',false)`)
		// A derived row stamped with another principal is allowed by design.
		wantProbe(t, ctx, tx, "", 1, `INSERT INTO item_open (tenant, scope, principal, shared) VALUES ('t1','s1','human:b',false)`)
		// DISPROVED as a policy guarantee: the principal changes freely.
		wantProbe(t, ctx, tx, "", 3, `UPDATE item_open SET principal = 'human:zed'`)
	})
	bound(t, ctx, conn, s.privileged, "t1", "s1,s2", "agent:s1", func(tx pgx.Tx) {
		// DISPROVED as a policy guarantee: both scopes are in reach, so the move passes.
		wantProbe(t, ctx, tx, "", 3, `UPDATE item_open SET scope = 's2' WHERE scope = 's1'`)
		// The column grant is the guarantee, and it holds in reach or out.
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `UPDATE item SET scope = 's2' WHERE scope = 's1'`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `UPDATE item SET principal = 'human:zed'`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `UPDATE item SET tenant = 't1'`)
		wantProbe(t, ctx, tx, "", 4, `UPDATE item SET body = 'seen'`)
		// DELETE then INSERT is a move the column grant cannot see. It stays
		// inside the reach, and the audited transfer is the only other path.
		wantProbe(t, ctx, tx, "", 1, `WITH gone AS (DELETE FROM item WHERE body = 'a-private' RETURNING tenant, shared, body)
			INSERT INTO item (tenant, scope, principal, shared, body) SELECT tenant, 's2', 'human:zed', shared, body FROM gone`)
	})
}

// Claim: an empty reach reaches nothing, in both modes, for every verb.
func TestSpikeEmptyReachReachesNothing(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	conn := s.Connect(t, s.ReadWrite)
	for _, role := range []string{s.strict, s.privileged} {
		// "," is what a careless join of two empty ids would produce.
		for _, scopes := range []string{"", ",", "s9"} {
			bound(t, ctx, conn, role, "t1", scopes, "human:a", func(tx pgx.Tx) {
				if got := bodies(t, ctx, tx, "item"); got != "" {
					t.Fatalf("%s with reach %q read %q", role, scopes, got)
				}
				wantProbe(t, ctx, tx, insufficientPrivilege, 0, `INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:a',false)`)
				wantProbe(t, ctx, tx, "", 0, `UPDATE item SET body = 'x'`)
				wantProbe(t, ctx, tx, "", 0, `DELETE FROM item`)
			})
		}
	}
	// What "," does reach: a row whose scope is the empty string. The row
	// shape must refuse an empty scope, and the library an empty reach entry.
	s.Exec(t, s.Fixture, `INSERT INTO item (tenant, scope, principal, shared, body) VALUES ('t1','','human:a',true,'empty-scope')`)
	bound(t, ctx, conn, s.privileged, "t1", ",", "human:a", func(tx pgx.Tx) {
		if got := bodies(t, ctx, tx, "item"); got != "empty-scope" {
			t.Fatalf("reach \",\" read %q, want the empty-scope row", got)
		}
	})
}

// Claim (caveat): BYPASSRLS and superuser ignore every policy, FORCE or not —
// but the attribute is the current role's, so even they are bound once they
// assume a mode role.
func TestSpikeBypassRLSAndSuperuserCaveats(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	every := "a-in-s2,a-in-t2,a-private,b-private,b-shared"
	for name, connection := range map[string]string{"fixture principal (BYPASSRLS)": s.Fixture, "superuser": s.Admin} {
		conn := s.Connect(t, connection)
		if got := bodies(t, ctx, conn, "item"); got != every {
			t.Fatalf("%s read %q, want every row", name, got)
		}
		// Arranged as the bypassing login, asserted as the mode role.
		if _, err := conn.Exec(ctx, `GRANT `+s.strict+` TO CURRENT_USER WITH INHERIT FALSE, SET TRUE`); err != nil && name == "superuser" {
			t.Fatal(err)
		}
		bound(t, ctx, conn, s.strict, "t1", "s1", "human:a", func(tx pgx.Tx) {
			if got := bodies(t, ctx, tx, "item"); got != "a-private,b-shared" {
				t.Fatalf("%s as strict read %q: a bypass survived SET ROLE", name, got)
			}
		})
	}
	// row_security = off never widens a bound role: it turns a filtered query
	// into an error (which is what pg_dump relies on).
	conn := s.Connect(t, s.ReadWrite)
	bound(t, ctx, conn, s.strict, "t1", "s1", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, "", 0, `SET LOCAL row_security = off`)
		if _, err := tx.Exec(ctx, `SET LOCAL row_security = off`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT * FROM item`); sqlState(err) != insufficientPrivilege {
			t.Fatalf("row_security=off under strict: SQLSTATE %q", sqlState(err))
		}
	})
}

// Claim: with each setting read as (SELECT ...), the policy is an InitPlan
// evaluated once and the (tenant, scope, principal) index serves it.
func TestSpikeInitPlanAndIndexAreUsed(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	s.Exec(t, s.Fixture,
		`INSERT INTO item (tenant, scope, principal, shared, body)
		 SELECT 't' || (n % 40), 's' || (n % 25), 'human:' || (n % 500), n % 10 = 0, 'bulk'
		 FROM generate_series(1, 60000) AS n`)
	s.Exec(t, s.Owner, `ANALYZE item`)
	conn := s.Connect(t, s.ReadWrite)
	explain := func(tx pgx.Tx, statement string) string {
		rows, err := tx.Query(ctx, `EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF) `+statement)
		if err != nil {
			t.Fatal(err)
		}
		lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(lines, "\n")
	}
	bound(t, ctx, conn, s.privileged, "t1", "s1,s2", "agent:s1", func(tx pgx.Tx) {
		plan := explain(tx, `SELECT * FROM item`)
		t.Logf("privileged, SELECT * FROM item:\n%s", plan)
		if !strings.Contains(plan, "InitPlan") || !strings.Contains(plan, "item_tenant_scope_principal_idx") {
			t.Fatal("the privileged plan lacks the InitPlan or the index")
		}
		if strings.Contains(plan, "Seq Scan") {
			t.Fatal("the privileged plan scans the table")
		}
	})
	bound(t, ctx, conn, s.strict, "t1", "s1", "human:7", func(tx pgx.Tx) {
		plan := explain(tx, `SELECT * FROM item`)
		t.Logf("strict, SELECT * FROM item:\n%s", plan)
		if !strings.Contains(plan, "InitPlan") || !strings.Contains(plan, "item_tenant_scope_principal_idx") || strings.Contains(plan, "Seq Scan") {
			t.Fatal("the strict plan lacks the InitPlan or the index")
		}
		// (shared OR principal = me) is not an index condition on principal:
		// the index narrows to partition and scope, and the rest is a filter.
		if !strings.Contains(plan, "Filter:") {
			t.Fatal("expected the strict read predicate as a filter")
		}
		// A caller that adds its own principal equality gets all three columns.
		own := explain(tx, `SELECT * FROM item WHERE principal = 'human:7'`)
		t.Logf("strict, own rows only:\n%s", own)
		if !strings.Contains(own, "principal = 'human:7'") || strings.Contains(own, "Seq Scan") {
			t.Fatal("the principal equality did not reach the index")
		}
	})
}

// Claim (side channel): uniqueness and foreign keys are checked against rows
// the caller cannot see. This test pins exactly what that reveals.
func TestSpikeUniqueAndForeignKeyLeaks(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	roles := s.strict + ", " + s.privileged
	s.Exec(t, s.Owner,
		// Three uniqueness shapes on the same row.
		`ALTER TABLE item ADD COLUMN global_key text, ADD COLUMN scope_key text, ADD COLUMN own_key text`,
		`CREATE UNIQUE INDEX item_global ON item (global_key)`,
		`CREATE UNIQUE INDEX item_scope ON item (tenant, scope, scope_key)`,
		`CREATE UNIQUE INDEX item_own ON item (tenant, scope, principal, own_key)`,
		// A child whose foreign key names only the parent's id.
		`CREATE TABLE note (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, item_id bigint NOT NULL REFERENCES item (id),
			tenant text NOT NULL, scope text NOT NULL, principal text NOT NULL, shared boolean NOT NULL)`,
		`ALTER TABLE note ENABLE ROW LEVEL SECURITY`, `ALTER TABLE note FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY note_all ON note FOR ALL TO `+roles+` USING (true) WITH CHECK (true)`,
		`GRANT SELECT, INSERT, DELETE ON note TO `+roles)
	s.Exec(t, s.Fixture, `UPDATE item SET global_key = 'k', scope_key = 'k', own_key = 'k' WHERE body = 'b-private'`)
	bPrivate := scalar[int64](t, ctx, s.Connect(t, s.Fixture), `SELECT id FROM item WHERE body = 'b-private'`)

	conn := s.Connect(t, s.ReadWrite)
	insert := func(column string) string {
		return `INSERT INTO item (tenant, scope, principal, shared, ` + column + `) VALUES ($1, $2, 'human:a', false, 'k')`
	}
	// human:a cannot see b-private, in the same scope.
	bound(t, ctx, conn, s.strict, "t1", "s1", "human:a", func(tx pgx.Tx) {
		// LEAK: a key unique across the table tells a caller that some row,
		// anywhere, holds it — and the error detail repeats the key.
		wantProbe(t, ctx, tx, uniqueViolation, 0, insert("global_key"), "t1", "s1")
		// LEAK, within one scope: another principal's key in the same scope.
		wantProbe(t, ctx, tx, uniqueViolation, 0, insert("scope_key"), "t1", "s1")
		// No leak: the index leads with the principal, so there is no collision.
		wantProbe(t, ctx, tx, "", 1, insert("own_key"), "t1", "s1")
		// ON CONFLICT DO NOTHING turns the same leak into a silent zero.
		wantProbe(t, ctx, tx, "", 0, insert("scope_key")+` ON CONFLICT DO NOTHING`, "t1", "s1")
		// LEAK: a foreign key to an invisible row succeeds, a missing id fails.
		// The caller learns the id exists and attaches its row to another's.
		note := `INSERT INTO note (item_id, tenant, scope, principal, shared) VALUES ($1, 't1', 's1', 'human:a', false)`
		wantProbe(t, ctx, tx, "", 1, note, bPrivate)
		wantProbe(t, ctx, tx, foreignKeyViolation, 0, note, int64(999999999))
	})
	// From another scope or partition the row check refuses before the index
	// is consulted, so a scope-led key reveals nothing across the wall.
	bound(t, ctx, conn, s.strict, "t1", "s2", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, insert("scope_key"), "t1", "s1") // aimed at the foreign scope
		wantProbe(t, ctx, tx, "", 1, insert("scope_key"), "t1", "s2")                    // same key, own scope
		wantProbe(t, ctx, tx, uniqueViolation, 0, insert("global_key"), "t1", "s2")      // the global key still leaks
	})
	bound(t, ctx, conn, s.strict, "t2", "s1", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, insert("scope_key"), "t1", "s1")
		wantProbe(t, ctx, tx, "", 1, insert("scope_key"), "t2", "s1")
		wantProbe(t, ctx, tx, uniqueViolation, 0, insert("global_key"), "t2", "s1")
	})
}

// Claim: the binding holds through savepoints. What a savepoint adds is rolled
// back with it; what it releases stays until the transaction ends.
func TestSpikeSavepointsKeepTheBinding(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	conn := s.Connect(t, s.ReadWrite)
	bound(t, ctx, conn, s.strict, "t1", "s1", "human:a", func(tx pgx.Tx) {
		exec := func(statement string, arguments ...any) {
			t.Helper()
			if _, err := tx.Exec(ctx, statement, arguments...); err != nil {
				t.Fatalf("%s: %v", statement, err)
			}
		}
		who := func() string {
			return scalar[string](t, ctx, tx, `SELECT current_user::text || '/' || current_setting('codefly.current_principal', true)`)
		}
		exec(`SAVEPOINT one`)
		if got := who(); got != s.strict+"/human:a" {
			t.Fatalf("inside a savepoint: %q", got)
		}
		// A statement that fails inside the savepoint does not lose the binding.
		if _, err := tx.Exec(ctx, `SELECT 1/0`); err == nil {
			t.Fatal("expected a failure")
		}
		exec(`ROLLBACK TO SAVEPOINT one`)
		if got := who(); got != s.strict+"/human:a" {
			t.Fatalf("after a failed savepoint: %q", got)
		}
		// A change made inside a savepoint is undone by rolling it back...
		exec(`SAVEPOINT two`)
		exec(`SELECT set_config('codefly.current_principal', 'human:b', true), set_config('role', $1, true)`, s.privileged)
		if got := who(); got != s.privileged+"/human:b" {
			t.Fatalf("inside the widening savepoint: %q", got)
		}
		exec(`ROLLBACK TO SAVEPOINT two`)
		if got := who(); got != s.strict+"/human:a" {
			t.Fatalf("after rolling the widening back: %q", got)
		}
		// ...and kept, for the rest of the transaction, by releasing it.
		exec(`SAVEPOINT three`)
		exec(`SELECT set_config('codefly.current_principal', 'human:b', true)`)
		exec(`RELEASE SAVEPOINT three`)
		if got := who(); got != s.strict+"/human:b" {
			t.Fatalf("after releasing a rebinding savepoint: %q", got)
		}
	})
	if got := scalar[string](t, ctx, conn, `SELECT current_user::text || '/' || current_setting('codefly.current_principal', true)`); got != s.Role("rw")+"/" {
		t.Fatalf("after the transaction: %q", got)
	}
}

// Claim: the READ ONLY a reader transaction begins with cannot be lifted by
// SQL inside it once the binding statement has run.
func TestSpikeReadOnlyTransactionCannotBeMadeWritable(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	conn := s.Connect(t, s.ReadWrite)
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, spikeBind, "t1", "s1", "human:a", "", s.strict); err != nil {
		t.Fatal(err)
	}
	wantProbe(t, ctx, tx, readOnlyTransaction, 0, `UPDATE item SET body = 'x'`)
	for _, statement := range []string{`SET TRANSACTION READ WRITE`, `SET LOCAL transaction_read_only = off`, `SELECT set_config('transaction_read_only', 'off', true)`} {
		state, _ := probe(t, ctx, tx, statement)
		if state != activeTransaction {
			t.Fatalf("%s => SQLSTATE %q, want %q", statement, state, activeTransaction)
		}
	}
	wantProbe(t, ctx, tx, readOnlyTransaction, 0, `UPDATE item SET body = 'x'`)
}

// Claim: binding and one statement travel as one pgx batch in one implicit
// transaction, so a single-statement read costs no extra round trip, and
// nothing is left on the connection afterwards.
func TestSpikeBindAndQueryInOneBatch(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	conn := s.Connect(t, s.ReadWrite)
	batch := &pgx.Batch{}
	batch.Queue(spikeBind, "t1", "s1", "human:a", "", s.strict)
	batch.Queue(`SELECT string_agg(body, ',' ORDER BY body) FROM item`)
	results := conn.SendBatch(ctx, batch)
	if _, err := results.Exec(); err != nil {
		t.Fatal(err)
	}
	var found string
	if err := results.QueryRow().Scan(&found); err != nil {
		t.Fatal(err)
	}
	if err := results.Close(); err != nil {
		t.Fatal(err)
	}
	if found != "a-private,b-shared" {
		t.Fatalf("batch read %q", found)
	}
	if got := scalar[string](t, ctx, conn, `SELECT current_user::text || '/' || current_setting('codefly.current_principal', true)`); got != s.Role("rw")+"/" {
		t.Fatalf("after the batch: %q", got)
	}
}

// THE CRITICAL CLAIM. Can SQL that runs inside a strict transaction escape it?
//
// Yes, two ways, and one of them cannot be closed in Postgres:
//
//  1. SET ROLE is checked against the session's login, not the current role.
//     A login that may SET both mode roles can go from strict to privileged
//     in the middle of a strict transaction. A login granted strict alone
//     cannot: that is a catalog fact, and the only real fence on the mode.
//  2. set_config is unprivileged. Any SQL the role runs can rebind the
//     principal, the reach or the partition, whatever the login is.
//
// RESET ROLE itself gains nothing: it lands on the login, which holds no
// table privilege.
func TestSpikeSQLInsideTheTransactionCanEscapeStrict(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	both := s.Connect(t, s.ReadWrite)

	bound(t, ctx, both, s.strict, "t1", "s1", "human:a", func(tx pgx.Tx) {
		// RESET ROLE: back to the login, and the table is closed.
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `RESET ROLE; SELECT * FROM item`)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE NONE; SELECT * FROM item`)
		// The strict role cannot become anything it likes...
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE `+s.Role("owner"))
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET SESSION AUTHORIZATION `+s.Role("owner"))
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `GRANT `+s.privileged+` TO `+s.strict)
		// ...but it can become privileged, because its LOGIN may.
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+s.privileged); err != nil {
			t.Fatalf("expected the escape to succeed on a login holding both roles: %v", err)
		}
		if got := bodies(t, ctx, tx, "item"); got != "a-private,b-private,b-shared" {
			t.Fatalf("after SET ROLE privileged, read %q", got)
		}
	})

	// Mitigation for (1): a login that was granted the strict role alone.
	strictOnly := s.Login(t, "people")
	s.Exec(t, s.Owner, `GRANT `+s.strict+` TO `+s.Role("people")+` WITH INHERIT FALSE, SET TRUE`)
	people := s.Connect(t, strictOnly)
	bound(t, ctx, people, s.strict, "t1", "s1", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE `+s.privileged)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SELECT set_config('role', $1, true)`, s.privileged)
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `RESET ROLE; SET ROLE `+s.privileged)
		if got := bodies(t, ctx, tx, "item"); got != "a-private,b-shared" {
			t.Fatalf("strict-only login read %q", got)
		}

		// (2) holds for every login: the settings are the caller's to rewrite.
		if _, err := tx.Exec(ctx, `SELECT set_config('codefly.current_principal', 'human:b', true)`); err != nil {
			t.Fatal(err)
		}
		if got := bodies(t, ctx, tx, "item"); got != "b-private,b-shared" {
			t.Fatalf("after rebinding the principal, read %q", got)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('codefly.current_tenant_id', 't2', true), set_config('codefly.current_principal', 'human:a', true)`); err != nil {
			t.Fatal(err)
		}
		if got := bodies(t, ctx, tx, "item"); got != "a-in-t2" {
			t.Fatalf("after rebinding the partition, read %q", got)
		}
	})

	// The other membership shape: INHERIT TRUE, SET FALSE. The login IS strict
	// — there is no role to set or reset, and no way to privileged — but it
	// then holds table privileges itself, so skipping the Store reads zero
	// rows instead of being refused.
	fixed := s.Login(t, "fixed")
	s.Exec(t, s.Owner, `GRANT `+s.strict+` TO `+s.Role("fixed")+` WITH INHERIT TRUE, SET FALSE`)
	pinned := s.Connect(t, fixed)
	if got := bodies(t, ctx, pinned, "item"); got != "" {
		t.Fatalf("an inheriting login with nothing bound read %q", got)
	}
	tx, err := pinned.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE `+s.strict)
	wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SET LOCAL ROLE `+s.privileged)
	if _, err := tx.Exec(ctx, `SELECT set_config('codefly.current_tenant_id', 't1', true), set_config('codefly.current_scopes', 's1', true), set_config('codefly.current_principal', 'human:a', true)`); err != nil {
		t.Fatal(err)
	}
	if got := bodies(t, ctx, tx, "item"); got != "a-private,b-shared" {
		t.Fatalf("an inheriting strict login read %q", got)
	}
}

// What the refusal of an unknown or ungranted role looks like, so the library
// can name it ErrModeNotGranted.
func TestSpikeAssumingAnUngrantedOrMissingRole(t *testing.T) {
	s, ctx := openSpike(t), spikeContext(t)
	conn := s.Connect(t, s.ReadWrite)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	wantProbe(t, ctx, tx, insufficientPrivilege, 0, `SELECT set_config('role', $1, true)`, s.Role("owner"))
	wantProbe(t, ctx, tx, invalidParameterValue, 0, `SELECT set_config('role', $1, true)`, s.Role("no_such_role"))
	// "none" is not a role: it is RESET ROLE, and it succeeds.
	wantProbe(t, ctx, tx, "", 1, `SELECT set_config('role', 'none', true)`)
}
