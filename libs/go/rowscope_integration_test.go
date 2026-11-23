//go:build controlplaneintegration

package postgres_test

// The Store against a real server, on a table package rowscope protected, with
// the principals a Codefly Postgres run hands a test: a migration owner and a
// fixture principal that are not superusers, and the runtime logins.

import (
	"context"
	"errors"
	"strings"
	"testing"

	postgres "github.com/codefly-dev/service-postgres/libs/go"
	"github.com/codefly-dev/service-postgres/libs/go/internal/rowscopefixture"
	"github.com/codefly-dev/service-postgres/libs/go/rowscope"
	"github.com/jackc/pgx/v5"
)

const rowScopeSeed = `INSERT INTO item (tenant, scope, principal, shared, body) VALUES
	('t1','s1','human:a',false,'a-private'),
	('t1','s1','human:b',false,'b-private'),
	('t1','s1','human:b',true ,'b-shared'),
	('t1','s2','human:a',false,'a-in-s2'),
	('t2','s1','human:a',false,'a-in-t2')`

func openRowScopeStore(t *testing.T, sandbox *rowscopefixture.Sandbox, binding postgres.Binding, roles postgres.Roles) *postgres.Store {
	t.Helper()
	store, closeStore, err := postgres.OpenStore(spikeContext(t), sandbox.ReadOnly, sandbox.ReadWrite, postgres.FixedBinder(binding), roles)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeStore)
	return store
}

func readBodies(t *testing.T, store *postgres.Store) string {
	t.Helper()
	var found string
	if err := store.Read(spikeContext(t), func(ctx context.Context, tx postgres.ReadTx) error {
		found = bodies(t, ctx, tx, "item")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return found
}

func TestRowScopeStoreBindsEachModeOnTheRuntimeLogins(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	sandbox.Migrate(t, "item")
	sandbox.Exec(t, sandbox.Fixture, rowScopeSeed)
	ctx := spikeContext(t)

	dana := postgres.Binding{Partition: "t1", Principal: "human:a", Reach: []string{"s1"}, Mode: postgres.Strict, Actor: "service:wiki"}
	strict := openRowScopeStore(t, sandbox, dana, sandbox.Roles())
	if got := readBodies(t, strict); got != "a-private,b-shared" {
		t.Fatalf("strict read %q", got)
	}
	installation := postgres.Binding{Partition: "t1", Principal: "agent:s1", Reach: []string{"s1"}, Mode: postgres.Privileged}
	privileged := openRowScopeStore(t, sandbox, installation, sandbox.Roles())
	if got := readBodies(t, privileged); got != "a-private,b-private,b-shared" {
		t.Fatalf("privileged read %q", got)
	}

	// What a transaction can see of its own binding: the role, the actor for
	// audit, and the existing user setting with its existing bare value.
	if err := strict.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
		got := scalar[string](t, ctx, tx, `SELECT concat_ws('|', current_user, session_user, current_setting('codefly.current_actor'),
			current_setting('codefly.current_user_id'), current_setting('codefly.current_principal'), current_setting('codefly.current_scopes'))`)
		want := strings.Join([]string{sandbox.Role("strict_write"), sandbox.Role("rw"), "service:wiki", "a", "human:a", "s1"}, "|")
		if got != want {
			t.Fatalf("binding inside the transaction = %q, want %q", got, want)
		}
		// Its own row, stamped by the caller and checked by the database.
		if _, err := tx.Exec(ctx, `INSERT INTO item (tenant, scope, principal, shared, body) VALUES ('t1','s1','human:a',false,'a-new')`); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE item SET body = body || '!' `)
		if err != nil || tag.RowsAffected() != 2 {
			t.Fatalf("strict updated %d rows (%v), want its own two", tag.RowsAffected(), err)
		}
		return tx.ScopedAdvisoryLock(ctx, "item", "a-new")
	}); err != nil {
		t.Fatal(err)
	}
	for statement, state := range map[string]string{
		`INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:b',false)`: insufficientPrivilege,
		`INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s2','human:a',false)`: insufficientPrivilege,
		`UPDATE item SET principal = 'human:a'`:                                                  insufficientPrivilege,
		`TRUNCATE item`:                                                                          insufficientPrivilege,
	} {
		err := strict.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
			_, err := tx.Exec(ctx, statement)
			return err
		})
		if sqlState(err) != state {
			t.Fatalf("%s => %v, want SQLSTATE %s", statement, err, state)
		}
	}
	// A refused or failed transaction left nothing behind, and neither did the
	// committed one outside what it may write.
	if got := bodies(t, ctx, sandbox.Connect(t, sandbox.Fixture), "item"); got != "a-in-s2,a-in-t2,a-new!,a-private!,b-private,b-shared" {
		t.Fatalf("the table holds %q", got)
	}

	// A binding that may not write gets no writer, on a login that could.
	dana.ReadOnly = true
	if err := openRowScopeStore(t, sandbox, dana, sandbox.Roles()).Write(ctx, func(context.Context, postgres.WriteTx) error { return nil }); !errors.Is(err, postgres.ErrReadOnly) {
		t.Fatalf("read-only binding: %v", err)
	}
}

func TestRowScopeModeIsFencedByTheLoginsMembership(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	sandbox.Migrate(t, "item")
	sandbox.Exec(t, sandbox.Fixture, rowScopeSeed)
	ctx := spikeContext(t)
	// A process that serves people: its logins are granted the strict roles
	// alone, the reader's the read one and the writer's the write one.
	peopleRO, peopleRW := sandbox.Login(t, "people_ro"), sandbox.Login(t, "people_rw")
	grant, err := rowscope.Bootstrap(postgres.Roles{StrictRead: sandbox.Role("strict_read"), StrictWrite: sandbox.Role("strict_write")},
		rowscope.Logins{StrictRead: []string{sandbox.Role("people_ro")}, StrictWrite: []string{sandbox.Role("people_rw")}})
	if err != nil {
		t.Fatal(err)
	}
	sandbox.Exec(t, sandbox.Owner, rowscope.Script(grant))

	installation := postgres.Binding{Partition: "t1", Principal: "agent:s1", Reach: []string{"s1"}, Mode: postgres.Privileged}
	// Even a Store misconfigured to name the privileged role cannot assume it.
	store, closeStore, err := postgres.OpenStore(ctx, peopleRO, peopleRW, postgres.FixedBinder(installation), sandbox.Roles())
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore()
	err = store.Read(ctx, func(context.Context, postgres.ReadTx) error {
		t.Fatal("a strict-only login ran a privileged transaction")
		return nil
	})
	if !errors.Is(err, postgres.ErrModeNotGranted) || !errors.Is(err, postgres.ErrUnauthorized) {
		t.Fatalf("privileged on a strict-only login: %v, want ErrModeNotGranted", err)
	}
	if err := store.Write(ctx, func(context.Context, postgres.WriteTx) error { return nil }); !errors.Is(err, postgres.ErrModeNotGranted) {
		t.Fatalf("a privileged write on a strict-only login: %v, want ErrModeNotGranted", err)
	}
	// A role that does not exist is the same refusal.
	missing, closeMissing, err := postgres.OpenStore(ctx, peopleRO, peopleRW, postgres.FixedBinder(installation),
		postgres.Roles{Privileged: sandbox.Role("no_such_role")})
	if err != nil {
		t.Fatal(err)
	}
	defer closeMissing()
	if err := missing.Read(ctx, func(context.Context, postgres.ReadTx) error { return nil }); !errors.Is(err, postgres.ErrModeNotGranted) {
		t.Fatalf("a role that does not exist: %v, want ErrModeNotGranted", err)
	}
	// And a connection that would start as a role is refused at open.
	if _, _, err := postgres.OpenStore(ctx, peopleRO, peopleRW+"?role="+sandbox.Role("strict_write"), postgres.FixedBinder(installation), sandbox.Roles()); err == nil {
		t.Fatal("a store connection with a startup role was accepted")
	}
}

func TestRowScopeProtectIsIdempotentAndLeavesOtherRolesAlone(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	table := sandbox.Migrate(t, "item")[0]
	sandbox.Exec(t, sandbox.Fixture, rowScopeSeed)
	ctx := spikeContext(t)
	// A maintenance role with its own grant and policy, as a module writes it.
	maintenance := sandbox.Role("retention")
	sandbox.Exec(t, sandbox.Owner,
		`CREATE ROLE `+maintenance+` NOLOGIN NOINHERIT`,
		`GRANT SELECT, DELETE ON item TO `+maintenance,
		`CREATE POLICY retention ON item FOR ALL TO `+maintenance+` USING (true)`)
	// A later migration makes one fewer column mutable and protects again.
	table.Mutable = []string{"body"}
	for range 2 {
		again, err := rowscope.Protect(table, sandbox.Roles(), rowscope.DefaultSettings())
		if err != nil {
			t.Fatal(err)
		}
		sandbox.Exec(t, sandbox.Owner, rowscope.Script(again))
	}
	store := openRowScopeStore(t, sandbox, postgres.Binding{Partition: "t1", Principal: "human:a", Reach: []string{"s1"}, Mode: postgres.Strict}, sandbox.Roles())
	for statement, state := range map[string]string{`UPDATE item SET body = 'x'`: "", `UPDATE item SET shared = true`: insufficientPrivilege} {
		err := store.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
			_, err := tx.Exec(ctx, statement)
			return err
		})
		if sqlState(err) != state {
			t.Fatalf("%s => %v, want SQLSTATE %q", statement, err, state)
		}
	}

	// The maintenance connection: a separate login, its role selected at
	// connect, crossing partitions by its own policy and nothing else.
	login := sandbox.Login(t, "retention_login")
	sandbox.Exec(t, sandbox.Owner, `GRANT `+maintenance+` TO `+sandbox.Role("retention_login")+` WITH INHERIT FALSE, SET TRUE`)
	maintain, closeMaintenance, err := postgres.OpenMaintenance(ctx, login, maintenance, postgres.WithRestrictedSession())
	if err != nil {
		t.Fatal(err)
	}
	defer closeMaintenance()
	reader, err := maintain.Reader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.InTransaction(ctx, func(ctx context.Context, tx postgres.ReadTx) error {
		if got := scalar[int](t, ctx, tx, `SELECT count(DISTINCT tenant) FROM item`); got != 2 {
			t.Fatalf("maintenance read %d partitions, want both", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// It is not a way into a mode: the maintenance login was never granted one.
	conn := sandbox.Connect(t, login)
	if _, err := conn.Exec(ctx, `SET ROLE `+sandbox.Role("privileged_write")); sqlState(err) != insufficientPrivilege {
		t.Fatalf("the maintenance login assumed a mode role: %v", err)
	}
}

// Everything a module's suite needs of a principal, obtained without a
// superuser: the fixture principal as fixture.go provisions it beside an owner
// that is not one (BYPASSRLS, CREATEROLE, a member of the owner).
func TestRowScopeFixturePrincipalArrangesWithoutSuperuser(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	sandbox.Migrate(t, "item")
	ctx := spikeContext(t)
	fixture := sandbox.Connect(t, sandbox.Fixture)
	if scalar[bool](t, ctx, fixture, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`) {
		t.Fatal("the sandbox's fixture principal is a superuser; this test proves nothing")
	}
	// Seed several partitions through forced row security, and read them back.
	sandbox.Exec(t, sandbox.Fixture, rowScopeSeed)
	if got := bodies(t, ctx, fixture, "item"); got != "a-in-s2,a-in-t2,a-private,b-private,b-shared" {
		t.Fatalf("the fixture principal read %q", got)
	}
	// A login of its own making, granted one mode: no ALTER ROLE ... BYPASSRLS,
	// no superuser, and the owner's ADMIN OPTION on the mode role is enough.
	people := sandbox.LoginBy(t, sandbox.Fixture, "suite_people")
	sandbox.Exec(t, sandbox.Fixture, `GRANT `+sandbox.Role("strict_read")+` TO `+sandbox.Role("suite_people")+` WITH INHERIT FALSE, SET TRUE`)
	bound(t, ctx, sandbox.Connect(t, people), sandbox.Role("strict_read"), "t1", "s1", "human:a", func(tx pgx.Tx) {
		if got := bodies(t, ctx, tx, "item"); got != "a-private,b-shared" {
			t.Fatalf("a suite-made strict login read %q", got)
		}
	})
	// It can assert as a mode role itself: the bypass is the login's, and a
	// transaction that assumed the role is bound like the runtime login's.
	sandbox.Exec(t, sandbox.Fixture, `GRANT `+sandbox.Role("strict_read")+` TO CURRENT_USER WITH INHERIT FALSE, SET TRUE`)
	bound(t, ctx, fixture, sandbox.Role("strict_read"), "t1", "s1", "human:b", func(tx pgx.Tx) {
		if got := bodies(t, ctx, tx, "item"); got != "b-private,b-shared" {
			t.Fatalf("the fixture principal as strict read %q", got)
		}
	})
	// Empty the table between tests: TRUNCATE is the owner's, and it is a member.
	sandbox.Exec(t, sandbox.Fixture, `TRUNCATE item`)
	if got := bodies(t, ctx, fixture, "item"); got != "" {
		t.Fatalf("after TRUNCATE the table holds %q", got)
	}
}

// The Postgres agent makes the first of a login's delegated roles its session
// default. With a mode role first, a connection that skips the Store starts
// with that role's privileges; with a role that holds nothing first, it is
// refused the table, and the Store binds exactly as before.
func TestRowScopeSessionDefaultRoleMustHoldNothing(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	sandbox.Migrate(t, "item")
	sandbox.Exec(t, sandbox.Fixture, rowScopeSeed)
	ctx := spikeContext(t)
	connect := sandbox.Role("connect")
	sandbox.Exec(t, sandbox.Owner, `CREATE ROLE `+connect+` NOLOGIN NOINHERIT`,
		`GRANT `+connect+` TO `+sandbox.Role("ro")+`, `+sandbox.Role("rw")+` WITH INHERIT FALSE, SET TRUE`)
	// The agent's reconciler does this, with an authority the owner lacks.
	sandbox.Exec(t, sandbox.Admin, `ALTER ROLE `+sandbox.Role("ro")+` SET role = `+connect, `ALTER ROLE `+sandbox.Role("rw")+` SET role = `+connect)

	raw := sandbox.Connect(t, sandbox.ReadWrite)
	if got := scalar[string](t, ctx, raw, `SELECT current_user::text`); got != connect {
		t.Fatalf("the session started as %q", got)
	}
	if _, err := raw.Exec(ctx, `SELECT * FROM item`); sqlState(err) != insufficientPrivilege {
		t.Fatalf("a connection that skipped the Store read the table: %v", err)
	}
	store := openRowScopeStore(t, sandbox, postgres.Binding{Partition: "t1", Principal: "human:a", Reach: []string{"s1"}, Mode: postgres.Strict}, sandbox.Roles())
	if got := readBodies(t, store); got != "a-private,b-shared" {
		t.Fatalf("strict read %q", got)
	}
	// RESET ROLE inside the transaction lands on the powerless default.
	if err := store.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
		_, err := tx.Exec(ctx, `RESET ROLE; SELECT * FROM item`)
		return err
	}); sqlState(err) != insufficientPrivilege {
		t.Fatalf("RESET ROLE reached the table: %v", err)
	}
}

// rawAs runs fn in one READ WRITE transaction of the login, around the Store,
// bound as the Store binds: the proof that a refusal is the database's and not
// the transaction's access mode or the library's.
func rawAs(t *testing.T, ctx context.Context, conn *pgx.Conn, role, reach, writeReach, principal string, fn func(pgx.Tx)) {
	t.Helper()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadWrite})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, accessBind, "t1", reach, writeReach, principal, role); err != nil {
		t.Fatalf("bind %s: %v", role, err)
	}
	fn(tx)
}

// A Read binding is refused a write three times over, and the test takes the
// first two away to show the third: the Store gives it no Writer; its read
// transaction is READ ONLY; and the role that transaction assumes holds SELECT
// alone, so the same statements on the reader's login in a READ WRITE
// transaction are permission denied. In both modes.
func TestRowScopeReadBindingIsRefusedWritesByTheDatabase(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	sandbox.Migrate(t, "item")
	sandbox.Exec(t, sandbox.Fixture, rowScopeSeed)
	ctx := spikeContext(t)
	for name, test := range map[string]struct {
		binding     postgres.Binding
		role, reads string
	}{
		"strict":     {postgres.Binding{Partition: "t1", Principal: "human:a", Reach: []string{"s1"}, Mode: postgres.Strict, Access: postgres.Read}, sandbox.Role("strict_read"), "a-private,b-shared"},
		"privileged": {postgres.Binding{Partition: "t1", Principal: "human:a", Reach: []string{"s1"}, Mode: postgres.Privileged, Access: postgres.Read}, sandbox.Role("privileged_read"), "a-private,b-private,b-shared"},
	} {
		store := openRowScopeStore(t, sandbox, test.binding, sandbox.Roles())
		if err := store.Write(ctx, func(context.Context, postgres.WriteTx) error {
			t.Fatal("a Read binding opened a write transaction")
			return nil
		}); !errors.Is(err, postgres.ErrReadOnly) {
			t.Fatalf("%s: write on a Read binding: %v, want ErrReadOnly", name, err)
		}
		if err := store.Read(ctx, func(ctx context.Context, tx postgres.ReadTx) error {
			if got := bodies(t, ctx, tx, "item"); got != test.reads {
				t.Fatalf("%s read %q, want %q", name, got, test.reads)
			}
			got := scalar[string](t, ctx, tx, `SELECT concat_ws('|', current_user, session_user, current_setting('transaction_read_only'), current_setting('codefly.current_write_scopes'))`)
			if want := test.role + "|" + sandbox.Role("ro") + "|on|"; got != want {
				t.Fatalf("%s: the read transaction is %q, want %q", name, got, want)
			}
			// ReadTx has no Exec, and Query can still spell a write.
			rows, err := tx.Query(ctx, `DELETE FROM item RETURNING id`)
			if err == nil {
				rows.Close()
				err = rows.Err()
			}
			if sqlState(err) != readOnlyTransaction {
				t.Fatalf("%s: a DELETE through ReadTx => %v", name, err)
			}
			return err
		}); sqlState(err) != readOnlyTransaction {
			t.Fatal(err)
		}
		// Now without READ ONLY and without the library.
		rawAs(t, ctx, sandbox.Connect(t, sandbox.ReadOnly), test.role, "s1", "s1", "human:a", func(tx pgx.Tx) {
			if got := bodies(t, ctx, tx, "item"); got != test.reads {
				t.Fatalf("%s read %q around the Store", name, got)
			}
			for _, statement := range writeAttempts {
				wantProbe(t, ctx, tx, insufficientPrivilege, 0, statement)
			}
		})
	}
	// A Binding that may write still reads on the read role: the reader's
	// login was never granted the other.
	writer := openRowScopeStore(t, sandbox, postgres.Binding{Partition: "t1", Principal: "human:a", Reach: []string{"s1"}, Mode: postgres.Strict, Access: postgres.ReadWrite}, sandbox.Roles())
	if err := writer.Read(ctx, func(ctx context.Context, tx postgres.ReadTx) error {
		if got := scalar[string](t, ctx, tx, `SELECT current_user::text`); got != sandbox.Role("strict_read") {
			t.Fatalf("a read of a ReadWrite binding assumed %q", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := bodies(t, ctx, sandbox.Connect(t, sandbox.Fixture), "item"); got != "a-in-s2,a-in-t2,a-private,b-private,b-shared" {
		t.Fatalf("the table holds %q", got)
	}
}

// The access is fenced like the mode: by what the pool's login may assume. A
// Store wired to assume a write role on its reader pool, or told that the
// write role is the read role, gets ErrModeNotGranted from the database, and
// no SQL on the reader's connection reaches a write role.
func TestRowScopeAccessIsFencedByTheLoginsMembership(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	sandbox.Migrate(t, "item")
	sandbox.Exec(t, sandbox.Fixture, rowScopeSeed)
	ctx := spikeContext(t)
	dana := postgres.Binding{Partition: "t1", Principal: "human:a", Reach: []string{"s1"}, Mode: postgres.Strict}
	crossed := openRowScopeStore(t, sandbox, dana, postgres.Roles{StrictRead: sandbox.Role("strict_write"), StrictWrite: sandbox.Role("strict_read")})
	if err := crossed.Read(ctx, func(context.Context, postgres.ReadTx) error {
		t.Fatal("the reader's login assumed a write role")
		return nil
	}); !errors.Is(err, postgres.ErrModeNotGranted) {
		t.Fatalf("a write role on the reader pool: %v, want ErrModeNotGranted", err)
	}
	if err := crossed.Write(ctx, func(context.Context, postgres.WriteTx) error {
		t.Fatal("the writer's login assumed a read role")
		return nil
	}); !errors.Is(err, postgres.ErrModeNotGranted) {
		t.Fatalf("a read role on the writer pool: %v, want ErrModeNotGranted", err)
	}
	// The two-role spelling of the same mistake.
	legacy := openRowScopeStore(t, sandbox, dana, postgres.Roles{Strict: sandbox.Role("strict_write")})
	if err := legacy.Read(ctx, func(context.Context, postgres.ReadTx) error { return nil }); !errors.Is(err, postgres.ErrModeNotGranted) {
		t.Fatalf("one write role for reads and writes: %v, want ErrModeNotGranted on the reader pool", err)
	}
	// SQL sent inside a real read transaction, as an injected statement would be.
	store := openRowScopeStore(t, sandbox, dana, sandbox.Roles())
	for _, role := range []string{sandbox.Role("strict_write"), sandbox.Role("privileged_write")} {
		err := store.Read(ctx, func(ctx context.Context, tx postgres.ReadTx) error {
			rows, err := tx.Query(ctx, `SELECT set_config('role', $1, true)`, role)
			if err == nil {
				rows.Close()
				err = rows.Err()
			}
			return err
		})
		if sqlState(err) != insufficientPrivilege {
			t.Fatalf("SET ROLE %s inside a read transaction: %v", role, err)
		}
	}
	// And the writer's login reaches no read role: each login holds one side.
	if _, err := sandbox.Connect(t, sandbox.ReadWrite).Exec(ctx, `SET ROLE `+sandbox.Role("privileged_read")); sqlState(err) != insufficientPrivilege {
		t.Fatalf("the writer's login assumed a read role: %v", err)
	}
}

// "Privileged read, strict write": one Binding, a different role per
// transaction kind. It reads every principal's rows in reach, and writes as
// itself: inside the write transaction it is strict, to read as to write.
func TestRowScopePrivilegedReadWithStrictWrite(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	sandbox.Migrate(t, "item")
	sandbox.Exec(t, sandbox.Fixture, rowScopeSeed)
	ctx := spikeContext(t)
	store := openRowScopeStore(t, sandbox, postgres.Binding{
		Partition: "t1", Principal: "human:a", Reach: []string{"s1"}, Mode: postgres.Privileged, WriteMode: postgres.Strict,
	}, sandbox.Roles())
	if got := readBodies(t, store); got != "a-private,b-private,b-shared" {
		t.Fatalf("read %q, want every principal's rows", got)
	}
	if err := store.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
		if got := scalar[string](t, ctx, tx, `SELECT current_user::text`); got != sandbox.Role("strict_write") {
			t.Fatalf("the write transaction assumed %q", got)
		}
		if got := bodies(t, ctx, tx, "item"); got != "a-private,b-shared" {
			t.Fatalf("inside the write transaction it read %q", got)
		}
		tag, err := tx.Exec(ctx, `UPDATE item SET body = body || '!'`)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("updated %d rows (%v), want its own one", tag.RowsAffected(), err)
		}
		tag, err = tx.Exec(ctx, `DELETE FROM item WHERE principal = 'human:b'`)
		if err != nil || tag.RowsAffected() != 0 {
			t.Fatalf("deleted %d of another principal's rows (%v)", tag.RowsAffected(), err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	err := store.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s1','human:b',false)`)
		return err
	})
	if sqlState(err) != insufficientPrivilege {
		t.Fatalf("an insert for another principal: %v", err)
	}
	if got := readBodies(t, store); got != "a-private!,b-private,b-shared" {
		t.Fatalf("afterwards it reads %q", got)
	}
}

// A Binding that reads two scopes and may write one: its write transaction
// sees both and changes only the one, in both modes, by the database.
func TestRowScopeWriteReachIsNarrowerThanTheReach(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	sandbox.Migrate(t, "item")
	ctx := spikeContext(t)
	for name, test := range map[string]struct {
		mode             postgres.Mode
		reads, afterward string
		updated          int64
	}{
		"strict":     {postgres.Strict, "a-in-s2,a-private,b-shared", "a-in-s2,a-in-t2,a-private!,b-private,b-shared,new", 1},
		"privileged": {postgres.Privileged, "a-in-s2,a-private,b-private,b-shared", "a-in-s2,a-in-t2,a-private!,b-private!,b-shared!,new", 3},
	} {
		sandbox.Exec(t, sandbox.Fixture, `TRUNCATE item`, rowScopeSeed)
		store := openRowScopeStore(t, sandbox, postgres.Binding{
			Partition: "t1", Principal: "human:a", Reach: []string{"s1", "s2"}, WriteReach: []string{"s1"}, Mode: test.mode,
		}, sandbox.Roles())
		if err := store.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
			if got := scalar[string](t, ctx, tx, `SELECT current_setting('codefly.current_scopes') || '|' || current_setting('codefly.current_write_scopes')`); got != "s1,s2|s1" {
				t.Fatalf("%s: the reaches are %q", name, got)
			}
			if got := bodies(t, ctx, tx, "item"); got != test.reads {
				t.Fatalf("%s read %q inside the write transaction, want %q", name, got, test.reads)
			}
			tag, err := tx.Exec(ctx, `UPDATE item SET body = body || '!'`)
			if err != nil || tag.RowsAffected() != test.updated {
				t.Fatalf("%s updated %d rows (%v), want %d", name, tag.RowsAffected(), err, test.updated)
			}
			tag, err = tx.Exec(ctx, `DELETE FROM item WHERE scope = 's2'`)
			if err != nil || tag.RowsAffected() != 0 {
				t.Fatalf("%s deleted %d rows of a scope it may only read (%v)", name, tag.RowsAffected(), err)
			}
			_, err = tx.Exec(ctx, `INSERT INTO item (tenant, scope, principal, shared, body) VALUES ('t1','s1','human:a',false,'new')`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		err := store.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
			_, err := tx.Exec(ctx, `INSERT INTO item (tenant, scope, principal, shared) VALUES ('t1','s2','human:a',false)`)
			return err
		})
		if sqlState(err) != insufficientPrivilege {
			t.Fatalf("%s: an insert into a scope it may only read: %v", name, err)
		}
		if got := bodies(t, ctx, sandbox.Connect(t, sandbox.Fixture), "item"); got != test.afterward {
			t.Fatalf("%s: the table holds %q, want %q", name, got, test.afterward)
		}
	}
}

// A store migrated before the read and write roles existed keeps working with
// the Roles it always named — and keeps exactly the floor it had: READ ONLY is
// the only thing between its reader's login and a write. Adding the four roles
// is one more migration with the same two helpers; the old roles go when
// nothing names them.
func TestRowScopeTwoRoleStoreKeepsWorkingAndCanAdoptTheFour(t *testing.T) {
	sandbox := rowscopefixture.Open(t)
	table := sandbox.MigrateTwoRoles(t, "item")[0]
	sandbox.Exec(t, sandbox.Fixture, rowScopeSeed)
	ctx := spikeContext(t)
	dana := postgres.Binding{Partition: "t1", Principal: "human:a", Reach: []string{"s1", "s2"}, Mode: postgres.Strict}
	store := openRowScopeStore(t, sandbox, dana, sandbox.TwoRoles())
	if got := readBodies(t, store); got != "a-in-s2,a-private,b-shared" {
		t.Fatalf("strict read %q", got)
	}
	if err := store.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
		tag, err := tx.Exec(ctx, `UPDATE item SET body = body || '!'`)
		if err != nil || tag.RowsAffected() != 2 {
			t.Fatalf("updated %d rows (%v), want its own two", tag.RowsAffected(), err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	readOnly := dana
	readOnly.Access = postgres.Read
	if err := openRowScopeStore(t, sandbox, readOnly, sandbox.TwoRoles()).Write(ctx, func(context.Context, postgres.WriteTx) error { return nil }); !errors.Is(err, postgres.ErrReadOnly) {
		t.Fatalf("a Read binding: %v, want ErrReadOnly", err)
	}
	// What its catalog cannot enforce, the Store refuses to promise.
	narrowed := dana
	narrowed.WriteReach = []string{"s1"}
	if err := openRowScopeStore(t, sandbox, narrowed, sandbox.TwoRoles()).Write(ctx, func(context.Context, postgres.WriteTx) error {
		t.Fatal("a two-role store opened a write narrower than its read")
		return nil
	}); !errors.Is(err, postgres.ErrSplitBinding) {
		t.Fatalf("a narrower write reach on the two-role form: %v, want ErrSplitBinding", err)
	}
	// The floor it has: on the reader's login, outside READ ONLY, a write lands.
	rawAs(t, ctx, sandbox.Connect(t, sandbox.ReadOnly), sandbox.Role("strict"), "s1", "s1", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, "", 1, `DELETE FROM item`)
	})

	// The adopting migration.
	adopt, err := rowscope.Bootstrap(sandbox.Roles(), rowscope.Logins{
		StrictRead: []string{sandbox.Role("ro")}, PrivilegedRead: []string{sandbox.Role("ro")},
		StrictWrite: []string{sandbox.Role("rw")}, PrivilegedWrite: []string{sandbox.Role("rw")},
	})
	if err != nil {
		t.Fatal(err)
	}
	protect, err := rowscope.Protect(table, sandbox.Roles(), rowscope.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	// Protect replaced every policy that named the old roles, so nothing but
	// their grants holds them.
	sandbox.Exec(t, sandbox.Owner, rowscope.Script(append(adopt, protect...)),
		`REVOKE ALL ON item FROM `+sandbox.Role("strict")+`, `+sandbox.Role("privileged"),
		`REVOKE USAGE ON SCHEMA public FROM `+sandbox.Role("strict")+`, `+sandbox.Role("privileged"),
		`DROP ROLE `+sandbox.Role("strict")+`, `+sandbox.Role("privileged"))
	adopted := openRowScopeStore(t, sandbox, narrowed, sandbox.Roles())
	if got := readBodies(t, adopted); got != "a-in-s2!,a-private!,b-shared" {
		t.Fatalf("after adopting, strict read %q", got)
	}
	if err := adopted.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
		tag, err := tx.Exec(ctx, `UPDATE item SET body = 'narrow'`)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("updated %d rows (%v), want the one in its write reach", tag.RowsAffected(), err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rawAs(t, ctx, sandbox.Connect(t, sandbox.ReadOnly), sandbox.Role("strict_read"), "s1", "s1", "human:a", func(tx pgx.Tx) {
		wantProbe(t, ctx, tx, insufficientPrivilege, 0, `DELETE FROM item`)
	})
	// The Store that still names the roles that are gone is refused, not served.
	if err := store.Read(ctx, func(context.Context, postgres.ReadTx) error { return nil }); !errors.Is(err, postgres.ErrModeNotGranted) {
		t.Fatalf("the dropped two-role form: %v, want ErrModeNotGranted", err)
	}
}
