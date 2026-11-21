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
		want := strings.Join([]string{sandbox.Role("strict"), sandbox.Role("rw"), "service:wiki", "a", "human:a", "s1"}, "|")
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
	// A process that serves people: its logins are granted the strict role alone.
	peopleRO, peopleRW := sandbox.Login(t, "people_ro"), sandbox.Login(t, "people_rw")
	grant, err := rowscope.Bootstrap(postgres.Roles{Strict: sandbox.Role("strict")},
		rowscope.Logins{Strict: []string{sandbox.Role("people_ro"), sandbox.Role("people_rw")}})
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
	if _, _, err := postgres.OpenStore(ctx, peopleRO, peopleRW+"?role="+sandbox.Role("strict"), postgres.FixedBinder(installation), sandbox.Roles()); err == nil {
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
	if _, err := conn.Exec(ctx, `SET ROLE `+sandbox.Role("privileged")); sqlState(err) != insufficientPrivilege {
		t.Fatalf("the maintenance login assumed a mode role: %v", err)
	}
}
