package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// connectionPolicyRecorder is a stand-in for an application's own authority
// rule. It records what each invocation saw so a test can tell the two
// lifecycle boundaries, the two capabilities and the two logins apart. Every
// field is guarded: pool background goroutines invoke the policy concurrently
// with the test body that reconfigures it.
type connectionPolicyRecorder struct {
	mu       sync.Mutex
	calls    []connectionPolicyCall
	refusal  error
	forbidal string
}

type connectionPolicyCall struct {
	user        string
	backend     int32
	hasDeadline bool
}

func (r *connectionPolicyRecorder) refuse(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refusal = err
}

func (r *connectionPolicyRecorder) forbid(role string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forbidal = role
}

func (r *connectionPolicyRecorder) observed() []connectionPolicyCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]connectionPolicyCall(nil), r.calls...)
}

func (r *connectionPolicyRecorder) users() []string {
	seen := map[string]bool{}
	var users []string
	for _, call := range r.observed() {
		if !seen[call.user] {
			seen[call.user] = true
			users = append(users, call.user)
		}
	}
	return users
}

func (r *connectionPolicyRecorder) backends() int {
	seen := map[int32]bool{}
	for _, call := range r.observed() {
		seen[call.backend] = true
	}
	return len(seen)
}

func (r *connectionPolicyRecorder) policy(ctx context.Context, conn *pgx.Conn) error {
	r.mu.Lock()
	refusal, forbidal := r.refusal, r.forbidal
	r.mu.Unlock()
	var call connectionPolicyCall
	var forbidden bool
	// CASE guarantees the membership test is skipped when no role is named;
	// pg_has_role would error on an absent role.
	if err := conn.QueryRow(ctx, `SELECT current_user, pg_backend_pid(),
		CASE WHEN $1 = '' THEN false ELSE pg_has_role(current_user, $1, 'MEMBER') END`,
		forbidal).Scan(&call.user, &call.backend, &forbidden); err != nil {
		return err
	}
	_, call.hasDeadline = ctx.Deadline()
	r.mu.Lock()
	r.calls = append(r.calls, call)
	r.mu.Unlock()
	if refusal != nil {
		return refusal
	}
	if forbidden {
		return errors.New("connection authority is not acceptable to this application")
	}
	return nil
}

// The DSN must name a disposable local database with a superuser fixture owner.
// CI supplies its own isolated container. No developer or hosted database is used.
func TestConnectionPolicyPostgres(t *testing.T) {
	dsn := os.Getenv("SESSION_POLICY_TEST_DSN")
	if dsn == "" {
		t.Skip("SESSION_POLICY_TEST_DSN is required for the real-database connection-policy regression")
	}
	endpoint, err := url.Parse(dsn)
	if err != nil || endpoint.Scheme != "postgres" || (endpoint.Hostname() != "127.0.0.1" && endpoint.Hostname() != "localhost" && endpoint.Hostname() != "::1") {
		t.Fatal("connection-policy regression requires a loopback PostgreSQL URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("cannot connect to isolated role fixture")
	}
	defer admin.Close(context.Background())
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	prefix := fmt.Sprintf("connpolicy_%d_", time.Now().UnixNano())
	role := func(name string) string { return prefix + name }
	ident := func(name string) string { return pgx.Identifier{role(name)}.Sanitize() }
	names := []string{"reader", "writer", "jobs"}
	for _, name := range names {
		attrs := "NOLOGIN"
		if name != "jobs" {
			attrs = "LOGIN NOINHERIT PASSWORD 'isolated-fixture-only'"
		}
		exec("CREATE ROLE " + ident(name) + " " + attrs)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		for _, name := range names {
			if _, err := admin.Exec(cleanup, "DROP ROLE "+ident(name)); err != nil {
				t.Error(err)
			}
		}
	}()
	connection := func(name string) string {
		u := *endpoint
		u.User = url.UserPassword(role(name), "isolated-fixture-only")
		return u.String()
	}
	auth := fakeAuthenticator{principal: testPrincipal{tenant: "tenant", user: "user"}}
	open := func(option ...Option) (*Factory, func(), error) {
		return Open(ctx, connection("reader"), connection("writer"), auth, option...)
	}
	// Backends belonging to the fixture logins, so a test can prove a pool was
	// actually closed rather than merely dropped on the floor.
	fixtureBackends := func() int {
		t.Helper()
		var count int
		if err := admin.QueryRow(ctx,
			`SELECT count(*) FROM pg_stat_activity WHERE usename = ANY($1)`,
			[]string{role("reader"), role("writer")}).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	requireNoFixtureBackends := func(what string) {
		t.Helper()
		for attempt := 0; attempt < 100; attempt++ {
			if fixtureBackends() == 0 {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s left connections open", what)
	}
	read := func(factory *Factory) error {
		reader, err := factory.Reader(ctx)
		if err != nil {
			return err
		}
		return reader.InTransaction(ctx, func(ctx context.Context, tx ReadTx) error {
			var one int
			return tx.QueryRow(ctx, "SELECT 1").Scan(&one)
		})
	}

	t.Run("both boundaries after prior hooks and restricted sessions", func(t *testing.T) {
		var mu sync.Mutex
		var order []string
		note := func(step string) {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, step)
		}
		steps := func() string {
			mu.Lock()
			defer mu.Unlock()
			return strings.Join(order, ",")
		}
		pc, err := pgxpool.ParseConfig(connection("reader"))
		if err != nil {
			t.Fatal(err)
		}
		pc.MaxConns = 1
		pc.AfterConnect = func(context.Context, *pgx.Conn) error { note("prior-connect"); return nil }
		pc.BeforeAcquire = func(context.Context, *pgx.Conn) bool { note("prior-checkout"); return true }
		recorder := &connectionPolicyRecorder{}
		c, err := configured(WithRestrictedSession(role("jobs")), WithConnectionPolicies(
			func(ctx context.Context, conn *pgx.Conn) error { note("policy"); return recorder.policy(ctx, conn) }, nil))
		if err != nil {
			t.Fatal(err)
		}
		installConnectionValidation(pc, c, connectionValidation{capability: "read-only", policy: c.readerPolicy})
		pool, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		if err := pool.Ping(ctx); err != nil {
			t.Fatal(err)
		}
		// A new physical connection runs the caller's hook, then the library's
		// restricted-session check, then the application policy; the checkout of
		// that same connection runs the checkout hook and both checks again.
		if steps() != "prior-connect,policy,prior-checkout,policy" {
			t.Fatalf("lifecycle order %q", steps())
		}
		if got := recorder.backends(); got != 1 {
			t.Fatalf("policy saw %d backends; both boundaries should validate one connection", got)
		}
		// The restricted-session check runs ahead of the policy, so a refusal
		// there means the application policy is never consulted.
		exec("GRANT " + ident("jobs") + " TO " + ident("reader"))
		defer exec("REVOKE " + ident("jobs") + " FROM " + ident("reader"))
		before := len(recorder.observed())
		if _, err := pool.Acquire(ctx); err == nil {
			t.Fatal("denied role served application traffic")
		}
		if len(recorder.observed()) != before {
			t.Fatal("application policy ran after the restricted-session check refused")
		}
	})

	t.Run("each capability validates its own login", func(t *testing.T) {
		reader, writer := &connectionPolicyRecorder{}, &connectionPolicyRecorder{}
		factory, close, err := open(WithConnectionPolicies(reader.policy, writer.policy))
		if err != nil {
			t.Fatal(err)
		}
		defer close()
		if err := read(factory); err != nil {
			t.Fatal(err)
		}
		write, err := factory.Writer(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := write.InTransaction(ctx, func(ctx context.Context, tx WriteTx) error {
			_, err := tx.Exec(ctx, "SELECT 1")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if got := reader.users(); len(got) != 1 || got[0] != role("reader") {
			t.Fatalf("reader policy saw %v", got)
		}
		if got := writer.users(); len(got) != 1 || got[0] != role("writer") {
			t.Fatalf("writer policy saw %v", got)
		}
		// One physical connection per capability, validated on both boundaries.
		for name, recorder := range map[string]*connectionPolicyRecorder{"reader": reader, "writer": writer} {
			if recorder.backends() != 1 || len(recorder.observed()) < 3 {
				t.Fatalf("%s policy ran %d times over %d backends", name, len(recorder.observed()), recorder.backends())
			}
		}
	})

	t.Run("a refused capability is never served and closes both pools", func(t *testing.T) {
		requireNoFixtureBackends("earlier subtest")
		refused := errors.New("refused for the regression")
		for _, test := range []struct{ name, capability string }{
			{name: "reader refuses", capability: "reader"},
			{name: "writer refuses", capability: "writer"},
		} {
			t.Run(test.name, func(t *testing.T) {
				reader, writer := &connectionPolicyRecorder{}, &connectionPolicyRecorder{}
				refusing := reader
				if test.capability == "writer" {
					refusing = writer
				}
				refusing.refuse(refused)
				factory, close, err := open(WithConnectionPolicies(reader.policy, writer.policy))
				if close != nil {
					close()
				}
				if err == nil {
					t.Fatal("refused capability opened a serving boundary")
				}
				if factory != nil {
					t.Fatal("refused capability returned a factory")
				}
				if !errors.Is(err, refused) || !strings.Contains(err.Error(), test.capability[:4]) {
					t.Fatalf("refusal did not name its capability: %v", err)
				}
				if strings.Contains(err.Error(), "isolated-fixture-only") {
					t.Fatal("refusal disclosed a credential")
				}
				// Startup failed partway: the pool opened before it must close too.
				requireNoFixtureBackends("failed startup")
			})
		}
		// Independence: the other capability still opens on its own.
		reader, writer := &connectionPolicyRecorder{}, &connectionPolicyRecorder{}
		factory, close, err := open(WithConnectionPolicies(reader.policy, writer.policy))
		if err != nil {
			t.Fatal(err)
		}
		if err := read(factory); err != nil {
			t.Fatal(err)
		}
		close()
		requireNoFixtureBackends("closed factory")
	})

	t.Run("authority change refuses a pooled connection exactly once", func(t *testing.T) {
		writer := &connectionPolicyRecorder{}
		writer.forbid(role("jobs"))
		factory, close, err := open(WithConnectionPolicies(nil, writer.policy))
		if err != nil {
			t.Fatal(err)
		}
		defer close()
		capability, err := factory.Writer(ctx)
		if err != nil {
			t.Fatal(err)
		}
		applied := 0
		transaction := func(ctx context.Context, tx WriteTx) error {
			applied++
			_, err := tx.Exec(ctx, "SELECT 1")
			return err
		}
		if err := capability.InTransaction(ctx, transaction); err != nil {
			t.Fatal(err)
		}
		exec("GRANT " + ident("jobs") + " TO " + ident("writer"))
		before := len(writer.observed())
		if err := capability.InTransaction(ctx, transaction); err == nil {
			t.Fatal("pooled connection served traffic under newly forbidden authority")
		}
		if applied != 1 {
			t.Fatal("application callback ran under forbidden authority")
		}
		// A refusal carries its reason out of pgx rather than being retried on a
		// fresh connection until the acquire attempt budget is exhausted.
		if refusals := len(writer.observed()) - before; refusals != 1 {
			t.Fatalf("refused checkout cost %d policy invocations and a reconnect for each", refusals)
		}
		exec("REVOKE " + ident("jobs") + " FROM " + ident("writer"))
		if err := capability.InTransaction(ctx, transaction); err != nil {
			t.Fatal(err)
		}
		if applied != 2 {
			t.Fatal("restored authority did not resume serving")
		}
	})

	t.Run("nil policies preserve existing behavior", func(t *testing.T) {
		factory, close, err := open(WithConnectionPolicies(nil, nil), WithMaintenanceConnectionPolicy(nil))
		if err != nil {
			t.Fatal(err)
		}
		defer close()
		if err := read(factory); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("cancelled context never serves traffic", func(t *testing.T) {
		recorder := &connectionPolicyRecorder{}
		factory, close, err := open(WithConnectionPolicies(recorder.policy, nil))
		if err != nil {
			t.Fatal(err)
		}
		defer close()
		cancelled, stop := context.WithCancel(ctx)
		stop()
		reader, err := factory.Reader(cancelled)
		if err != nil {
			t.Fatal(err)
		}
		applied := false
		if err := reader.InTransaction(cancelled, func(context.Context, ReadTx) error {
			applied = true
			return nil
		}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled transaction = %v", err)
		}
		if applied {
			t.Fatal("application callback ran under a cancelled context")
		}
		// A cancelled caller cannot open a boundary either.
		expired, stopExpired := context.WithCancel(ctx)
		stopExpired()
		_, closeExpired, err := Open(expired, connection("reader"), connection("writer"), auth,
			WithConnectionPolicies(recorder.policy, nil))
		if closeExpired != nil {
			closeExpired()
		}
		if err == nil {
			t.Fatal("cancelled context opened a serving boundary")
		}
	})

	t.Run("the operation timeout bounds an otherwise unbounded connect", func(t *testing.T) {
		// puddle builds connections under a context whose deadline comes from the
		// pool, not the caller, so without the library's bound this policy would
		// block the connect path forever and this subtest would hang.
		pc, err := pgxpool.ParseConfig(connection("reader"))
		if err != nil {
			t.Fatal(err)
		}
		c, err := configured(
			WithConnectionPolicies(func(ctx context.Context, _ *pgx.Conn) error { <-ctx.Done(); return nil }, nil),
			WithOperationTimeout(500*time.Millisecond),
		)
		if err != nil {
			t.Fatal(err)
		}
		installConnectionValidation(pc, c, connectionValidation{capability: "read-only", policy: c.readerPolicy})
		pool, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		// context.Background: the caller imposes no deadline of its own.
		if err := pool.Ping(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unbounded connect-time policy = %v", err)
		}
	})

	t.Run("background pool refill runs the policy under the same bound", func(t *testing.T) {
		pc, err := pgxpool.ParseConfig(connection("reader"))
		if err != nil {
			t.Fatal(err)
		}
		pc.MinConns, pc.MaxConns = 1, 2
		pc.HealthCheckPeriod = 100 * time.Millisecond
		recorder := &connectionPolicyRecorder{}
		c, err := configured(WithConnectionPolicies(recorder.policy, nil), WithOperationTimeout(10*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		installConnectionValidation(pc, c, connectionValidation{capability: "read-only", policy: c.readerPolicy})
		pool, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		if err := pool.Ping(ctx); err != nil {
			t.Fatal(err)
		}
		// Reset drops every connection; the pool's own maintenance loop rebuilds
		// to MinConns with a background context that carries no caller deadline.
		before := recorder.backends()
		pool.Reset()
		refilled := false
		for attempt := 0; attempt < 100 && !refilled; attempt++ {
			time.Sleep(50 * time.Millisecond)
			refilled = recorder.backends() > before
		}
		if !refilled {
			t.Fatal("background refill never validated a connection")
		}
		for index, call := range recorder.observed() {
			if !call.hasDeadline {
				t.Fatalf("policy invocation %d ran with no deadline", index)
			}
		}
	})

	t.Run("maintenance is a separate capability in both directions", func(t *testing.T) {
		// The maintenance login selects the application role at startup, so it
		// must be a member of it. NOINHERIT keeps that membership from carrying
		// the group's privileges into the login's own session.
		exec("GRANT " + ident("jobs") + " TO " + ident("writer"))
		defer exec("REVOKE " + ident("jobs") + " FROM " + ident("writer"))
		refused := errors.New("refused for the regression")
		request, maintenance := &connectionPolicyRecorder{}, &connectionPolicyRecorder{}
		request.refuse(refused)
		// Reader and writer policies never reach the maintenance capability.
		capability, close, err := OpenMaintenance(ctx, connection("writer"), role("jobs"),
			WithConnectionPolicies(request.policy, request.policy))
		if err != nil {
			t.Fatal(err)
		}
		close()
		if calls := len(request.observed()); calls != 0 {
			t.Fatalf("request policies ran %d times on the maintenance capability", calls)
		}
		if capability == nil {
			t.Fatal("maintenance capability was not returned")
		}
		// The maintenance policy sees the maintenance application role.
		_, close, err = OpenMaintenance(ctx, connection("writer"), role("jobs"),
			WithMaintenanceConnectionPolicy(maintenance.policy))
		if err != nil {
			t.Fatal(err)
		}
		close()
		if got := maintenance.users(); len(got) != 1 || got[0] != role("jobs") {
			t.Fatalf("maintenance policy saw %v", got)
		}
		// And it refuses that capability on its own.
		refusing := &connectionPolicyRecorder{}
		refusing.refuse(refused)
		_, close, err = OpenMaintenance(ctx, connection("writer"), role("jobs"),
			WithMaintenanceConnectionPolicy(refusing.policy))
		if close != nil {
			close()
		}
		if !errors.Is(err, refused) || !strings.Contains(err.Error(), "maintenance") {
			t.Fatalf("maintenance refusal = %v", err)
		}
		// The maintenance policy never reaches the request capabilities.
		factory, close, err := open(WithMaintenanceConnectionPolicy(refusing.policy))
		if err != nil {
			t.Fatal(err)
		}
		if err := read(factory); err != nil {
			t.Fatal(err)
		}
		close()
		// A policy neither replaces nor relaxes the mandatory role qualification.
		exec("ALTER ROLE " + ident("jobs") + " LOGIN")
		defer exec("ALTER ROLE " + ident("jobs") + " NOLOGIN")
		permissive := &connectionPolicyRecorder{}
		_, close, err = OpenMaintenance(ctx, connection("writer"), role("jobs"),
			WithMaintenanceConnectionPolicy(permissive.policy))
		if close != nil {
			close()
		}
		if err == nil {
			t.Fatal("a permissive policy bypassed the mandatory maintenance qualification")
		}
	})
}
