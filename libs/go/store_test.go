package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestReaderBindsAuthenticatedScopeAndCannotExposeMutation(t *testing.T) {
	readerBackend := &fakeBeginner{tx: &fakeTransaction{}}
	factory := newTestFactory(t, readerBackend, &fakeBeginner{tx: &fakeTransaction{}}, fakeAuthenticator{
		principal: testPrincipal{tenant: "tenant-a", user: "user-a"},
	})

	reader, err := factory.Reader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.InTransaction(context.Background(), func(_ context.Context, tx ReadTx) error {
		if _, mutationExposed := tx.(interface {
			Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
		}); mutationExposed {
			t.Fatal("read transaction exposed mutation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if readerBackend.options.AccessMode != pgx.ReadOnly {
		t.Fatalf("reader access mode = %v, want read only", readerBackend.options.AccessMode)
	}
	if !readerBackend.tx.committed {
		t.Fatal("successful reader transaction was not committed")
	}
	wantScope := []any{"codefly.current_tenant_id", "tenant-a", "codefly.current_user_id", "user-a"}
	if len(readerBackend.tx.executions) != 1 || !reflect.DeepEqual(readerBackend.tx.executions[0].arguments, wantScope) {
		t.Fatalf("scope arguments = %#v, want %#v", readerBackend.tx.executions, wantScope)
	}
}

func TestWriterRequiresAuthorizationBeforeOpeningTransaction(t *testing.T) {
	writeBackend := &fakeBeginner{tx: &fakeTransaction{}}
	factory := newTestFactory(t, &fakeBeginner{tx: &fakeTransaction{}}, writeBackend, fakeAuthenticator{
		principal:      testPrincipal{tenant: "tenant-a", user: "user-a"},
		writeAuthError: errors.New("policy denied"),
	})

	if _, err := factory.Writer(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("writer error = %v, want ErrUnauthorized", err)
	}
	if writeBackend.beginCalls != 0 {
		t.Fatal("unauthorized writer opened a database transaction")
	}
}

func TestWriterBindsScopeAndExposesMutation(t *testing.T) {
	writeBackend := &fakeBeginner{tx: &fakeTransaction{}}
	factory := newTestFactory(t, &fakeBeginner{tx: &fakeTransaction{}}, writeBackend, fakeAuthenticator{
		principal: testPrincipal{tenant: "tenant-b", user: "user-b"},
	})

	writer, err := factory.Writer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.InTransaction(context.Background(), func(ctx context.Context, tx WriteTx) error {
		_, err := tx.Exec(ctx, "repository mutation", "value")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if writeBackend.options.AccessMode != pgx.ReadWrite {
		t.Fatalf("writer access mode = %v, want read write", writeBackend.options.AccessMode)
	}
	if len(writeBackend.tx.executions) != 2 || writeBackend.tx.executions[1].statement != "repository mutation" {
		t.Fatalf("writer executions = %#v", writeBackend.tx.executions)
	}
}

func TestRequireTenantAndUserValidateArtifactScopeWithoutDatabaseAccess(t *testing.T) {
	readerBackend := &fakeBeginner{tx: &fakeTransaction{}}
	writerBackend := &fakeBeginner{tx: &fakeTransaction{}}
	factory := newTestFactory(t, readerBackend, writerBackend, fakeAuthenticator{
		principal: testPrincipal{tenant: "tenant-a", user: "user-a"},
	})
	if err := factory.RequireTenant(t.Context(), " tenant-a "); err != nil {
		t.Fatal(err)
	}
	if err := factory.RequireTenant(t.Context(), "tenant-b"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("mismatched tenant error=%v, want ErrUnauthorized", err)
	}
	if err := factory.RequireUser(t.Context(), " user-a "); err != nil {
		t.Fatal(err)
	}
	if err := factory.RequireUser(t.Context(), "user-b"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("mismatched user error=%v, want ErrUnauthorized", err)
	}
	if readerBackend.beginCalls != 0 || writerBackend.beginCalls != 0 {
		t.Fatal("artifact verification accessed the database")
	}
}

func TestMissingOrIncompletePrincipalFailsBeforeDatabaseAccess(t *testing.T) {
	tests := []struct {
		name      string
		principal Principal
		authError error
	}{
		{name: "resolver error", authError: errors.New("no bearer token")},
		{name: "nil principal"},
		{name: "typed nil principal", principal: (*pointerPrincipal)(nil)},
		{name: "missing tenant", principal: testPrincipal{user: "user-a"}},
		{name: "missing user", principal: testPrincipal{tenant: "tenant-a"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			readerBackend := &fakeBeginner{tx: &fakeTransaction{}}
			factory := newTestFactory(t, readerBackend, &fakeBeginner{tx: &fakeTransaction{}}, fakeAuthenticator{
				principal: test.principal,
				authError: test.authError,
			})
			if _, err := factory.Reader(context.Background()); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("reader error = %v, want ErrUnauthenticated", err)
			}
			if readerBackend.beginCalls != 0 {
				t.Fatal("unauthenticated reader opened a database transaction")
			}
		})
	}
}

func TestCallbackFailureRollsBackWithoutCommit(t *testing.T) {
	backend := &fakeBeginner{tx: &fakeTransaction{}}
	factory := newTestFactory(t, backend, &fakeBeginner{tx: &fakeTransaction{}}, fakeAuthenticator{
		principal: testPrincipal{tenant: "tenant-a", user: "user-a"},
	})
	reader, err := factory.Reader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("repository failed")
	if err := reader.InTransaction(context.Background(), func(context.Context, ReadTx) error { return want }); !errors.Is(err, want) {
		t.Fatalf("transaction error = %v, want callback error", err)
	}
	if backend.tx.committed || backend.tx.rollbackCalls != 1 {
		t.Fatalf("commit=%t rollback_calls=%d", backend.tx.committed, backend.tx.rollbackCalls)
	}
}

func TestScopeSettingNamesFailClosed(t *testing.T) {
	for _, settings := range [][2]string{
		{"tenant", "app.user"},
		{"app..tenant", "app.user"},
		{".tenant", "app.user"},
		{"app.tenant;reset role", "app.user"},
		{"app.same", "app.same"},
	} {
		if _, err := newFactory(
			&fakeBeginner{tx: &fakeTransaction{}},
			&fakeBeginner{tx: &fakeTransaction{}},
			fakeAuthenticator{principal: testPrincipal{tenant: "tenant", user: "user"}},
			WithScopeSettings(settings[0], settings[1]),
		); err == nil {
			t.Fatalf("unsafe settings were accepted: %q", settings)
		}
	}
}

func TestTransactionRejectsNilContextBeforeDatabaseAccess(t *testing.T) {
	backend := &fakeBeginner{tx: &fakeTransaction{}}
	factory := newTestFactory(t, backend, &fakeBeginner{tx: &fakeTransaction{}}, fakeAuthenticator{
		principal: testPrincipal{tenant: "tenant-a", user: "user-a"},
	})
	reader, err := factory.Reader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.InTransaction(nil, func(context.Context, ReadTx) error { return nil }); err == nil {
		t.Fatal("nil transaction context was accepted")
	}
	if backend.beginCalls != 0 {
		t.Fatal("nil-context transaction reached the database")
	}
}

func TestOperationTimeoutBoundsConnectionAcquisition(t *testing.T) {
	backend := &blockingBeginner{}
	factory, err := newFactory(
		backend,
		&fakeBeginner{tx: &fakeTransaction{}},
		fakeAuthenticator{principal: testPrincipal{tenant: "tenant-a", user: "user-a"}},
		WithOperationTimeout(10*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := factory.Reader(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = reader.InTransaction(context.Background(), func(context.Context, ReadTx) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("transaction error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("operation timeout returned too slowly: %s", elapsed)
	}
}

func TestOperationTimeoutMustBePositive(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		if _, err := newFactory(
			&fakeBeginner{tx: &fakeTransaction{}},
			&fakeBeginner{tx: &fakeTransaction{}},
			fakeAuthenticator{principal: testPrincipal{tenant: "tenant", user: "user"}},
			WithOperationTimeout(timeout),
		); err == nil {
			t.Fatalf("accepted operation timeout %s", timeout)
		}
	}
}

func TestWorkloadIssuerBindsOpaqueTenantUserScopeAndWriteCapability(t *testing.T) {
	issuer, err := NewWorkloadIssuer(fakeAuthenticator{authError: ErrUnauthenticated})
	if err != nil {
		t.Fatal(err)
	}
	workload, err := issuer.Issue(" tenant-a ", " reconciler ", true)
	if err != nil {
		t.Fatal(err)
	}
	readerBackend := &fakeBeginner{tx: &fakeTransaction{}}
	writerBackend := &fakeBeginner{tx: &fakeTransaction{}}
	factory := newTestFactory(t, readerBackend, writerBackend, issuer)
	ctx := workload.Context(context.Background())

	reader, err := factory.Reader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.InTransaction(ctx, func(context.Context, ReadTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	writer, err := factory.Writer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.InTransaction(ctx, func(context.Context, WriteTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	want := []any{"codefly.current_tenant_id", "tenant-a", "codefly.current_user_id", "workload:reconciler"}
	if !reflect.DeepEqual(readerBackend.tx.executions[0].arguments, want) || !reflect.DeepEqual(writerBackend.tx.executions[0].arguments, want) {
		t.Fatalf("workload scopes reader=%#v writer=%#v want=%#v", readerBackend.tx.executions, writerBackend.tx.executions, want)
	}
}

func TestWorkloadIssuerReadOnlyAndIssuerIsolationFailBeforeWriterTransaction(t *testing.T) {
	deniedRequests := fakeAuthenticator{authError: ErrUnauthenticated}
	issuer, err := NewWorkloadIssuer(deniedRequests)
	if err != nil {
		t.Fatal(err)
	}
	readOnly, err := issuer.Issue("tenant-a", "index-reader", false)
	if err != nil {
		t.Fatal(err)
	}
	writerBackend := &fakeBeginner{tx: &fakeTransaction{}}
	factory := newTestFactory(t, &fakeBeginner{tx: &fakeTransaction{}}, writerBackend, issuer)
	if _, err := factory.Writer(readOnly.Context(t.Context())); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("read-only workload writer error=%v, want ErrUnauthorized", err)
	}
	if writerBackend.beginCalls != 0 {
		t.Fatal("read-only workload opened a writer transaction")
	}

	foreignIssuer, err := NewWorkloadIssuer(deniedRequests)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := foreignIssuer.Issue("tenant-b", "foreign", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.Reader(foreign.Context(t.Context())); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("foreign workload reader error=%v, want ErrUnauthenticated", err)
	}
}

func TestWorkloadIssuerPreservesVerifiedRequestAuthenticator(t *testing.T) {
	requests := fakeAuthenticator{principal: testPrincipal{tenant: "request-tenant", user: "request-user"}}
	issuer, err := NewWorkloadIssuer(requests)
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeBeginner{tx: &fakeTransaction{}}
	factory := newTestFactory(t, backend, &fakeBeginner{tx: &fakeTransaction{}}, issuer)
	reader, err := factory.Reader(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.InTransaction(t.Context(), func(context.Context, ReadTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	want := []any{"codefly.current_tenant_id", "request-tenant", "codefly.current_user_id", "request-user"}
	if !reflect.DeepEqual(backend.tx.executions[0].arguments, want) {
		t.Fatalf("request scope=%#v want=%#v", backend.tx.executions, want)
	}
}

func newTestFactory(t *testing.T, reader, writer transactionBeginner, authenticator Authenticator) *Factory {
	t.Helper()
	factory, err := newFactory(reader, writer, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

type testPrincipal struct {
	tenant string
	user   string
}

func (p testPrincipal) DatabaseTenantID() string { return p.tenant }
func (p testPrincipal) DatabaseUserID() string   { return p.user }

type pointerPrincipal struct{}

func (*pointerPrincipal) DatabaseTenantID() string { return "tenant" }
func (*pointerPrincipal) DatabaseUserID() string   { return "user" }

type fakeAuthenticator struct {
	principal      Principal
	authError      error
	writeAuthError error
}

func (a fakeAuthenticator) AuthenticatedPrincipal(context.Context) (Principal, error) {
	return a.principal, a.authError
}

func (a fakeAuthenticator) AuthorizeDatabaseWrite(context.Context, Principal) error {
	return a.writeAuthError
}

type fakeBeginner struct {
	tx         *fakeTransaction
	options    pgx.TxOptions
	beginCalls int
	beginError error
}

type blockingBeginner struct{}

func (*blockingBeginner) BeginTx(ctx context.Context, _ pgx.TxOptions) (transaction, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (b *fakeBeginner) BeginTx(_ context.Context, options pgx.TxOptions) (transaction, error) {
	b.beginCalls++
	b.options = options
	if b.beginError != nil {
		return nil, b.beginError
	}
	return b.tx, nil
}

type execution struct {
	statement string
	arguments []any
}

type fakeTransaction struct {
	executions    []execution
	execError     error
	committed     bool
	commitError   error
	rollbackCalls int
}

func (t *fakeTransaction) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}

func (t *fakeTransaction) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected query row")
}

func (t *fakeTransaction) Exec(_ context.Context, statement string, arguments ...any) (pgconn.CommandTag, error) {
	t.executions = append(t.executions, execution{statement: statement, arguments: arguments})
	return pgconn.CommandTag{}, t.execError
}

func (t *fakeTransaction) Commit(context.Context) error {
	t.committed = true
	return t.commitError
}

func (t *fakeTransaction) Rollback(context.Context) error {
	t.rollbackCalls++
	return nil
}
