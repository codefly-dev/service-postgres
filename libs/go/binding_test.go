package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var testRoles = Roles{Strict: "app_x_strict", Privileged: "app_x_privileged"}

func newTestStore(t *testing.T, reader, writer transactionBeginner, binder Binder, roles Roles, options ...Option) *Store {
	t.Helper()
	store, err := newStore(reader, writer, binder, roles, options...)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func strictBinding() Binding {
	return Binding{Partition: "p1", Principal: "human:dana", Reach: []string{"s1", "s2"}, Mode: Strict, Actor: "service:wiki"}
}

func TestStoreBindsSettingsAndRoleInOneStatement(t *testing.T) {
	reader, writer := &fakeBeginner{tx: &fakeTransaction{}}, &fakeBeginner{tx: &fakeTransaction{}}
	store := newTestStore(t, reader, writer, FixedBinder(strictBinding()), testRoles)

	if err := store.Read(context.Background(), func(_ context.Context, tx ReadTx) error {
		if _, mutationExposed := tx.(interface {
			Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
		}); mutationExposed {
			t.Fatal("read transaction exposed mutation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if reader.options.AccessMode != pgx.ReadOnly || writer.beginCalls != 0 {
		t.Fatalf("read used access mode %v and %d writer transactions", reader.options.AccessMode, writer.beginCalls)
	}
	want := []any{
		"codefly.current_tenant_id", "p1",
		"codefly.current_user_id", "dana", // the existing setting keeps its bare value
		"codefly.current_scopes", "s1,s2",
		"codefly.current_principal", "human:dana",
		"codefly.current_actor", "service:wiki",
		"app_x_strict",
		"codefly.current_write_scopes", "", // a read transaction has no write reach
	}
	if len(reader.tx.executions) != 1 || !reflect.DeepEqual(reader.tx.executions[0].arguments, want) {
		t.Fatalf("binding arguments = %#v, want %#v", reader.tx.executions, want)
	}
	if statement := reader.tx.executions[0].statement; !strings.Contains(statement, "set_config('role', $11, true)") || strings.Count(statement, ", true)") != 7 {
		t.Fatalf("binding statement is not seven transaction-local settings: %s", statement)
	}

	privileged := strictBinding()
	privileged.Mode = Privileged
	store = newTestStore(t, reader, writer, FixedBinder(privileged), testRoles)
	if err := store.Write(context.Background(), func(context.Context, WriteTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if writer.options.AccessMode != pgx.ReadWrite || writer.tx.executions[0].arguments[10] != "app_x_privileged" || writer.tx.executions[0].arguments[12] != "s1,s2" || !writer.tx.committed {
		t.Fatalf("privileged write bound %#v", writer.tx.executions)
	}
}

func TestStoreRefusesAnIncompleteBindingBeforeDatabaseAccess(t *testing.T) {
	change := func(edit func(*Binding)) Binding {
		binding := strictBinding()
		edit(&binding)
		return binding
	}
	for name, test := range map[string]struct {
		binder Binder
		want   error
		also   error
	}{
		"binder error":    {BinderFunc(func(context.Context) (Binding, error) { return Binding{}, errors.New("no admission") }), ErrNoBinding, ErrUnauthenticated},
		"zero binding":    {FixedBinder(Binding{}), ErrNoBinding, ErrUnauthenticated},
		"empty partition": {FixedBinder(change(func(b *Binding) { b.Partition = " " })), ErrNoPartition, ErrUnauthenticated},
		"empty principal": {FixedBinder(change(func(b *Binding) { b.Principal = "" })), ErrNoPrincipal, ErrUnauthenticated},
		"bare principal":  {FixedBinder(change(func(b *Binding) { b.Principal = "dana" })), ErrNoPrincipal, ErrUnauthenticated},
		"kindless":        {FixedBinder(change(func(b *Binding) { b.Principal = ":dana" })), ErrNoPrincipal, ErrUnauthenticated},
		"idless":          {FixedBinder(change(func(b *Binding) { b.Principal = "human:" })), ErrNoPrincipal, ErrUnauthenticated},
		"zero mode":       {FixedBinder(change(func(b *Binding) { b.Mode = 0 })), ErrUnknownMode, ErrUnauthorized},
		"unknown mode":    {FixedBinder(change(func(b *Binding) { b.Mode = 3 })), ErrUnknownMode, ErrUnauthorized},
		"nil reach":       {FixedBinder(change(func(b *Binding) { b.Reach = nil })), ErrNoReach, ErrUnauthorized},
		"empty reach":     {FixedBinder(change(func(b *Binding) { b.Reach = []string{} })), ErrNoReach, ErrUnauthorized},
		"empty scope":     {FixedBinder(change(func(b *Binding) { b.Reach = []string{"s1", ""} })), ErrInvalidReach, ErrUnauthorized},
		"comma in scope":  {FixedBinder(change(func(b *Binding) { b.Reach = []string{"s1,s2"} })), ErrInvalidReach, ErrUnauthorized},
		"padded scope":    {FixedBinder(change(func(b *Binding) { b.Reach = []string{" s1"} })), ErrInvalidReach, ErrUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			reader, writer := &fakeBeginner{tx: &fakeTransaction{}}, &fakeBeginner{tx: &fakeTransaction{}}
			store := newTestStore(t, reader, writer, test.binder, testRoles)
			if _, err := store.Reader(context.Background()); !errors.Is(err, test.want) || !errors.Is(err, test.also) {
				t.Fatalf("reader error = %v, want %v (and %v)", err, test.want, test.also)
			}
			if _, err := store.Writer(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("writer error = %v, want %v", err, test.want)
			}
			if err := store.Write(context.Background(), func(context.Context, WriteTx) error { return nil }); !errors.Is(err, test.want) {
				t.Fatalf("write error = %v, want %v", err, test.want)
			}
			if reader.beginCalls != 0 || writer.beginCalls != 0 {
				t.Fatal("a refused binding opened a database transaction")
			}
		})
	}
	var missing *Store
	if _, err := missing.Reader(context.Background()); !errors.Is(err, ErrNoBinding) {
		t.Fatalf("nil store error = %v", err)
	}
}

// The typed errors must stay distinguishable from each other: a caller maps
// "nobody" and "nowhere" to different answers.
func TestBindingErrorsAreDistinct(t *testing.T) {
	all := []error{ErrNoBinding, ErrNoPartition, ErrNoPrincipal, ErrUnknownMode, ErrNoReach, ErrInvalidReach, ErrModeNotGranted, ErrReadOnly,
		ErrUnknownAccess, ErrWriteExceedsRead, ErrSplitBinding}
	for i, one := range all {
		for j, other := range all {
			if i != j && errors.Is(one, other) {
				t.Fatalf("%v is %v", one, other)
			}
		}
	}
}

func TestStoreModeIsOnlyWhatItsRolesAllow(t *testing.T) {
	writer := &fakeBeginner{tx: &fakeTransaction{}}
	privileged := strictBinding()
	privileged.Mode = Privileged
	// A process that serves people names the strict role alone.
	store := newTestStore(t, &fakeBeginner{tx: &fakeTransaction{}}, writer, FixedBinder(privileged), Roles{Strict: "app_x_strict"})
	if _, err := store.Writer(context.Background()); !errors.Is(err, ErrModeNotGranted) || !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("writer error = %v, want ErrModeNotGranted", err)
	}
	if writer.beginCalls != 0 {
		t.Fatal("an ungranted mode opened a database transaction")
	}
	// The database's own refusal is named the same way.
	for _, code := range []string{"42501", "22023"} {
		refusing := &fakeBeginner{tx: &fakeTransaction{execError: &pgconn.PgError{Code: code}}}
		store = newTestStore(t, refusing, refusing, FixedBinder(privileged), testRoles)
		err := store.Write(context.Background(), func(context.Context, WriteTx) error {
			t.Fatal("callback ran without its role")
			return nil
		})
		if !errors.Is(err, ErrModeNotGranted) || refusing.tx.committed {
			t.Fatalf("SQLSTATE %s: error = %v, committed = %v", code, err, refusing.tx.committed)
		}
	}
	other := &fakeBeginner{tx: &fakeTransaction{execError: &pgconn.PgError{Code: "57014"}}}
	store = newTestStore(t, other, other, FixedBinder(privileged), testRoles)
	if err := store.Write(context.Background(), func(context.Context, WriteTx) error { return nil }); err == nil || errors.Is(err, ErrModeNotGranted) {
		t.Fatalf("an unrelated failure was reported as %v", err)
	}
}

func TestStoreRolesAndSettingsFailClosed(t *testing.T) {
	backend := &fakeBeginner{tx: &fakeTransaction{}}
	binder := FixedBinder(strictBinding())
	for name, roles := range map[string]Roles{
		"none named":    {},
		"same role":     {Strict: "one", Privileged: "one"},
		"reset keyword": {Strict: "NONE"},
		"padded":        {Strict: " strict"},
		"too long":      {Privileged: strings.Repeat("x", 64)},
	} {
		if _, err := newStore(backend, backend, binder, roles); err == nil {
			t.Fatalf("%s: roles %#v accepted", name, roles)
		}
	}
	if _, err := newStore(backend, backend, nil, testRoles); err == nil {
		t.Fatal("nil binder accepted")
	}
	var typedNil BinderFunc
	if _, err := newStore(backend, backend, typedNil, testRoles); err == nil {
		t.Fatal("typed nil binder accepted")
	}
	for _, option := range []Option{
		WithBindingSettings("scopes", "codefly.principal", "codefly.actor"),
		WithBindingSettings("codefly.scopes", "codefly.principal;drop", "codefly.actor"),
		WithBindingSettings("codefly.one", "codefly.one", "codefly.actor"),
		WithBindingSettings("codefly.current_tenant_id", "codefly.principal", "codefly.actor"),
		WithWriteReachSetting("write_scopes"),
		WithWriteReachSetting("codefly.current_scopes"),
	} {
		if _, err := newStore(backend, backend, binder, testRoles, option); err == nil {
			t.Fatal("unsafe or repeated binding setting accepted")
		}
	}
	store := newTestStore(t, backend, backend, binder, testRoles,
		WithScopeSettings("app.partition", "app.user"), WithBindingSettings("app.reach", "app.principal", "app.actor"))
	if err := store.Read(context.Background(), func(context.Context, ReadTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	arguments := backend.tx.executions[0].arguments
	if arguments[0] != "app.partition" || arguments[2] != "app.user" || arguments[4] != "app.reach" || arguments[6] != "app.principal" || arguments[8] != "app.actor" {
		t.Fatalf("custom settings not installed: %#v", arguments)
	}
}

func TestReadOnlyBindingCannotObtainAWriter(t *testing.T) {
	writer := &fakeBeginner{tx: &fakeTransaction{}}
	binding := strictBinding()
	binding.ReadOnly = true
	store := newTestStore(t, &fakeBeginner{tx: &fakeTransaction{}}, writer, FixedBinder(binding), testRoles)
	if _, err := store.Reader(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Writer(context.Background()); !errors.Is(err, ErrReadOnly) || !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("writer error = %v, want ErrReadOnly", err)
	}
	if writer.beginCalls != 0 {
		t.Fatal("a read-only binding opened a writer transaction")
	}
}

func TestBindingIsNormalizedAndNotSharedWithItsCaller(t *testing.T) {
	backend := &fakeBeginner{tx: &fakeTransaction{}}
	reach := []string{"s2", "s1", "s2"}
	binder := FixedBinder(Binding{Partition: " p1 ", Principal: "agent:s1", Reach: reach, Mode: Privileged})
	reach[0] = "elsewhere"
	store := newTestStore(t, backend, backend, binder, testRoles)
	if err := store.Read(context.Background(), func(context.Context, ReadTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	arguments := backend.tx.executions[0].arguments
	if arguments[1] != "p1" || arguments[5] != "s2,s1" || arguments[9] != "" {
		t.Fatalf("binding not normalized: %#v", arguments)
	}
}

func TestCapabilityCarriesARecordedBindingAndIsItsStoresAlone(t *testing.T) {
	backend := &fakeBeginner{tx: &fakeTransaction{}}
	nobody := BinderFunc(func(context.Context) (Binding, error) { return Binding{}, errors.New("no call") })
	store := newTestStore(t, backend, backend, nobody, testRoles)
	other := newTestStore(t, backend, backend, nobody, testRoles)

	if _, err := store.Capability(Binding{Partition: "p1", Principal: "human:dana", Mode: Strict}); !errors.Is(err, ErrNoReach) {
		t.Fatalf("capability without reach: %v", err)
	}
	recorded := strictBinding()
	recorded.ReadOnly = true
	capability, err := store.Capability(recorded)
	if err != nil {
		t.Fatal(err)
	}
	recorded.Reach[0] = "elsewhere"
	ctx := capability.Context(context.Background())
	if err := store.Read(ctx, func(context.Context, ReadTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if arguments := backend.tx.executions[0].arguments; arguments[5] != "s1,s2" || arguments[10] != "app_x_strict" {
		t.Fatalf("capability bound %#v", arguments)
	}
	// What was recorded cannot be upgraded by the worker that replays it.
	if _, err := store.Writer(ctx); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("capability writer error = %v", err)
	}
	if _, err := other.Reader(ctx); !errors.Is(err, ErrNoBinding) {
		t.Fatalf("another store honoured the capability: %v", err)
	}
	var none *Capability
	if _, err := store.Reader(none.Context(nil)); !errors.Is(err, ErrNoBinding) {
		t.Fatalf("nil capability bound a context: %v", err)
	}
}

// The existing Factory installs exactly what it always did: a Store's wider
// binding is not something a consumer of Open starts receiving.
func TestFactoryScopeIsUnchangedByBindings(t *testing.T) {
	backend := &fakeBeginner{tx: &fakeTransaction{}}
	factory := newTestFactory(t, backend, backend, fakeAuthenticator{principal: testPrincipal{tenant: "tenant-a", user: "user-a"}})
	writer, err := factory.Writer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.InTransaction(context.Background(), func(context.Context, WriteTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	execution := backend.tx.executions[0]
	if execution.statement != `SELECT set_config($1, $2, true), set_config($3, $4, true)` || len(execution.arguments) != 4 {
		t.Fatalf("factory installed %q with %#v", execution.statement, execution.arguments)
	}
}

var accessRoles = AccessRoles("app_x")

// The role a transaction assumes is decided by the Binding's mode and by which
// capability was asked for, never by the handler: a Reader is the read role
// whatever the access, a Writer the write role of the write mode.
func TestStoreAssumesTheRoleOfTheModeAndTheAccess(t *testing.T) {
	if accessRoles != (Roles{StrictRead: "app_x_strict_read", StrictWrite: "app_x_strict_write", PrivilegedRead: "app_x_privileged_read", PrivilegedWrite: "app_x_privileged_write"}) {
		t.Fatalf("AccessRoles = %#v", accessRoles)
	}
	change := func(edit func(*Binding)) Binding {
		binding := strictBinding()
		edit(&binding)
		return binding
	}
	for name, test := range map[string]struct {
		binding           Binding
		roles             Roles
		read, write       string
		writeReach        string
		readErr, writeErr error
	}{
		"strict, access unnamed":        {strictBinding(), accessRoles, "app_x_strict_read", "app_x_strict_write", "s1,s2", nil, nil},
		"strict read-write":             {change(func(b *Binding) { b.Access = ReadWrite }), accessRoles, "app_x_strict_read", "app_x_strict_write", "s1,s2", nil, nil},
		"strict read":                   {change(func(b *Binding) { b.Access = Read }), accessRoles, "app_x_strict_read", "", "", nil, ErrReadOnly},
		"privileged read":               {change(func(b *Binding) { b.Mode, b.Access = Privileged, Read }), accessRoles, "app_x_privileged_read", "", "", nil, ErrReadOnly},
		"privileged read-write":         {change(func(b *Binding) { b.Mode = Privileged }), accessRoles, "app_x_privileged_read", "app_x_privileged_write", "s1,s2", nil, nil},
		"privileged read, strict write": {change(func(b *Binding) { b.Mode, b.WriteMode = Privileged, Strict }), accessRoles, "app_x_privileged_read", "app_x_strict_write", "s1,s2", nil, nil},
		"reads two scopes, writes one":  {change(func(b *Binding) { b.WriteReach = []string{"s2", "s2"} }), accessRoles, "app_x_strict_read", "app_x_strict_write", "s2", nil, nil},
		// The deprecated field still narrows, and is never overruled.
		"ReadOnly alone":             {change(func(b *Binding) { b.ReadOnly = true }), accessRoles, "app_x_strict_read", "", "", nil, ErrReadOnly},
		"ReadOnly against ReadWrite": {change(func(b *Binding) { b.ReadOnly, b.Access = true, ReadWrite }), accessRoles, "app_x_strict_read", "", "", nil, ErrReadOnly},
		// What a Read binding says about writing is still checked.
		"read with a wider write mode":  {change(func(b *Binding) { b.Access, b.WriteMode = Read, Privileged }), accessRoles, "", "", "", ErrWriteExceedsRead, ErrWriteExceedsRead},
		"strict read, privileged write": {change(func(b *Binding) { b.WriteMode = Privileged }), accessRoles, "", "", "", ErrWriteExceedsRead, ErrWriteExceedsRead},
		"write reach outside the reach": {change(func(b *Binding) { b.WriteReach = []string{"s1", "s3"} }), accessRoles, "", "", "", ErrWriteExceedsRead, ErrWriteExceedsRead},
		"write reach named and empty":   {change(func(b *Binding) { b.WriteReach = []string{} }), accessRoles, "", "", "", ErrNoReach, ErrNoReach},
		"write reach with a comma":      {change(func(b *Binding) { b.WriteReach = []string{"s1,s2"} }), accessRoles, "", "", "", ErrInvalidReach, ErrInvalidReach},
		"unknown access":                {change(func(b *Binding) { b.Access = 3 }), accessRoles, "", "", "", ErrUnknownAccess, ErrUnknownAccess},
		"unknown write mode":            {change(func(b *Binding) { b.WriteMode = 7 }), accessRoles, "", "", "", ErrUnknownMode, ErrUnknownMode},
		// A Store names only the roles its process runs.
		"a store of readers":         {strictBinding(), Roles{StrictRead: "r"}, "r", "", "", nil, ErrModeNotGranted},
		"a store of writers":         {strictBinding(), Roles{StrictWrite: "w"}, "", "w", "s1,s2", ErrModeNotGranted, nil},
		"no role for the write mode": {change(func(b *Binding) { b.Mode, b.WriteMode = Privileged, Strict }), Roles{PrivilegedRead: "r", PrivilegedWrite: "w"}, "r", "", "", nil, ErrModeNotGranted},
		// The two-role form: one role per mode for both, and nothing split.
		"two roles":                  {strictBinding(), testRoles, "app_x_strict", "app_x_strict", "s1,s2", nil, nil},
		"two roles, read":            {change(func(b *Binding) { b.Access = Read }), testRoles, "app_x_strict", "", "", nil, ErrReadOnly},
		"two roles, split mode":      {change(func(b *Binding) { b.Mode, b.WriteMode = Privileged, Strict }), testRoles, "app_x_privileged", "", "", nil, ErrSplitBinding},
		"two roles, split reach":     {change(func(b *Binding) { b.WriteReach = []string{"s1"} }), testRoles, "app_x_strict", "", "", nil, ErrSplitBinding},
		"two roles and a read role":  {strictBinding(), Roles{Strict: "both", StrictRead: "r"}, "r", "both", "s1,s2", nil, nil},
		"two roles and a write role": {change(func(b *Binding) { b.WriteReach = []string{"s1"} }), Roles{Strict: "both", StrictWrite: "w"}, "both", "w", "s1", nil, nil},
	} {
		t.Run(name, func(t *testing.T) {
			reader, writer := &fakeBeginner{tx: &fakeTransaction{}}, &fakeBeginner{tx: &fakeTransaction{}}
			store := newTestStore(t, reader, writer, FixedBinder(test.binding), test.roles)
			err := store.Read(context.Background(), func(context.Context, ReadTx) error { return nil })
			if !errors.Is(err, test.readErr) || (test.readErr == nil && err != nil) {
				t.Fatalf("read error = %v, want %v", err, test.readErr)
			}
			if test.readErr == nil {
				arguments := reader.tx.executions[0].arguments
				if arguments[10] != test.read || arguments[12] != "" || reader.options.AccessMode != pgx.ReadOnly {
					t.Fatalf("read assumed %v with write reach %q, want %q and none", arguments[10], arguments[12], test.read)
				}
			}
			err = store.Write(context.Background(), func(context.Context, WriteTx) error { return nil })
			if !errors.Is(err, test.writeErr) || (test.writeErr == nil && err != nil) {
				t.Fatalf("write error = %v, want %v", err, test.writeErr)
			}
			if test.writeErr != nil {
				if writer.beginCalls != 0 {
					t.Fatal("a refused write opened a transaction")
				}
				return
			}
			arguments := writer.tx.executions[0].arguments
			if arguments[10] != test.write || arguments[11] != "codefly.current_write_scopes" || arguments[12] != test.writeReach || arguments[5] != "s1,s2" {
				t.Fatalf("write assumed %v with write reach %q in reach %q, want %q and %q", arguments[10], arguments[12], arguments[5], test.write, test.writeReach)
			}
		})
	}
}

func TestStoreRolesMustBeDistinctAcrossModesAndAccesses(t *testing.T) {
	backend := &fakeBeginner{tx: &fakeTransaction{}}
	for name, roles := range map[string]Roles{
		"read is write":           {StrictRead: "one", StrictWrite: "one"},
		"read role of both modes": {StrictRead: "one", PrivilegedRead: "one"},
		"two-role form reused":    {Strict: "one", StrictRead: "one"},
		"reset keyword":           {PrivilegedRead: "none"},
	} {
		if _, err := newStore(backend, backend, FixedBinder(strictBinding()), roles); err == nil {
			t.Fatalf("%s: roles %#v accepted", name, roles)
		}
	}
}

// A capability carries the access it was minted with: the worker that replays
// it cannot write on a Read one, and cannot write wider than it recorded.
func TestCapabilityCarriesItsAccess(t *testing.T) {
	backend := &fakeBeginner{tx: &fakeTransaction{}}
	nobody := BinderFunc(func(context.Context) (Binding, error) { return Binding{}, errors.New("no call") })
	store := newTestStore(t, backend, backend, nobody, accessRoles)
	recorded := strictBinding()
	recorded.Mode, recorded.WriteMode, recorded.WriteReach = Privileged, Strict, []string{"s1"}
	capability, err := store.Capability(recorded)
	if err != nil {
		t.Fatal(err)
	}
	recorded.WriteReach[0] = "s2"
	if err := store.Write(capability.Context(context.Background()), func(context.Context, WriteTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if arguments := backend.tx.executions[0].arguments; arguments[10] != "app_x_strict_write" || arguments[12] != "s1" {
		t.Fatalf("capability bound %#v", arguments)
	}
	// One no transaction of this Store could honour is refused when minted.
	readers := newTestStore(t, backend, backend, nobody, Roles{PrivilegedRead: "r"})
	if _, err := readers.Capability(strictBinding()); !errors.Is(err, ErrModeNotGranted) {
		t.Fatalf("capability for a mode with no role: %v", err)
	}
}
