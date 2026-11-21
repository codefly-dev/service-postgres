package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Row confinement. A Store binds every transaction to one Binding: the
// partition, the reach and the principal as transaction-local settings, and
// the mode as a database role assumed for the transaction. This package does
// not know what any of the five words means to an application. It installs
// them; the application's migrations write the policies that read them
// (package rowscope emits the standard ones).
//
// What it guarantees and what it does not is proved, claim by claim, in
// rowscope_spike_integration_test.go. In one sentence: a statement sent as
// written cannot reach a row outside its Binding, and SQL that itself issues
// SET ROLE or set_config is not such a statement.

var (
	// ErrNoBinding: nothing verified is bound to the context. It is also
	// ErrUnauthenticated, so an existing mapping to a transport code holds.
	ErrNoBinding = fmt.Errorf("%w: no binding on this context", ErrUnauthenticated)
	// ErrNoPartition: the binding names no partition.
	ErrNoPartition = fmt.Errorf("%w: the binding has an empty partition", ErrUnauthenticated)
	// ErrNoPrincipal: the binding names no principal, or not as "kind:id".
	ErrNoPrincipal = fmt.Errorf("%w: the binding's principal is not a kind:id reference", ErrUnauthenticated)
	// ErrUnknownMode: the binding's mode is not one this package defines. The
	// zero Mode is unknown on purpose: a Binding nobody decided opens nothing.
	ErrUnknownMode = fmt.Errorf("%w: the binding has an unknown mode", ErrUnauthorized)
	// ErrNoReach: the binding reaches no scope. It reaches nothing, never
	// everything, and no transaction is opened to find that out.
	ErrNoReach = fmt.Errorf("%w: the binding reaches no scope", ErrUnauthorized)
	// ErrInvalidReach: a scope in the reach is empty or cannot be carried in
	// the reach setting, which is a comma-separated list.
	ErrInvalidReach = fmt.Errorf("%w: a scope in the binding's reach is empty or contains a comma", ErrUnauthorized)
	// ErrModeNotGranted: this Store has no role for the mode, or its login may
	// not assume it. Membership is a catalog fact; nothing here can widen it.
	ErrModeNotGranted = fmt.Errorf("%w: this login may not assume the mode's role", ErrUnauthorized)
	// ErrReadOnly: the binding may not write.
	ErrReadOnly = fmt.Errorf("%w: this binding may not write", ErrUnauthorized)
)

// Mode selects which of the Store's two roles a transaction assumes. There is
// no third value: crossing a partition is Maintenance, built from a different
// connection at the composition root, and a Binding cannot spell it.
type Mode uint8

const (
	// Strict reaches the principal's own rows and the rows shared with a scope
	// in reach, and writes only its own.
	Strict Mode = iota + 1
	// Privileged reaches every principal's rows in the scopes in reach.
	Privileged
)

func (mode Mode) String() string {
	switch mode {
	case Strict:
		return "strict"
	case Privileged:
		return "privileged"
	default:
		return "unknown"
	}
}

// Binding is everything one transaction is confined to. It is decided before
// it reaches this package, by whatever adapts the application's verified
// caller: nothing here chooses a mode, and no repository is handed one.
type Binding struct {
	// Partition is the wall no transaction crosses. Required.
	Partition string
	// Principal is whose rows, as "kind:id". Required.
	Principal string
	// Reach is the scopes the transaction may touch. An empty reach is
	// ErrNoReach.
	Reach []string
	// Mode is required; the zero value is ErrUnknownMode.
	Mode Mode
	// Actor is who is executing, recorded for audit. No policy reads it.
	Actor string
	// ReadOnly refuses a Writer whatever the caller asks for.
	ReadOnly bool
}

// Binder resolves the already decided Binding of a call from its context.
type Binder interface {
	Bind(context.Context) (Binding, error)
}

// BinderFunc adapts a function to a Binder.
type BinderFunc func(context.Context) (Binding, error)

func (bind BinderFunc) Bind(ctx context.Context) (Binding, error) { return bind(ctx) }

// FixedBinder binds every context to one Binding. It is for tests and for a
// process that is one caller by construction; a request path derives its
// Binding per call.
func FixedBinder(binding Binding) Binder {
	binding.Reach = append([]string(nil), binding.Reach...)
	return BinderFunc(func(context.Context) (Binding, error) { return binding, nil })
}

// Roles names the NOLOGIN roles the application's migrations created, one per
// mode. A Store for a process that only ever runs one mode names that role
// alone, and its login should be granted that role alone.
type Roles struct {
	Strict     string
	Privileged string
}

func (roles Roles) of(mode Mode) string {
	switch mode {
	case Strict:
		return roles.Strict
	case Privileged:
		return roles.Privileged
	default:
		return ""
	}
}

func (roles Roles) validate() error {
	if roles.Strict == "" && roles.Privileged == "" {
		return errors.New("a Postgres store requires the role of at least one mode")
	}
	if roles.Strict == roles.Privileged {
		return errors.New("the strict and privileged roles must be distinct")
	}
	for _, role := range []string{roles.Strict, roles.Privileged} {
		// "none" is not a role: assuming it is RESET ROLE.
		if role != strings.TrimSpace(role) || len(role) > 63 || strings.ContainsRune(role, 0) || strings.EqualFold(role, "none") {
			return fmt.Errorf("mode role %q is not a role name", role)
		}
	}
	return nil
}

// WithBindingSettings changes the transaction-local settings a Store installs
// beside the two WithScopeSettings names: the reach, the principal reference
// and the actor. The defaults are "codefly.current_scopes",
// "codefly.current_principal" and "codefly.current_actor".
func WithBindingSettings(reachSetting, principalSetting, actorSetting string) Option {
	return func(configuration *config) error {
		for name, setting := range map[string]string{"reach": reachSetting, "principal": principalSetting, "actor": actorSetting} {
			if err := validateSettingName(setting); err != nil {
				return fmt.Errorf("%s setting: %w", name, err)
			}
		}
		configuration.reachSetting = reachSetting
		configuration.principalSetting = principalSetting
		configuration.actorSetting = actorSetting
		return nil
	}
}

// Store is the request-time database boundary of a row-confined store. Like
// Factory it owns the private reader and writer pools and exposes neither; it
// differs in what it binds, a whole Binding and its mode's role, and in who
// decides, a Binder.
type Store struct {
	reader transactionBeginner
	writer transactionBeginner
	binder Binder
	roles  Roles
	config config
}

// OpenStore constructs the boundary from Codefly's distinct reader and writer
// connections, exactly as Open does. Neither connection may select a startup
// role: a login that starts as a mode role holds that role's privileges with
// nothing bound, and RESET ROLE returns to it.
func OpenStore(
	ctx context.Context,
	readOnlyConnection string,
	readWriteConnection string,
	binder Binder,
	roles Roles,
	options ...Option,
) (*Store, func(), error) {
	if ctx == nil {
		return nil, nil, errors.New("scoped Postgres context is required")
	}
	if isNil(binder) {
		return nil, nil, errors.New("Postgres binder is required")
	}
	if err := roles.validate(); err != nil {
		return nil, nil, err
	}
	readerPool, writerPool, configuration, err := openCapabilityPools(ctx, readOnlyConnection, readWriteConnection, options...)
	if err != nil {
		return nil, nil, err
	}
	closePools := func() {
		readerPool.Close()
		writerPool.Close()
	}
	for _, pool := range []*pgxpool.Pool{readerPool, writerPool} {
		if pool.Config().ConnConfig.RuntimeParams["role"] != "" {
			closePools()
			return nil, nil, errors.New("a Postgres store connection must not select a startup role")
		}
	}
	store, err := NewStore(readerPool, writerPool, binder, roles, options...)
	if err != nil {
		closePools()
		return nil, nil, profileConnectionError(configuration.readerProfile, profileConnectionError(configuration.writerProfile, err))
	}
	var closeOnce sync.Once
	return store, func() { closeOnce.Do(closePools) }, nil
}

// NewStore binds preconfigured pools at a trusted composition boundary, like
// NewFactory. The caller owns their lifecycle and that their logins hold no
// table privilege of their own.
func NewStore(reader, writer *pgxpool.Pool, binder Binder, roles Roles, options ...Option) (*Store, error) {
	if reader == nil {
		return nil, errors.New("read-only Postgres pool is required")
	}
	if writer == nil {
		return nil, errors.New("read-write Postgres pool is required")
	}
	return newStore(poolBeginner{pool: reader}, poolBeginner{pool: writer}, binder, roles, options...)
}

func newStore(reader, writer transactionBeginner, binder Binder, roles Roles, options ...Option) (*Store, error) {
	if reader == nil || writer == nil {
		return nil, errors.New("Postgres transaction beginners are required")
	}
	if isNil(binder) {
		return nil, errors.New("Postgres binder is required")
	}
	if err := roles.validate(); err != nil {
		return nil, err
	}
	configuration, err := configured(options...)
	if err != nil {
		return nil, err
	}
	settings := []string{
		configuration.tenantSetting, configuration.userSetting,
		configuration.reachSetting, configuration.principalSetting, configuration.actorSetting,
	}
	for index, setting := range settings {
		for _, other := range settings[:index] {
			if setting == other {
				return nil, fmt.Errorf("binding setting %q is used twice", setting)
			}
		}
	}
	return &Store{reader: reader, writer: writer, binder: binder, roles: roles, config: configuration}, nil
}

// Reader resolves the call's Binding and returns a read-only capability bound
// to it.
func (s *Store) Reader(ctx context.Context) (*Reader, error) {
	_, scope, err := s.bind(ctx)
	if err != nil {
		return nil, err
	}
	return &Reader{beginner: s.reader, scope: scope, operationTimeout: s.config.operationTimeout, isolation: s.config.readIsolation}, nil
}

// Writer resolves the call's Binding and returns a write capability bound to
// it. Whether the call may write was decided with the Binding.
func (s *Store) Writer(ctx context.Context) (*Writer, error) {
	binding, scope, err := s.bind(ctx)
	if err != nil {
		return nil, err
	}
	if binding.ReadOnly {
		return nil, ErrReadOnly
	}
	return &Writer{beginner: s.writer, scope: scope, operationTimeout: s.config.operationTimeout}, nil
}

// Read runs fn in one read-only transaction bound to the call's Binding.
func (s *Store) Read(ctx context.Context, fn func(context.Context, ReadTx) error) error {
	reader, err := s.Reader(ctx)
	if err != nil {
		return err
	}
	return reader.InTransaction(ctx, fn)
}

// Write runs fn in one read-write transaction bound to the call's Binding.
func (s *Store) Write(ctx context.Context, fn func(context.Context, WriteTx) error) error {
	writer, err := s.Writer(ctx)
	if err != nil {
		return err
	}
	return writer.InTransaction(ctx, fn)
}

type capabilityContextKey struct{}

type boundCapability struct {
	store   *Store
	binding Binding
}

// Capability is an opaque Binding for work that has no call to derive one
// from: a job replaying the Binding its admission recorded. It is minted at a
// trusted composition root, can be attached to a context and cannot be
// inspected or altered, and one Store never honours another's.
type Capability struct {
	bound boundCapability
}

// Capability validates binding and returns it as an opaque capability of this
// Store.
func (s *Store) Capability(binding Binding) (*Capability, error) {
	if s == nil {
		return nil, errors.New("Postgres store is not configured")
	}
	normalized, _, err := s.scope(binding)
	if err != nil {
		return nil, err
	}
	return &Capability{bound: boundCapability{store: s, binding: normalized}}, nil
}

// Context binds the capability to ctx. Nil contexts become Background; a nil
// capability leaves the context unbound.
func (capability *Capability) Context(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if capability == nil || capability.bound.store == nil {
		return ctx
	}
	return context.WithValue(ctx, capabilityContextKey{}, capability.bound)
}

func (s *Store) bind(ctx context.Context) (Binding, transactionScope, error) {
	if s == nil || isNil(s.binder) || ctx == nil {
		return Binding{}, transactionScope{}, ErrNoBinding
	}
	if bound, ok := ctx.Value(capabilityContextKey{}).(boundCapability); ok && bound.store == s {
		return s.scope(bound.binding)
	}
	binding, err := s.binder.Bind(ctx)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrUnauthorized) {
			return Binding{}, transactionScope{}, err
		}
		return Binding{}, transactionScope{}, errors.Join(ErrNoBinding, err)
	}
	return s.scope(binding)
}

// scope validates a Binding and turns it into what one transaction installs.
// Everything refused here is refused before a connection is acquired.
func (s *Store) scope(binding Binding) (Binding, transactionScope, error) {
	binding.Partition = strings.TrimSpace(binding.Partition)
	binding.Principal = strings.TrimSpace(binding.Principal)
	binding.Actor = strings.TrimSpace(binding.Actor)
	if binding.Partition == "" {
		if binding.Principal == "" && binding.Mode == 0 && len(binding.Reach) == 0 {
			return Binding{}, transactionScope{}, ErrNoBinding
		}
		return Binding{}, transactionScope{}, ErrNoPartition
	}
	kind, id, found := strings.Cut(binding.Principal, ":")
	if !found || id == "" || !isPrincipalKind(kind) {
		return Binding{}, transactionScope{}, ErrNoPrincipal
	}
	if binding.Mode != Strict && binding.Mode != Privileged {
		return Binding{}, transactionScope{}, ErrUnknownMode
	}
	reach := make([]string, 0, len(binding.Reach))
	for _, scope := range binding.Reach {
		if scope == "" || scope != strings.TrimSpace(scope) || strings.Contains(scope, ",") {
			return Binding{}, transactionScope{}, ErrInvalidReach
		}
		duplicate := false
		for _, kept := range reach {
			duplicate = duplicate || kept == scope
		}
		if !duplicate {
			reach = append(reach, scope)
		}
	}
	if len(reach) == 0 {
		return Binding{}, transactionScope{}, ErrNoReach
	}
	binding.Reach = reach
	role := s.roles.of(binding.Mode)
	if role == "" {
		return Binding{}, transactionScope{}, ErrModeNotGranted
	}
	return binding, transactionScope{
		tenantSetting: s.config.tenantSetting,
		tenantID:      binding.Partition,
		// The setting existing policies read keeps its existing, bare value
		// until the last of them reads the principal reference instead.
		userSetting: s.config.userSetting,
		userID:      id,
		bound: &boundScope{
			reachSetting:     s.config.reachSetting,
			reach:            strings.Join(reach, ","),
			principalSetting: s.config.principalSetting,
			principal:        binding.Principal,
			actorSetting:     s.config.actorSetting,
			actor:            binding.Actor,
			role:             role,
		},
	}, nil
}

// boundScope is what a Store's transaction installs beyond the two settings
// every scoped transaction has.
type boundScope struct {
	reachSetting     string
	reach            string
	principalSetting string
	principal        string
	actorSetting     string
	actor            string
	role             string
}

func isPrincipalKind(kind string) bool {
	if kind == "" {
		return false
	}
	for _, character := range kind {
		if character < 'a' || character > 'z' {
			return false
		}
	}
	return true
}

// installBinding is the one statement that binds a Store's transaction: five
// transaction-local settings and the role. The role is an ordinary setting, so
// this is SET LOCAL ROLE with the name as a parameter.
func installBinding(ctx context.Context, tx transaction, scope transactionScope) error {
	bound := scope.bound
	_, err := tx.Exec(ctx,
		`SELECT set_config($1, $2, true), set_config($3, $4, true), set_config($5, $6, true), set_config($7, $8, true), set_config($9, $10, true), set_config('role', $11, true)`,
		scope.tenantSetting, scope.tenantID, scope.userSetting, scope.userID,
		bound.reachSetting, bound.reach, bound.principalSetting, bound.principal,
		bound.actorSetting, bound.actor, bound.role,
	)
	if err == nil {
		return nil
	}
	// 42501: the login is not a member of the role with SET. 22023: there is
	// no such role. Either way the mode is not this login's to assume.
	var refused *pgconn.PgError
	if errors.As(err, &refused) && (refused.Code == "42501" || refused.Code == "22023") {
		return errors.Join(ErrModeNotGranted, err)
	}
	return err
}
