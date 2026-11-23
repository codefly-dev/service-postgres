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
// the mode and the access as a database role assumed for the transaction.
// This package does not know what any of the six words means to an
// application. It installs them; the application's migrations write the
// policies that read them (package rowscope emits the standard ones).
//
// What it guarantees and what it does not is proved, claim by claim, in
// rowscope_spike_integration_test.go and
// rowscope_access_spike_integration_test.go. In one sentence: a statement sent
// as written cannot reach a row outside its Binding, and SQL that itself
// issues SET ROLE or set_config is not such a statement — except that no SQL
// can assume a role its login was not granted, which is what fences the mode
// and the access.

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
	// ErrModeNotGranted: this Store has no role for the mode and the access of
	// the transaction, or the pool's login may not assume it. Membership is a
	// catalog fact; nothing here can widen it.
	ErrModeNotGranted = fmt.Errorf("%w: this login may not assume the mode's role", ErrUnauthorized)
	// ErrReadOnly: the binding may not write.
	ErrReadOnly = fmt.Errorf("%w: this binding may not write", ErrUnauthorized)
	// ErrUnknownAccess: the binding's access is not one this package defines.
	ErrUnknownAccess = fmt.Errorf("%w: the binding has an unknown access", ErrUnauthorized)
	// ErrWriteExceedsRead: the binding would write where it may not read: a
	// write mode wider than its mode, or a write reach outside its reach.
	ErrWriteExceedsRead = fmt.Errorf("%w: the binding's writes exceed its reads", ErrUnauthorized)
	// ErrSplitBinding: the binding's writes are narrower than its reads, and
	// this Store's write role for the mode is the two-role form's, which
	// predates the write reach and has one role per mode.
	ErrSplitBinding = fmt.Errorf("%w: this store's two-role form cannot confine writes more narrowly than reads", ErrUnauthorized)
)

// Mode selects, with Access, which of the Store's roles a transaction assumes.
// There is no third value: crossing a partition is Maintenance, built from a different
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

// Access is whether a Binding may write at all. Like the mode it is decided
// before the Binding reaches this package, from what the admitted call is
// allowed to do, and like the mode it is a database role: a Read binding's
// transactions assume a role that holds SELECT and nothing else, so a write is
// refused with permission denied whether or not the transaction is READ ONLY.
type Access uint8

const (
	// Read may read and never write.
	Read Access = iota + 1
	// ReadWrite may also write, as far as WriteMode and WriteReach go.
	ReadWrite
)

func (access Access) String() string {
	switch access {
	case Read:
		return "read"
	case ReadWrite:
		return "read-write"
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
	// Reach is the scopes the transaction may read. An empty reach is
	// ErrNoReach.
	Reach []string
	// Mode is whose rows it reads. Required; the zero value is ErrUnknownMode.
	Mode Mode
	// Actor is who is executing, recorded for audit. No policy reads it.
	Actor string
	// Access is Read or ReadWrite. The zero value is what ReadOnly says, so a
	// Binding written before Access existed means what it meant.
	Access Access
	// WriteMode is whose rows it writes, when that is narrower than Mode: a
	// Privileged Binding with a Strict WriteMode reads every principal's rows
	// and writes its own. The zero value is Mode. Wider than Mode is
	// ErrWriteExceedsRead.
	WriteMode Mode
	// WriteReach is the scopes it may write, when that is fewer than Reach.
	// Nil is Reach. A scope outside Reach is ErrWriteExceedsRead; to write
	// nowhere, say Access: Read.
	WriteReach []string
	// ReadOnly is Access: Read, from before Access existed. It still wins over
	// an Access that says otherwise: a Binding is never widened by a field.
	//
	// Deprecated: set Access.
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
// mode and access. A read transaction assumes the mode's read role, which
// holds SELECT alone; a write transaction assumes the write role of the
// Binding's write mode. A Store names only the roles its process runs, and
// each of its logins should be granted only those: the reader's login the
// read roles, the writer's login the write roles, never both.
type Roles struct {
	// Strict and Privileged are the two-role form: one role per mode, assumed
	// for reads and writes alike wherever the mode's read or write role below
	// is not named. A store that created two roles keeps working with them; on
	// its reader pool READ ONLY is then the only thing that refuses a write,
	// and migrationtest.CheckRowScope reports what is missing.
	Strict     string
	Privileged string

	StrictRead      string
	StrictWrite     string
	PrivilegedRead  string
	PrivilegedWrite string
}

// AccessRoles returns the four roles of a store by the naming convention:
// <store>_strict_read, <store>_strict_write, <store>_privileged_read and
// <store>_privileged_write.
func AccessRoles(store string) Roles {
	return Roles{
		StrictRead: store + "_strict_read", StrictWrite: store + "_strict_write",
		PrivilegedRead: store + "_privileged_read", PrivilegedWrite: store + "_privileged_write",
	}
}

func firstNamed(names ...string) string {
	for _, name := range names {
		if name != "" {
			return name
		}
	}
	return ""
}

// read is the role a read transaction of the mode assumes.
func (roles Roles) read(mode Mode) string {
	switch mode {
	case Strict:
		return firstNamed(roles.StrictRead, roles.Strict)
	case Privileged:
		return firstNamed(roles.PrivilegedRead, roles.Privileged)
	default:
		return ""
	}
}

// write is the role a write transaction of the mode assumes. separate reports
// that it is a write role proper, which package rowscope binds to the write
// reach, and not the two-role form's.
func (roles Roles) write(mode Mode) (role string, separate bool) {
	switch mode {
	case Strict:
		return firstNamed(roles.StrictWrite, roles.Strict), roles.StrictWrite != ""
	case Privileged:
		return firstNamed(roles.PrivilegedWrite, roles.Privileged), roles.PrivilegedWrite != ""
	default:
		return "", false
	}
}

func (roles Roles) named() []string {
	var named []string
	for _, role := range []string{roles.Strict, roles.StrictRead, roles.StrictWrite, roles.Privileged, roles.PrivilegedRead, roles.PrivilegedWrite} {
		if role != "" {
			named = append(named, role)
		}
	}
	return named
}

func (roles Roles) validate() error {
	named := roles.named()
	if len(named) == 0 {
		return errors.New("a Postgres store requires the role of at least one mode")
	}
	for index, role := range named {
		for _, other := range named[:index] {
			if role == other {
				return fmt.Errorf("role %q is named twice: the roles of each mode and access must be distinct", role)
			}
		}
		// "none" is not a role: assuming it is RESET ROLE.
		if role != strings.TrimSpace(role) || len(role) > 63 || strings.ContainsRune(role, 0) || strings.EqualFold(role, "none") {
			return fmt.Errorf("mode role %q is not a role name", role)
		}
	}
	return nil
}

// WithWriteReachSetting changes the transaction-local setting a Store installs
// the write reach in. The default is "codefly.current_write_scopes". It is
// empty in every read transaction.
func WithWriteReachSetting(writeReachSetting string) Option {
	return func(configuration *config) error {
		if err := validateSettingName(writeReachSetting); err != nil {
			return fmt.Errorf("write reach setting: %w", err)
		}
		configuration.writeReachSetting = writeReachSetting
		return nil
	}
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
// differs in what it binds, a whole Binding and the role of its mode and
// access, and in who decides, a Binder.
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
		configuration.writeReachSetting,
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
// to it. Its transactions assume the read role of the Binding's mode, whatever
// the Binding's access: the reader's login is never granted a write role.
func (s *Store) Reader(ctx context.Context) (*Reader, error) {
	binding, err := s.bind(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := s.readScope(binding)
	if err != nil {
		return nil, err
	}
	return &Reader{beginner: s.reader, scope: scope, operationTimeout: s.config.operationTimeout, isolation: s.config.readIsolation}, nil
}

// Writer resolves the call's Binding and returns a write capability bound to
// it. Whether the call may write, as whom and where was decided with the
// Binding: a Read binding is ErrReadOnly, and the transaction assumes the
// write role of the Binding's write mode. What it reads inside a write
// transaction is what that role reads: in the Binding's whole reach, and in
// the write mode.
func (s *Store) Writer(ctx context.Context) (*Writer, error) {
	binding, err := s.bind(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := s.writeScope(binding)
	if err != nil {
		return nil, err
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
	normalized, err := normalizeBinding(binding)
	if err != nil {
		return nil, err
	}
	// A capability no transaction of this Store could ever honour is refused
	// where it is minted, not where it is replayed.
	_, readErr := s.readScope(normalized)
	_, writeErr := s.writeScope(normalized)
	if readErr != nil && writeErr != nil {
		return nil, readErr
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

func (s *Store) bind(ctx context.Context) (Binding, error) {
	if s == nil || isNil(s.binder) || ctx == nil {
		return Binding{}, ErrNoBinding
	}
	if bound, ok := ctx.Value(capabilityContextKey{}).(boundCapability); ok && bound.store == s {
		return normalizeBinding(bound.binding)
	}
	binding, err := s.binder.Bind(ctx)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrUnauthorized) {
			return Binding{}, err
		}
		return Binding{}, errors.Join(ErrNoBinding, err)
	}
	return normalizeBinding(binding)
}

// normalizeBinding validates a Binding and makes everything it leaves to a
// default explicit. Everything refused here is refused before a connection is
// acquired, and nothing here widens: a default is the narrower reading, except
// the access of a Binding that names none, which is what ReadOnly always meant.
func normalizeBinding(binding Binding) (Binding, error) {
	binding.Partition = strings.TrimSpace(binding.Partition)
	binding.Principal = strings.TrimSpace(binding.Principal)
	binding.Actor = strings.TrimSpace(binding.Actor)
	if binding.Partition == "" {
		if binding.Principal == "" && binding.Mode == 0 && len(binding.Reach) == 0 {
			return Binding{}, ErrNoBinding
		}
		return Binding{}, ErrNoPartition
	}
	kind, id, found := strings.Cut(binding.Principal, ":")
	if !found || id == "" || !isPrincipalKind(kind) {
		return Binding{}, ErrNoPrincipal
	}
	if binding.Mode != Strict && binding.Mode != Privileged {
		return Binding{}, ErrUnknownMode
	}
	reach, err := normalizeReach(binding.Reach)
	if err != nil {
		return Binding{}, err
	}
	if len(reach) == 0 {
		return Binding{}, ErrNoReach
	}
	binding.Reach = reach

	switch {
	case binding.Access > ReadWrite:
		return Binding{}, ErrUnknownAccess
	case binding.ReadOnly:
		binding.Access = Read
	case binding.Access == 0:
		binding.Access = ReadWrite
	}
	binding.ReadOnly = binding.Access == Read
	switch binding.WriteMode {
	case 0:
		binding.WriteMode = binding.Mode
	case Strict:
	case Privileged:
		if binding.Mode != Privileged {
			return Binding{}, ErrWriteExceedsRead
		}
	default:
		return Binding{}, ErrUnknownMode
	}
	writeReach := reach
	if binding.WriteReach != nil {
		if writeReach, err = normalizeReach(binding.WriteReach); err != nil {
			return Binding{}, err
		}
		for _, scope := range writeReach {
			if !contains(reach, scope) {
				return Binding{}, ErrWriteExceedsRead
			}
		}
		// A write reach that was named and is empty is a Binding that says it
		// may write and names nowhere to. That is a mistake, not a Read.
		if len(writeReach) == 0 && binding.Access == ReadWrite {
			return Binding{}, ErrNoReach
		}
	}
	binding.WriteReach = writeReach
	if binding.Access == Read {
		// What a Read binding says about writing is checked and then dropped.
		binding.WriteMode, binding.WriteReach = 0, nil
	}
	return binding, nil
}

func normalizeReach(scopes []string) ([]string, error) {
	reach := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope == "" || scope != strings.TrimSpace(scope) || strings.Contains(scope, ",") {
			return nil, ErrInvalidReach
		}
		if !contains(reach, scope) {
			reach = append(reach, scope)
		}
	}
	return reach, nil
}

func contains(scopes []string, scope string) bool {
	for _, kept := range scopes {
		if kept == scope {
			return true
		}
	}
	return false
}

// readScope is what a read transaction of a normalized Binding installs: the
// mode's read role, and no write reach at all.
func (s *Store) readScope(binding Binding) (transactionScope, error) {
	role := s.roles.read(binding.Mode)
	if role == "" {
		return transactionScope{}, ErrModeNotGranted
	}
	return s.transactionScope(binding, role, nil), nil
}

// writeScope is what a write transaction of a normalized Binding installs: the
// write mode's write role and the write reach.
func (s *Store) writeScope(binding Binding) (transactionScope, error) {
	if binding.Access != ReadWrite {
		return transactionScope{}, ErrReadOnly
	}
	role, separate := s.roles.write(binding.WriteMode)
	if role == "" {
		return transactionScope{}, ErrModeNotGranted
	}
	if !separate && (binding.WriteMode != binding.Mode || len(binding.WriteReach) != len(binding.Reach)) {
		return transactionScope{}, ErrSplitBinding
	}
	return s.transactionScope(binding, role, binding.WriteReach), nil
}

func (s *Store) transactionScope(binding Binding, role string, writeReach []string) transactionScope {
	_, id, _ := strings.Cut(binding.Principal, ":")
	return transactionScope{
		tenantSetting: s.config.tenantSetting,
		tenantID:      binding.Partition,
		// The setting existing policies read keeps its existing, bare value
		// until the last of them reads the principal reference instead.
		userSetting: s.config.userSetting,
		userID:      id,
		bound: &boundScope{
			reachSetting:      s.config.reachSetting,
			reach:             strings.Join(binding.Reach, ","),
			principalSetting:  s.config.principalSetting,
			principal:         binding.Principal,
			actorSetting:      s.config.actorSetting,
			actor:             binding.Actor,
			role:              role,
			writeReachSetting: s.config.writeReachSetting,
			writeReach:        strings.Join(writeReach, ","),
		},
	}
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
	// The write reach is installed in every transaction and is empty in a read
	// one, so a write policy that reads it fails closed there.
	writeReachSetting string
	writeReach        string
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

// installBinding is the one statement that binds a Store's transaction: six
// transaction-local settings and the role. The role is an ordinary setting, so
// this is SET LOCAL ROLE with the name as a parameter.
func installBinding(ctx context.Context, tx transaction, scope transactionScope) error {
	bound := scope.bound
	_, err := tx.Exec(ctx,
		`SELECT set_config($1, $2, true), set_config($3, $4, true), set_config($5, $6, true), set_config($7, $8, true), set_config($9, $10, true), set_config('role', $11, true), set_config($12, $13, true)`,
		scope.tenantSetting, scope.tenantID, scope.userSetting, scope.userID,
		bound.reachSetting, bound.reach, bound.principalSetting, bound.principal,
		bound.actorSetting, bound.actor, bound.role,
		bound.writeReachSetting, bound.writeReach,
	)
	if err == nil {
		return nil
	}
	// 42501: the login is not a member of the role with SET. 22023: there is
	// no such role. Either way the mode, or the access, is not this login's to
	// assume.
	var refused *pgconn.PgError
	if errors.As(err, &refused) && (refused.Code == "42501" || refused.Code == "22023") {
		return errors.Join(ErrModeNotGranted, err)
	}
	return err
}
