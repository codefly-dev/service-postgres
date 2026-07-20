// Package postgres provides authenticated, transaction-scoped access to a
// Codefly Postgres service. It deliberately has no admin capability: schema
// ownership and cross-tenant maintenance belong to separately wired control
// plane dependencies, never to request handlers.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUnauthenticated = errors.New("postgres scope requires an authenticated principal")
	ErrUnauthorized    = errors.New("postgres write capability is not authorized")
)

// Principal is the minimal authenticated identity required by tenant RLS.
// Applications adapt their verified auth/proto identity to this interface at
// the request boundary; repositories never accept tenant or user IDs directly.
type Principal interface {
	DatabaseTenantID() string
	DatabaseUserID() string
}

// Authenticator resolves an already verified principal from context and owns
// the application-specific decision to issue a write capability.
type Authenticator interface {
	AuthenticatedPrincipal(context.Context) (Principal, error)
	AuthorizeDatabaseWrite(context.Context, Principal) error
}

// WorkloadIssuer decorates an application's request authenticator with
// server-owned background-work capabilities. Workload identity is carried by
// a private context value tied to this issuer instance, so external metadata
// and workload values issued by another composition root cannot forge it.
type WorkloadIssuer struct {
	requests Authenticator
}

type workloadContextKey struct{}

type workloadPrincipal struct {
	issuer   *WorkloadIssuer
	tenantID string
	userID   string
	writable bool
}

func (principal workloadPrincipal) DatabaseTenantID() string { return principal.tenantID }
func (principal workloadPrincipal) DatabaseUserID() string   { return principal.userID }

// Workload is an opaque database identity issued at a trusted composition
// root. Callers can bind it to a context but cannot inspect or alter its scope.
type Workload struct {
	principal workloadPrincipal
}

// NewWorkloadIssuer adds server workload identities to a verified request
// authenticator. Pass the issuer itself to NewFactory.
func NewWorkloadIssuer(requests Authenticator) (*WorkloadIssuer, error) {
	if isNil(requests) {
		return nil, errors.New("request authenticator is required")
	}
	return &WorkloadIssuer{requests: requests}, nil
}

// Issue creates a tenant/user-bound workload capability. writable=false is a
// read-only application capability even when the underlying writer pool exists.
func (issuer *WorkloadIssuer) Issue(tenantID, workloadID string, writable bool) (*Workload, error) {
	if issuer == nil || issuer.requests == nil {
		return nil, errors.New("workload issuer is not configured")
	}
	tenantID = strings.TrimSpace(tenantID)
	workloadID = strings.TrimSpace(workloadID)
	if tenantID == "" || workloadID == "" {
		return nil, errors.New("workload tenant and identity are required")
	}
	return &Workload{principal: workloadPrincipal{
		issuer: issuer, tenantID: tenantID, userID: "workload:" + workloadID, writable: writable,
	}}, nil
}

// Context binds the opaque workload to ctx. Nil contexts become Background;
// a nil workload leaves the context unauthenticated.
func (workload *Workload) Context(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if workload == nil || workload.principal.issuer == nil {
		return ctx
	}
	return context.WithValue(ctx, workloadContextKey{}, workload.principal)
}

func (issuer *WorkloadIssuer) AuthenticatedPrincipal(ctx context.Context) (Principal, error) {
	if issuer == nil || issuer.requests == nil || ctx == nil {
		return nil, ErrUnauthenticated
	}
	if principal, ok := ctx.Value(workloadContextKey{}).(workloadPrincipal); ok && principal.issuer == issuer && principal.tenantID != "" && principal.userID != "" {
		return principal, nil
	}
	return issuer.requests.AuthenticatedPrincipal(ctx)
}

func (issuer *WorkloadIssuer) AuthorizeDatabaseWrite(ctx context.Context, principal Principal) error {
	if issuer == nil || issuer.requests == nil {
		return ErrUnauthorized
	}
	if workload, ok := principal.(workloadPrincipal); ok && workload.issuer == issuer {
		if workload.writable {
			return nil
		}
		return errors.New("database workload has no write capability")
	}
	return issuer.requests.AuthorizeDatabaseWrite(ctx, principal)
}

var _ Authenticator = (*WorkloadIssuer)(nil)

// ReadTx intentionally exposes query operations only. Even if it is
// circumvented, the transaction and its dedicated credential are read-only at
// the database layer as defense in depth.
type ReadTx interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// WriteTx adds mutation to ReadTx. A writer may query to enforce invariants;
// a reader can never obtain Exec through this API.
type WriteTx interface {
	ReadTx
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	ScopedAdvisoryLock(context.Context, string, ...string) error
}

type config struct {
	tenantSetting    string
	userSetting      string
	operationTimeout time.Duration
}

// Option configures the RLS settings used by application policies.
type Option func(*config) error

// WithScopeSettings changes the transaction-local Postgres settings. Custom
// settings must use the extension-style namespace required by Postgres, e.g.
// "app.current_tenant_id" and "app.current_user_id".
func WithScopeSettings(tenantSetting, userSetting string) Option {
	return func(configuration *config) error {
		if err := validateSettingName(tenantSetting); err != nil {
			return fmt.Errorf("tenant setting: %w", err)
		}
		if err := validateSettingName(userSetting); err != nil {
			return fmt.Errorf("user setting: %w", err)
		}
		if tenantSetting == userSetting {
			return errors.New("tenant and user settings must be distinct")
		}
		configuration.tenantSetting = tenantSetting
		configuration.userSetting = userSetting
		return nil
	}
}

// WithOperationTimeout bounds each complete database transaction, including
// pool acquisition, scope installation, repository work, and commit. Callers
// keep control of policy by opting in; an earlier deadline already present on
// the request context always wins.
//
// This is intentionally an operation timeout rather than only a SQL statement
// timeout: a dead database or stale container port can otherwise block while
// acquiring a connection before Postgres ever receives a statement.
func WithOperationTimeout(timeout time.Duration) Option {
	return func(configuration *config) error {
		if timeout <= 0 {
			return errors.New("Postgres operation timeout must be positive")
		}
		configuration.operationTimeout = timeout
		return nil
	}
}

// Factory owns the private reader/writer pools and converts authenticated
// request context into bound capabilities. It never exposes either raw pool.
type Factory struct {
	reader        transactionBeginner
	writer        transactionBeginner
	authenticator Authenticator
	config        config
}

// NewFactory constructs the request-time database boundary. The pools must be
// built from Codefly's read-only-connection and read-write-connection secrets,
// respectively.
func NewFactory(reader, writer *pgxpool.Pool, authenticator Authenticator, options ...Option) (*Factory, error) {
	if reader == nil {
		return nil, errors.New("read-only Postgres pool is required")
	}
	if writer == nil {
		return nil, errors.New("read-write Postgres pool is required")
	}
	return newFactory(poolBeginner{pool: reader}, poolBeginner{pool: writer}, authenticator, options...)
}

func newFactory(reader, writer transactionBeginner, authenticator Authenticator, options ...Option) (*Factory, error) {
	if reader == nil || writer == nil {
		return nil, errors.New("Postgres transaction beginners are required")
	}
	if isNil(authenticator) {
		return nil, errors.New("Postgres authenticator is required")
	}
	configuration, err := configured(options...)
	if err != nil {
		return nil, err
	}
	return &Factory{
		reader:        reader,
		writer:        writer,
		authenticator: authenticator,
		config:        configuration,
	}, nil
}

// Reader resolves the authenticated principal and returns a bound read-only
// capability. It does not authorize or construct a writer.
func (f *Factory) Reader(ctx context.Context) (*Reader, error) {
	_, scope, err := f.principal(ctx)
	if err != nil {
		return nil, err
	}
	return &Reader{beginner: f.reader, scope: scope, operationTimeout: f.config.operationTimeout}, nil
}

// Writer resolves the authenticated principal and requires an explicit
// application authorization decision before returning a write capability.
func (f *Factory) Writer(ctx context.Context) (*Writer, error) {
	principal, scope, err := f.principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := f.authenticator.AuthorizeDatabaseWrite(ctx, principal); err != nil {
		return nil, errors.Join(ErrUnauthorized, err)
	}
	return &Writer{beginner: f.writer, scope: scope, operationTimeout: f.config.operationTimeout}, nil
}

// RequireTenant verifies that a tenant identity embedded in an immutable
// domain artifact matches the authenticated database scope. It does not return
// the scope and must never be used to construct SQL predicates; RLS remains
// the authority for row visibility and writes.
func (f *Factory) RequireTenant(ctx context.Context, tenantID string) error {
	_, scope, err := f.principal(ctx)
	if err != nil {
		return err
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(tenantID) != scope.tenantID {
		return errors.Join(ErrUnauthorized, errors.New("artifact tenant does not match authenticated database scope"))
	}
	return nil
}

// RequireUser verifies that a user identity embedded in an immutable domain
// artifact matches the authenticated database scope. Like RequireTenant, it
// performs no database access and must not be used to construct SQL scope;
// transaction-local settings and RLS remain authoritative.
func (f *Factory) RequireUser(ctx context.Context, userID string) error {
	_, scope, err := f.principal(ctx)
	if err != nil {
		return err
	}
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(userID) != scope.userID {
		return errors.Join(ErrUnauthorized, errors.New("artifact user does not match authenticated database scope"))
	}
	return nil
}

func (f *Factory) principal(ctx context.Context) (Principal, transactionScope, error) {
	if f == nil || isNil(f.authenticator) || ctx == nil {
		return nil, transactionScope{}, ErrUnauthenticated
	}
	principal, err := f.authenticator.AuthenticatedPrincipal(ctx)
	if err != nil {
		return nil, transactionScope{}, errors.Join(ErrUnauthenticated, err)
	}
	if isNil(principal) {
		return nil, transactionScope{}, ErrUnauthenticated
	}
	tenantID := strings.TrimSpace(principal.DatabaseTenantID())
	userID := strings.TrimSpace(principal.DatabaseUserID())
	if tenantID == "" || userID == "" {
		return nil, transactionScope{}, ErrUnauthenticated
	}
	return principal, transactionScope{
		tenantSetting: f.config.tenantSetting,
		tenantID:      tenantID,
		userSetting:   f.config.userSetting,
		userID:        userID,
	}, nil
}

// Reader is an authenticated, principal-bound read capability.
type Reader struct {
	beginner         transactionBeginner
	scope            transactionScope
	operationTimeout time.Duration
}

// InTransaction runs fn in a database-enforced read-only transaction after
// installing tenant/user scope with transaction-local settings.
func (r *Reader) InTransaction(ctx context.Context, fn func(context.Context, ReadTx) error) error {
	if fn == nil {
		return errors.New("read transaction callback is required")
	}
	return runTransaction(ctx, r.beginner, r.scope, r.operationTimeout, pgx.ReadOnly, func(ctx context.Context, tx transaction) error {
		return fn(ctx, readTx{tx: tx})
	})
}

// Writer is an authenticated, authorized, principal-bound write capability.
type Writer struct {
	beginner         transactionBeginner
	scope            transactionScope
	operationTimeout time.Duration
}

// InTransaction runs fn in a read-write transaction after installing
// transaction-local tenant/user scope.
func (w *Writer) InTransaction(ctx context.Context, fn func(context.Context, WriteTx) error) error {
	if fn == nil {
		return errors.New("write transaction callback is required")
	}
	return runTransaction(ctx, w.beginner, w.scope, w.operationTimeout, pgx.ReadWrite, func(ctx context.Context, tx transaction) error {
		return fn(ctx, writeTx{tx: tx, tenantSetting: w.scope.tenantSetting})
	})
}

type transactionScope struct {
	tenantSetting string
	tenantID      string
	userSetting   string
	userID        string
}

type transactionBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (transaction, error)
}

type transaction interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

type poolBeginner struct {
	pool *pgxpool.Pool
}

func (p poolBeginner) BeginTx(ctx context.Context, options pgx.TxOptions) (transaction, error) {
	return p.pool.BeginTx(ctx, options)
}

type readTx struct {
	tx transaction
}

func (r readTx) Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error) {
	return r.tx.Query(ctx, sql, arguments...)
}

func (r readTx) QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row {
	return r.tx.QueryRow(ctx, sql, arguments...)
}

type writeTx struct {
	tx            transaction
	tenantSetting string
}

func (w writeTx) Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error) {
	return w.tx.Query(ctx, sql, arguments...)
}

func (w writeTx) QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row {
	return w.tx.QueryRow(ctx, sql, arguments...)
}

func (w writeTx) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	return w.tx.Exec(ctx, sql, arguments...)
}

// ScopedAdvisoryLock serializes a logical resource inside the authenticated
// tenant without exposing that tenant to application code. Namespace and
// components are encoded as an unambiguous tuple before Postgres maps it onto
// its transaction-scoped 64-bit advisory-lock space.
func (w writeTx) ScopedAdvisoryLock(ctx context.Context, namespace string, components ...string) error {
	namespace = strings.TrimSpace(namespace)
	if ctx == nil || w.tx == nil || w.tenantSetting == "" || namespace == "" {
		return errors.New("scoped Postgres advisory lock requires a transaction, context, and namespace")
	}
	encoded, err := json.Marshal(components)
	if err != nil {
		return fmt.Errorf("encode scoped Postgres advisory lock: %w", err)
	}
	_, err = w.tx.Exec(ctx, `
		SELECT pg_advisory_xact_lock(hashtextextended(
			jsonb_build_array(
				NULLIF(current_setting($1, true), ''),
				$2::text,
				$3::jsonb
			)::text,
			0
		))
	`, w.tenantSetting, namespace, string(encoded))
	if err != nil {
		return fmt.Errorf("acquire scoped Postgres advisory lock: %w", err)
	}
	return nil
}

func runTransaction(
	ctx context.Context,
	beginner transactionBeginner,
	scope transactionScope,
	operationTimeout time.Duration,
	accessMode pgx.TxAccessMode,
	callback func(context.Context, transaction) error,
) error {
	if ctx == nil {
		return errors.New("scoped Postgres transaction context is required")
	}
	if operationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, operationTimeout)
		defer cancel()
	}
	tx, err := beginner.BeginTx(ctx, pgx.TxOptions{AccessMode: accessMode})
	if err != nil {
		return fmt.Errorf("begin scoped Postgres transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`SELECT set_config($1, $2, true), set_config($3, $4, true)`,
		scope.tenantSetting, scope.tenantID, scope.userSetting, scope.userID,
	); err != nil {
		return fmt.Errorf("install Postgres transaction scope: %w", err)
	}
	if err := callback(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit scoped Postgres transaction: %w", err)
	}
	return nil
}

func configured(options ...Option) (config, error) {
	configuration := config{
		tenantSetting: "codefly.current_tenant_id",
		userSetting:   "codefly.current_user_id",
	}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&configuration); err != nil {
			return config{}, err
		}
	}
	return configuration, nil
}

func validateSettingName(setting string) error {
	segments := strings.Split(setting, ".")
	if len(segments) < 2 {
		return fmt.Errorf("setting %q must contain a namespace", setting)
	}
	for _, segment := range segments {
		if segment == "" {
			return fmt.Errorf("setting %q contains an empty namespace segment", setting)
		}
		for _, character := range segment {
			if character == '_' ||
				(character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') {
				continue
			}
			return fmt.Errorf("setting %q contains an unsafe character", setting)
		}
	}
	return nil
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
