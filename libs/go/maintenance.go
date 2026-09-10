package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithReadIsolation selects the snapshot semantics of read transactions only.
// Writer isolation remains unchanged; applications retain their locking rules.
func WithReadIsolation(level pgx.TxIsoLevel) Option {
	return func(c *config) error {
		switch level {
		case pgx.ReadCommitted, pgx.RepeatableRead, pgx.Serializable:
			c.readIsolation = level
			return nil
		default:
			return errors.New("unsupported Postgres read isolation")
		}
	}
}

// Maintenance is a service-owned capability for cross-tenant coordination.
// It is wired separately from authenticated request Factories and must never be
// passed to request handlers. It grants no privileges: application migrations
// and the owning service's role reconciler define its exact database access.
// There is no synthetic tenant and no admin/migration API or exposed pool.
type Maintenance struct {
	backend transactionBeginner
	config  config
}

// NewMaintenance binds a preconfigured pool at a trusted composition boundary,
// like NewFactory. The caller owns its lifecycle and privilege qualification.
// Deployments should prefer OpenMaintenance, which validates the login and role.
func NewMaintenance(pool *pgxpool.Pool, options ...Option) (*Maintenance, error) {
	if pool == nil {
		return nil, errors.New("maintenance Postgres pool is required")
	}
	c, err := configured(options...)
	if err != nil {
		return nil, err
	}
	return &Maintenance{backend: poolBeginner{pool: pool}, config: c}, nil
}

// OpenMaintenance selects an explicit application group through a service-owned
// connection capability. It rejects privileged logins, login-enabled application
// roles and database owners. It never creates roles or changes memberships.
func OpenMaintenance(ctx context.Context, connection, applicationRole string, options ...Option) (*Maintenance, func(), error) {
	if ctx == nil || strings.TrimSpace(connection) == "" || strings.TrimSpace(applicationRole) == "" {
		return nil, nil, errors.New("maintenance context, connection and application role are required")
	}
	c, err := configured(options...)
	if err != nil {
		return nil, nil, err
	}
	if c.operationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.operationTimeout)
		defer cancel()
	}
	pc, err := pgxpool.ParseConfig(connection)
	if err != nil {
		return nil, nil, errors.New("invalid maintenance Postgres connection")
	}
	if role := pc.ConnConfig.RuntimeParams["role"]; role != "" && role != applicationRole {
		return nil, nil, errors.New("maintenance application role conflicts with connection")
	}
	pc.ConnConfig.RuntimeParams["role"] = applicationRole
	if c.accessTokenProvider != nil {
		installAccessTokenProvider(pc, c.accessTokenProvider)
	}
	// Qualify each new backend, including after a reconnect or credential rotation.
	pc.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		var safe bool
		err := conn.QueryRow(ctx, `SELECT current_user=$1 AND NOT a.rolcanlogin
		 AND NOT (a.rolsuper OR a.rolcreatedb OR a.rolcreaterole OR a.rolreplication OR a.rolbypassrls)
		 AND NOT (l.rolsuper OR l.rolcreatedb OR l.rolcreaterole OR l.rolreplication OR l.rolbypassrls)
		 AND d.datdba NOT IN (a.oid,l.oid)
		 FROM pg_roles a, pg_roles l, pg_database d
		 WHERE a.rolname=current_user AND l.rolname=session_user AND d.datname=current_database()`, applicationRole).Scan(&safe)
		if err != nil {
			return errors.New("cannot qualify maintenance Postgres role")
		}
		if !safe {
			return errors.New("maintenance requires a restricted login and non-owner application group")
		}
		return nil
	}
	installRestrictedSession(pc, c)
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, nil, errors.New("cannot open maintenance Postgres capability")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, err
	}
	maintenance, err := NewMaintenance(pool, options...)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	var once sync.Once
	return maintenance, func() { once.Do(pool.Close) }, nil
}

func (m *Maintenance) scope() transactionScope {
	// Clear tenant/user settings transaction-locally, including when a connection
	// arrived with session defaults. RLS can authorize only the explicit role.
	return transactionScope{tenantSetting: m.config.tenantSetting, userSetting: m.config.userSetting}
}

func (m *Maintenance) Reader(ctx context.Context) (*Reader, error) {
	if m == nil || m.backend == nil || ctx == nil {
		return nil, ErrUnauthenticated
	}
	return &Reader{beginner: m.backend, scope: m.scope(), operationTimeout: m.config.operationTimeout, isolation: m.config.readIsolation}, nil
}

func (m *Maintenance) Writer(ctx context.Context) (*Writer, error) {
	if m == nil || m.backend == nil || ctx == nil {
		return nil, ErrUnauthorized
	}
	return &Writer{beginner: m.backend, scope: m.scope(), operationTimeout: m.config.operationTimeout}, nil
}
