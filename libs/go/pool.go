package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenPool opens one authenticated pool for one capability, and nothing else.
//
// It exists because every other constructor here is opinionated: Open splits a
// service across a reader and a writer and installs the scoped RLS factory,
// OpenMaintenance selects an application role and refuses a privileged login.
// A service that owns its own tenancy model — one runtime principal, its own
// authority on whose tenant a call is about — fits neither, and so wrote
// pgxpool.New itself. Four services in this fleet did, which is four copies of
// the transport and credential decisions this package already makes.
//
// So this is the primitive under the others, exposed: the profile decides the
// transport and the pinned authority, the options decide the credential, and the
// caller gets a pool whose first connection has already succeeded. It grants no
// role, installs no session policy and judges no privilege — a caller wanting
// those wants Open or OpenMaintenance.
//
// The returned closer is safe to call more than once.
func OpenPool(ctx context.Context, connection string, profile ConnectionProfile, options ...Option) (*pgxpool.Pool, func(), error) {
	if ctx == nil {
		return nil, nil, errors.New("Postgres context is required")
	}
	if connection == "" {
		return nil, nil, errors.New("Postgres connection is required")
	}
	configuration, err := configured(options...)
	if err != nil {
		return nil, nil, err
	}
	// Resolved before the configuration is parsed, because whether a credential
	// provider is installed decides whether a password in the URL is legal.
	if err := resolveExternalIdentity(ctx, &configuration); err != nil {
		return nil, nil, err
	}
	if configuration.operationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, configuration.operationTimeout)
		defer cancel()
	}
	poolConfig, err := ParseConnection(connection, profile, configuration.accessTokenProvider != nil)
	if err != nil {
		return nil, nil, fmt.Errorf("parse Postgres capability: %w", err)
	}
	if configuration.accessTokenProvider != nil {
		installAccessTokenProvider(poolConfig, configuration.accessTokenProvider)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, nil, profileConnectionError(profile, fmt.Errorf("open Postgres capability: %w", err))
	}
	// pgxpool connects lazily, so without this the first failure of a wrong
	// credential, an unverifiable server or an unreachable address would surface
	// at the first query rather than at boot, where it belongs.
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, profileConnectionError(profile, fmt.Errorf("ping Postgres capability: %w", err))
	}
	var once sync.Once
	return pool, func() { once.Do(pool.Close) }, nil
}
