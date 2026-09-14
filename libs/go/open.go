package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Open constructs an authenticated database boundary from Codefly's distinct
// reader and writer connection capabilities. Raw pools remain private; the
// returned closer is safe to invoke more than once.
func Open(
	ctx context.Context,
	readOnlyConnection string,
	readWriteConnection string,
	authenticator Authenticator,
	options ...Option,
) (*Factory, func(), error) {
	if ctx == nil {
		return nil, nil, errors.New("scoped Postgres context is required")
	}
	configuration, err := configured(options...)
	if err != nil {
		return nil, nil, err
	}
	if configuration.operationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, configuration.operationTimeout)
		defer cancel()
	}
	readerConfig, writerConfig, err := capabilityConfigsWithProfiles(readOnlyConnection, readWriteConnection, configuration)
	if err != nil {
		return nil, nil, err
	}
	if configuration.accessTokenProvider != nil {
		installAccessTokenProvider(readerConfig, configuration.accessTokenProvider)
		installAccessTokenProvider(writerConfig, configuration.accessTokenProvider)
	}
	installRestrictedSession(readerConfig, configuration)
	installRestrictedSession(writerConfig, configuration)
	readerPool, err := pgxpool.NewWithConfig(ctx, readerConfig)
	if err != nil {
		return nil, nil, profileConnectionError(configuration.readerProfile, fmt.Errorf("open read-only Postgres capability: %w", err))
	}
	writerPool, err := pgxpool.NewWithConfig(ctx, writerConfig)
	if err != nil {
		readerPool.Close()
		return nil, nil, profileConnectionError(configuration.writerProfile, fmt.Errorf("open read-write Postgres capability: %w", err))
	}
	closePools := func() {
		readerPool.Close()
		writerPool.Close()
	}
	if err := readerPool.Ping(ctx); err != nil {
		closePools()
		return nil, nil, profileConnectionError(configuration.readerProfile, fmt.Errorf("ping read-only Postgres capability: %w", err))
	}
	if err := writerPool.Ping(ctx); err != nil {
		closePools()
		return nil, nil, profileConnectionError(configuration.writerProfile, fmt.Errorf("ping read-write Postgres capability: %w", err))
	}
	factory, err := NewFactory(readerPool, writerPool, authenticator, options...)
	if err != nil {
		closePools()
		return nil, nil, profileConnectionError(configuration.readerProfile, profileConnectionError(configuration.writerProfile, err))
	}
	var closeOnce sync.Once
	return factory, func() { closeOnce.Do(closePools) }, nil
}

func capabilityConfigs(readOnlyConnection, readWriteConnection string) (*pgxpool.Config, *pgxpool.Config, error) {
	return capabilityConfigsWithProfiles(readOnlyConnection, readWriteConnection, config{})
}

func capabilityConfigsWithProfiles(readOnlyConnection, readWriteConnection string, c config) (*pgxpool.Config, *pgxpool.Config, error) {
	if strings.TrimSpace(readOnlyConnection) == "" || strings.TrimSpace(readWriteConnection) == "" {
		return nil, nil, errors.New("distinct read-only and read-write Postgres connections are required")
	}
	readerConfig, err := ParseConnection(readOnlyConnection, c.readerProfile, c.accessTokenProvider != nil)
	if err != nil {
		return nil, nil, fmt.Errorf("parse read-only Postgres capability: %w", err)
	}
	writerConfig, err := ParseConnection(readWriteConnection, c.writerProfile, c.accessTokenProvider != nil)
	if err != nil {
		return nil, nil, fmt.Errorf("parse read-write Postgres capability: %w", err)
	}
	readerUser := strings.TrimSpace(readerConfig.ConnConfig.User)
	writerUser := strings.TrimSpace(writerConfig.ConnConfig.User)
	if readerUser == "" || writerUser == "" || readerUser == writerUser {
		return nil, nil, errors.New("read-only and read-write Postgres capabilities must use distinct database roles")
	}
	if c.distinctProxySockets && c.readerProfile.Transport == LocalIdentityProxy && c.writerProfile.Transport == LocalIdentityProxy && readerConfig.ConnConfig.Host == writerConfig.ConnConfig.Host {
		return nil, nil, ErrConnectionProfile
	}
	return readerConfig, writerConfig, nil
}
