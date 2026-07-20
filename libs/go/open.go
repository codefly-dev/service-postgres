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
	readerConfig, writerConfig, err := capabilityConfigs(readOnlyConnection, readWriteConnection)
	if err != nil {
		return nil, nil, err
	}
	readerPool, err := pgxpool.NewWithConfig(ctx, readerConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("open read-only Postgres capability: %w", err)
	}
	writerPool, err := pgxpool.NewWithConfig(ctx, writerConfig)
	if err != nil {
		readerPool.Close()
		return nil, nil, fmt.Errorf("open read-write Postgres capability: %w", err)
	}
	closePools := func() {
		readerPool.Close()
		writerPool.Close()
	}
	if err := readerPool.Ping(ctx); err != nil {
		closePools()
		return nil, nil, fmt.Errorf("ping read-only Postgres capability: %w", err)
	}
	if err := writerPool.Ping(ctx); err != nil {
		closePools()
		return nil, nil, fmt.Errorf("ping read-write Postgres capability: %w", err)
	}
	factory, err := NewFactory(readerPool, writerPool, authenticator, options...)
	if err != nil {
		closePools()
		return nil, nil, err
	}
	var closeOnce sync.Once
	return factory, func() { closeOnce.Do(closePools) }, nil
}

func capabilityConfigs(readOnlyConnection, readWriteConnection string) (*pgxpool.Config, *pgxpool.Config, error) {
	if strings.TrimSpace(readOnlyConnection) == "" || strings.TrimSpace(readWriteConnection) == "" {
		return nil, nil, errors.New("distinct read-only and read-write Postgres connections are required")
	}
	readerConfig, err := pgxpool.ParseConfig(readOnlyConnection)
	if err != nil {
		return nil, nil, fmt.Errorf("parse read-only Postgres capability: %w", err)
	}
	writerConfig, err := pgxpool.ParseConfig(readWriteConnection)
	if err != nil {
		return nil, nil, fmt.Errorf("parse read-write Postgres capability: %w", err)
	}
	readerUser := strings.TrimSpace(readerConfig.ConnConfig.User)
	writerUser := strings.TrimSpace(writerConfig.ConnConfig.User)
	if readerUser == "" || writerUser == "" || readerUser == writerUser {
		return nil, nil, errors.New("read-only and read-write Postgres capabilities must use distinct database roles")
	}
	return readerConfig, writerConfig, nil
}
