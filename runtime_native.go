package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// nativeOwnerRole is a database's migration owner on its run's shared server.
// The run's services all ship the same local POSTGRES_USER, and a server's
// roles are server-wide, so the owner is named after the database the way its
// runtime roles already are. Consumers receive it inside the owner connection
// string, as they received POSTGRES_USER.
func nativeOwnerRole(database string) string {
	return runtimeRolePrefix(database) + "_owner"
}

// initNative attaches this service to its run's server, gives it its database
// there, publishes its endpoint, and migrates — the native half of Init. A
// failure releases whatever it took, so a refused service holds no server.
func (s *Runtime) initNative(ctx context.Context, instance *basev0.NetworkInstance) (initErr error) {
	server, err := acquireRunServer(ctx,
		runServerKey(s.Identity.WorkspacePath, s.Environment.NamingScope),
		s.Unique(), s.LogLevel, newPGLogWriter(s.Wool))
	if err != nil {
		return err
	}
	s.nixRuntime = server
	defer func() {
		if initErr != nil {
			_, releaseErr := s.releaseNative(context.WithoutCancel(ctx))
			initErr = errors.Join(initErr, releaseErr)
		}
	}()
	if err := server.provisionDatabase(ctx, s.Unique(), s.DatabaseName, s.postgresUser, s.postgresPassword); err != nil {
		return err
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(instance.Port)))
	if server.forwarder, err = forwardToSocket(address, server.socketPath()); err != nil {
		return err
	}
	if s.extensionAdmin, err = withConnectTimeout(server.adminDSN(s.DatabaseName), s.Settings.Timeouts.connect()); err != nil {
		return err
	}
	s.retainedDataPath = server.dataDir
	s.released = false
	s.Wool.Debug("database ready on the run's native postgres server")
	return s.migrateOnInit(ctx)
}

// releaseNative closes this service's endpoint and releases its hold on the
// run's server, which stops when this was its last service. It returns what
// happened, for the Stop or Destroy result.
func (s *Runtime) releaseNative(ctx context.Context) (string, error) {
	stopped, err := s.nixRuntime.release(ctx)
	if err != nil {
		return "", fmt.Errorf("release the run's native postgres server: %w", err)
	}
	s.nixRuntime = nil
	s.extensionAdmin = ""
	s.released = true
	if stopped {
		return "stopped native postgres", nil
	}
	return "released this service's database; the run's native postgres server keeps serving its other services", nil
}

// extensionConnection is the connection extensions are created with.
func (s *Runtime) extensionConnection() string {
	if s.extensionAdmin != "" {
		return s.extensionAdmin
	}
	return s.connection
}
