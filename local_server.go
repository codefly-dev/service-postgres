package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/lib/pq"
	"google.golang.org/protobuf/proto"
)

const localServerConnectionKey = "local-server-connection"

// resolveLocalServer consumes only the mappings and configuration Codefly
// supplied for a declared dependency. In particular, there is no DSN setting,
// fixed port, discovery file or second process supervisor here.
func (s *Runtime) resolveLocalServer(ctx context.Context, req *runtimev0.InitRequest) (*basev0.NetworkMapping, string, error) {
	if len(strings.Split(s.LocalServer, "/")) != 2 || s.LocalServer == s.Unique() {
		return nil, "", fmt.Errorf("local-server must name another declared module/service dependency")
	}
	if s.externalIdentity() || s.KeepRunning || s.Image != "" {
		return nil, "", fmt.Errorf("local-server cannot be combined with external-identity, keep-running or docker-image: the dependency owns server authentication and execution")
	}
	if s.DatabaseName == "" || len(s.DatabaseName) > 63 || s.DatabaseName == "postgres" || strings.HasPrefix(s.DatabaseName, "template") {
		return nil, "", fmt.Errorf("local-server requires a non-system database name of at most 63 bytes")
	}
	var mapping *basev0.NetworkMapping
	for _, candidate := range req.DependenciesNetworkMappings {
		if candidate.GetEndpoint() != nil && resources.ServiceUniqueFromEndpoint(candidate.Endpoint) == s.LocalServer {
			if mapping != nil {
				return nil, "", fmt.Errorf("local-server dependency must expose exactly one database endpoint")
			}
			mapping = candidate
		}
	}
	if mapping == nil {
		return nil, "", fmt.Errorf("local-server %q has no declared dependency mapping", s.LocalServer)
	}
	native := resources.FilterNetworkInstance(ctx, mapping.Instances, resources.NewNativeNetworkAccess())
	if native == nil {
		return nil, "", fmt.Errorf("local-server has no native mapping for bootstrap")
	}
	var connection string
	for _, configuration := range resources.FilterConfigurations(req.DependenciesConfigurations, resources.NewRuntimeContextNative()) {
		if configuration.Origin != s.LocalServer {
			continue
		}
		if connection != "" {
			return nil, "", fmt.Errorf("local-server has ambiguous native configuration")
		}
		value, err := resources.GetConfigurationValue(ctx, configuration, "postgres", localServerConnectionKey)
		if err != nil {
			return nil, "", err
		}
		connection = value
	}
	parsed, err := url.Parse(connection)
	if err != nil || parsed == nil || parsed.Scheme != "postgresql" || parsed.User == nil || parsed.Host != native.Address || parsed.Path == "" {
		return nil, "", fmt.Errorf("local-server requires its owner's exported connection matching the resolved native mapping; borrowing from another logical database is not supported")
	}
	if parsed.User.Username() == s.postgresUser || strings.TrimPrefix(parsed.Path, "/") == s.DatabaseName {
		return nil, "", fmt.Errorf("local-server requires a distinct database and POSTGRES_USER; the server owner's identity cannot be reused")
	}
	return mapping, connection, nil
}

func (s *Runtime) initOnLocalServer(ctx context.Context, req *runtimev0.InitRequest) (*runtimev0.InitResponse, error) {
	s.released = true // Failed Init must never permit Start against a partial schema.
	if err := s.LoadConfiguration(ctx, req.Configuration); err != nil {
		return s.Runtime.InitError(err)
	}
	mapping, bootstrap, err := s.resolveLocalServer(ctx, req)
	if err != nil {
		return s.Runtime.InitError(err)
	}
	// Keep this service's logical endpoint identity; accept the dependency's
	// concrete mappings for every consumer network (native and container).
	own := proto.Clone(mapping).(*basev0.NetworkMapping)
	own.Endpoint = proto.Clone(s.TcpEndpoint).(*basev0.Endpoint)
	s.NetworkMappings = []*basev0.NetworkMapping{own}
	s.Runtime.RuntimeConfigurations = nil
	for _, instance := range own.Instances {
		configuration, err := s.CreateConnectionConfiguration(ctx, req.Configuration, instance, false)
		if err != nil {
			return s.Runtime.InitError(err)
		}
		s.Runtime.RuntimeConfigurations = append(s.Runtime.RuntimeConfigurations, configuration)
	}
	native := resources.FilterNetworkInstance(ctx, own.Instances, resources.NewNativeNetworkAccess())
	owner, err := s.createOwnerConnectionString(ctx, req.Configuration, native.Address, false)
	if err != nil {
		return s.Runtime.InitError(err)
	}
	s.connection, err = withConnectTimeout(owner, s.Timeouts.connect())
	if err != nil {
		return s.Runtime.InitError(err)
	}
	bootstrap, err = withConnectTimeout(bootstrap, s.Timeouts.connect())
	if err != nil {
		return s.Runtime.InitError(err)
	}
	if err = s.provisionLocalDatabase(ctx, bootstrap); err != nil {
		return s.Runtime.InitError(err)
	}
	s.released = false
	return s.Runtime.InitResponse()
}

// The server owner remains the only lifecycle owner. A cluster-wide lock in
// that owner's database serializes role claims across concurrent borrowers;
// migrations retain their existing per-database advisory lock as well.
func (s *Runtime) provisionLocalDatabase(ctx context.Context, bootstrap string) error {
	db, err := sql.Open("postgres", bootstrap)
	if err != nil {
		return fmt.Errorf("open local server bootstrap: %w", err)
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("connect local server bootstrap: %w", err)
	}
	defer conn.Close()
	lockCtx, cancelLock := context.WithTimeout(ctx, s.Timeouts.migrationLock())
	_, err = conn.ExecContext(lockCtx, `SELECT pg_advisory_lock(193, 1)`)
	cancelLock()
	if err != nil {
		return fmt.Errorf("local-server role allocation lock: %w", err)
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// This pool belongs only to this operation; closing it also releases the
		// session lock if an expired context prevented explicit unlock.
		_, _ = conn.ExecContext(releaseCtx, `SELECT pg_advisory_unlock(193, 1)`)
	}()
	var version int
	if err = conn.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::integer / 10000`).Scan(&version); err != nil {
		return err
	}
	var expected int
	if _, err = fmt.Sscanf(image.Tag, "postgres-%d", &expected); err != nil {
		return err
	}
	if version != expected {
		return fmt.Errorf("local-server PostgreSQL major %d differs from agent's required major %d", version, expected)
	}
	roles, err := s.localDatabaseRoles()
	if err != nil {
		return err
	}
	marker := "codefly-local-database:" + s.Unique() + ":" + s.DatabaseName
	// Durable claims survive interruption between CREATE DATABASE, migrations
	// and grants. A failed/dirty migration does not surrender its role names.
	if _, err = conn.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS codefly_local_server;
 CREATE TABLE IF NOT EXISTS codefly_local_server.roles (name text PRIMARY KEY, owner text NOT NULL);
 REVOKE ALL ON SCHEMA codefly_local_server FROM PUBLIC;
 REVOKE ALL ON codefly_local_server.roles FROM PUBLIC`); err != nil {
		return err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, role := range roles {
		var claim string
		err = tx.QueryRowContext(ctx, `SELECT owner FROM codefly_local_server.roles WHERE name=$1`, role).Scan(&claim)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == nil && claim != marker {
			return fmt.Errorf("local-server role %q is already claimed by another database", role)
		}
		if err == sql.ErrNoRows {
			var exists bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return fmt.Errorf("local-server role %q already exists outside this database's claim", role)
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO codefly_local_server.roles(name, owner) VALUES ($1, $2)`, role, marker); err != nil {
				return err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	// Migration owners are privileged local bootstrap identities, as on the
	// existing owned-server path. Application consumers still receive only the
	// distinct managed reader/writer logins. Never use owner-connection in apps.
	var ownerExists bool
	if err = conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)`, s.postgresUser).Scan(&ownerExists); err != nil {
		return err
	}
	if !ownerExists {
		if _, err = conn.ExecContext(ctx, `CREATE ROLE `+pq.QuoteIdentifier(s.postgresUser)+` LOGIN SUPERUSER`); err != nil {
			return err
		}
	}
	if _, err = conn.ExecContext(ctx, `ALTER ROLE `+pq.QuoteIdentifier(s.postgresUser)+` PASSWORD `+pq.QuoteLiteral(s.postgresPassword)); err != nil {
		return err
	}
	var owner string
	err = conn.QueryRowContext(ctx, `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=$1`, s.DatabaseName).Scan(&owner)
	if err == sql.ErrNoRows {
		_, err = conn.ExecContext(ctx, `CREATE DATABASE `+pq.QuoteIdentifier(s.DatabaseName)+` OWNER `+pq.QuoteIdentifier(s.postgresUser))
	} else if err == nil && owner != s.postgresUser {
		return fmt.Errorf("local-server database %q belongs to another owner", s.DatabaseName)
	}
	if err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, `REVOKE ALL ON DATABASE `+pq.QuoteIdentifier(s.DatabaseName)+` FROM PUBLIC`); err != nil {
		return err
	}
	return s.migrateOnInit(ctx)
}

func (s *Runtime) localDatabaseRoles() ([]string, error) {
	reader, writer, err := s.runtimeAccess()
	if err != nil {
		return nil, err
	}
	roles := []string{s.postgresUser, reader, writer}
	delegated, err := normalizedRuntimeReadWriteRoles(s.RuntimeReadWriteRoles, reader, writer)
	if err != nil {
		return nil, err
	}
	roles = append(roles, delegated...)
	logins, err := s.runtimeLogins()
	if err != nil {
		return nil, err
	}
	for _, login := range logins {
		roles = append(roles, login.role)
		roles = append(roles, login.readWriteRoles...)
	}
	seen := map[string]bool{}
	result := []string{}
	for _, role := range roles {
		if role == "" || len(role) > 63 || strings.HasPrefix(role, "pg_") {
			return nil, fmt.Errorf("local-server role names must be non-system identifiers of at most 63 bytes")
		}
		if !seen[role] {
			seen[role] = true
			result = append(result, role)
		}
	}
	return result, nil
}

// Once an owned server is explicitly shared, its database must also require
// explicit CONNECT grants, just like the borrowed databases. Existing managed
// runtime grants are retained; no database or table content is deleted.
func (s *Runtime) restrictLocalDatabase(ctx context.Context) error {
	db, err := sql.Open("postgres", s.connection)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, `REVOKE ALL ON DATABASE `+pq.QuoteIdentifier(s.DatabaseName)+` FROM PUBLIC`)
	return err
}
