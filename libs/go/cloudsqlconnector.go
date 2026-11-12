package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cloud.google.com/go/cloudsqlconn"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/compute/metadata"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A Cloud SQL instance is reached through the connector rather than by
// address, and that is what removes the server's authority from the delivery
// path.
//
// Every other managed transport here has to be TOLD who the server is: a
// pinned authority (PinnedAuthorityTLS) is a certificate somebody resolved,
// copied into configuration and must re-deliver when it rotates. The
// connector asks instead. With the workload's own identity it calls the SQL
// Admin API — a Google endpoint verified against public roots — for the
// instance's current server authority and for a short-lived client
// certificate bound to that identity, then opens mutual TLS to the instance's
// private address and checks the certificate it is shown names the instance it
// asked for. So no anchor exists to deliver, mount, pin or let go stale, and
// with IAM authentication on, the login needs no password either: the server
// reads the principal from the client certificate's token.
//
// The process is a TLS CLIENT here. It terminates nothing and carries no
// authority of its own: everything it presents was issued to it minutes ago
// by the cloud, for the identity Kubernetes already gave the pod.

// cloudSQLConnectorHost is the host the driver is configured with. The
// connector ignores it — it dials the instance named by the profile — but pgx
// wants a host, and a reserved name that resolves nowhere (RFC 2606) means a
// pool built from this config without the connector's dial function installed
// fails rather than reaching anything.
const cloudSQLConnectorHost = "cloud-sql-connector.invalid"

// errNoCloudSQLDialer is what a pool built by ParseConnection alone reports:
// the configuration is valid, but only openCloudSQLPool installs the dialer.
var errNoCloudSQLDialer = errors.New("Cloud SQL connector capability opened without the connector: use OpenPool")

// errConnectorOpenPoolOnly refuses the connector where this package has not
// wired it: Open and OpenMaintenance build their pools without a dialer.
var errConnectorOpenPoolOnly = fmt.Errorf("%w: transport %q is opened by OpenPool only", ErrConnectionProfile, CloudSQLConnector)

// cloudSQLDialer is the slice of *cloudsqlconn.Dialer this package uses, so a
// test can stand in for the Admin API and the instance.
type cloudSQLDialer interface {
	Dial(ctx context.Context, instance string, options ...cloudsqlconn.DialOption) (net.Conn, error)
	Close() error
}

// newCloudSQLDialer builds the connector for the workload's own identity.
//
// Private IP only: the instances this serves have no public address, and a
// dialer allowed to fall back to one would turn a missing route into a
// connection attempt across the internet. IAM authentication on: the login is
// the workload's service account and there is no password. Built-in metrics
// off: the connector would otherwise export telemetry to the cloud's
// monitoring API, an outbound call and a grant this workload was never given.
var newCloudSQLDialer = func(ctx context.Context) (cloudSQLDialer, error) {
	return cloudsqlconn.NewDialer(ctx,
		cloudsqlconn.WithIAMAuthN(),
		cloudsqlconn.WithDefaultDialOptions(cloudsqlconn.WithPrivateIP()),
		cloudsqlconn.WithBuiltInMetrics(false),
	)
}

// cloudSQLWorkloadLogin is the Cloud SQL login of the workload's own service
// account: its email without the ".gserviceaccount.com" Cloud SQL strips.
var cloudSQLWorkloadLogin = func(ctx context.Context) (string, error) {
	email, err := metadata.EmailWithContext(ctx, "default")
	if err != nil {
		return "", fmt.Errorf("resolve the workload's own service account: %w", err)
	}
	login := strings.TrimSuffix(strings.TrimSpace(email), gcpServiceAccountSuffix)
	if !gcpSQLLoginPattern.MatchString(login) {
		return "", fmt.Errorf("the workload's own service account %q is not a Cloud SQL service-account login", elide(login))
	}
	return login, nil
}

// validateInstance holds a profile's Instance to its transport: required, and
// a well-formed connection name, for the connector; absent for every other
// transport, which reaches its server by host and would silently ignore it.
func (p ConnectionProfile) validateInstance() error {
	if p.Transport != CloudSQLConnector {
		if p.Instance != "" {
			return fmt.Errorf("%w: transport %q reaches its server by host and names no Cloud SQL instance", ErrConnectionProfile, p.Transport)
		}
		return nil
	}
	if p.Instance == "" {
		return fmt.Errorf("%w: transport %q dials an instance, and the profile names none", ErrConnectionProfile, p.Transport)
	}
	if _, err := instance.ParseConnName(p.Instance); err != nil {
		return fmt.Errorf("%w: %q is not a Cloud SQL connection name (project:region:instance)", ErrConnectionProfile, elide(p.Instance))
	}
	if p.Host != "" || p.Port != 0 {
		return fmt.Errorf("%w: transport %q is addressed by its instance, never by host or port", ErrConnectionProfile, p.Transport)
	}
	return nil
}

// parseCloudSQLConnection validates a connector URL — a login and a database,
// nothing else — and returns a driver configuration with its own TLS off and a
// dial function that refuses until openCloudSQLPool installs the connector's.
func parseCloudSQLConnection(connection string, profile ConnectionProfile, tokenHook bool) (*pgxpool.Config, error) {
	// The connector authenticates the login itself; a token hook would put an
	// access token in the password field of a connection that needs none.
	if tokenHook {
		return nil, ErrConnectionProfile
	}
	u, err := url.Parse(connection)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Opaque != "" || u.Fragment != "" || u.User == nil {
		return nil, ErrConnectionProfile
	}
	login := u.User.Username()
	database := strings.TrimPrefix(u.Path, "/")
	if _, hasPassword := u.User.Password(); hasPassword || u.Host != "" || login == "" || database == "" || !strings.HasPrefix(u.Path, "/") || strings.ContainsAny(database, "/\x00\r\n") || strings.ContainsAny(login, "\x00\r\n") {
		return nil, ErrConnectionProfile
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrConnectionProfile
	}
	for key, values := range q {
		if len(values) != 1 || strings.ContainsAny(values[0], "\x00\r\n") {
			return nil, ErrConnectionProfile
		}
		switch key {
		case "role":
			if profile.ApplicationRole == "" || values[0] != profile.ApplicationRole {
				return nil, ErrConnectionProfile
			}
		case "connect_timeout", "pool_max_conns", "pool_min_conns", "pool_min_idle_conns", "pool_max_conn_lifetime", "pool_max_conn_idle_time", "pool_health_check_period", "pool_max_conn_lifetime_jitter", "application_name":
		default:
			// sslmode, certificates, passfile, host and port included: each is
			// the connector's to decide, and a URL that states one is asking
			// for something this transport does not do.
			return nil, ErrConnectionProfile
		}
	}
	if q.Get("role") != profile.ApplicationRole {
		return nil, ErrConnectionProfile
	}
	if profile.Database != "" && database != profile.Database || profile.User != "" && login != profile.User {
		return nil, ErrConnectionProfile
	}
	for key, value := range map[string]string{"sslmode": "disable", "sslrootcert": "", "sslcert": "", "sslkey": "", "passfile": "/dev/null"} {
		q.Set(key, value)
	}
	u.Host = cloudSQLConnectorHost
	u.RawQuery = q.Encode()
	pc, err := pgxpool.ParseConfig(u.String())
	if err != nil {
		return nil, ErrConnectionProfile
	}
	c := pc.ConnConfig
	if c.Host != cloudSQLConnectorHost || c.Database != database || c.User != login || c.Password != "" || c.TLSConfig != nil || len(c.Fallbacks) != 0 {
		return nil, ErrConnectionProfile
	}
	for key, value := range c.RuntimeParams {
		if key == "role" && value == profile.ApplicationRole && profile.ApplicationRole != "" {
			continue
		}
		if key == "application_name" && value == q.Get(key) {
			continue
		}
		return nil, ErrConnectionProfile
	}
	// The host is never resolved and never dialled: the connector reaches the
	// instance by name. Until it is installed, connecting fails by saying so.
	c.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
	c.DialFunc = func(context.Context, string, string) (net.Conn, error) { return nil, errNoCloudSQLDialer }
	return pc, nil
}

// openCloudSQLPool is OpenPool for the connector transport.
//
// The login may be omitted from the URL (`postgres:///records`), and then it
// is the workload's own — the one login a pod's identity can authenticate as
// without an impersonation grant, and the one a deployment can name without
// knowing which service account the cell minted. A login that names another
// principal is refused: reaching it would need that principal's token, which
// this path does not mint.
func openCloudSQLPool(ctx context.Context, connection string, profile ConnectionProfile, configuration config) (*pgxpool.Pool, func(), error) {
	if err := profile.validate(); err != nil {
		return nil, nil, err
	}
	if configuration.accessTokenProvider != nil {
		return nil, nil, fmt.Errorf("%w: the Cloud SQL connector authenticates the login itself, and an access-token provider would authenticate it a second way", ErrExternalIdentity)
	}
	if configuration.externalIdentity != IssuerGCPCloudSQL {
		return nil, nil, fmt.Errorf("%w: transport %q requires the %q external identity, the credential the connector authenticates with", ErrExternalIdentity, CloudSQLConnector, IssuerGCPCloudSQL)
	}
	if configuration.operationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, configuration.operationTimeout)
		defer cancel()
	}
	connection, err := withWorkloadLogin(ctx, connection)
	if err != nil {
		return nil, nil, err
	}
	poolConfig, err := ParseConnection(connection, profile, false)
	if err != nil {
		return nil, nil, fmt.Errorf("parse Postgres capability: %w", err)
	}
	dialer, err := newCloudSQLDialer(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("start the Cloud SQL connector: %w", err)
	}
	instanceName := profile.Instance
	poolConfig.ConnConfig.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.Dial(ctx, instanceName, cloudsqlconn.WithPrivateIP())
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		_ = dialer.Close()
		return nil, nil, profileConnectionError(profile, fmt.Errorf("open Postgres capability: %w", err))
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		_ = dialer.Close()
		return nil, nil, profileConnectionError(profile, fmt.Errorf("ping Postgres capability: %w", err))
	}
	var once sync.Once
	return pool, func() {
		once.Do(func() {
			pool.Close()
			_ = dialer.Close()
		})
	}, nil
}

// withWorkloadLogin fills an omitted login with the workload's own and refuses
// one that names another principal.
func withWorkloadLogin(ctx context.Context, connection string) (string, error) {
	u, err := url.Parse(connection)
	if err != nil {
		return "", ErrConnectionProfile
	}
	own, err := cloudSQLWorkloadLogin(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrExternalIdentity, err)
	}
	if u.User == nil || u.User.Username() == "" {
		if u.User != nil {
			if _, hasPassword := u.User.Password(); hasPassword {
				return "", ErrConnectionProfile
			}
		}
		u.User = url.User(own)
		return u.String(), nil
	}
	if u.User.Username() != own {
		return "", fmt.Errorf("%w: the connection logs in as %q, but the workload is %q; the connector authenticates only the workload's own login", ErrExternalIdentity, elide(u.User.Username()), own)
	}
	return connection, nil
}

// CloudSQLSocket serves the instance on a private Unix socket for a process
// that cannot take a dial function — the migration runner's `migrate` child,
// which is handed a URL and opens its own connection.
//
// It is the connector's tunnel exposed in-process, not a proxy: the directory
// is created 0700 inside parent (which the caller owns and removes), so only
// this process's own user reaches it; every accepted connection is dialled
// through the connector as the workload's own identity, over private IP, with
// the instance's authority fetched from the cloud. What travels on the socket
// is the driver's plaintext, which never leaves the process's own filesystem.
// The URL to give a client is `postgres://<login>@/<database>?host=<dir>&sslmode=disable`.
//
// The returned closer stops accepting, closes every forwarded connection and
// the connector, and removes the socket. It is safe to call more than once.
func CloudSQLSocket(ctx context.Context, parent, instanceName string) (string, func() error, error) {
	if err := (ConnectionProfile{Transport: CloudSQLConnector, Instance: instanceName}).validate(); err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp(parent, "cloudsql-")
	if err != nil {
		return "", nil, fmt.Errorf("create the connector socket directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("restrict the connector socket directory: %w", err)
	}
	dialer, err := newCloudSQLDialer(ctx)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("start the Cloud SQL connector: %w", err)
	}
	socket := filepath.Join(dir, ".s.PGSQL.5432")
	// The limit libpq and the kernel share for a socket path; a longer parent
	// fails as an opaque bind error otherwise.
	if len(socket) > 103 {
		_ = dialer.Close()
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("the connector socket path %q is longer than a Unix socket allows; use a shorter parent", socket)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		_ = dialer.Close()
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("listen on the connector socket: %w", err)
	}
	serving, stop := context.WithCancel(context.Background())
	var open sync.WaitGroup
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			open.Add(1)
			go func() {
				defer open.Done()
				defer client.Close()
				server, err := dialer.Dial(serving, instanceName, cloudsqlconn.WithPrivateIP())
				if err != nil {
					return
				}
				defer server.Close()
				// Either side closing ends both, and a stopped socket closes
				// every connection it still forwards.
				done := make(chan struct{})
				defer close(done)
				go func() {
					select {
					case <-serving.Done():
						client.Close()
						server.Close()
					case <-done:
					}
				}()
				go func() { _, _ = io.Copy(server, client); server.Close() }()
				_, _ = io.Copy(client, server)
			}()
		}
	}()
	var once sync.Once
	var closeErr error
	return dir, func() error {
		once.Do(func() {
			stop()
			closeErr = listener.Close()
			open.Wait()
			if err := dialer.Close(); closeErr == nil {
				closeErr = err
			}
			if err := os.RemoveAll(dir); closeErr == nil {
				closeErr = err
			}
		})
		return closeErr
	}, nil
}
