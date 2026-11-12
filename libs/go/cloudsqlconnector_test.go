package postgres

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn"
	"github.com/jackc/pgx/v5"
)

const testInstance = "obin-test-data:us-east1:obin-test-shared"

// fakeCloudSQLDialer stands in for the connector: it records what it was asked
// to dial and either refuses or forwards to a plaintext fixture server.
type fakeCloudSQLDialer struct {
	mu        sync.Mutex
	instances []string
	options   int
	closed    int
	forward   string
}

func (f *fakeCloudSQLDialer) Dial(ctx context.Context, instance string, options ...cloudsqlconn.DialOption) (net.Conn, error) {
	f.mu.Lock()
	f.instances = append(f.instances, instance)
	f.options = len(options)
	f.mu.Unlock()
	if f.forward == "" {
		return nil, errors.New("fake connector: refused")
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", f.forward)
}

func (f *fakeCloudSQLDialer) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

func withFakeConnector(t *testing.T, dialer *fakeCloudSQLDialer, login string) {
	t.Helper()
	previousDialer, previousLogin := newCloudSQLDialer, cloudSQLWorkloadLogin
	newCloudSQLDialer = func(context.Context) (cloudSQLDialer, error) { return dialer, nil }
	cloudSQLWorkloadLogin = func(context.Context) (string, error) { return login, nil }
	t.Cleanup(func() { newCloudSQLDialer, cloudSQLWorkloadLogin = previousDialer, previousLogin })
}

func connectorProfile() ConnectionProfile {
	return ConnectionProfile{Transport: CloudSQLConnector, Instance: testInstance}
}

func TestCloudSQLConnectorProfileNamesItsInstanceAndNothingElse(t *testing.T) {
	cases := map[string]ConnectionProfile{
		"no instance":         {Transport: CloudSQLConnector},
		"not a name":          {Transport: CloudSQLConnector, Instance: "10.87.0.7"},
		"two parts":           {Transport: CloudSQLConnector, Instance: "project:instance-only"},
		"host beside it":      {Transport: CloudSQLConnector, Instance: testInstance, Host: "10.87.0.7"},
		"port beside it":      {Transport: CloudSQLConnector, Instance: testInstance, Port: 5432},
		"an anchor beside it": {Transport: CloudSQLConnector, Instance: testInstance, ServerTrustAnchorPEM: "-----BEGIN CERTIFICATE-----"},
		"instance elsewhere":  {Transport: PinnedAuthorityTLS, Instance: testInstance},
	}
	for name, profile := range cases {
		t.Run(name, func(t *testing.T) {
			if err := profile.validate(); err == nil {
				t.Fatalf("%+v was accepted", profile)
			}
		})
	}
	if err := connectorProfile().validate(); err != nil {
		t.Fatalf("a connector profile naming its instance was refused: %v", err)
	}
}

func TestCloudSQLConnectorURLCarriesALoginAndADatabaseOnly(t *testing.T) {
	cleanProfileEnvironment(t)
	refused := map[string]string{
		"password":       "postgres://svc%40obin-test-data.iam:secret@/records",
		"host":           "postgres://svc%40obin-test-data.iam@10.87.0.7/records",
		"port":           "postgres://svc%40obin-test-data.iam@:5432/records",
		"no database":    "postgres://svc%40obin-test-data.iam@/",
		"no login":       "postgres:///records",
		"sslmode":        "postgres://svc%40obin-test-data.iam@/records?sslmode=verify-full",
		"plaintext":      "postgres://svc%40obin-test-data.iam@/records?sslmode=disable",
		"a trust anchor": "postgres://svc%40obin-test-data.iam@/records?sslrootcert=/etc/ca.pem",
		"a client cert":  "postgres://svc%40obin-test-data.iam@/records?sslcert=/etc/c.pem",
		"a passfile":     "postgres://svc%40obin-test-data.iam@/records?passfile=/dev/null",
		"a socket host":  "postgres://svc%40obin-test-data.iam@/records?host=/tmp",
		"an unknown key": "postgres://svc%40obin-test-data.iam@/records?target_session_attrs=any",
		"a stray role":   "postgres://svc%40obin-test-data.iam@/records?role=app_records",
	}
	for name, connection := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConnection(connection, connectorProfile(), false); err == nil {
				t.Fatalf("%s was accepted", connection)
			}
		})
	}
	if _, err := ParseConnection("postgres://svc%40obin-test-data.iam@/records", connectorProfile(), true); err == nil {
		t.Fatal("a token hook was accepted beside the connector, which authenticates the login itself")
	}

	config, err := ParseConnection("postgres://svc%40obin-test-data.iam@/records?application_name=records", connectorProfile(), false)
	if err != nil {
		t.Fatalf("a login and a database were refused: %v", err)
	}
	c := config.ConnConfig
	if c.User != "svc@obin-test-data.iam" || c.Database != "records" || c.Password != "" {
		t.Fatalf("parsed %q/%q with a password %t", c.User, c.Database, c.Password != "")
	}
	if c.TLSConfig != nil {
		t.Fatal("the driver negotiates its own TLS inside the connector's tunnel")
	}
	if c.Host != cloudSQLConnectorHost {
		t.Fatalf("host %q: a pool without the connector must reach nothing", c.Host)
	}
	if _, err := c.DialFunc(context.Background(), "tcp", "anything:5432"); !errors.Is(err, errNoCloudSQLDialer) {
		t.Fatalf("a config parsed without OpenPool dialled: %v", err)
	}
}

func TestCloudSQLConnectorIsOpenedByOpenPoolOnly(t *testing.T) {
	plain := ConnectionProfile{Transport: MeshProtected}
	if _, err := configured(WithConnectionProfiles(connectorProfile(), plain)); !errors.Is(err, ErrConnectionProfile) {
		t.Fatalf("Open accepted the connector without wiring it: %v", err)
	}
	if _, err := configured(WithMaintenanceConnectionProfile(connectorProfile())); !errors.Is(err, ErrConnectionProfile) {
		t.Fatalf("OpenMaintenance accepted the connector without wiring it: %v", err)
	}
}

func TestCloudSQLConnectorRequiresTheCloudSQLIdentity(t *testing.T) {
	cleanProfileEnvironment(t)
	dialer := &fakeCloudSQLDialer{}
	withFakeConnector(t, dialer, "svc@obin-test-data.iam")
	ctx := context.Background()
	for name, options := range map[string][]Option{
		"no identity":  nil,
		"azure":        {WithExternalIdentity(IssuerAzureEntra)},
		"a token hook": {WithExternalIdentity(IssuerGCPCloudSQL), WithAccessTokenProvider(func(context.Context, string) (string, error) { return "t", nil })},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := OpenPool(ctx, "postgres:///records", connectorProfile(), options...); !errors.Is(err, ErrExternalIdentity) {
				t.Fatalf("opened with %s: %v", name, err)
			}
		})
	}
	if len(dialer.instances) != 0 {
		t.Fatal("the connector dialled before the declaration was checked")
	}
}

func TestCloudSQLConnectorLogsInAsTheWorkloadOnly(t *testing.T) {
	cleanProfileEnvironment(t)
	dialer := &fakeCloudSQLDialer{}
	withFakeConnector(t, dialer, "svc@obin-test-data.iam")
	ctx := context.Background()
	_, _, err := OpenPool(ctx, "postgres://other%40obin-test-data.iam@/records", connectorProfile(), WithExternalIdentity(IssuerGCPCloudSQL))
	if !errors.Is(err, ErrExternalIdentity) || !strings.Contains(err.Error(), "own login") {
		t.Fatalf("another principal's login was attempted: %v", err)
	}

	// An omitted login is the workload's own, and the instance is dialled by
	// name over private IP. The fake refuses, so the boot fails as unavailable
	// and releases the connector.
	_, _, err = OpenPool(ctx, "postgres:///records", connectorProfile(), WithExternalIdentity(IssuerGCPCloudSQL))
	if !errors.Is(err, ErrConnectionUnavailable) {
		t.Fatalf("a refused dial reported %v", err)
	}
	if len(dialer.instances) == 0 || dialer.instances[0] != testInstance || dialer.options != 1 {
		t.Fatalf("dialled %v with %d options, want %s over private IP", dialer.instances, dialer.options, testInstance)
	}
	if dialer.closed != 1 {
		t.Fatalf("connector closed %d times after a failed boot", dialer.closed)
	}
}

// Run against a disposable local server that trusts the fixture login with no
// password: CLOUD_SQL_CONNECTOR_TEST_ADDR=127.0.0.1:<port>. The fake connector
// forwards to it in plaintext, standing in for the connector's tunnel, so this
// proves the driver speaks through the dialled connection as the workload's
// own login, with no password and no TLS of its own.
func TestCloudSQLConnectorPostgres(t *testing.T) {
	address := os.Getenv("CLOUD_SQL_CONNECTOR_TEST_ADDR")
	if address == "" {
		t.Skip("CLOUD_SQL_CONNECTOR_TEST_ADDR is required")
	}
	cleanProfileEnvironment(t)
	dialer := &fakeCloudSQLDialer{forward: address}
	withFakeConnector(t, dialer, "svc@obin-test-data.iam")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, closePool, err := OpenPool(ctx, "postgres:///records", connectorProfile(), WithExternalIdentity(IssuerGCPCloudSQL))
	if err != nil {
		t.Fatal(err)
	}
	var user, database string
	if err := pool.QueryRow(ctx, "SELECT current_user, current_database()").Scan(&user, &database); err != nil {
		t.Fatal(err)
	}
	if user != "svc@obin-test-data.iam" || database != "records" {
		t.Fatalf("connected as %s to %s", user, database)
	}
	closePool()
	closePool()
	if dialer.closed != 1 {
		t.Fatalf("connector closed %d times", dialer.closed)
	}
}

func TestCloudSQLSocketIsPrivateAndDialsTheInstance(t *testing.T) {
	dialer := &fakeCloudSQLDialer{}
	withFakeConnector(t, dialer, "svc@obin-test-data.iam")
	parent := shortTempDir(t)
	if _, _, err := CloudSQLSocket(context.Background(), parent, "10.87.0.7"); err == nil {
		t.Fatal("a socket was served for an address rather than an instance")
	}
	dir, closeSocket, err := CloudSQLSocket(context.Background(), parent, testInstance)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 || filepath.Dir(dir) != parent {
		t.Fatalf("socket directory %s is %v under %s, want 0700 inside the caller's directory", dir, info.Mode().Perm(), filepath.Dir(dir))
	}
	conn, err := net.Dial("unix", filepath.Join(dir, ".s.PGSQL.5432"))
	if err != nil {
		t.Fatal(err)
	}
	// The fake refuses, so the forwarded connection is closed at once.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a refused dial left the client connected")
	}
	conn.Close()
	if err := closeSocket(); err != nil {
		t.Fatal(err)
	}
	_ = closeSocket()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("the socket directory outlived its closer")
	}
	if len(dialer.instances) != 1 || dialer.instances[0] != testInstance || dialer.options != 1 || dialer.closed != 1 {
		t.Fatalf("dialled %v with %d options, closed %d times", dialer.instances, dialer.options, dialer.closed)
	}
}

// Gated like TestCloudSQLConnectorPostgres: a client that takes a URL — the
// migrate child's shape — reaches the server through the private socket.
func TestCloudSQLSocketPostgres(t *testing.T) {
	address := os.Getenv("CLOUD_SQL_CONNECTOR_TEST_ADDR")
	if address == "" {
		t.Skip("CLOUD_SQL_CONNECTOR_TEST_ADDR is required")
	}
	withFakeConnector(t, &fakeCloudSQLDialer{forward: address}, "svc@obin-test-data.iam")
	dir, closeSocket, err := CloudSQLSocket(context.Background(), shortTempDir(t), testInstance)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSocket()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, "postgres://svc%40obin-test-data.iam@/records?sslmode=disable&host="+dir)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	var user string
	if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&user); err != nil || user != "svc@obin-test-data.iam" {
		t.Fatalf("connected as %q: %v", user, err)
	}
}

// shortTempDir is a parent short enough for a Unix socket path on every
// platform the suite runs on (macOS allows 104 bytes; t.TempDir is longer).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sq")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
