package postgres

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Run with qualification/connection-profiles/run.py. Its database, certificate,
// roles and passwords are disposable local fixtures, never provider identities.
func TestConnectionProfilesPostgres(t *testing.T) {
	dsn := os.Getenv("CONNECTION_PROFILE_TEST_DSN")
	if dsn == "" {
		t.Skip("CONNECTION_PROFILE_TEST_DSN is required")
	}
	cleanProfileEnvironment(t)
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Query().Get("sslmode") != "verify-full" {
		t.Fatal("requires isolated loopback TLS fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE ROLE profile_reader LOGIN NOINHERIT PASSWORD 'fixture-first';
CREATE ROLE profile_writer LOGIN NOINHERIT PASSWORD 'fixture-first';
CREATE ROLE profile_maintenance LOGIN NOINHERIT PASSWORD 'fixture-first';
CREATE ROLE profile_request NOLOGIN NOINHERIT;
CREATE ROLE profile_jobs NOLOGIN NOINHERIT;
GRANT profile_request TO profile_writer;
GRANT profile_jobs TO profile_maintenance;
CREATE TABLE profile_rows(tenant text NOT NULL, payload text NOT NULL);
INSERT INTO profile_rows VALUES ('tenant-a','a'),('tenant-b','b');
ALTER TABLE profile_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile_rows FORCE ROW LEVEL SECURITY;
GRANT SELECT ON profile_rows TO profile_reader;
GRANT SELECT,INSERT ON profile_rows TO profile_request;
GRANT SELECT,INSERT,UPDATE,DELETE ON profile_rows TO profile_jobs;
CREATE POLICY profile_scope ON profile_rows TO profile_reader,profile_request USING(tenant=current_setting('scope.tenant',true)) WITH CHECK(tenant=current_setting('scope.tenant',true));
CREATE POLICY profile_background ON profile_rows TO profile_jobs USING(true) WITH CHECK(true);`)
	var password atomic.Value
	password.Store("fixture-first")
	var calls atomic.Int64
	provider := func(_ context.Context, principal string) (string, error) {
		if principal != "profile_reader" && principal != "profile_writer" && principal != "profile_maintenance" {
			t.Error("unexpected physical login")
		}
		calls.Add(1)
		return password.Load().(string), nil
	}
	connection := func(login, role string, transport ConnectionTransport) string {
		out := *u
		out.User = url.User(login)
		q := out.Query()
		if role != "" {
			q.Set("role", role)
		}
		if transport == LocalIdentityProxy {
			out.Host = ""
			q = url.Values{"host": {os.Getenv("CONNECTION_PROFILE_TEST_SOCKET")}, "port": {u.Port()}, "sslmode": {"disable"}, "passfile": {"/dev/null"}}
			if role != "" {
				q.Set("role", role)
			}
		}
		out.RawQuery = q.Encode()
		return out.String()
	}
	for _, transport := range []ConnectionTransport{VerifiedTLS, LocalIdentityProxy} {
		t.Run(string(transport), func(t *testing.T) {
			readerProfile := ConnectionProfile{Transport: transport}
			writerProfile := ConnectionProfile{Transport: transport, ApplicationRole: "profile_request"}
			maintenanceProfile := ConnectionProfile{Transport: transport, ApplicationRole: "profile_jobs"}
			opts := []Option{WithConnectionProfiles(readerProfile, writerProfile), WithScopeSettings("scope.tenant", "scope.user"), WithRestrictedSession("profile_jobs"), WithOperationTimeout(3 * time.Second)}
			maintOpts := []Option{WithMaintenanceConnectionProfile(maintenanceProfile), WithRestrictedSession(), WithScopeSettings("scope.tenant", "scope.user"), WithOperationTimeout(3 * time.Second)}
			if transport == VerifiedTLS {
				opts = append(opts, WithAccessTokenProvider(provider))
				maintOpts = append(maintOpts, WithAccessTokenProvider(provider))
			}
			factory, close, err := Open(ctx, connection("profile_reader", "", transport), connection("profile_writer", "profile_request", transport), fakeAuthenticator{principal: testPrincipal{tenant: "tenant-a", user: "user-a"}}, opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer close()
			if err := factory.RequireTenant(ctx, "tenant-b"); err == nil {
				t.Fatal("cross-tenant scope accepted")
			}
			reader, err := factory.Reader(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.InTransaction(ctx, func(ctx context.Context, tx ReadTx) error {
				var n int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM profile_rows").Scan(&n); err != nil {
					return err
				}
				if n != 1 {
					t.Fatal("request RLS leaked rows", n)
				}
				var current, session, tenant, user string
				if err := tx.QueryRow(ctx, "SELECT current_user,session_user,current_setting('scope.tenant'),current_setting('scope.user')").Scan(&current, &session, &tenant, &user); err != nil {
					return err
				}
				if current != "profile_reader" || session != current || tenant != "tenant-a" || user != "user-a" {
					t.Fatal("parsed reader identity/scope changed")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			writer, err := factory.Writer(ctx)
			if err != nil {
				t.Fatal(err)
			}
			checkWriter := func() error {
				return writer.InTransaction(ctx, func(ctx context.Context, tx WriteTx) error {
					var current, session string
					if err := tx.QueryRow(ctx, "SELECT current_user,session_user").Scan(&current, &session); err != nil {
						return err
					}
					if current != "profile_request" || session != "profile_writer" {
						t.Fatal("parsed writer role changed")
					}
					return nil
				})
			}
			if err := checkWriter(); err != nil {
				t.Fatal(err)
			}
			if err := writer.InTransaction(ctx, func(ctx context.Context, tx WriteTx) error {
				_, err := tx.Exec(ctx, "INSERT INTO profile_rows VALUES ('tenant-b','forbidden')")
				return err
			}); err == nil {
				t.Fatal("cross-tenant write accepted")
			}
			if err := writer.InTransaction(ctx, func(ctx context.Context, tx WriteTx) error {
				_, err := tx.Exec(ctx, "SET LOCAL ROLE profile_jobs")
				return err
			}); err == nil {
				t.Fatal("request could assume maintenance")
			}
			if transport == VerifiedTLS {
				before := calls.Load()
				exec("ALTER ROLE profile_reader PASSWORD 'fixture-second'; ALTER ROLE profile_writer PASSWORD 'fixture-second'; ALTER ROLE profile_maintenance PASSWORD 'fixture-second';")
				password.Store("fixture-second")
				exec("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename IN ('profile_reader','profile_writer')")
				// pgx may expose the terminated in-flight socket once; retry only
				// this side-effect-free identity read to observe a fresh backend.
				var reconnect error
				for i := 0; i < 3; i++ {
					reconnect = checkWriter()
					if reconnect == nil {
						break
					}
				}
				if reconnect != nil || calls.Load() <= before {
					t.Fatal("token was not refreshed on reconnect", reconnect)
				}
			}
			maintenance, closeMaintenance, err := OpenMaintenance(ctx, connection("profile_maintenance", "profile_jobs", transport), "profile_jobs", maintOpts...)
			if err != nil {
				t.Fatal(err)
			}
			defer closeMaintenance()
			mr, err := maintenance.Reader(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := mr.InTransaction(ctx, func(ctx context.Context, tx ReadTx) error {
				var n int
				var current, tenant, user string
				if err := tx.QueryRow(ctx, "SELECT count(*),current_user,current_setting('scope.tenant',true),current_setting('scope.user',true) FROM profile_rows").Scan(&n, &current, &tenant, &user); err != nil {
					return err
				}
				if n != 2 || current != "profile_jobs" || tenant != "" || user != "" {
					t.Fatal("maintenance inherited request scope or lost capability", n, current, tenant, user)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			closeMaintenance()
			closeMaintenance()
			close()
			close()
			if err := checkWriter(); err == nil {
				t.Fatal("closed request capability reused")
			}
			if err := mr.InTransaction(ctx, func(context.Context, ReadTx) error { return nil }); err == nil {
				t.Fatal("closed maintenance capability reused")
			}
		})
	}
	t.Run("wrong CA hostname and token error are redacted", func(t *testing.T) {
		reader := connection("profile_reader", "", VerifiedTLS)
		writer := connection("profile_writer", "profile_request", VerifiedTLS)
		for _, kind := range []string{"hostname", "ca", "provider"} {
			badReader := reader
			token := AccessTokenProvider(provider)
			if kind == "hostname" {
				badReader = strings.Replace(reader, "127.0.0.1", "localhost", 1)
			}
			if kind == "ca" {
				parsed, _ := url.Parse(reader)
				q := parsed.Query()
				q.Set("sslrootcert", os.Getenv("CONNECTION_PROFILE_TEST_WRONG_CA"))
				parsed.RawQuery = q.Encode()
				badReader = parsed.String()
			}
			if kind == "provider" {
				token = func(context.Context, string) (string, error) { return "", errors.New("private-credential-value") }
			}
			_, close, err := Open(ctx, badReader, writer, fakeAuthenticator{principal: testPrincipal{tenant: "tenant-a", user: "user-a"}}, WithConnectionProfiles(ConnectionProfile{Transport: VerifiedTLS}, ConnectionProfile{Transport: VerifiedTLS, ApplicationRole: "profile_request"}), WithAccessTokenProvider(token), WithOperationTimeout(3*time.Second))
			if close != nil {
				close()
			}
			if !errors.Is(err, ErrConnectionUnavailable) {
				t.Fatal("TLS/token failure was not rejected and redacted", kind, err)
			}
		}
		_, close, err := OpenMaintenance(ctx, connection("profile_maintenance", "profile_jobs", VerifiedTLS), "profile_jobs", WithMaintenanceConnectionProfile(ConnectionProfile{Transport: VerifiedTLS, ApplicationRole: "profile_jobs"}), WithAccessTokenProvider(func(context.Context, string) (string, error) { return "", errors.New("private-maintenance-credential") }))
		if close != nil {
			close()
		}
		if !errors.Is(err, ErrConnectionUnavailable) {
			t.Fatal("maintenance provider failure was not redacted", err)
		}
	})
}
