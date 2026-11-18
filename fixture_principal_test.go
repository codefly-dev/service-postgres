package main

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/shared"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// The fixture principal is one contract on both backends, so both run the same
// assertions: what a test's dependency stack may ask for must not depend on
// which backend the host happened to select.
func TestFixturePrincipalDocker(t *testing.T) {
	assertFixturePrincipal(t, resources.NewRuntimeContextContainer())
}

func TestFixturePrincipalNix(t *testing.T) {
	requireNix(t)
	assertFixturePrincipal(t, resources.NewRuntimeContextNix())
}

func TestFixturePrincipalIsRefusedToAPersistentRunDocker(t *testing.T) {
	assertFixturePrincipalIsRefusedToAPersistentRun(t, resources.NewRuntimeContextContainer())
}

func TestFixturePrincipalIsRefusedToAPersistentRunNix(t *testing.T) {
	requireNix(t)
	assertFixturePrincipalIsRefusedToAPersistentRun(t, resources.NewRuntimeContextNix())
}

const fixtureTestPassword = "fixture-password"

// askForFixturePrincipal makes the run ask for the fixture principal the way
// every principal of this agent is asked for: by its password in the service's
// "postgres" secret configuration.
func (f *postgresFixture) askForFixturePrincipal() {
	values := f.configuration.Infos[0]
	values.ConfigurationValues = append(values.ConfigurationValues,
		&basev0.ConfigurationValue{Key: fixturePasswordKey, Value: fixtureTestPassword, Secret: true})
}

func (f *postgresFixture) withdrawFixturePrincipal() {
	values := f.configuration.Infos[0]
	kept := values.ConfigurationValues[:0]
	for _, value := range values.ConfigurationValues {
		if value.Key != fixturePasswordKey {
			kept = append(kept, value)
		}
	}
	values.ConfigurationValues = kept
}

// exportedConnection is one connection the agent handed out at Init, or empty
// when it handed out none under that key.
func exportedConnection(t *testing.T, ctx context.Context, init *runtimev0.InitResponse, key string) string {
	t.Helper()
	configuration, err := resources.ExtractConfiguration(init.RuntimeConfigurations, resources.NewRuntimeContextNative())
	require.NoError(t, err)
	value, err := resources.GetConfigurationValue(ctx, configuration, "postgres", key)
	require.NoError(t, err)
	return value
}

func roleExists(t *testing.T, ctx context.Context, connection, role string) bool {
	t.Helper()
	db, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	defer db.Close()
	var exists bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists))
	return exists
}

// assertFixturePrincipal: a disposable run that asks gets a separately named
// login that writes and reads across a FORCEd row-security policy, which binds
// every other principal; the owner connection keeps its meaning; and the
// principal is gone once the service is released.
func assertFixturePrincipal(t *testing.T, runtimeContext *basev0.RuntimeContext) {
	ctx := context.Background()
	fixture := newPostgresFixture(t, ctx, runtimeContext)
	fixture.environment.NamingScope = fmt.Sprintf("invfixture%d", time.Now().UnixNano()%1_000_000)
	fixture.environment.Disposable = true
	fixture.askForFixturePrincipal()

	runtime, init := fixture.start(t, ctx)
	require.Equal(t, runtimev0.InitStatus_READY, init.GetStatus().GetState(), init.GetStatus().GetMessage())
	fixtureConnection := exportedConnection(t, ctx, init, fixtureConnectionKey)
	require.NotEmpty(t, fixtureConnection, "a disposable run that asks is handed %s", fixtureConnectionKey)
	ownerConnection := exportedConnection(t, ctx, init, ownerConnectionKey)
	require.NotEqual(t, ownerConnection, fixtureConnection, "the fixture principal is its own login, never the owner renamed")
	role := fixtureRole(runtime.DatabaseName)

	owner, err := sql.Open("postgres", ownerConnection)
	require.NoError(t, err)
	defer owner.Close()
	const boundPassword = "bound-password"
	for _, statement := range []string{
		`CREATE TABLE tenant_rows (tenant TEXT NOT NULL, body TEXT NOT NULL)`,
		`ALTER TABLE tenant_rows ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE tenant_rows FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY tenant_isolation ON tenant_rows USING (tenant = current_setting('app.tenant', true))`,
		`CREATE ROLE fixture_test_bound LOGIN PASSWORD ` + pq.QuoteLiteral(boundPassword),
		`GRANT CONNECT ON DATABASE ` + pq.QuoteIdentifier(runtime.DatabaseName) + ` TO fixture_test_bound`,
		`GRANT SELECT, INSERT ON tenant_rows TO fixture_test_bound`,
		// What a migration does: an application role the owner creates.
		`CREATE ROLE fixture_test_app NOLOGIN`,
	} {
		_, err = owner.ExecContext(ctx, statement)
		require.NoError(t, err, statement)
	}

	// The policy binds whoever does not bypass row security. A login with
	// plain table grants is that on both backends.
	bound, err := sql.Open("postgres", withUser(t, ownerConnection, "fixture_test_bound", boundPassword))
	require.NoError(t, err)
	defer bound.Close()
	_, err = bound.ExecContext(ctx, `INSERT INTO tenant_rows VALUES ('tenant-a', 'seed')`)
	require.ErrorContains(t, err, "row-level security", "the policy must bind a principal that does not bypass it")

	// The owner connection keeps its meaning. Where it is not a superuser (the
	// native run server), FORCE binds it on its own table: the gap this
	// principal exists to close explicitly.
	var ownerIsSuperuser bool
	require.NoError(t, owner.QueryRowContext(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&ownerIsSuperuser))
	if !ownerIsSuperuser {
		_, err = owner.ExecContext(ctx, `INSERT INTO tenant_rows VALUES ('tenant-a', 'seed')`)
		require.ErrorContains(t, err, "row-level security", "FORCE binds the table's own owner")
	}

	principal, err := sql.Open("postgres", fixtureConnection)
	require.NoError(t, err)
	defer principal.Close()
	var user string
	var superuser, bypass bool
	require.NoError(t, principal.QueryRowContext(ctx,
		`SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&user, &superuser, &bypass))
	require.Equal(t, role, user)
	require.True(t, bypass, "the fixture principal bypasses row security")
	require.Equal(t, ownerIsSuperuser, superuser,
		"the fixture principal holds the owner's authority and no more: a superuser only where the owner is one")
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		_, err = principal.ExecContext(ctx, `INSERT INTO tenant_rows VALUES ($1, 'seed')`, tenant)
		require.NoError(t, err, "the fixture principal seeds any tenant's rows")
	}
	var seen int
	require.NoError(t, principal.QueryRowContext(ctx, `SELECT count(*) FROM tenant_rows`).Scan(&seen))
	require.Equal(t, 2, seen, "the fixture principal reads across tenants")
	require.NoError(t, bound.QueryRowContext(ctx, `SELECT count(*) FROM tenant_rows`).Scan(&seen))
	require.Zero(t, seen, "the rows it seeded are still behind the policy for everyone else")
	// What a suite does through its owner pool: schema changes on the owner's
	// relations, and emptying them between tests.
	_, err = principal.ExecContext(ctx, `ALTER TABLE tenant_rows ADD COLUMN note TEXT`)
	require.NoError(t, err, "the fixture principal holds the owner's rights on the owner's relations")
	_, err = principal.ExecContext(ctx, `TRUNCATE tenant_rows`)
	require.NoError(t, err)
	// A migration suite also hands a relation to a role it creates and takes
	// it back, which a superuser does without being granted that role. And it
	// leaves things behind: a role and a relation of its own here.
	for _, statement := range []string{
		// The owner's authority over the roles its migrations created: a suite
		// grants an application role to a login it makes up.
		`GRANT fixture_test_app TO fixture_test_bound`,
		`CREATE ROLE fixture_test_handover NOLOGIN`,
		`GRANT USAGE, CREATE ON SCHEMA public TO fixture_test_handover`,
		`ALTER TABLE tenant_rows OWNER TO fixture_test_handover`,
		`ALTER TABLE tenant_rows OWNER TO ` + pq.QuoteIdentifier(runtime.postgresUser),
		`CREATE ROLE fixture_test_left NOLOGIN`,
		`GRANT fixture_test_left TO fixture_test_bound`,
		`CREATE TABLE fixture_test_left_rows (id INT)`,
	} {
		_, err = principal.ExecContext(ctx, statement)
		require.NoError(t, err, statement)
	}
	require.NoError(t, principal.Close())
	require.NoError(t, bound.Close())
	require.NoError(t, owner.Close())

	// The principal goes when the service is released: the same state, started
	// again by a run that does not ask, holds no such role.
	stopped, err := runtime.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.StopStatus_SUCCESS, stopped.GetStatus().GetState(), stopped.GetStatus().GetMessage())
	fixture.withdrawFixturePrincipal()
	restarted, again := fixture.start(t, ctx)
	require.Equal(t, runtimev0.InitStatus_READY, again.GetStatus().GetState(), again.GetStatus().GetMessage())
	require.Empty(t, exportedConnection(t, ctx, again, fixtureConnectionKey), "a run that does not ask is handed no fixture connection")
	require.False(t, roleExists(t, ctx, restarted.connection, role), "the fixture principal must not outlive the service that asked for it")
	require.Error(t, connects(ctx, fixtureConnection), "the connection handed out earlier no longer authenticates")
	var leftOwner string
	leftover, err := sql.Open("postgres", restarted.connection)
	require.NoError(t, err)
	defer leftover.Close()
	require.NoError(t, leftover.QueryRowContext(ctx,
		`SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname = 'fixture_test_left_rows'`).Scan(&leftOwner))
	require.Equal(t, restarted.postgresUser, leftOwner, "what the fixture principal created is the migration owner's once it is gone")
	require.NoError(t, leftover.Close())

	// A run that was interrupted never releases its service: the role is still
	// in the state it left. The same run starts over it, and a start that does
	// not ask removes it.
	earlier := []*Runtime{runtime, restarted}
	_, err = restarted.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	fixture.askForFixturePrincipal()
	interrupted, _ := fixture.start(t, ctx)
	interrupted.fixtureProvisioned = false
	_, err = interrupted.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	resumed, init := fixture.start(t, ctx)
	require.Equal(t, runtimev0.InitStatus_READY, init.GetStatus().GetState(), init.GetStatus().GetMessage())
	require.NoError(t, connects(ctx, exportedConnection(t, ctx, init, fixtureConnectionKey)), "the run starts over the principal it left")
	resumed.fixtureProvisioned = false
	_, err = resumed.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	earlier = append(earlier, interrupted, resumed)
	fixture.withdrawFixturePrincipal()
	restarted, again = fixture.start(t, ctx)
	require.Equal(t, runtimev0.InitStatus_READY, again.GetStatus().GetState(), again.GetStatus().GetMessage())
	require.False(t, roleExists(t, ctx, restarted.connection, role), "a start that does not ask removes the principal an interrupted run left")

	// Each invocation that used the run's state claims it until it is destroyed.
	for _, invocation := range earlier {
		_, err = invocation.Destroy(ctx, &runtimev0.DestroyRequest{})
		require.NoError(t, err)
	}
	native := restarted.nativeRoot
	destroyed, err := restarted.Destroy(ctx, &runtimev0.DestroyRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.DestroyStatus_SUCCESS, destroyed.GetStatus().GetState(), destroyed.GetStatus().GetMessage())
	if native != "" {
		require.NoDirExists(t, native, "a disposable run's server goes with the run, and every role on it")
	}
}

// assertFixturePrincipalIsRefusedToAPersistentRun: a run whose state is a
// developer's is refused the principal by name, before anything is started,
// whether it has no naming scope or one its caller named. Without the ask the
// same run starts and holds no such role.
func assertFixturePrincipalIsRefusedToAPersistentRun(t *testing.T, runtimeContext *basev0.RuntimeContext) {
	ctx := context.Background()
	fixture := newPostgresFixture(t, ctx, runtimeContext)
	fixture.askForFixturePrincipal()

	for _, scope := range []string{"", "named-by-a-developer"} {
		fixture.environment.NamingScope = scope
		runtime := NewRuntime()
		_, err := runtime.Load(ctx, &runtimev0.LoadRequest{
			Identity:     fixture.identity,
			Environment:  shared.Must(fixture.environment.Proto()),
			DisableCatch: true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = runtime.Destroy(context.Background(), &runtimev0.DestroyRequest{}) })
		init, err := runtime.Init(ctx, &runtimev0.InitRequest{
			RuntimeContext:          fixture.runtimeContext,
			Configuration:           fixture.configuration,
			ProposedNetworkMappings: fixture.networkMappings,
		})
		require.NoError(t, err)
		require.Equal(t, runtimev0.InitStatus_ERROR, init.GetStatus().GetState(), "scope %q", scope)
		message := init.GetStatus().GetMessage()
		require.Contains(t, message, "fixture principal")
		require.Contains(t, message, fixturePasswordKey, "the refusal names what asked")
		require.Contains(t, message, "disposable run")
		require.NotContains(t, message, fixtureTestPassword)
		require.Empty(t, init.RuntimeConfigurations, "a refused run is handed no connection at all")
		requireNoListener(t, fixture.address)
		stopped, err := runtime.Stop(ctx, &runtimev0.StopRequest{})
		require.NoError(t, err)
		require.Equal(t, "no postgres owned by this invocation; database state retained", stopped.GetStatus().GetMessage(),
			"the refusal comes before anything is started")
	}

	fixture.environment.NamingScope = ""
	fixture.withdrawFixturePrincipal()
	runtime, init := fixture.start(t, ctx)
	require.Equal(t, runtimev0.InitStatus_READY, init.GetStatus().GetState(), init.GetStatus().GetMessage())
	require.Empty(t, exportedConnection(t, ctx, init, fixtureConnectionKey))
	require.False(t, roleExists(t, ctx, runtime.connection, fixtureRole(runtime.DatabaseName)),
		"a developer's database never holds a fixture principal")
}

// TestFixturePrincipalIsNotARuntimeLogin: the fixture principal's keys are
// managed, so a declared runtime login cannot take its name.
func TestFixturePrincipalIsNotARuntimeLogin(t *testing.T) {
	_, err := resolveRuntimeLogins(&Settings{
		DatabaseName:  "store",
		RuntimeLogins: []RuntimeLogin{{Name: "fixture", ReadWriteRoles: []string{"app_runtime"}}},
	})
	require.ErrorContains(t, err, "reserved")
}

// TestFixturePrincipalIsAPasswordLogin: external-identity mode holds no
// passwords, so it cannot be asked for one.
func TestFixturePrincipalIsAPasswordLogin(t *testing.T) {
	service := NewService()
	service.DatabaseName = "store"
	service.AuthMode = authModeExternalIdentity
	service.postgresUser = "owner"
	service.fixturePassword = fixtureTestPassword
	require.ErrorContains(t, service.validateCredentials(), "fixture principal")
}

// TestFixturePasswordIsDistinct: the fixture principal bypasses what every
// other credential is bound by, so it never shares a password with one.
func TestFixturePasswordIsDistinct(t *testing.T) {
	service := NewService()
	service.DatabaseName = "store"
	service.postgresUser = "owner"
	service.postgresPassword = "owner-password"
	service.readOnlyPassword = "read-only-password"
	service.readWritePassword = "read-write-password"
	service.fixturePassword = "read-write-password"
	require.ErrorContains(t, service.validateCredentials(), "fixture principal password must be distinct")
	service.fixturePassword = fixtureTestPassword
	require.NoError(t, service.validateCredentials())
}
