package main

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/resources"
	runners "github.com/codefly-dev/core/runners/base"
	"github.com/codefly-dev/core/shared"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func requireNix(t *testing.T) {
	t.Helper()
	if !runners.CheckNixInstalled() || !runners.IsNixSupported() {
		t.Skip("nix not installed/supported on this host")
	}
}

// withDatabase is connection pointed at another database of the same server.
func withDatabase(t *testing.T, connection, database string) string {
	t.Helper()
	parsed, err := url.Parse(connection)
	require.NoError(t, err)
	parsed.Path = "/" + database
	return parsed.String()
}

func withUser(t *testing.T, connection, user, password string) string {
	t.Helper()
	parsed, err := url.Parse(connection)
	require.NoError(t, err)
	parsed.User = url.UserPassword(user, password)
	return parsed.String()
}

func connects(ctx context.Context, connection string) error {
	db, err := sql.Open("postgres", connection)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.PingContext(ctx)
}

// TestRunServerIsSharedAndIsolated is the run server's contract end to end:
// two services of one run get one postmaster, each its own database at its own
// endpoint; neither service's logins reach the other's database; releasing one
// leaves the other serving; the last release stops the server; and the data
// is there for the next run.
func TestRunServerIsSharedAndIsolated(t *testing.T) {
	requireNix(t)
	ctx := context.Background()
	workspace := t.TempDir()
	alpha := newPostgresFixtureAt(t, ctx, workspace, "alpha", "store", resources.NewRuntimeContextNix())
	beta := newPostgresFixtureAt(t, ctx, workspace, "beta", "store", resources.NewRuntimeContextNix())

	runAlpha, _ := alpha.start(t, ctx)
	runBeta, _ := beta.start(t, ctx)

	// One server for the run.
	require.Equal(t, runAlpha.nixRuntime.dataDir, runBeta.nixRuntime.dataDir)
	attached, running, err := attachedPostmaster(runAlpha.nixRuntime.root, runAlpha.nixRuntime.dataDir)
	require.NoError(t, err)
	require.True(t, running)
	postmaster := attached.Postmaster.PID

	// Each service at its own endpoint, with its own data.
	requireListener(t, alpha.address)
	requireListener(t, beta.address)
	writeSentinel(t, ctx, runAlpha.connection, alpha.serviceName, "00000000-0000-0000-0000-0000000000a1")
	writeSentinel(t, ctx, runBeta.connection, beta.serviceName, "00000000-0000-0000-0000-0000000000b1")

	// The owner is the database's own, and not a superuser.
	require.Equal(t, nativeOwnerRole("alpha"), runAlpha.postgresUser)
	db, err := sql.Open("postgres", runAlpha.connection)
	require.NoError(t, err)
	var superuser bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&superuser))
	require.NoError(t, db.Close())
	require.False(t, superuser, "a service's migration owner must not be the run server's superuser")

	// Isolation: no login of one service reaches the other's database, or the
	// server's maintenance database.
	readOnly, _ := runtimeRoleNames(runAlpha.DatabaseName)
	alphaReader := withUser(t, runAlpha.connection, readOnly, runAlpha.readOnlyPassword)
	require.NoError(t, connects(ctx, alphaReader), "the reader reaches its own database")
	for name, connection := range map[string]string{
		"owner into the other database":  withDatabase(t, runAlpha.connection, runBeta.DatabaseName),
		"reader into the other database": withDatabase(t, alphaReader, runBeta.DatabaseName),
		"owner into postgres":            withDatabase(t, runAlpha.connection, "postgres"),
		"owner into template1":           withDatabase(t, runAlpha.connection, "template1"),
	} {
		require.ErrorContains(t, connects(ctx, connection), "permission denied", name)
	}

	// Releasing one service leaves the run's server serving the other.
	stopped, err := runAlpha.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Contains(t, stopped.GetStatus().GetMessage(), "keeps serving its other services")
	requireNoListener(t, alpha.address)
	require.True(t, hasSentinel(t, ctx, runBeta.connection, beta.serviceName, "00000000-0000-0000-0000-0000000000b1"))

	// The last release stops it.
	stopped, err = runBeta.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Contains(t, stopped.GetStatus().GetMessage(), "stopped native postgres")
	requireNoListener(t, beta.address)
	require.False(t, processAlive(postmaster), "the run's postmaster must be gone once no service holds it")

	// The next run finds its data.
	revived, _ := alpha.start(t, ctx)
	require.True(t, hasSentinel(t, ctx, revived.connection, alpha.serviceName, "00000000-0000-0000-0000-0000000000a1"))
}

// TestRunServerRefusesTwoServicesClaimingOneDatabase: a server's databases are
// its services', one each, and a second claim is refused naming both.
func TestRunServerRefusesTwoServicesClaimingOneDatabase(t *testing.T) {
	requireNix(t)
	ctx := context.Background()
	workspace := t.TempDir()
	first := newPostgresFixtureAt(t, ctx, workspace, "shared", "first", resources.NewRuntimeContextNix())
	second := newPostgresFixtureAt(t, ctx, workspace, "shared", "second", resources.NewRuntimeContextNix())

	run, _ := first.start(t, ctx)

	refused := NewRuntime()
	_, err := refused.Load(ctx, &runtimev0.LoadRequest{Identity: second.identity, Environment: shared.Must(second.environment.Proto()), DisableCatch: true})
	require.NoError(t, err)
	init, err := refused.Init(ctx, &runtimev0.InitRequest{
		RuntimeContext:          second.runtimeContext,
		Configuration:           second.configuration,
		ProposedNetworkMappings: second.networkMappings,
	})
	require.NoError(t, err)
	require.Equal(t, runtimev0.InitStatus_ERROR, init.GetStatus().GetState())
	require.Contains(t, init.GetStatus().GetMessage(),
		`database "shared" on this run's postgres server belongs to shared/first, not shared/second`)
	require.Nil(t, refused.nixRuntime, "a refused service holds no server")
	requireNoListener(t, second.address)

	// The refusal took nothing from the service that holds the database.
	require.NoError(t, connects(ctx, run.connection))
}

// TestAbandonedRunServerIsCollected: a run killed without releasing leaves a
// server nobody holds; the next agent to initialize anywhere stops it.
func TestAbandonedRunServerIsCollected(t *testing.T) {
	requireNix(t)
	ctx := context.Background()
	abandoned := newPostgresFixtureAt(t, ctx, t.TempDir(), "gone", "store", resources.NewRuntimeContextNix())
	run, _ := abandoned.start(t, ctx)
	dataDir := run.nixRuntime.dataDir
	attached, running, err := attachedPostmaster(run.nixRuntime.root, dataDir)
	require.NoError(t, err)
	require.True(t, running)
	postmaster := attached.Postmaster.PID

	// The run dies: its agent's record names a process that no longer exists,
	// and its endpoint went with it.
	require.NoError(t, run.nixRuntime.forwarder.Close())
	run.nixRuntime.serverCancel()
	writeHolder(t, run.nixRuntime.root, "store", serverHolder{Service: "gone/store", Agent: processMark{PID: 2147483646}})
	require.NoError(t, os.Remove(run.nixRuntime.holder))
	run.nixRuntime = nil

	next := newPostgresFixtureAt(t, ctx, t.TempDir(), "next", "store", resources.NewRuntimeContextNix())
	next.start(t, ctx)
	require.False(t, processAlive(postmaster), "an abandoned run's server must be stopped by the next run")
}

// TestLockFileHeldByARealPostmasterIsRefused is the case where the lock file
// must be left exactly as it is. A record this agent cannot read — lost, or
// written by a version that did not keep one — does not make the postmaster
// holding the cluster disposable: removing its lock file would let a second
// postmaster start on the same data directory, which is how a cluster is
// corrupted. The run refuses and names the process instead, and signals
// nothing.
func TestLockFileHeldByARealPostmasterIsRefused(t *testing.T) {
	requireNix(t)
	ctx := context.Background()
	fixture := newPostgresFixtureAt(t, ctx, t.TempDir(), "held", "store", resources.NewRuntimeContextNix())
	run, _ := fixture.start(t, ctx)
	root := run.nixRuntime.root
	pidPath := filepath.Join(run.nixRuntime.dataDir, "postmaster.pid")
	postmaster, running := postmasterPidFileOwner(pidPath)
	require.True(t, running)

	// The record goes missing while its postmaster keeps serving.
	recorded, err := os.ReadFile(postmasterRecordPath(root))
	require.NoError(t, err)
	require.NoError(t, os.Remove(postmasterRecordPath(root)))
	t.Cleanup(func() { _ = os.WriteFile(postmasterRecordPath(root), recorded, 0o600) })

	_, attached, err := attachedPostmaster(root, run.nixRuntime.dataDir)
	require.False(t, attached)
	require.ErrorContains(t, err, "stop it before running again")
	require.FileExists(t, pidPath, "a live postmaster's lock file is never removed")
	require.True(t, processAlive(postmaster), "and its postmaster is never signalled")

	// Unreadable record, same answer: nothing of this run's may be stopped on
	// a PID alone, so the server is still there for the restored record.
	require.NoError(t, os.WriteFile(postmasterRecordPath(root), []byte("{"), 0o600))
	_, attached, err = attachedPostmaster(root, run.nixRuntime.dataDir)
	require.False(t, attached)
	require.ErrorContains(t, err, "stop it before running again")
	require.True(t, processAlive(postmaster))
}

// TestRunServerRefusesAnOwnerRoleAnotherServiceCreated closes the one way a
// service could reach another's data on the shared server. A migration owner
// may create roles, because migrations create the application's own roles,
// and PostgreSQL 16 and later grant a role created that way back to its
// creator WITH ADMIN OPTION. A service that creates a role named after
// ANOTHER service's database, before that service has ever run, would have
// been adopted as that database's owner while keeping the admin grant — which
// is enough to take the role and read the data.
func TestRunServerRefusesAnOwnerRoleAnotherServiceCreated(t *testing.T) {
	requireNix(t)
	ctx := context.Background()
	workspace := t.TempDir()
	squatter := newPostgresFixtureAt(t, ctx, workspace, "squatter", "store", resources.NewRuntimeContextNix())
	victim := newPostgresFixtureAt(t, ctx, workspace, "victim", "store", resources.NewRuntimeContextNix())

	run, _ := squatter.start(t, ctx)
	// The squatter's migrations create the victim's owner role before the
	// victim first runs. This is exactly what a migration is allowed to do.
	db, err := sql.Open("postgres", run.connection)
	require.NoError(t, err)
	defer db.Close()
	stolen := nativeOwnerRole("victim")
	_, err = db.ExecContext(ctx, `CREATE ROLE `+pq.QuoteIdentifier(stolen)+` LOGIN`)
	require.NoError(t, err, "a migration owner may create roles")

	refused := NewRuntime()
	_, err = refused.Load(ctx, &runtimev0.LoadRequest{
		Identity: victim.identity, Environment: shared.Must(victim.environment.Proto()), DisableCatch: true,
	})
	require.NoError(t, err)
	init, err := refused.Init(ctx, &runtimev0.InitRequest{
		RuntimeContext:          victim.runtimeContext,
		Configuration:           victim.configuration,
		ProposedNetworkMappings: victim.networkMappings,
	})
	require.NoError(t, err)
	require.Equal(t, runtimev0.InitStatus_ERROR, init.GetStatus().GetState())
	require.Contains(t, init.GetStatus().GetMessage(), "was not created for victim/store")
	require.Nil(t, refused.nixRuntime, "a refused service holds no server")
}
