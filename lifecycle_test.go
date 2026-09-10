package main

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"path"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/network"
	"github.com/codefly-dev/core/resources"
	runners "github.com/codefly-dev/core/runners/base"
	"github.com/codefly-dev/core/shared"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// postgresFixture is one scaffolded postgres service plus the identity,
// configuration, and fixed network mappings needed to run its agent lifecycle
// repeatedly against the same state.
type postgresFixture struct {
	serviceName     string
	workspaceDir    string
	identity        *basev0.ServiceIdentity
	environment     *resources.Environment
	configuration   *basev0.Configuration
	networkMappings []*basev0.NetworkMapping
	runtimeContext  *basev0.RuntimeContext
	address         string
}

func newPostgresFixture(t *testing.T, ctx context.Context, runtimeContext *basev0.RuntimeContext) *postgresFixture {
	t.Helper()

	workspace := &resources.Workspace{Name: "test"}
	workspaceDir := t.TempDir()
	serviceName := fmt.Sprintf("svc-%v", time.Now().UnixMilli())
	service := resources.Service{Name: serviceName, Version: "test-me"}
	require.NoError(t, service.SaveAtDir(ctx, path.Join(workspaceDir, "mod", service.Name)))

	identity := &basev0.ServiceIdentity{
		Name:                service.Name,
		Module:              "mod",
		Workspace:           workspace.Name,
		WorkspacePath:       workspaceDir,
		RelativeToWorkspace: fmt.Sprintf("mod/%s", service.Name),
	}

	builder := NewBuilder()
	loaded, err := builder.Load(ctx, &builderv0.LoadRequest{
		DisableCatch: true,
		Identity:     identity,
		CreationMode: &builderv0.CreationMode{Communicate: false},
	})
	require.NoError(t, err)
	require.NotNil(t, loaded)
	_, err = builder.Create(ctx, &builderv0.CreateRequest{})
	require.NoError(t, err)

	environment := resources.LocalEnvironment()

	// Endpoints are read off a loaded runtime, and the resulting mappings are
	// then reused by every lifecycle in this fixture: a restart must reattach to
	// the same port and the same state, not draw a fresh one.
	endpoints := NewRuntime()
	_, err = endpoints.Load(ctx, &runtimev0.LoadRequest{
		Identity:     identity,
		Environment:  shared.Must(environment.Proto()),
		DisableCatch: true,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(endpoints.Endpoints))

	networkManager, err := network.NewRuntimeManager(ctx, nil)
	require.NoError(t, err)
	networkManager.WithTemporaryPorts()
	networkMappings, err := networkManager.GenerateNetworkMappings(
		ctx,
		environment,
		workspace,
		endpoints.Identity,
		endpoints.Endpoints,
		runtimeContext,
	)
	require.NoError(t, err)
	require.Equal(t, 1, len(networkMappings))

	instance, err := resources.FindNetworkInstanceInNetworkMappings(
		ctx,
		networkMappings,
		endpoints.TcpEndpoint,
		resources.NewNativeNetworkAccess(),
	)
	require.NoError(t, err)
	require.NotNil(t, instance)

	return &postgresFixture{
		serviceName:  serviceName,
		workspaceDir: workspaceDir,
		identity:     identity,
		environment:  environment,
		configuration: &basev0.Configuration{
			Origin:         fmt.Sprintf("mod/%s", service.Name),
			RuntimeContext: resources.NewRuntimeContextFree(),
			Infos: []*basev0.ConfigurationInformation{
				{Name: "postgres",
					ConfigurationValues: []*basev0.ConfigurationValue{
						{Key: "POSTGRES_USER", Value: "postgres"},
						{Key: "POSTGRES_PASSWORD", Value: "owner-password"},
						{Key: "POSTGRES_READ_ONLY_PASSWORD", Value: "read-only-password"},
						{Key: "POSTGRES_READ_WRITE_PASSWORD", Value: "read-write-password"},
					},
				},
			},
		},
		networkMappings: networkMappings,
		runtimeContext:  runtimeContext,
		address:         instance.Address,
	}
}

// start drives Load → Init → Start on a fresh Runtime against this fixture's
// state, the way a new codefly invocation would.
func (f *postgresFixture) start(t *testing.T, ctx context.Context) (*Runtime, *runtimev0.InitResponse) {
	t.Helper()

	runtime := NewRuntime()
	_, err := runtime.Load(ctx, &runtimev0.LoadRequest{
		Identity:     f.identity,
		Environment:  shared.Must(f.environment.Proto()),
		DisableCatch: true,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(runtime.Endpoints))

	init, err := runtime.Init(ctx, &runtimev0.InitRequest{
		RuntimeContext:          f.runtimeContext,
		Configuration:           f.configuration,
		ProposedNetworkMappings: f.networkMappings,
	})
	require.NoError(t, err)
	require.NotNil(t, init)
	// Cleanup exists to not leak a container or a postmaster, and several
	// runtimes in one test share the same one — a later destroy legitimately
	// finds nothing, or catches a slow removal still in flight. Destroy's own
	// contract is asserted in the test body; here a failure is only logged.
	t.Cleanup(func() {
		destroyed, destroyErr := runtime.Destroy(context.Background(), &runtimev0.DestroyRequest{})
		if destroyErr != nil {
			t.Logf("cleanup destroy: %v", destroyErr)
			return
		}
		if state := destroyed.GetStatus().GetState(); state != runtimev0.DestroyStatus_SUCCESS {
			t.Logf("cleanup destroy state = %v: %s", state, destroyed.GetStatus().GetMessage())
		}
	})

	_, err = runtime.Start(ctx, &runtimev0.StartRequest{})
	require.NoError(t, err)
	return runtime, init
}

// TestLifecycleContractDocker and TestLifecycleContractNix run one lifecycle
// contract against both backends, so stop, keep-running, and destroy are held
// to the same state-ownership rules rather than to per-backend habits.
func TestLifecycleContractDocker(t *testing.T) {
	assertLifecycleContract(t, resources.NewRuntimeContextContainer())
}

func TestLifecycleContractNix(t *testing.T) {
	if !runners.CheckNixInstalled() || !runners.IsNixSupported() {
		t.Skip("nix not installed/supported on this host")
	}
	assertLifecycleContract(t, resources.NewRuntimeContextNix())
}

func assertLifecycleContract(t *testing.T, runtimeContext *basev0.RuntimeContext) {
	ctx := context.Background()
	fixture := newPostgresFixture(t, ctx, runtimeContext)

	runtime, _ := fixture.start(t, ctx)
	// Positive control. requireNoListener treats every dial error as proof the
	// port was released, so it passes vacuously against an address that was
	// never reachable — and the sentinel assertions would not notice, because
	// they connect through a separately derived connection string.
	requireListener(t, fixture.address)
	const sentinel = "00000000-0000-0000-0000-0000000000aa"
	writeSentinel(t, ctx, runtime.connection, fixture.serviceName, sentinel)
	retained := runtime.retainedDataPath
	require.NotEmpty(t, retained, "init must record where the database state lives")

	// keep-running is the one row of the contract that is backend-specific: only
	// docker can reattach to a live server, so nix must refuse to leave one
	// rather than hand the next Init a locked data directory.
	runtime.Settings.KeepRunning = true
	kept, err := runtime.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.StopStatus_SUCCESS, kept.GetStatus().GetState(), kept.GetStatus().GetMessage())
	if runtimeContext.Kind == resources.RuntimeContextNix {
		require.Contains(t, kept.GetStatus().GetMessage(), "stopped native postgres")
		requireNoListener(t, fixture.address)
		require.True(t, runtime.released, "a nix stop must release even when keep-running is set")
	} else {
		require.Contains(t, kept.GetStatus().GetMessage(), "kept postgres running")
		require.True(t,
			hasSentinel(t, ctx, runtime.connection, fixture.serviceName, sentinel),
			"keep-running must leave a healthy, reusable server behind",
		)
	}

	runtime.Settings.KeepRunning = false
	stopped, err := runtime.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.StopStatus_SUCCESS, stopped.GetStatus().GetState(), stopped.GetStatus().GetMessage())
	require.Contains(t, stopped.GetStatus().GetMessage(), "database state retained at "+retained)
	requireNoListener(t, fixture.address)

	repeated, err := runtime.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.StopStatus_SUCCESS, repeated.GetStatus().GetState(), repeated.GetStatus().GetMessage())
	requireNoListener(t, fixture.address)

	restarted, _ := fixture.start(t, ctx)
	require.True(t,
		hasSentinel(t, ctx, restarted.connection, fixture.serviceName, sentinel),
		"stop must retain data a later invocation reads back",
	)

	destroyed, err := restarted.Destroy(ctx, &runtimev0.DestroyRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.DestroyStatus_SUCCESS, destroyed.GetStatus().GetState(), destroyed.GetStatus().GetMessage())
	require.Contains(t, destroyed.GetStatus().GetMessage(), "database state retained at "+retained)
	requireNoListener(t, fixture.address)
	// The cluster's own directory is mode 0700 and owned by the container's
	// postgres user, so its contents are not readable from here on every host —
	// the reachable proof is that the reported location still exists, and that
	// a further invocation reads the sentinel back out of it.
	require.DirExists(t, retained)

	destroyedAgain, err := restarted.Destroy(ctx, &runtimev0.DestroyRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.DestroyStatus_SUCCESS, destroyedAgain.GetStatus().GetState(), destroyedAgain.GetStatus().GetMessage())

	revived, _ := fixture.start(t, ctx)
	require.True(t,
		hasSentinel(t, ctx, revived.connection, fixture.serviceName, sentinel),
		"destroy carries no disposal authorization, so its data must survive it",
	)
}

// TestStopOwnsNothingWithoutInit proves a runtime that never ran Init releases
// nothing and still reports success, so a partially failed or skipped Init
// leaves stop bounded rather than reaching for a stranger's postgres.
func TestStopOwnsNothingWithoutInit(t *testing.T) {
	runtime := NewRuntime()
	stopped, err := runtime.Stop(context.Background(), &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.StopStatus_SUCCESS, stopped.GetStatus().GetState(), stopped.GetStatus().GetMessage())
	require.Equal(t, "no postgres owned by this invocation; database state retained", stopped.GetStatus().GetMessage())
}

// TestKeepRunningIsRefusedOnNix pins the one row of the contract that is
// backend-specific. The nix runtime always launches a NEW postmaster and
// deliberately leaves a live owner's lock file alone, so a postmaster retained
// by keep-running makes the next Init start a second one against the same data
// directory and port — which postgres refuses. Stopping is the only answer
// there, and the data is retained either way.
func TestKeepRunningIsRefusedOnNix(t *testing.T) {
	runtime := NewRuntime()
	runtime.Runtime.WithContext(resources.NewRuntimeContextNix())
	runtime.Settings.KeepRunning = true

	stopped, err := runtime.Stop(context.Background(), &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.StopStatus_SUCCESS, stopped.GetStatus().GetState(), stopped.GetStatus().GetMessage())
	require.NotContains(t, stopped.GetStatus().GetMessage(), "kept postgres running",
		"nix cannot reattach to a live postmaster, so keep-running must not retain one")
}

// TestKeepRunningIsHonouredOnDocker is the other side of that gate: the
// container backend does reattach by name, so the setting still means what it
// says there.
func TestKeepRunningIsHonouredOnDocker(t *testing.T) {
	runtime := NewRuntime()
	runtime.Runtime.WithContext(resources.NewRuntimeContextContainer())
	runtime.Settings.KeepRunning = true

	stopped, err := runtime.Stop(context.Background(), &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.StopStatus_SUCCESS, stopped.GetStatus().GetState(), stopped.GetStatus().GetMessage())
	require.Contains(t, stopped.GetStatus().GetMessage(), "kept postgres running")
}

// TestStartAfterStopFailsFast: Start probes the database for ninety seconds
// before giving up, which is a long way to discover that the server it waits
// for was deliberately stopped and only Init can bring back.
func TestStartAfterStopFailsFast(t *testing.T) {
	runtime := NewRuntime()
	runtime.released = true

	begun := time.Now()
	started, err := runtime.Start(context.Background(), &runtimev0.StartRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.StartStatus_ERROR, started.GetStatus().GetState())
	require.Contains(t, started.GetStatus().GetMessage(), "run Init before Start")
	require.Less(t, time.Since(begun), 5*time.Second, "start must refuse immediately, not probe a stopped server")
}

// TestStopAfterFailedInitOwnsNothing covers the other half:// TestStopAfterFailedInitOwnsNothing covers the other half: an Init that fails
// before it starts anything must leave stop bounded — no backend call, no
// error, nothing released.
func TestStopAfterFailedInitOwnsNothing(t *testing.T) {
	ctx := context.Background()
	fixture := newPostgresFixture(t, ctx, resources.NewRuntimeContextContainer())

	runtime := NewRuntime()
	_, err := runtime.Load(ctx, &runtimev0.LoadRequest{
		Identity:     fixture.identity,
		Environment:  shared.Must(fixture.environment.Proto()),
		DisableCatch: true,
	})
	require.NoError(t, err)

	init, err := runtime.Init(ctx, &runtimev0.InitRequest{
		RuntimeContext:          fixture.runtimeContext,
		Configuration:           &basev0.Configuration{Origin: "mod/" + fixture.serviceName},
		ProposedNetworkMappings: fixture.networkMappings,
	})
	require.NoError(t, err)
	require.Equal(t, runtimev0.InitStatus_ERROR, init.GetStatus().GetState(),
		"init without postgres credentials must fail before it starts a server")

	stopped, err := runtime.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.StopStatus_SUCCESS, stopped.GetStatus().GetState(), stopped.GetStatus().GetMessage())
	require.Equal(t, "no postgres owned by this invocation; database state retained", stopped.GetStatus().GetMessage())
}

// TestRetentionSummaryCarriesNoSecret keeps the cleanup result reportable: it
// names the retained location and nothing that could authenticate to it.
func TestRetentionSummaryCarriesNoSecret(t *testing.T) {
	runtime := NewRuntime()
	runtime.retainedDataPath = "/codefly/runtime-cache/svc/postgres-data"
	runtime.connection = "postgres://postgres:owner-password@localhost:5432/svc"

	summary := runtime.retentionSummary("stopped postgres container")
	require.Equal(t,
		"stopped postgres container; database state retained at /codefly/runtime-cache/svc/postgres-data",
		summary,
	)
	require.NotContains(t, summary, "owner-password")
}

func writeSentinel(t *testing.T, ctx context.Context, connection, relation, id string) {
	t.Helper()
	db, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.ExecContext(ctx, `INSERT INTO `+pq.QuoteIdentifier(relation)+` (id) VALUES ($1)`, id)
	require.NoError(t, err)
}

func hasSentinel(t *testing.T, ctx context.Context, connection, relation, id string) bool {
	t.Helper()
	db, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	defer db.Close()
	var exists bool
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM `+pq.QuoteIdentifier(relation)+` WHERE id = $1)`, id).Scan(&exists))
	return exists
}

// requireListener proves the address under test is genuinely reachable while
// postgres is up, so requireNoListener's later silence means something.
func requireListener(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	require.NoErrorf(t, err, "%s must accept connections while postgres is running", address)
	require.NoError(t, conn.Close())
}

// requireNoListener proves the execution resource is gone, not merely asked to
// go: nothing accepts TCP on the address the stopped postgres was published on.
func requireNoListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			return
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("%s still accepts connections after stop", address)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
