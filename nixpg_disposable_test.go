package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	runtimev1 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v1"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/runners/runstate"
	"github.com/stretchr/testify/require"
)

// TestDisposableRunStateIsRemovedWhenTheRunDestroysIt: a run whose caller
// declared its state disposable (a generated naming scope: temporary ports, a
// test's dependency stack) leaves no server directory behind. Stop still
// retains it, because a service restarts inside a run; the directory goes when
// the run's last service is destroyed.
func TestDisposableRunStateIsRemovedWhenTheRunDestroysIt(t *testing.T) {
	requireNix(t)
	ctx := context.Background()
	workspace := t.TempDir()
	alpha := newPostgresFixtureAt(t, ctx, workspace, "alpha", "store", resources.NewRuntimeContextNix())
	beta := newPostgresFixtureAt(t, ctx, workspace, "beta", "store", resources.NewRuntimeContextNix())
	for _, fixture := range []*postgresFixture{alpha, beta} {
		fixture.environment.NamingScope = "invdisposable"
		fixture.environment.Disposable = true
	}

	runAlpha, _ := alpha.start(t, ctx)
	runBeta, _ := beta.start(t, ctx)
	root := runAlpha.nixRuntime.root
	require.Equal(t, root, runBeta.nixRuntime.root)
	writeSentinel(t, ctx, runBeta.connection, beta.serviceName, "00000000-0000-0000-0000-0000000000b1")

	stopped, err := runAlpha.Stop(ctx, &runtimev1.StopRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev1.StopStatus_SUCCESS, stopped.GetStatus().GetState(), stopped.GetStatus().GetMessage())
	require.DirExists(t, filepath.Join(root, "pgdata"), "stop is not the end of a run")

	destroyed, err := runAlpha.Destroy(ctx, &runtimev1.DestroyRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev1.DestroyStatus_SUCCESS, destroyed.GetStatus().GetState(), destroyed.GetStatus().GetMessage())
	require.Contains(t, destroyed.GetStatus().GetMessage(), "database state retained",
		"the run's other service still uses the server")
	require.True(t, hasSentinel(t, ctx, runBeta.connection, beta.serviceName, "00000000-0000-0000-0000-0000000000b1"))

	destroyed, err = runBeta.Destroy(ctx, &runtimev1.DestroyRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev1.DestroyStatus_SUCCESS, destroyed.GetStatus().GetState(), destroyed.GetStatus().GetMessage())
	require.Contains(t, destroyed.GetStatus().GetMessage(), "disposable database state removed from "+root)
	require.NoDirExists(t, root, "a disposable run must not leave its server directory behind")

	again, err := runBeta.Destroy(ctx, &runtimev1.DestroyRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev1.DestroyStatus_SUCCESS, again.GetStatus().GetState(), again.GetStatus().GetMessage())
}

const claimHelperDir = "CFPG_TEST_CLAIM_DIR"

// TestHelperClaimRunState is not a test: re-executed with claimHelperDir set,
// it claims that directory as an agent would and exits, which leaves the
// record of a run that was killed.
func TestHelperClaimRunState(t *testing.T) {
	dir := os.Getenv(claimHelperDir)
	if dir == "" {
		return
	}
	run := runstate.Run{Workspace: "/work/shop", NamingScope: os.Getenv(claimHelperDir + "_SCOPE")}
	run.Disposable = run.NamingScope != ""
	_, err := runstate.Claim(dir, run)
	require.NoError(t, err)
}

// abandonedRunServer is the directory of a run server whose agents are gone.
func abandonedRunServer(t *testing.T, servers, name, scope string) string {
	t.Helper()
	root := filepath.Join(servers, name)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "pgdata"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pgdata", "PG_VERSION"), []byte(nativeMajor), 0o600))
	claim := exec.Command(os.Args[0], "-test.run=^TestHelperClaimRunState$")
	claim.Env = append(os.Environ(), claimHelperDir+"="+root, claimHelperDir+"_SCOPE="+scope)
	out, err := claim.CombinedOutput()
	require.NoError(t, err, string(out))
	return root
}

// TestAbandonedDisposableRunStateIsCollected: a killed run never destroys its
// agents. The next agent to initialize on the machine removes the directory
// such a run left when that run was disposable, and only then.
// TestKilledRunsServer covers the server it left running.
func TestAbandonedDisposableRunStateIsCollected(t *testing.T) {
	servers := t.TempDir()
	disposable := abandonedRunServer(t, servers, "disposable", "invkilled")
	persistent := abandonedRunServer(t, servers, "persistent", "")
	unclaimed := filepath.Join(servers, "unclaimed")
	require.NoError(t, os.MkdirAll(filepath.Join(unclaimed, "pgdata"), 0o700))
	held := filepath.Join(servers, "held")
	require.NoError(t, os.MkdirAll(filepath.Join(held, "pgdata"), 0o700))
	_, err := runstate.Claim(held, runstate.Run{Workspace: "/work/shop", NamingScope: "invlive", Disposable: true})
	require.NoError(t, err)

	collectAbandonedServers(servers)

	require.NoDirExists(t, disposable)
	require.FileExists(t, filepath.Join(persistent, "pgdata", "PG_VERSION"), "a developer's database is never removed")
	require.DirExists(t, unclaimed)
	require.DirExists(t, held, "a live agent still uses it")
}
