package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/codefly-dev/core/resources"
	runners "github.com/codefly-dev/core/runners/base"
	"github.com/stretchr/testify/require"
)

// These tests cover what a run that was killed leaves behind. The run is a
// real one: a process of its own that starts a native service and exits
// without stopping it, which leaves a postmaster nobody will stop.

const killedRunEnv = "CFPG_TEST_KILLED_RUN"

// TestHelperKilledRun is not a test: re-executed with killedRunEnv set, it is
// an agent that starts a native service in that workspace and is killed.
func TestHelperKilledRun(t *testing.T) {
	workspace := os.Getenv(killedRunEnv)
	if workspace == "" {
		return
	}
	if os.Getenv(killedRunEnv+"_LAUNCHER") != "" {
		// Stand in for the run: launch the agent, and be gone before the test
		// looks, as a killed CLI is.
		agent := exec.Command(os.Args[0], "-test.run=^TestHelperKilledRun$")
		agent.Env = append(os.Environ(), killedRunEnv+"_LAUNCHER=")
		out, err := agent.CombinedOutput()
		require.NoError(t, err, string(out))
		return
	}
	// The store of the suite that launched this process, not this process's.
	servers := os.Getenv(killedRunEnv + "_SERVERS")
	runServersDir = func() (string, error) { return servers, nil }

	ctx := context.Background()
	fixture := newPostgresFixtureAt(t, ctx, workspace, "gone", "store", resources.NewRuntimeContextNix())
	if scope := os.Getenv(killedRunEnv + "_SCOPE"); scope != "" {
		fixture.environment.NamingScope = scope
		fixture.environment.Disposable = true
	}
	run, _ := fixture.start(t, ctx)
	postmaster, running := postmasterPidFileOwner(filepath.Join(run.nixRuntime.dataDir, "postmaster.pid"))
	require.True(t, running)
	require.NoError(t, os.WriteFile(os.Getenv(killedRunEnv+"_OUT"),
		[]byte(run.nixRuntime.root+"\n"+strconv.Itoa(postmaster)), 0o600))
	// Killed: nothing is stopped, released or destroyed.
	os.Exit(0)
}

// killedRunServer is the directory and the postmaster of a native service
// whose agent is gone without having stopped it. scope makes its run a
// disposable one; killedRun says whether the run that launched the agent is
// gone too.
func killedRunServer(t *testing.T, scope string, killedRun bool) (string, int) {
	t.Helper()
	servers, err := runServersDir()
	require.NoError(t, err)
	out := filepath.Join(t.TempDir(), "server")
	agent := exec.Command(os.Args[0], "-test.run=^TestHelperKilledRun$")
	agent.Env = append(os.Environ(),
		killedRunEnv+"="+t.TempDir(),
		killedRunEnv+"_SERVERS="+servers,
		killedRunEnv+"_SCOPE="+scope,
		killedRunEnv+"_OUT="+out)
	if killedRun {
		agent.Env = append(agent.Env, killedRunEnv+"_LAUNCHER=1")
	}
	output, err := agent.CombinedOutput()
	require.NoError(t, err, string(output))
	data, err := os.ReadFile(out)
	require.NoError(t, err, string(output))
	root, pidText, _ := strings.Cut(string(data), "\n")
	pid, err := strconv.Atoi(pidText)
	require.NoError(t, err)
	require.True(t, isPostmaster(pid), "the killed run left no postmaster")
	t.Cleanup(func() {
		if !isPostmaster(pid) {
			return
		}
		_ = syscall.Kill(pid, syscall.SIGINT)
		for deadline := time.Now().Add(30 * time.Second); isPostmaster(pid) && time.Now().Before(deadline); {
			time.Sleep(100 * time.Millisecond)
		}
	})
	return root, pid
}

// isPostmaster reports whether pid is a running postgres server.
func isPostmaster(pid int) bool {
	identity, err := runners.InspectProcess(pid)
	return err == nil && isPostmasterExecutable(identity.Executable)
}

// TestKilledRunsServer: a killed run leaves its postmaster running. The next
// agent to initialize on the machine stops it and removes its directory when
// that run was disposable and is gone, and only then: a developer's server is
// theirs to stop, and the server of a run that goes on is that run's.
func TestKilledRunsServer(t *testing.T) {
	requireNix(t)
	ctx := context.Background()
	killed, killedPostmaster := killedRunServer(t, "invkilled", true)
	persistent, persistentPostmaster := killedRunServer(t, "", true)
	// The agent died; the run that launched it (this test) goes on.
	running, runningPostmaster := killedRunServer(t, "invrunning", false)

	next := newPostgresFixtureAt(t, ctx, t.TempDir(), "next", "store", resources.NewRuntimeContextNix())
	next.start(t, ctx)

	require.False(t, isPostmaster(killedPostmaster), "the server a killed disposable run left must be stopped by the next run")
	require.NoDirExists(t, killed, "and its directory removed")
	require.True(t, isPostmaster(persistentPostmaster), "a developer's server is theirs to stop")
	require.FileExists(t, filepath.Join(persistent, "pgdata", "PG_VERSION"))
	require.True(t, isPostmaster(runningPostmaster), "a run that goes on keeps its server")
	require.FileExists(t, filepath.Join(running, "pgdata", "PG_VERSION"))
}
