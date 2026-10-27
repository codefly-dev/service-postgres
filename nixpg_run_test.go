package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// shortTempDir is a temporary directory whose path fits a Unix socket.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "cfpg-test-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestServerOptionsBindNoTCPPort(t *testing.T) {
	options, err := serverOptions("/tmp/cfpg-abc", "")
	require.NoError(t, err)
	require.Contains(t, options, "-c listen_addresses=''")
	require.Contains(t, options, "-k /tmp/cfpg-abc")
	require.Contains(t, options, "-c max_connections=500")
	require.NotContains(t, options, "log_min_messages")

	quiet, err := serverOptions("/tmp/cfpg-abc", "WARNING")
	require.NoError(t, err)
	require.Contains(t, quiet, "-c log_min_messages=warning")
}

// TestServerOptionsRefuseWhatTheShellWouldInterpret: pg_ctl hands the options
// to /bin/sh, so nothing that the shell would read as syntax may reach them.
func TestServerOptionsRefuseWhatTheShellWouldInterpret(t *testing.T) {
	_, err := serverOptions("/tmp/cfpg abc", "")
	require.Error(t, err)
	_, err = serverOptions("/tmp/cfpg-abc", "warning; rm -rf /")
	require.Error(t, err)
}

func TestNativeOwnerRoleIsTheDatabasesOwn(t *testing.T) {
	owner := nativeOwnerRole("robin_sessions")
	readOnly, readWrite := runtimeRoleNames("robin_sessions")
	require.LessOrEqual(t, len(owner), 63)
	require.NotEqual(t, readOnly, owner)
	require.NotEqual(t, readWrite, owner)
	require.Equal(t, owner, nativeOwnerRole("robin_sessions"))
	require.NotEqual(t, owner, nativeOwnerRole("documents"))
	require.True(t, strings.HasSuffix(owner, "_owner"))
}

func writeHolder(t *testing.T, root, name string, holder serverHolder) string {
	t.Helper()
	data, err := json.Marshal(holder)
	require.NoError(t, err)
	path := filepath.Join(root, "holders", name+".json")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// TestPruneHoldersKeepsOnlyLiveRuns is what decides when a run's server stops:
// an agent that is gone, or whose codefly run is gone, holds nothing.
func TestPruneHoldersKeepsOnlyLiveRuns(t *testing.T) {
	root := t.TempDir()
	self, err := markProcess(os.Getpid())
	require.NoError(t, err)
	parent, err := markProcess(os.Getppid())
	require.NoError(t, err)

	exited := exec.Command("sleep", "60")
	require.NoError(t, exited.Start())
	gone, err := markProcess(exited.Process.Pid)
	require.NoError(t, err)
	require.NoError(t, exited.Process.Kill())
	_ = exited.Wait()

	reused := self
	reused.StartID++ // the same PID, a different process

	live := writeHolder(t, root, "live", serverHolder{Service: "mod/a", Agent: self, Run: &parent})
	deadAgent := writeHolder(t, root, "dead-agent", serverHolder{Service: "mod/b", Agent: gone})
	deadRun := writeHolder(t, root, "dead-run", serverHolder{Service: "mod/c", Agent: self, Run: &gone})
	reusedPID := writeHolder(t, root, "reused", serverHolder{Service: "mod/d", Agent: reused})
	garbage := filepath.Join(root, "holders", "garbage.json")
	require.NoError(t, os.WriteFile(garbage, []byte("{"), 0o600))

	count, err := pruneHolders(root)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.FileExists(t, live)
	for _, path := range []string{deadAgent, deadRun, reusedPID, garbage} {
		require.NoFileExists(t, path)
	}
}

func TestReleaseOfAnUnattachedHandleStopsNothing(t *testing.T) {
	stopped, err := (&nixPostgres{}).release(t.Context())
	require.NoError(t, err)
	require.False(t, stopped)
}
