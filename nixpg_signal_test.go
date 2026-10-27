package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// liveStranger starts a process that is not a postgres server, dies on SIGINT,
// and outlives the test unless something kills it. Its PID stands in for the
// number a postmaster had before it died and the kernel handed on.
func liveStranger(t *testing.T) int {
	t.Helper()
	stranger := exec.Command("sleep", "300")
	require.NoError(t, stranger.Start())
	t.Cleanup(func() {
		_ = stranger.Process.Kill()
		_ = stranger.Wait()
	})
	return stranger.Process.Pid
}

// abandonedRoot is a run server root left behind by a run that died: holders,
// a cluster directory, and a postmaster.pid naming pid. Nothing records a
// postmaster, because nothing orderly happened here.
func abandonedRoot(t *testing.T, servers, name string, pid int) string {
	t.Helper()
	root := filepath.Join(servers, name)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "holders"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "pgdata"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pgdata", "postmaster.pid"),
		[]byte(strconv.Itoa(pid)+"\n"+filepath.Join(root, "pgdata")+"\n1700000000\n5432\n/tmp/cfpg-gone\n"), 0o600))
	return root
}

func stillAlive(t *testing.T, pid int) bool {
	t.Helper()
	// A SIGINT'd `sleep` dies promptly; give it room to, so this cannot pass
	// by being quicker than the signal.
	time.Sleep(500 * time.Millisecond)
	return processAlive(pid)
}

// TestStaleLockFileIsNeverSignalled is the regression for the one way this
// agent could reach outside its own run: a postmaster.pid outlives the
// postmaster that wrote it (SIGKILL, OOM, a machine that lost power), PIDs are
// reused, and collection runs over every other run root on the machine at
// every native start. Signalling the number in that file makes an unrelated
// process of this user the target.
func TestStaleLockFileIsNeverSignalled(t *testing.T) {
	ctx := context.Background()
	servers := t.TempDir()
	stranger := liveStranger(t)
	root := abandonedRoot(t, servers, "abandoned", stranger)

	stopped, err := stopServer(root, filepath.Join(root, "pgdata"))
	require.NoError(t, err)
	require.False(t, stopped, "no postmaster was recorded, so none was stopped")

	collectAbandonedServers(ctx, servers, filepath.Join(servers, "other"))

	require.True(t, stillAlive(t, stranger),
		"a process that merely inherited the PID in a stale postmaster.pid must never be signalled")
}

// TestRecordedPostmasterIsSignalledOnlyAsTheSameBirth: the record is not a
// PID either. A recorded birth whose process is gone — its number now
// answered by something else — is nobody to signal.
func TestRecordedPostmasterIsSignalledOnlyAsTheSameBirth(t *testing.T) {
	servers := t.TempDir()
	stranger := liveStranger(t)
	root := abandonedRoot(t, servers, "reused", stranger)

	mark, err := markProcess(stranger)
	require.NoError(t, err)
	mark.StartID++ // the same number, a different process
	record, err := json.Marshal(postmasterRecord{Postmaster: mark, SocketDir: "/tmp/cfpg-gone"})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(postmasterRecordPath(root), record, 0o600))

	stopped, err := stopServer(root, filepath.Join(root, "pgdata"))
	require.NoError(t, err)
	require.False(t, stopped)
	require.True(t, stillAlive(t, stranger),
		"a recorded birth that no longer owns its PID must not be signalled")
	require.NoFileExists(t, postmasterRecordPath(root),
		"a record no server answers to is dropped, so a later start is not told about it")
}

// TestStaleLockFileDoesNotWedgeTheRun is the other half of the same stale
// file: it must not be read as "a server is already running" either, or the
// run waits on a stranger's process instead of starting its own server.
func TestStaleLockFileDoesNotWedgeTheRun(t *testing.T) {
	servers := t.TempDir()
	stranger := liveStranger(t)
	root := abandonedRoot(t, servers, "wedged", stranger)
	pidPath := filepath.Join(root, "pgdata", "postmaster.pid")

	record, running, err := attachedPostmaster(root, filepath.Join(root, "pgdata"))
	require.NoError(t, err)
	require.False(t, running, "a stale lock file is not a running server")
	require.Zero(t, record.Postmaster.PID)
	require.NoFileExists(t, pidPath, "the stale lock file is cleared so the server can start")
	require.True(t, stillAlive(t, stranger), "clearing it signals nothing")
}

func TestIsPostmasterExecutable(t *testing.T) {
	require.True(t, isPostmasterExecutable("postgres"))
	require.True(t, isPostmasterExecutable("postmaster"))
	for _, stranger := range []string{"", "sleep", "postgres-wrapper", "pg_ctl", "node"} {
		require.False(t, isPostmasterExecutable(stranger), stranger)
	}
}
