package main

import (
	"os"
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

func TestReleaseOfAnUnattachedHandleStopsNothing(t *testing.T) {
	stopped, err := (&nixPostgres{}).release(t.Context())
	require.NoError(t, err)
	require.False(t, stopped)
}
