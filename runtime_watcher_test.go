package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/core/agents/helpers/code"
	"github.com/codefly-dev/core/agents/services"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/stretchr/testify/require"
)

// watcherTestRuntime is a loaded agent whose Location is a real service
// directory: the hot-reload watcher walks that tree, so the files it selects on
// (service.codefly.yaml, migrations/*.sql) must exist before it starts.
func watcherTestRuntime(t *testing.T) (*Runtime, string) {
	t.Helper()
	runtime := NewRuntime()
	require.NoError(t, runtime.HeadlessLoad(context.Background(), &basev0.ServiceIdentity{
		Workspace: "workspace",
		Module:    "module",
		Name:      "postgres",
		Version:   "1.2.3",
	}))

	location := t.TempDir()
	runtime.Location = location
	require.NoError(t, os.WriteFile(filepath.Join(location, "service.codefly.yaml"), []byte("name: postgres\n"), 0o600))
	migrations := filepath.Join(location, "migrations")
	require.NoError(t, os.MkdirAll(migrations, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(migrations, "1_base.up.sql"), []byte("SELECT 1;\n"), 0o600))
	return runtime, filepath.Join(migrations, "1_base.up.sql")
}

// countingWatch arms a watcher whose handler only counts invocations, so a
// leaked watcher shows up as an extra count rather than as database damage.
func countingWatch(t *testing.T, runtime *Runtime, calls *atomic.Int64) {
	t.Helper()
	require.NoError(t, runtime.SetupWatcher(context.Background(),
		services.NewWatchConfiguration(requirements),
		func(code.Change) error {
			calls.Add(1)
			return nil
		}))
}

// settle waits past the debounce window so any already-pending event has been
// delivered and counted before a test takes a baseline.
func settle() {
	time.Sleep(services.WatchDebounce + 2*time.Second)
}

// touchMigration rewrites a watched migration file and waits past the debounce
// window, so one save produces exactly one handler call PER LIVE WATCHER.
func touchMigration(t *testing.T, path string, generation int) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("SELECT %d;\n", generation)), 0o600))
	settle()
}

// TestStopTearsDownHotReloadWatcher pins the teardown that keeps overlapping
// replays from existing at all. core's SetupWatcher REPLACES s.Events,
// s.Watcher and s.watcherCancel without cancelling the watcher already stored
// there, and core documents StopWatcher as the mandatory teardown. A Stop that
// skips it therefore leaves the old watcher — and its debounce goroutine —
// running against the same EventHandler, so the next Start has two live
// watchers and every later save replays each migration twice: two full
// Force/Steps(-1)/Steps(1) cycles, i.e. two DROP/CREATE rounds over that
// migration's tables. Serializing the replays hides the corruption but not the
// duplicated destruction, so the leak has to be fixed at the source.
//
// Counts are compared as deltas around each save: the assertion is "one save
// reaches exactly one watcher", which stays exact whether or not arming a
// watcher emits an initial scan event.
func TestStopTearsDownHotReloadWatcher(t *testing.T) {
	runtime, migration := watcherTestRuntime(t)
	ctx := context.Background()

	var calls atomic.Int64
	countingWatch(t, runtime, &calls)
	settle()
	before := calls.Load()

	_, err := runtime.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)

	// Whatever Stop left behind must be inert: a save now must reach nobody.
	touchMigration(t, migration, 2)
	require.EqualValues(t, before, calls.Load(), "Stop must leave no watcher firing EventHandler")

	// A fresh Start arms exactly one watcher, so one save is exactly one replay.
	countingWatch(t, runtime, &calls)
	settle()
	before = calls.Load()

	touchMigration(t, migration, 3)
	require.EqualValues(t, before+1, calls.Load(),
		"Start after Stop must leave exactly one live watcher; a leaked one replays every migration twice")
}

// TestDestroyTearsDownHotReloadWatcher covers the other teardown path: Destroy
// removes the database the watcher replays against, so a watcher outliving it
// would keep firing EventHandler at a torn-down database. Destroy's own docker
// teardown is irrelevant here and its result is deliberately ignored —
// StopWatcher runs before Destroy branches on the runner, so the watcher must
// be inert whether or not a container was there to remove.
func TestDestroyTearsDownHotReloadWatcher(t *testing.T) {
	runtime, migration := watcherTestRuntime(t)
	ctx := context.Background()

	var calls atomic.Int64
	countingWatch(t, runtime, &calls)
	settle()
	before := calls.Load()

	_, _ = runtime.Destroy(ctx, &runtimev0.DestroyRequest{})

	touchMigration(t, migration, 2)
	require.EqualValues(t, before, calls.Load(), "no watcher may survive Destroy")
}
