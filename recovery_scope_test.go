package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	runners "github.com/codefly-dev/core/runners/base"
	"github.com/codefly-dev/core/runners/dockerrun"
	"github.com/codefly-dev/core/runners/runstate"
)

// Source validation launches this suite below the Go runner. Fixture
// containers belong to this test process, not its inherited CLI scope.
func TestMain(m *testing.M) {
	code := func() int {
		dir, err := os.MkdirTemp("", "service-postgres-test-scope-*")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer os.RemoveAll(dir)
		scope, err := dockerrun.NewContainerRecoveryScope(dir, dir, "service-postgres-tests")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := dockerrun.SetContainerRecoveryScope(scope); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		// Native run servers started by this suite live under the suite's own
		// directory, never beside a developer's real runs, and none outlives it.
		servers := filepath.Join(dir, "run-servers")
		runServersDir = func() (string, error) { return servers, nil }
		defer stopEveryRunServer(servers)
		return m.Run()
	}()
	os.Exit(code)
}

func stopEveryRunServer(servers string) {
	entries, _ := os.ReadDir(servers)
	for _, entry := range entries {
		root := filepath.Join(servers, entry.Name())
		left, err := runstate.Tracked(root)
		for _, server := range left {
			err = errors.Join(err, runners.SignalProcess(context.Background(), server, syscall.SIGINT))
		}
		if err != nil || len(left) > 0 {
			fmt.Fprintf(os.Stderr, "run server %s outlived its test (stopped=%v err=%v)\n", entry.Name(), len(left) > 0, err)
		}
	}
}
