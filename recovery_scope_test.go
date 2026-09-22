package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/codefly-dev/core/runners/dockerrun"
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
		return m.Run()
	}()
	os.Exit(code)
}
