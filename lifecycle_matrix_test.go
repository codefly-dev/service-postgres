package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codefly-dev/core/resources"
	runners "github.com/codefly-dev/core/runners/base"
	"github.com/codefly-dev/core/runners/testmatrix"
)

// TestPostgresLifecycle_Matrix exercises the postgres agent's toolchain parity
// across native, nix, and docker — the architectural rule that every plugin
// tests all three execution backends. It writes the agent's embedded flake into
// the matrix dir so the nix backend provisions postgresql_16 (mirroring the
// postgres:16 Docker image), then verifies `initdb` is reachable in each.
//
// Run a single backend with Only(...) (e.g. when Docker is down):
//
//	go test -run TestPostgresLifecycle_Matrix ./...   # all available backends
func TestPostgresLifecycle_Matrix(t *testing.T) {
	dir, err := os.MkdirTemp("", "postgres-matrix-*")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	defer os.RemoveAll(dir)

	// The nix backend (testmatrix) constructs NewNixEnvironment(dir), which needs
	// a flake.nix in dir; the agent's embedded flake provides postgresql_16.
	if err := os.WriteFile(filepath.Join(dir, "flake.nix"), []byte(pgFlakeNix), 0o644); err != nil {
		t.Fatalf("write flake.nix: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flake.lock"), []byte(pgFlakeLock), 0o644); err != nil {
		t.Fatalf("write flake.lock: %v", err)
	}

	img := &resources.DockerImage{Name: "postgres", Tag: "16.1-alpine"}

	testmatrix.ForEachEnvironment(t, dir,
		func(t *testing.T, env runners.RunnerEnvironment) {
			proc, err := env.NewProcess("initdb", "--version")
			if err != nil {
				t.Fatalf("NewProcess: %v", err)
			}
			var buf bytes.Buffer
			proc.WithOutput(&buf)
			if err := proc.Run(context.Background()); err != nil {
				t.Fatalf("initdb --version failed: %v\n%s", err, buf.String())
			}
			// Version-agnostic reach check: any reachable postgres toolchain
			// passes (a host may carry a different major than the nix/docker
			// pins; this asserts parity of REACH, not exact version).
			if !strings.Contains(buf.String(), "PostgreSQL") {
				t.Fatalf("expected an initdb version banner, got %q", buf.String())
			}
		},
		testmatrix.WithDockerImage(img),
	)
}
