package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The bootstrap image's readiness wait is shell, and its contract — give up
// nonzero inside a budget, and tell a database that is merely unavailable apart
// from one that is misconfigured — only holds when a shell actually runs it.
// This executes the rendered CMD as a real subprocess against stub clients, so
// a regression in the rendered text fails here rather than in a cluster.
func TestBootstrapReadinessWaitEndsWithinItsBudget(t *testing.T) {
	const budget = 4 * time.Second
	// The loop checks the deadline before sleeping, so it can overshoot by one
	// poll interval plus process spawn. It can also stop up to a second early:
	// `date +%s` has second granularity, so the deadline it computes is
	// anywhere inside the second the loop started in.
	const overshoot = 6 * time.Second
	const granularity = time.Second
	// A real DSN shape, so a run that echoes what it connected to fails the
	// credential assertion below.
	const connection = "postgresql://owner:s3cr3tpassword@10.255.255.1:5432/app?sslmode=disable"

	tests := []struct {
		name             string
		readinessStatus  int
		withMigration    bool
		wantExit         int
		wantMessage      string
		wantMinElapsed   time.Duration
		wantMaxElapsed   time.Duration
		wantBootstrapRan bool
	}{
		{
			name:            "unavailable database exhausts the budget",
			readinessStatus: 2,
			withMigration:   true,
			wantExit:        1,
			wantMessage:     "did not accept connections within 4s (last pg_isready status 2)",
			wantMinElapsed:  budget - granularity,
			wantMaxElapsed:  budget + overshoot,
		},
		{
			// An unusable configuration is not worth waiting out: it must fail
			// well before the budget rather than after it.
			name:            "invalid connection parameters fail immediately",
			readinessStatus: 3,
			withMigration:   true,
			wantExit:        78,
			wantMessage:     "database connection parameters are invalid",
			wantMaxElapsed:  budget,
		},
		{
			name:             "available database proceeds to bootstrap",
			readinessStatus:  0,
			wantExit:         0,
			wantMaxElapsed:   budget,
			wantBootstrapRan: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stubs := t.TempDir()
			writeClientStub(t, stubs, "pg_isready", test.readinessStatus)
			writeClientStub(t, stubs, "psql", 0)

			command := exec.Command("sh", "-c", bootstrapCommand(t, int(budget/time.Second), test.withMigration))
			command.Env = append(os.Environ(),
				"PATH="+stubs+string(os.PathListSeparator)+os.Getenv("PATH"),
				migrationConnectionEnvironmentKey+"="+connection,
			)
			started := time.Now()
			output, err := command.CombinedOutput()
			elapsed := time.Since(started)

			if got := exitCode(t, err); got != test.wantExit {
				t.Fatalf("exit code = %d, want %d\n%s", got, test.wantExit, output)
			}
			if test.wantMessage != "" && !strings.Contains(string(output), test.wantMessage) {
				t.Fatalf("output does not report the failing phase %q:\n%s", test.wantMessage, output)
			}
			// A terminal error must stay useful without becoming a credential
			// leak: the DSN password never reaches the Job's logs.
			if strings.Contains(string(output), "s3cr3tpassword") {
				t.Fatalf("bootstrap output leaked the connection password:\n%s", output)
			}
			if elapsed < test.wantMinElapsed {
				t.Fatalf("gave up after %s, before the %s budget was spent", elapsed, test.wantMinElapsed)
			}
			if elapsed > test.wantMaxElapsed {
				t.Fatalf("took %s, beyond the %s bound", elapsed, test.wantMaxElapsed)
			}
			// The readiness loop is a gate: bootstrap work must not run against
			// a database that never answered.
			if ran := clientStubRan(t, stubs, "psql"); ran != test.wantBootstrapRan {
				t.Fatalf("bootstrap ran = %t, want %t\n%s", ran, test.wantBootstrapRan, output)
			}
		})
	}
}

// bootstrapCommand renders the bootstrap program the image's CMD runs, so a
// regression in the rendered text fails here rather than in a cluster.
func bootstrapCommand(t *testing.T, readinessSeconds int, withMigration bool) string {
	t.Helper()
	parameters := DockerTemplating{
		MigrationConnectionEnvironment: migrationConnectionEnvironmentKey,
		ReadinessTimeoutSeconds:        readinessSeconds,
	}
	if withMigration {
		parameters.Lineages = []BootstrapLineage{{Label: "store", Stage: "00-store", Ledger: "schema_migrations"}}
	}
	return renderStagedTemplate(t, "templates/bootstrap/bootstrap.sh.tmpl", parameters)
}

// writeClientStub installs a postgres client the bootstrap CMD invokes,
// recording that it ran and exiting with the given status.
func writeClientStub(t *testing.T, directory, name string, status int) {
	t.Helper()
	script := fmt.Sprintf("#!/bin/sh\ntouch %s\nexit %d\n", filepath.Join(directory, name+".ran"), status)
	if err := os.WriteFile(filepath.Join(directory, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func clientStubRan(t *testing.T, directory, name string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(directory, name+".ran"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return exit.ExitCode()
}
