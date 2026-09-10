package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"text/template"
	"time"
)

func TestBootstrapImageAlwaysReconcilesRuntimeAccess(t *testing.T) {
	tests := []struct {
		name           string
		withMigrations bool
	}{
		{name: "with migrations", withMigrations: true},
		{name: "without migrations", withMigrations: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parameters := DockerTemplating{
				MigrationConnectionKeyHolder: "{" + migrationConnectionEnvironmentKey + "}",
				RuntimeAccessLockID:          runtimeAccessLockID,
				WithMigration:                test.withMigrations,
				ReadinessTimeoutSeconds:      300,
				ReadOnlyRole:                 "codefly_app_ro",
				ReadWriteRole:                "codefly_app_rw",
				Schemas:                      []string{"public", "audit"},
			}
			dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", parameters)
			if strings.Contains(dockerfile, `CMD set -eu; \ /`) {
				t.Fatal("bootstrap command escaped a space instead of continuing onto the next shell command")
			}
			if !strings.Contains(dockerfile, "psql \"${"+migrationConnectionEnvironmentKey+"}\"") {
				t.Fatal("bootstrap image does not always reconcile runtime roles")
			}
			if !strings.Contains(dockerfile, "pg_isready -q -d \"${"+migrationConnectionEnvironmentKey+"}\"") {
				t.Fatal("bootstrap image does not wait for Postgres readiness")
			}
			for _, required := range []string{
				"readiness_deadline=$(($(date +%s) + 300))",
				"did not accept connections within 300s",
				"exit 1",
				"exit 78",
			} {
				if !strings.Contains(dockerfile, required) {
					t.Fatalf("bootstrap readiness wait is not bounded: missing %q", required)
				}
			}
			for _, required := range []string{
				"ARG TARGETARCH",
				`architecture="${TARGETARCH:-$(apk --print-arch)}"`,
				"x86_64) architecture=amd64",
				"aarch64) architecture=arm64",
				`case "${architecture}" in`,
				"amd64) checksum=",
				"arm64) checksum=",
				`*) echo "unsupported target architecture: ${architecture}" >&2; exit 1 ;;`,
				"/releases/download/" + bootstrapLock.Migrate.Version + "/migrate.linux-${architecture}.tar.gz",
			} {
				if !strings.Contains(dockerfile, required) {
					t.Fatalf("bootstrap image is not target-architecture portable: missing %q", required)
				}
			}
			// The migration no longer runs from the Dockerfile CMD. It runs as a
			// child of the psql session holding the runtime-access advisory
			// lock, so both bootstrap steps share ONE lock domain instead of
			// colliding on the tracking table. The image still INSTALLS the
			// binary, so this asserts on the invocation form only.
			if strings.Contains(dockerfile, "/usr/local/bin/migrate -path") {
				t.Fatal("migrate must not run as its own process outside the locked psql session")
			}

			// The orchestration script holds the lock across both steps and
			// includes the access script rather than absorbing it: a consumer
			// substituting runtime-access.sql must not silently lose the
			// migration with it.
			bootstrapSQL := renderBootstrapTemplate(t, parameters)
			if !strings.Contains(bootstrapSQL, "pg_advisory_lock("+runtimeAccessLockID+")") {
				t.Fatal("bootstrap does not hold the runtime-access advisory lock")
			}
			if !strings.Contains(bootstrapSQL, `\i /app/runtime-access.sql`) {
				t.Fatal("bootstrap does not include the runtime-access script")
			}
			hasMigration := strings.Contains(bootstrapSQL, `/usr/local/bin/migrate -path`)
			if hasMigration != test.withMigrations {
				t.Fatalf("migration command present = %t, want %t", hasMigration, test.withMigrations)
			}

			accessSQL := renderRuntimeAccessTemplate(t, parameters)
			// runtime-access.sql stays purely about access.
			if strings.Contains(accessSQL, "/usr/local/bin/migrate") {
				t.Fatal("runtime-access.sql must not run migrations; a substituted copy would drop them")
			}
			for _, required := range []string{
				"NOBYPASSRLS",
				"NOCREATEROLE",
				"default_transaction_read_only = on",
				"REVOKE CREATE ON SCHEMA",
				"codefly_app_ro",
				"codefly_app_rw",
				"public",
				"audit",
			} {
				if !strings.Contains(accessSQL, required) {
					t.Fatalf("runtime access bootstrap missing %q", required)
				}
			}
			for _, forbidden := range []string{"POSTGRES_PASSWORD", "connection=", " WITH BYPASSRLS"} {
				if strings.Contains(accessSQL, forbidden) {
					t.Fatalf("runtime access bootstrap contains forbidden material %q", forbidden)
				}
			}
		})
	}
}

func TestBootstrapImageBuildsWhenDockerOmitsTargetArchitecture(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	parameters := DockerTemplating{
		MigrationConnectionKeyHolder: "{" + migrationConnectionEnvironmentKey + "}",
		RuntimeAccessLockID:          runtimeAccessLockID,
		ReadinessTimeoutSeconds:      defaultBootstrapReadinessSeconds,
	}
	if err := os.WriteFile(
		filepath.Join(root, "Dockerfile"),
		[]byte(renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", parameters)),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runtime-access.sql"), []byte("SELECT 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bootstrap.sql"),
		[]byte(renderBootstrapTemplate(t, parameters)), 0o644); err != nil {
		t.Fatal(err)
	}
	tag := fmt.Sprintf("service-postgres-bootstrap-targetarch-test:%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = exec.Command("docker", "image", "rm", tag).Run()
	})
	command := exec.Command("docker", "build", "--build-arg", "TARGETARCH=", "--tag", tag, root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("legacy Docker build without TARGETARCH failed: %v\n%s", err, output)
	}
}

// TestBootstrapImageAppliesOnlyRealMigrations drives the deployed bootstrap end
// to end against a disposable Postgres: the image must prune exactly what the
// runtime filter hides — nothing more — and then apply every real migration,
// whatever extension it carries.
func TestBootstrapImageAppliesOnlyRealMigrations(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}
	parameters := DockerTemplating{
		MigrationConnectionKeyHolder: "{" + migrationConnectionEnvironmentKey + "}",
		RuntimeAccessLockID:          runtimeAccessLockID,
		WithMigration:                true,
		MigrationFileNamePattern:     migrationFileNamePattern,
		ReadinessTimeoutSeconds:      defaultBootstrapReadinessSeconds,
	}
	dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", parameters)
	// One definition of a migration filename: a prune that drifts from the
	// runtime filter deletes files the runtime would have applied.
	if !strings.Contains(dockerfile, migrationFileNamePattern) {
		t.Fatalf("bootstrap prune does not use the runtime filename pattern %q", migrationFileNamePattern)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runtime-access.sql"), []byte("SELECT 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bootstrap.sql"),
		[]byte(renderBootstrapTemplate(t, parameters)), 0o644); err != nil {
		t.Fatal(err)
	}
	migrations := filepath.Join(root, "migrations")
	if err := os.MkdirAll(migrations, 0o755); err != nil {
		t.Fatal(err)
	}
	// Version 3 deliberately uses a non-.sql extension: golang-migrate applies it,
	// so pruning it would leave the bootstrap reporting success over an
	// unmigrated database.
	kept := map[string]string{
		"1_init.up.sql":         "CREATE TABLE deployed_one (id INT PRIMARY KEY);",
		"1_init.down.sql":       "DROP TABLE deployed_one;",
		"2_add_index.up.sql":    "CREATE INDEX deployed_one_id_idx ON deployed_one (id);",
		"2_add_index.down.sql":  "DROP INDEX deployed_one_id_idx;",
		"3_flavored.up.pgsql":   "CREATE TABLE deployed_three (id INT PRIMARY KEY);",
		"3_flavored.down.pgsql": "DROP TABLE deployed_three;",
	}
	stray := []string{
		"2_add_index.up.sql~",
		"2_add_index.up.sql.bak",
		"2_add_index.up.sql.orig",
		".2_add_index.up.sql.swp",
		"3_flavored.up.pgsql~",
	}
	for name, body := range kept {
		if err := os.WriteFile(filepath.Join(migrations, name), []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range stray {
		body := "CREATE TABLE stray_must_not_apply (id INT);\n"
		if err := os.WriteFile(filepath.Join(migrations, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	tag := fmt.Sprintf("service-postgres-bootstrap-migrations-test:%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = exec.Command("docker", "image", "rm", tag).Run()
	})
	if output, err := exec.Command("docker", "build", "--tag", tag, root).CombinedOutput(); err != nil {
		t.Fatalf("bootstrap image build failed: %v\n%s", err, output)
	}

	output, err := exec.Command("docker", "run", "--rm", tag, "ls", "-A", "/app/migrations").CombinedOutput()
	if err != nil {
		t.Fatalf("list packaged migrations: %v\n%s", err, output)
	}
	packaged := strings.Fields(string(output))
	for name := range kept {
		if !slices.Contains(packaged, name) {
			t.Errorf("bootstrap image dropped migration %q: %v", name, packaged)
		}
	}
	for _, name := range stray {
		if slices.Contains(packaged, name) {
			t.Errorf("bootstrap image packaged stray file %q, which blocks the whole lineage", name)
		}
	}

	database := startBootstrapPostgres(t)
	bootstrap := exec.Command(
		"docker", "run", "--rm",
		"--network", "container:"+database,
		"--env", migrationConnectionEnvironmentKey+"=postgres://postgres:bootstrap-test@127.0.0.1:5432/postgres?sslmode=disable",
		tag,
	)
	if output, err := bootstrap.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap job failed against a real database: %v\n%s", err, output)
	}

	// psql renders booleans as t/f.
	for relation, want := range map[string]string{
		"public.deployed_one":         "t",
		"public.deployed_three":       "t",
		"public.stray_must_not_apply": "f",
	} {
		got := queryBootstrapPostgres(t, database, fmt.Sprintf("SELECT to_regclass('%s') IS NOT NULL", relation))
		if got != want {
			t.Errorf("relation %s present = %q, want %q", relation, got, want)
		}
	}
	// Concatenation casts the boolean to text, so dirty reads "false" here.
	if ledger := queryBootstrapPostgres(t, database, "SELECT version || '/' || dirty FROM schema_migrations"); ledger != "3/false" {
		t.Errorf("migration ledger = %q, want %q", ledger, "3/false")
	}
}

// startBootstrapPostgres runs the Postgres image this repository already pins
// for its runtime and returns the container name, ready for connections.
func startBootstrapPostgres(t *testing.T) string {
	t.Helper()
	dockerfile, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	var image string
	for _, line := range strings.Split(string(dockerfile), "\n") {
		if rest, found := strings.CutPrefix(line, "ARG POSTGRES_IMAGE="); found {
			image = strings.TrimSpace(rest)
			break
		}
	}
	if image == "" {
		t.Fatal("no pinned POSTGRES_IMAGE in Dockerfile")
	}

	name := fmt.Sprintf("service-postgres-bootstrap-db-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "--force", name).Run()
	})
	run := exec.Command(
		"docker", "run", "--detach", "--name", name,
		"--env", "POSTGRES_PASSWORD=bootstrap-test",
		image,
	)
	if output, err := run.CombinedOutput(); err != nil {
		t.Fatalf("start disposable postgres: %v\n%s", err, output)
	}
	for range 60 {
		// The bootstrap connects over TCP; the initialization server can accept
		// Unix-socket connections before the final TCP listener is available.
		if exec.Command("docker", "exec", name, "pg_isready", "--host", "127.0.0.1", "--username", "postgres").Run() == nil {
			return name
		}
		time.Sleep(time.Second)
	}
	logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
	t.Fatalf("disposable postgres never became ready\n%s", logs)
	return ""
}

func queryBootstrapPostgres(t *testing.T, container string, query string) string {
	t.Helper()
	output, err := exec.Command(
		"docker", "exec", container,
		"psql", "--username", "postgres", "--no-align", "--tuples-only", "--command", query,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("query %q: %v\n%s", query, err, output)
	}
	return strings.TrimSpace(string(output))
}

func TestRuntimeAccessTemplateUsesDelegatedRolesAsExclusiveWriteAuthority(t *testing.T) {
	parameters := DockerTemplating{
		MigrationConnectionKeyHolder: "{" + migrationConnectionEnvironmentKey + "}",
		ReadOnlyRole:                 "codefly_app_ro",
		ReadWriteRole:                "codefly_app_rw",
		Schemas:                      []string{"public"},
		ReadWriteRoles:               []string{"app_tenant", "app_worker"},
	}

	accessSQL := renderRuntimeAccessTemplate(t, parameters)
	for _, forbidden := range []string{
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES",
		"GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES",
		"GRANT USAGE, SELECT, UPDATE ON SEQUENCES",
	} {
		if strings.Contains(accessSQL, forbidden) {
			t.Fatalf("delegated read-write login retained direct authority %q", forbidden)
		}
	}
	for _, required := range []string{
		"REVOKE ALL PRIVILEGES ON ALL TABLES",
		"REVOKE ALL PRIVILEGES ON ALL SEQUENCES",
		"GRANT %I TO %I",
		"app_tenant",
		"app_worker",
	} {
		if !strings.Contains(accessSQL, required) {
			t.Fatalf("delegated runtime access is missing %q", required)
		}
	}
}

func TestRuntimeAccessTemplatePreservesDirectWriterWithoutDelegatedRoles(t *testing.T) {
	parameters := DockerTemplating{
		MigrationConnectionKeyHolder: "{" + migrationConnectionEnvironmentKey + "}",
		ReadOnlyRole:                 "codefly_app_ro",
		ReadWriteRole:                "codefly_app_rw",
		Schemas:                      []string{"public"},
	}

	accessSQL := renderRuntimeAccessTemplate(t, parameters)
	for _, required := range []string{
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES",
		"GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES",
		"GRANT USAGE, SELECT, UPDATE ON SEQUENCES",
	} {
		if !strings.Contains(accessSQL, required) {
			t.Fatalf("direct runtime access is missing %q", required)
		}
	}
}

func renderBuilderTemplate(t *testing.T, name string, parameters DockerTemplating) string {
	return renderTemplate(t, builderFS, name, parameters)
}

func renderRuntimeAccessTemplate(t *testing.T, parameters DockerTemplating) string {
	return renderTemplate(t, runtimeFS, "templates/runtime/runtime-access.sql.tmpl", parameters)
}

// renderBootstrapTemplate renders the orchestration script the image runs: it
// holds the runtime-access lock across the migration and the grants.
func renderBootstrapTemplate(t *testing.T, parameters DockerTemplating) string {
	return renderTemplate(t, runtimeFS, "templates/runtime/bootstrap.sql.tmpl", parameters)
}

func renderTemplate(t *testing.T, fsys fs.FS, name string, parameters DockerTemplating) string {
	t.Helper()
	source, err := fs.ReadFile(fsys, name)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := template.New(name).Parse(string(source))
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := parsed.Execute(&rendered, parameters); err != nil {
		t.Fatal(err)
	}
	return rendered.String()
}
