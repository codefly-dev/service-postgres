package main

import (
	"bytes"
	"context"
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

	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
)

// testBootstrapTemplating mirrors what Build derives from a resolved schema
// plan, so the template tests exercise the same shape the builder renders.
func testBootstrapTemplating(lineages ...BootstrapLineage) DockerTemplating {
	return DockerTemplating{
		MigrationConnectionEnvironment: migrationConnectionEnvironmentKey,
		RuntimeAccessLockID:            runtimeAccessLockID,
		ReadOnlyRole:                   "codefly_app_ro",
		ReadWriteRole:                  "codefly_app_rw",
		Schemas:                        []string{"public", "audit"},
		ReadinessTimeoutSeconds:        defaultBootstrapReadinessSeconds,
		Extensions:                     []BootstrapExtension{{Name: "vector"}, {Name: "hstore", Required: true}},
		Lineages:                       lineages,
	}
}

func TestBootstrapImageAlwaysReconcilesRuntimeAccess(t *testing.T) {
	tests := []struct {
		name     string
		lineages []BootstrapLineage
	}{
		{name: "with migrations", lineages: []BootstrapLineage{
			{Label: "store", Stage: "00-store", Ledger: "schema_migrations"},
		}},
		{name: "without migrations"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parameters := testBootstrapTemplating(test.lineages...)
			program := renderStagedTemplate(t, "templates/bootstrap/bootstrap.sh.tmpl", parameters)
			dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", parameters)

			// The program gates the run and then hands every database step to
			// the one locked psql session.
			if !strings.Contains(program, "psql \"${connection}\" --no-psqlrc --set=ON_ERROR_STOP=1 --file=/app/bootstrap.sql") {
				t.Fatal("bootstrap program does not run the locked bootstrap session")
			}
			if !strings.Contains(program, "pg_isready -q -d \"${connection}\"") {
				t.Fatal("bootstrap program does not wait for Postgres readiness")
			}
			for _, required := range []string{
				fmt.Sprintf("readiness_deadline=$(($(date +%%s) + %d))", defaultBootstrapReadinessSeconds),
				fmt.Sprintf("did not accept connections within %ds", defaultBootstrapReadinessSeconds),
				"exit 1",
				"exit 78",
			} {
				if !strings.Contains(program, required) {
					t.Fatalf("bootstrap readiness wait is not bounded: missing %q", required)
				}
			}
			if !strings.Contains(program, "connection=\"${"+migrationConnectionEnvironmentKey+":-}\"") {
				t.Fatalf("bootstrap program does not read the connection from %s", migrationConnectionEnvironmentKey)
			}
			// The image is built from the service directory by a separate
			// process, so staged content that drifted must stop the run rather
			// than apply fewer migrations and report success.
			verifies := strings.Contains(program, "sha256sum -c sources.sha256")
			if verifies != (len(test.lineages) > 0) {
				t.Fatalf("staged-source verification present = %t, want %t", verifies, len(test.lineages) > 0)
			}

			// The migration no longer runs from the Dockerfile CMD. It runs as a
			// child of the psql session holding the runtime-access advisory
			// lock, so both bootstrap steps share ONE lock domain instead of
			// colliding on the tracking table. The image still INSTALLS the
			// binary, so this asserts on the invocation form only.
			if strings.Contains(dockerfile, "/usr/local/bin/migrate -path") {
				t.Fatal("migrate must not run as its own process outside the locked psql session")
			}

			// The orchestration script holds the lock across every step and
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
			if !strings.Contains(bootstrapSQL, `\i /app/bootstrap/extensions.sql`) {
				t.Fatal("bootstrap does not always create the required extensions")
			}
			hasMigration := strings.Contains(bootstrapSQL, `/usr/local/bin/migrate -path`)
			if hasMigration != (len(test.lineages) > 0) {
				t.Fatalf("migration command present = %t, want %t", hasMigration, len(test.lineages) > 0)
			}
			// ON_ERROR_STOP does not cover \!, so a failed migration must be
			// caught explicitly or the grants would run over an unmigrated schema.
			if strings.Count(bootstrapSQL, `\if :SHELL_ERROR`) != len(test.lineages) {
				t.Fatalf("each migration must check its child exit status:\n%s", bootstrapSQL)
			}

			accessSQL := renderRuntimeAccessTemplate(t, parameters)
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

// TestBootstrapProgramAppliesEveryLineageToItsOwnLedger is the deployed half of
// the local multi-source contract: each source is applied to its own ledger, in
// TestBootstrapProgramAppliesEveryLineageToItsOwnLedger is the deployed half of
// the local multi-source contract: each source is applied to its own ledger, in
// declared order, inside the one session holding the runtime-access lock, and
// the own source keeps golang-migrate's default table name.
func TestBootstrapProgramAppliesEveryLineageToItsOwnLedger(t *testing.T) {
	parameters := testBootstrapTemplating(
		BootstrapLineage{Label: "store", Stage: "00-store", Ledger: "schema_migrations"},
		BootstrapLineage{Label: "api", Stage: "01-api", Ledger: "schema_migrations_api"},
		BootstrapLineage{Label: "billing", Stage: "02-billing", Ledger: "schema_migrations_billing"},
	)
	bootstrapSQL := renderBootstrapTemplate(t, parameters)

	previous := -1
	for _, expected := range []string{
		`-path /app/bootstrap/sources/00-store -database "${` + migrationConnectionEnvironmentKey + `}${CODEFLY_LEDGER_SEPARATOR}x-migrations-table=schema_migrations"`,
		`-path /app/bootstrap/sources/01-api -database "${` + migrationConnectionEnvironmentKey + `}${CODEFLY_LEDGER_SEPARATOR}x-migrations-table=schema_migrations_api"`,
		`-path /app/bootstrap/sources/02-billing -database "${` + migrationConnectionEnvironmentKey + `}${CODEFLY_LEDGER_SEPARATOR}x-migrations-table=schema_migrations_billing"`,
	} {
		at := strings.Index(bootstrapSQL, expected)
		if at < 0 {
			t.Fatalf("bootstrap does not apply %q:\n%s", expected, bootstrapSQL)
		}
		if at < previous {
			t.Fatalf("bootstrap applies %q out of declared order", expected)
		}
		previous = at
	}
	// Every lineage runs between the lock and the grants, or a concurrent pod
	// could migrate while this one rewrites the same tracking table.
	lock := strings.Index(bootstrapSQL, "pg_advisory_lock(")
	grants := strings.Index(bootstrapSQL, `\i /app/runtime-access.sql`)
	if lock < 0 || grants < 0 || lock > previous || previous > grants {
		t.Fatalf("migrations do not run between the lock and the grants:\n%s", bootstrapSQL)
	}
	// The ledger is a DSN query parameter, so the separator is resolved by the
	// program against a connection string that may already carry a query.
	program := renderStagedTemplate(t, "templates/bootstrap/bootstrap.sh.tmpl", parameters)
	if !strings.Contains(program, `*\?*) CODEFLY_LEDGER_SEPARATOR="&"`) {
		t.Fatal("bootstrap program overwrites an existing DSN query instead of appending the ledger")
	}
	if !strings.Contains(program, "export CODEFLY_LEDGER_SEPARATOR") {
		t.Fatal("the ledger separator does not reach the migrate child process")
	}
}

// TestBootstrapExtensionsAreCreatedBestEffort keeps the deployed extension
// behavior identical to the local runtimes: a missing shared library warns and
// the bootstrap continues, while every other failure still stops the run.
func TestBootstrapExtensionsAreCreatedBestEffort(t *testing.T) {
	extensions := renderStagedTemplate(t, "templates/bootstrap/extensions.sql.tmpl", testBootstrapTemplating())

	for _, required := range []string{
		`\set ON_ERROR_STOP on`,
		`CREATE EXTENSION IF NOT EXISTS "vector";`,
		`CREATE EXTENSION IF NOT EXISTS "hstore";`,
		"EXCEPTION WHEN OTHERS THEN",
		"RAISE WARNING",
	} {
		if !strings.Contains(extensions, required) {
			t.Fatalf("generated extensions program missing %q", required)
		}
	}
	// A required extension must abort the bootstrap exactly as it fails the local
	// runtime's readiness, so it may not be wrapped in the tolerant DO block.
	optional, _, found := strings.Cut(extensions, `CREATE EXTENSION IF NOT EXISTS "hstore";`)
	if !found {
		t.Fatal("required extension is not created")
	}
	if strings.Count(optional, "EXCEPTION WHEN OTHERS THEN") != 1 {
		t.Fatalf("required extension is created best-effort instead of failing closed:\n%s", extensions)
	}
}

// TestBootstrapImageCopiesOnlyTheStagedArtifact guards the image contents: the
// build context is the whole service directory, which carries local
// configuration and secrets, so a wholesale copy would bake them into the image.
func TestBootstrapImageCopiesOnlyTheStagedArtifact(t *testing.T) {
	dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", testBootstrapTemplating())

	if strings.Contains(dockerfile, "COPY . .") {
		t.Fatal("bootstrap image copies the whole service directory, including local secrets")
	}
	for _, required := range []string{
		"COPY bootstrap /app/bootstrap",
		"COPY runtime-access.sql /app/runtime-access.sql",
		`CMD ["/bin/sh", "/app/bootstrap/bootstrap.sh"]`,
	} {
		if !strings.Contains(dockerfile, required) {
			t.Fatalf("bootstrap image is missing %q", required)
		}
	}
}

func TestBootstrapImageIsTargetArchitecturePortable(t *testing.T) {
	dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", testBootstrapTemplating())
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
}

func TestBootstrapImageBuildsWhenDockerOmitsTargetArchitecture(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	parameters := testBootstrapTemplating()
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
	if err := os.MkdirAll(filepath.Join(root, "bootstrap"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bootstrap", "bootstrap.sh"), []byte("set -eu\n"), 0o644); err != nil {
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

// TestBootstrapImageAppliesOnlyRealMigrations covers the leftovers a migrations
// directory accumulates. An editor backup kept beside a migration parses as the
// same version and direction as the file it shadows, so migrate rejects the
// whole lineage as a duplicate. Staging recognizes a migration with the one
// runtime filename definition, so a leftover never reaches the build context at
// all — this proves it end to end, against a real database.
func TestBootstrapImageAppliesOnlyRealMigrations(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	builder := newBuildTestBuilder(t)
	migrations := builder.Local("migrations")
	if err := os.RemoveAll(migrations); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(migrations, 0o755); err != nil {
		t.Fatal(err)
	}
	// Version 3 deliberately uses a non-.sql extension: golang-migrate applies it,
	// so dropping it would leave the bootstrap reporting success over an
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
		if err := os.WriteFile(filepath.Join(migrations, name),
			[]byte("CREATE TABLE stray_must_not_apply (id INT);\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	outputDirectory := t.TempDir()
	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	if err != nil {
		t.Fatal(err)
	}
	if state := response.GetState().GetState(); state != builderv0.BuildStatus_SUCCESS {
		t.Fatalf("build state = %v: %s", state, response.GetState().GetMessage())
	}

	entries, err := os.ReadDir(filepath.Join(outputDirectory, "bootstrap", "sources", "00-store"))
	if err != nil {
		t.Fatal(err)
	}
	var packaged []string
	for _, entry := range entries {
		packaged = append(packaged, entry.Name())
	}
	for name := range kept {
		if !slices.Contains(packaged, name) {
			t.Errorf("staging dropped migration %q: %v", name, packaged)
		}
	}
	for _, name := range stray {
		if slices.Contains(packaged, name) {
			t.Errorf("staging packaged stray file %q, which blocks the whole lineage", name)
		}
	}

	tag := fmt.Sprintf("service-postgres-bootstrap-migrations-test:%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = exec.Command("docker", "image", "rm", tag).Run()
	})
	build := exec.Command("docker", "build",
		"--file", filepath.Join(outputDirectory, "builder", "Dockerfile"),
		"--tag", tag, outputDirectory)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap image build failed: %v\n%s", err, output)
	}

	database := startBootstrapPostgres(t)
	bootstrap := exec.Command(
		"docker", "run", "--rm",
		"--network", "container:"+database,
		"--env", migrationConnectionEnvironmentKey+"=postgres://postgres:bootstrap-test@127.0.0.1:5432/postgres?sslmode=disable",
		// The recipe renders the real runtime-access program, which reconciles
		// the runtime roles from these; only a hand-stubbed context can omit them.
		"--env", "POSTGRES_USER=postgres",
		"--env", "POSTGRES_READ_ONLY_PASSWORD=read-only-secret",
		"--env", "POSTGRES_READ_WRITE_PASSWORD=read-write-secret",
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
	parameters := testBootstrapTemplating()
	parameters.Schemas = []string{"public"}
	parameters.ReadWriteRoles = []string{"app_tenant", "app_worker"}

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
	parameters := testBootstrapTemplating()
	parameters.Schemas = []string{"public"}

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

func renderStagedTemplate(t *testing.T, name string, parameters DockerTemplating) string {
	return renderTemplate(t, bootstrapFS, name, parameters)
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
