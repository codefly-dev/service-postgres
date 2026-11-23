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

// testBootstrapTemplating mirrors what Build derives for a service with no
// declared login, so the template tests exercise the shape the builder renders.
func testBootstrapTemplating() DockerTemplating {
	return DockerTemplating{ReadinessTimeoutSeconds: defaultBootstrapReadinessSeconds}
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
		"COPY --from=migrate-builder /bootstrap /app/bootstrap",
		"FROM scratch",
		"USER 65534:65534",
		`ENTRYPOINT ["/usr/local/bin/managed-bootstrap", "-package", "/app/bootstrap", "-migrate", "/usr/local/bin/migrate"]`,
	} {
		if !strings.Contains(dockerfile, required) {
			t.Fatalf("bootstrap image is missing %q", required)
		}
	}
}

func TestBootstrapImageIsTargetArchitecturePortable(t *testing.T) {
	dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", testBootstrapTemplating())
	for _, required := range []string{
		"FROM --platform=$BUILDPLATFORM " + bootstrapLock.Migrate.Toolchain,
		"ARG TARGETARCH",
		`architecture="${TARGETARCH:-$(go env GOARCH)}"`,
		`case "$architecture" in amd64|arm64)`,
		`GOARCH="$architecture"`,
		"CGO_ENABLED=0 GOOS=linux",
		`*) echo "unsupported target architecture: $architecture" >&2; exit 1 ;;`,
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
	if err := os.MkdirAll(filepath.Join(root, "bootstrap"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := stageBootstrapMigrate(filepath.Join(root, "bootstrap")); err != nil {
		t.Fatal(err)
	}
	tag := uniqueDockerName("service-postgres-bootstrap-targetarch-test:")
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

	tag := uniqueDockerName("service-postgres-bootstrap-migrations-test:")
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
	// The runner refuses an owner connection to any database but the plan's.
	queryBootstrapPostgres(t, database, "CREATE DATABASE "+builder.DatabaseName)
	bootstrap := exec.Command(
		"docker", "run", "--rm",
		"--network", "container:"+database,
		"--env", migrationConnectionEnvironmentKey+"=postgres://postgres:bootstrap-test@127.0.0.1:5432/"+builder.DatabaseName+"?sslmode=disable",
		// The runner reconciles the runtime logins with these passwords.
		"--env", "POSTGRES_READ_ONLY_PASSWORD=read-only-secret",
		"--env", "POSTGRES_READ_WRITE_PASSWORD=read-write-secret",
		tag,
	)
	if output, err := bootstrap.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap job failed against a real database: %v\n%s", err, output)
	}

	// psql renders booleans as t/f (queried in the database container).
	for relation, want := range map[string]string{
		"public.deployed_one":         "t",
		"public.deployed_three":       "t",
		"public.stray_must_not_apply": "f",
	} {
		got := queryBootstrapDatabase(t, database, builder.DatabaseName, fmt.Sprintf("SELECT to_regclass('%s') IS NOT NULL", relation))
		if got != want {
			t.Errorf("relation %s present = %q, want %q", relation, got, want)
		}
	}
	// Concatenation casts the boolean to text, so dirty reads "false" here.
	if ledger := queryBootstrapDatabase(t, database, builder.DatabaseName, "SELECT version || '/' || dirty FROM schema_migrations"); ledger != "3/false" {
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

	name := uniqueDockerName("service-postgres-bootstrap-db-")
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
	return queryBootstrapDatabase(t, container, "postgres", query)
}

func queryBootstrapDatabase(t *testing.T, container, database, query string) string {
	t.Helper()
	output, err := exec.Command(
		"docker", "exec", container,
		"psql", "--username", "postgres", "--dbname", database, "--no-align", "--tuples-only", "--command", query,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("query %q: %v\n%s", query, err, output)
	}
	return strings.TrimSpace(string(output))
}

func renderBuilderTemplate(t *testing.T, name string, parameters DockerTemplating) string {
	return renderTemplate(t, builderFS, name, parameters)
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
