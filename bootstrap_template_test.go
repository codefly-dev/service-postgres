package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
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
				WithMigration:                test.withMigrations,
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
			if !strings.Contains(
				dockerfile,
				"until pg_isready -d \"${"+migrationConnectionEnvironmentKey+"}\" >/dev/null 2>&1; do sleep 2; done",
			) {
				t.Fatal("bootstrap image does not wait for Postgres readiness")
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
			hasMigration := strings.Contains(dockerfile, "/usr/local/bin/migrate -path")
			if hasMigration != test.withMigrations {
				t.Fatalf("migration command present = %t, want %t", hasMigration, test.withMigrations)
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

func TestBootstrapImageBuildsWhenDockerOmitsTargetArchitecture(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	parameters := DockerTemplating{
		MigrationConnectionKeyHolder: "{" + migrationConnectionEnvironmentKey + "}",
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
	tag := fmt.Sprintf("service-postgres-bootstrap-targetarch-test:%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = exec.Command("docker", "image", "rm", tag).Run()
	})
	command := exec.Command("docker", "build", "--build-arg", "TARGETARCH=", "--tag", tag, root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("legacy Docker build without TARGETARCH failed: %v\n%s", err, output)
	}
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
