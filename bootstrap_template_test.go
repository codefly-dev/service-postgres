package main

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
	"text/template"
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
			hasMigration := strings.Contains(dockerfile, "/usr/local/bin/migrate -path")
			if hasMigration != test.withMigrations {
				t.Fatalf("migration command present = %t, want %t", hasMigration, test.withMigrations)
			}

			accessSQL := renderBuilderTemplate(t, "templates/builder/runtime-access.sql.tmpl", parameters)
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

func renderBuilderTemplate(t *testing.T, name string, parameters DockerTemplating) string {
	t.Helper()
	source, err := fs.ReadFile(builderFS, name)
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
