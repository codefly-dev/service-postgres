package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestMigrationSources_YAMLRoundTrip locks the shared-database config: several
// services target ONE postgres while each owns its own migrations/ folder.
func TestMigrationSources_YAMLRoundTrip(t *testing.T) {
	src := []byte(`
database-name: app
migration-sources:
  - name: api
  - name: billing
    path: ../billing/db/migrations
`)
	var s Settings
	if err := yaml.Unmarshal(src, &s); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	if len(s.MigrationSources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(s.MigrationSources))
	}
	if s.MigrationSources[0].Name != "api" || s.MigrationSources[0].Path != "" {
		t.Errorf("source 0: %+v", s.MigrationSources[0])
	}
	if s.MigrationSources[1].Name != "billing" || s.MigrationSources[1].Path != "../billing/db/migrations" {
		t.Errorf("source 1: %+v", s.MigrationSources[1])
	}
}

func TestValidSourceName(t *testing.T) {
	for _, ok := range []string{"api", "billing", "svc_1", "ABC"} {
		if !validSourceName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "a b", "a;b", "a-b", "a.b", `a"b`} {
		if validSourceName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

// TestMigrationSources_Resolution checks that the own migrations dir gets the
// default tracking table, named sources get schema_migrations_<name> + the
// sibling-default path, and missing dirs are skipped.
func TestMigrationSources_Resolution(t *testing.T) {
	root := t.TempDir()
	svcDir := filepath.Join(root, "store")
	mustMkdir(t, filepath.Join(svcDir, "migrations"))
	mustMkdir(t, filepath.Join(root, "api", "migrations"))           // sibling default path
	mustMkdir(t, filepath.Join(root, "billing", "db", "migrations")) // explicit path

	s := NewRuntime()
	s.Location = svcDir
	s.Settings.DatabaseName = "app"
	s.Settings.MigrationSources = []MigrationSource{
		{Name: "api"},
		{Name: "billing", Path: "../billing/db/migrations"},
		{Name: "ghost"}, // dir missing → skipped
	}

	sources, err := s.migrationSources(context.Background())
	if err != nil {
		t.Fatalf("migrationSources: %v", err)
	}
	if len(sources) != 3 {
		t.Fatalf("expected 3 resolved sources (own, api, billing), got %d: %+v", len(sources), sources)
	}
	// Own source first, default table.
	if sources[0].name != "" || sources[0].table != "" {
		t.Errorf("own source: %+v", sources[0])
	}
	if sources[1].name != "api" || sources[1].table != "schema_migrations_api" {
		t.Errorf("api source: %+v", sources[1])
	}
	if sources[1].dir != filepath.Join(root, "api", "migrations") {
		t.Errorf("api dir resolved wrong: %q", sources[1].dir)
	}
	if sources[2].name != "billing" || sources[2].dir != filepath.Join(root, "billing", "db", "migrations") {
		t.Errorf("billing source: %+v", sources[2])
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
}
