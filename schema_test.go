package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// newSchemaRuntime returns a runtime rooted at a service directory that already
// owns a valid ./migrations, so a test only varies the declaration under test.
func newSchemaRuntime(t *testing.T) (*Runtime, string) {
	t.Helper()
	root := t.TempDir()
	svcDir := filepath.Join(root, "store")
	mustMigrationDir(t, filepath.Join(svcDir, "migrations"))
	s := NewRuntime()
	s.Location = svcDir
	s.Settings.DatabaseName = "app"
	return s, root
}

// TestDeclaredMigrationSourcesFailClosed proves every way a declaration can be
// wrong is rejected before a database connection exists. Each case previously
// resolved to a warning and a silently partial schema.
func TestDeclaredMigrationSourcesFailClosed(t *testing.T) {
	overlength := strings.Repeat("a", maxIdentifierBytes-len(migrationTablePrefix)+1)
	for _, tc := range []struct {
		name     string
		declared []MigrationSource
		wants    string
	}{
		{
			name:     "empty name",
			declared: []MigrationSource{{Name: "  "}},
			wants:    "declares an empty name",
		},
		{
			name:     "unsafe name",
			declared: []MigrationSource{{Name: "api;drop"}},
			wants:    "unsafe name",
		},
		{
			name:     "duplicate name",
			declared: []MigrationSource{{Name: "api"}, {Name: "api", Path: "../other/migrations"}},
			wants:    `both track their versions in "schema_migrations_api"`,
		},
		{
			name:     "overlength name truncates into another ledger",
			declared: []MigrationSource{{Name: overlength}},
			wants:    "PostgreSQL truncates identifiers",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newSchemaRuntime(t)
			s.Settings.MigrationSources = tc.declared
			_, err := s.resolveSchemaPrerequisites(context.Background())
			if err == nil {
				t.Fatalf("expected %s to be rejected", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("error %q does not explain the problem (want %q)", err, tc.wants)
			}
		})
	}
}

// TestMigrationSourceNameFitsTrackingTable locks the boundary: a name that fits
// its tracking table exactly is accepted, one byte more is not, because
// PostgreSQL would truncate two such lineages onto one ledger.
func TestMigrationSourceNameFitsTrackingTable(t *testing.T) {
	longest := strings.Repeat("a", maxIdentifierBytes-len(migrationTablePrefix))
	s, root := newSchemaRuntime(t)
	mustMigrationDir(t, filepath.Join(root, longest, "migrations"))
	s.Settings.MigrationSources = []MigrationSource{{Name: longest}}

	sources, _, err := s.resolveMigrationSources(context.Background())
	if err != nil {
		t.Fatalf("longest fitting name rejected: %v", err)
	}
	if got := sources[len(sources)-1].table; len(got) != maxIdentifierBytes {
		t.Errorf("tracking table %q is %d bytes, want %d", got, len(got), maxIdentifierBytes)
	}
}

// TestRequiredMigrationSourceDirectoryFailsClosed proves a declared source with
// nothing behind it fails rather than being skipped with a warning.
func TestRequiredMigrationSourceDirectoryFailsClosed(t *testing.T) {
	t.Run("missing directory", func(t *testing.T) {
		s, _ := newSchemaRuntime(t)
		s.Settings.MigrationSources = []MigrationSource{{Name: "ghost"}}
		_, err := s.resolveSchemaPrerequisites(context.Background())
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("missing directory must fail: %v", err)
		}
	})

	t.Run("no migration in directory", func(t *testing.T) {
		s, root := newSchemaRuntime(t)
		if err := os.MkdirAll(filepath.Join(root, "api", "migrations"), 0o755); err != nil {
			t.Fatal(err)
		}
		s.Settings.MigrationSources = []MigrationSource{{Name: "api"}}
		_, err := s.resolveSchemaPrerequisites(context.Background())
		if err == nil || !strings.Contains(err.Error(), "holds no migration") {
			t.Fatalf("empty directory must fail: %v", err)
		}
	})

	// A path that is not a directory is a typo, not an absent lineage — it must
	// not resolve to the "may ship no migrations yet" escape hatch.
	t.Run("path is not a directory", func(t *testing.T) {
		s, root := newSchemaRuntime(t)
		if err := os.MkdirAll(filepath.Join(root, "api"), 0o755); err != nil {
			t.Fatal(err)
		}
		notADirectory := filepath.Join(root, "api", "migrations")
		if err := os.WriteFile(notADirectory, []byte("oops"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, optional := range []bool{false, true} {
			s.Settings.MigrationSources = []MigrationSource{{Name: "api", Optional: optional}}
			_, err := s.resolveSchemaPrerequisites(context.Background())
			if err == nil || !strings.Contains(err.Error(), "cannot read migration directory") {
				t.Fatalf("optional=%v: a non-directory path must fail: %v", optional, err)
			}
		}
	})

	// The migration engine silently ignores a file it cannot parse, so a typo in
	// a filename would drop the migration without a trace.
	t.Run("misnamed migration file", func(t *testing.T) {
		s, root := newSchemaRuntime(t)
		dir := filepath.Join(root, "api", "migrations")
		mustMigrationDir(t, dir)
		if err := os.WriteFile(filepath.Join(dir, "2-typo.up.sql"), []byte("SELECT 1;"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.Settings.MigrationSources = []MigrationSource{{Name: "api"}}
		_, err := s.resolveSchemaPrerequisites(context.Background())
		if err == nil || !strings.Contains(err.Error(), "ignored by the migration engine") {
			t.Fatalf("misnamed migration must fail: %v", err)
		}
	})
}

// TestOptionalMigrationSourceReportsSkip covers the escape hatch: a service that
// declares this database before it ships migrations reports a structured skip.
func TestOptionalMigrationSourceReportsSkip(t *testing.T) {
	s, root := newSchemaRuntime(t)
	if err := os.MkdirAll(filepath.Join(root, "empty", "migrations"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.Settings.MigrationSources = []MigrationSource{
		{Name: "absent", Optional: true},
		{Name: "empty", Optional: true},
	}

	prerequisites, err := s.resolveSchemaPrerequisites(context.Background())
	if err != nil {
		t.Fatalf("optional sources must not fail: %v", err)
	}
	if len(prerequisites.sources) != 1 {
		t.Fatalf("only the own source applies, got %+v", prerequisites.sources)
	}
	if len(prerequisites.skipped) != 2 {
		t.Fatalf("expected both optional sources reported as skipped, got %+v", prerequisites.skipped)
	}
	for _, skipped := range prerequisites.skipped {
		if skipped.kind != prerequisiteMigrationSource || skipped.reason == "" {
			t.Errorf("skip lacks a structured outcome: %+v", skipped)
		}
	}
	// An optional declaration is still a declaration: a broken layout fails.
	broken := filepath.Join(root, "broken", "migrations")
	if err := os.MkdirAll(broken, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "1-typo.up.sql"), []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Settings.MigrationSources = []MigrationSource{{Name: "broken", Optional: true}}
	if _, err := s.resolveSchemaPrerequisites(context.Background()); err == nil {
		t.Error("an optional source with a misnamed migration must still fail")
	}
}

// TestOwnMigrationsStayOptional locks the documented legacy behavior: a service
// that authors no migrations of its own is not a misconfiguration.
func TestOwnMigrationsStayOptional(t *testing.T) {
	s := NewRuntime()
	s.Location = t.TempDir()
	s.Settings.DatabaseName = "app"

	prerequisites, err := s.resolveSchemaPrerequisites(context.Background())
	if err != nil {
		t.Fatalf("absent own migrations must stay compatible: %v", err)
	}
	if len(prerequisites.sources) != 0 {
		t.Errorf("expected no source, got %+v", prerequisites.sources)
	}
	if len(prerequisites.skipped) != 0 {
		t.Errorf("an undeclared own directory is not a declared prerequisite: %+v", prerequisites.skipped)
	}
}

// TestResolveExtensions locks required-by-default: a declared extension is
// required, the convenience defaults stay best-effort, and declaring a default
// promotes it.
func TestResolveExtensions(t *testing.T) {
	requests, err := resolveExtensions([]Extension{
		{Name: "postgis"},
		{Name: "pg_stat_statements", Optional: true},
		{Name: "vector"},
	})
	if err != nil {
		t.Fatalf("resolveExtensions: %v", err)
	}
	required := map[string]bool{}
	for _, request := range requests {
		if _, duplicate := required[request.name]; duplicate {
			t.Errorf("extension %q resolved twice", request.name)
		}
		required[request.name] = request.required
	}
	for name, want := range map[string]bool{
		"postgis":            true,
		"pg_stat_statements": false,
		"vector":             true, // a default named explicitly becomes required
		"pgcrypto":           false,
		"citext":             false,
	} {
		got, resolved := required[name]
		if !resolved {
			t.Errorf("extension %q was not resolved", name)
			continue
		}
		if got != want {
			t.Errorf("extension %q required=%v, want %v", name, got, want)
		}
	}
}

func TestResolveExtensionsRejectsUnsafeDeclarations(t *testing.T) {
	for _, tc := range []struct {
		declared []Extension
		wants    string
	}{
		{declared: []Extension{{Name: " "}}, wants: "declares an empty name"},
		{declared: []Extension{{Name: `pg"; DROP`}}, wants: "unsafe name"},
	} {
		_, err := resolveExtensions(tc.declared)
		if err == nil || !strings.Contains(err.Error(), tc.wants) {
			t.Errorf("declaration %+v: got %v, want %q", tc.declared, err, tc.wants)
		}
	}
}

// TestExtensionsYAMLAcceptsBothForms keeps the pre-existing bare-name list
// working while allowing an explicitly optional declaration.
func TestExtensionsYAMLAcceptsBothForms(t *testing.T) {
	var s Settings
	if err := yaml.Unmarshal([]byte(`
extensions:
  - postgis
  - name: pg_stat_statements
    optional: true
`), &s); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	if len(s.Extensions) != 2 {
		t.Fatalf("expected 2 extensions, got %+v", s.Extensions)
	}
	if s.Extensions[0] != (Extension{Name: "postgis"}) {
		t.Errorf("bare form: %+v", s.Extensions[0])
	}
	if s.Extensions[1] != (Extension{Name: "pg_stat_statements", Optional: true}) {
		t.Errorf("mapping form: %+v", s.Extensions[1])
	}
}

// TestMigrationSourceOptionalYAMLRoundTrip locks the new declaration key.
func TestMigrationSourceOptionalYAMLRoundTrip(t *testing.T) {
	var s Settings
	if err := yaml.Unmarshal([]byte(`
migration-sources:
  - name: api
  - name: billing
    optional: true
`), &s); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	if len(s.MigrationSources) != 2 {
		t.Fatalf("expected 2 sources, got %+v", s.MigrationSources)
	}
	if s.MigrationSources[0].Optional {
		t.Error("a source is required unless it declares otherwise")
	}
	if !s.MigrationSources[1].Optional {
		t.Error("optional was not populated")
	}
}
