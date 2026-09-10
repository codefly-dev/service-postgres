package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
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
// default tracking table and named sources get schema_migrations_<name> plus
// the sibling-default path.
func TestMigrationSources_Resolution(t *testing.T) {
	root := t.TempDir()
	svcDir := filepath.Join(root, "store")
	mustMigrationDir(t, filepath.Join(svcDir, "migrations"))
	mustMigrationDir(t, filepath.Join(root, "api", "migrations"))           // sibling default path
	mustMigrationDir(t, filepath.Join(root, "billing", "db", "migrations")) // explicit path

	s := NewRuntime()
	s.Location = svcDir
	s.Settings.DatabaseName = "app"
	s.Settings.MigrationSources = []MigrationSource{
		{Name: "api"},
		{Name: "billing", Path: "../billing/db/migrations"},
	}

	sources, skipped, err := s.resolveMigrationSources()
	if err != nil {
		t.Fatalf("resolveMigrationSources: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("expected no skipped prerequisite, got %+v", skipped)
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

// mustMkdir creates a bare directory: no migration in it.
func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
}

// mustMigrationDir creates a migrations directory holding one real, correctly
// named migration, the shape a declared source is required to have.
func mustMigrationDir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	if err := os.WriteFile(filepath.Join(p, "1_init.up.sql"), []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatalf("write migration in %s: %v", p, err)
	}
}

// TestMigrationSourceIgnoresEditorLeftovers locks the acceptance case from the
// bug: a backup file keeping the migration's own prefix parses as the same
// version and direction and used to make golang-migrate reject the whole
// lineage as a duplicate. Version 3 uses a non-.sql extension, which
// golang-migrate accepts and the filter must therefore keep: hiding it would
// leave Up() reporting ErrNoChange over an unapplied migration.
func TestMigrationSourceIgnoresEditorLeftovers(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"1_init.up.sql":         "CREATE TABLE one ();",
		"1_init.down.sql":       "DROP TABLE one;",
		"2_pending.up.sql":      "CREATE TABLE two ();",
		"2_pending.down.sql":    "DROP TABLE two;",
		"3_flavored.up.pgsql":   "CREATE TABLE three ();",
		"3_flavored.down.pgsql": "DROP TABLE three;",
		"2_pending.up.sql~":     "CREATE TABLE stale ();",
		"2_pending.up.sql.bak":  "CREATE TABLE stale ();",
		"2_pending.up.sql.orig": "CREATE TABLE stale ();",
		".2_pending.up.sql.swp": "binary",
		"#2_pending.up.sql#":    "CREATE TABLE stale ();",
		"README.md":             "not a migration",
	} {
		mustWrite(t, filepath.Join(dir, name), body)
	}
	mustMkdir(t, filepath.Join(dir, "archive"))

	driver, err := migrationSource{dir: dir}.openSource()
	if err != nil {
		t.Fatalf("openSource: %v", err)
	}
	defer driver.Close()

	first, err := driver.First()
	if err != nil || first != 1 {
		t.Fatalf("First() = %d, %v; want 1", first, err)
	}
	next, err := driver.Next(1)
	if err != nil || next != 2 {
		t.Fatalf("Next(1) = %d, %v; want 2", next, err)
	}
	next, err = driver.Next(2)
	if err != nil || next != 3 {
		t.Fatalf("Next(2) = %d, %v; want 3 — a migration is not defined by its extension", next, err)
	}
	if _, err := driver.Next(3); err == nil {
		t.Fatal("Next(3) must report the end of the lineage")
	}

	body, _, err := driver.ReadUp(2)
	if err != nil {
		t.Fatalf("ReadUp(2): %v", err)
	}
	defer body.Close()
	content, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read migration body: %v", err)
	}
	if string(content) != "CREATE TABLE two ();" {
		t.Fatalf("ReadUp(2) served %q, want the real migration", content)
	}
}

// TestMigrationSourceRejectsConflictingVersions keeps a genuine authoring
// mistake failing, and naming both files.
func TestMigrationSourceRejectsConflictingVersions(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "1_init.up.sql"), "CREATE TABLE one ();")
	mustWrite(t, filepath.Join(dir, "2_add_index.up.sql"), "CREATE INDEX a ON one (id);")
	mustWrite(t, filepath.Join(dir, "02_add_column.up.sql"), "ALTER TABLE one ADD COLUMN id INT;")

	_, err := migrationSource{dir: dir}.openSource()
	if err == nil {
		t.Fatal("two up files for version 2 must fail")
	}
	for _, name := range []string{"02_add_column.up.sql", "2_add_index.up.sql"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name the conflicting file %q", err, name)
		}
	}
}

// TestMigrationSourceServesOneDirectorySnapshot pins the property that keeps the
// conflict check and the applied set in agreement: the files are read once, so a
// save landing mid-apply cannot change what an open driver runs.
func TestMigrationSourceServesOneDirectorySnapshot(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "1_init.up.sql"), "CREATE TABLE one ();")

	driver, err := migrationSource{dir: dir}.openSource()
	if err != nil {
		t.Fatalf("openSource: %v", err)
	}
	defer driver.Close()

	mustWrite(t, filepath.Join(dir, "2_added_later.up.sql"), "CREATE TABLE two ();")

	if _, err := driver.Next(1); err == nil {
		t.Fatal("a file written after the source was opened must not join the lineage mid-apply")
	}
}

func mustWrite(t *testing.T, p string, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

// TestCountMigrationsAgreesWithTheSourceDriver keeps schema validation and the
// migration engine on ONE definition of a migration filename. If the resolver
// counted fewer files than the driver exposes, a lineage the driver applies
// perfectly well would be rejected as holding no migration — a .pgsql-only
// lineage is the case that bites. The corpus is the driver test's, deliberately.
func TestCountMigrationsAgreesWithTheSourceDriver(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"1_init.up.sql":         "CREATE TABLE one ();",
		"1_init.down.sql":       "DROP TABLE one;",
		"2_pending.up.sql":      "CREATE TABLE two ();",
		"2_pending.down.sql":    "DROP TABLE two;",
		"3_flavored.up.pgsql":   "CREATE TABLE three ();",
		"3_flavored.down.pgsql": "DROP TABLE three;",
		"2_pending.up.sql~":     "CREATE TABLE stale ();",
		"2_pending.up.sql.bak":  "CREATE TABLE stale ();",
		"2_pending.up.sql.orig": "CREATE TABLE stale ();",
		".2_pending.up.sql.swp": "binary",
		"#2_pending.up.sql#":    "CREATE TABLE stale ();",
		"README.md":             "not a migration",
	} {
		mustWrite(t, filepath.Join(dir, name), body)
	}
	mustMkdir(t, filepath.Join(dir, "archive"))

	count, err := countMigrations(dir)
	if err != nil {
		t.Fatalf("the resolver rejected a lineage the driver accepts: %v", err)
	}
	if count != 3 {
		t.Errorf("countMigrations = %d, want 3 — every up migration the driver exposes, whatever its extension", count)
	}
}
