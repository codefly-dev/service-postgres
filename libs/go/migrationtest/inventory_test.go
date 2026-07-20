package migrationtest

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDirectoryRequiresACompleteContiguousLineage(t *testing.T) {
	directory := t.TempDir()
	writeMigrationFile(t, directory, "0001_create.initial.up.sql", "CREATE TABLE first (id bigint);")
	writeMigrationFile(t, directory, "0001_create.initial.down.sql", "DROP TABLE first;")
	writeMigrationFile(t, directory, "0002_extend.up.sql", "ALTER TABLE first ADD COLUMN value text;")
	writeMigrationFile(t, directory, "0002_extend.down.sql", "ALTER TABLE first DROP COLUMN value;")

	migrations, err := LoadDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) != 2 || migrations[0].Version != 1 || migrations[1].Version != 2 {
		t.Fatalf("inventory=%+v, want contiguous versions 1 and 2", migrations)
	}
	if migrations[0].Name != "create.initial" || migrations[1].Name != "extend" || !strings.Contains(migrations[1].UpSQL, "ADD COLUMN") {
		t.Fatalf("second migration=%+v", migrations[1])
	}
}

func TestLoadDirectoryRejectsMalformedLineages(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"missing direction": func(t *testing.T, directory string) {
			writeMigrationFile(t, directory, "1_create.up.sql", "SELECT 1;")
		},
		"version gap": func(t *testing.T, directory string) {
			writeMigrationFile(t, directory, "2_create.up.sql", "SELECT 1;")
			writeMigrationFile(t, directory, "2_create.down.sql", "SELECT 1;")
		},
		"direction names differ": func(t *testing.T, directory string) {
			writeMigrationFile(t, directory, "1_create.up.sql", "SELECT 1;")
			writeMigrationFile(t, directory, "1_remove.down.sql", "SELECT 1;")
		},
		"empty body": func(t *testing.T, directory string) {
			writeMigrationFile(t, directory, "1_create.up.sql", "   \n")
			writeMigrationFile(t, directory, "1_create.down.sql", "SELECT 1;")
		},
		"malformed SQL filename": func(t *testing.T, directory string) {
			writeMigrationFile(t, directory, "create.sql", "SELECT 1;")
		},
	}
	for name, arrange := range tests {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			arrange(t, directory)
			if _, err := LoadDirectory(directory); err == nil {
				t.Fatal("invalid migration lineage was accepted")
			}
		})
	}
}

func TestControlPlaneNamesAreSafeAndBounded(t *testing.T) {
	name, err := uniqueDatabaseName(strings.Repeat("a", 60))
	if err != nil {
		t.Fatal(err)
	}
	if len(name) > 63 {
		t.Fatalf("database name length=%d, want <=63", len(name))
	}
	if err := validateDatabaseName(name); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "1starts_with_digit", "has-dash", "quoted\"name", "space name"} {
		if err := validateDatabaseName(invalid); err == nil {
			t.Fatalf("unsafe database name %q was accepted", invalid)
		}
	}
}

func TestApplySQLRejectsMissingCapabilitiesBeforeDatabaseAccess(t *testing.T) {
	if err := ApplySQL(nil, nil, "SELECT 1", "missing context"); err == nil {
		t.Fatal("nil context was accepted")
	}
	if err := ApplySQL(context.Background(), nil, "SELECT 1", "missing database"); err == nil {
		t.Fatal("nil database was accepted")
	}
	var db *sql.DB
	if err := ApplySQL(context.Background(), db, "SELECT 1", "typed nil database"); err == nil {
		t.Fatal("typed nil database was accepted")
	}
}

func writeMigrationFile(t *testing.T, directory, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
