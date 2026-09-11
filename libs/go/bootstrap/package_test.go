package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/service-postgres/libs/go/schemaplan"
)

func packageFixture(t *testing.T, sql string) (string, schemaplan.Plan, Binding) {
	t.Helper()
	dir := t.TempDir()
	h := sha256.Sum256([]byte(sql))
	l := schemaplan.Lineage{Label: "application", Ledger: "schema_migrations_application", Stage: "00-application", Files: []schemaplan.File{{Name: "001_table.up.sql", Digest: "sha256:" + hex.EncodeToString(h[:])}}}
	l.Digest = l.ContentDigest()
	p := schemaplan.Plan{ContractVersion: schemaplan.ContractVersion, Database: "bootstrap_proof", Lineages: []schemaplan.Lineage{l}, Access: schemaplan.Access{ReadOnlyRole: "bootstrap_ro", ReadWriteRole: "bootstrap_rw", Schemas: []string{"public"}}}
	p.Digest = p.ContentDigest()
	b := Binding{OwnerRole: "bootstrap_owner", ReadOnlyPrincipals: []string{"bootstrap_reader"}, ReadWritePrincipals: []string{"bootstrap_writer"}}
	os.MkdirAll(filepath.Join(dir, "sources", l.Stage), 0700)
	os.WriteFile(filepath.Join(dir, "sources", l.Stage, l.Files[0].Name), []byte(sql), 0600)
	writePlan(t, dir, p, &b)
	return dir, p, b
}
func writePlan(t *testing.T, dir string, p schemaplan.Plan, b *Binding) {
	t.Helper()
	p.Digest = p.ContentDigest()
	data, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(data)
	b.PlanSHA256 = hex.EncodeToString(h[:])
	b.PlanDigest = p.Digest
	if e = os.WriteFile(filepath.Join(dir, "plan.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
}

func TestPackageRejectsDriftAndAmbiguousInputs(t *testing.T) {
	for _, kind := range []string{"changed-bytes", "extra-file", "symlink", "traversal", "duplicate-ledger", "duplicate-version", "owner-is-group", "principal-is-group", "missing-principals", "wrong-pin", "group-login-association", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			dir, p, b := packageFixture(t, "CREATE TABLE example(id integer);")
			file := filepath.Join(dir, "sources", "00-application", "001_table.up.sql")
			switch kind {
			case "changed-bytes":
				os.WriteFile(file, []byte("SELECT 'private sentinel';"), 0600)
			case "extra-file":
				os.WriteFile(filepath.Join(filepath.Dir(file), "002_unexpected.up.sql"), []byte("SELECT 1"), 0600)
			case "symlink":
				os.Remove(file)
				os.Symlink("/etc/passwd", file)
			case "traversal":
				p.Lineages[0].Stage = "../elsewhere"
				writePlan(t, dir, p, &b)
			case "duplicate-ledger":
				p.Lineages = append(p.Lineages, p.Lineages[0])
				writePlan(t, dir, p, &b)
			case "duplicate-version":
				f := p.Lineages[0].Files[0]
				f.Name = "1_duplicate.up.sql"
				p.Lineages[0].Files = append(p.Lineages[0].Files, f)
				p.Lineages[0].Digest = p.Lineages[0].ContentDigest()
				os.WriteFile(filepath.Join(filepath.Dir(file), f.Name), []byte("CREATE TABLE example(id integer);"), 0600)
				writePlan(t, dir, p, &b)
			case "owner-is-group":
				b.OwnerRole = p.Access.ReadOnlyRole
			case "principal-is-group":
				b.ReadWritePrincipals = []string{p.Access.ReadOnlyRole}
			case "missing-principals":
				b.ReadOnlyPrincipals = nil
			case "wrong-pin":
				b.PlanSHA256 = strings.Repeat("0", 64)
			case "group-login-association":
				b.ReadOnlyPrincipals = b.ReadWritePrincipals
			case "unknown-field":
				data, _ := os.ReadFile(filepath.Join(dir, "plan.json"))
				data = append([]byte(`{"password":"private sentinel",`), data[1:]...)
				os.WriteFile(filepath.Join(dir, "plan.json"), data, 0600)
				h := sha256.Sum256(data)
				b.PlanSHA256 = hex.EncodeToString(h[:])
			}
			_, tmp, e := snapshot(dir, b)
			if tmp != "" {
				os.RemoveAll(tmp)
			}
			if e == nil {
				t.Fatal("accepted unsafe package")
			}
			if strings.Contains(e.Error(), "private sentinel") {
				t.Fatal("sensitive contents leaked")
			}
		})
	}
}

func TestSnapshotRetainsVerifiedBytes(t *testing.T) {
	dir, _, b := packageFixture(t, "SELECT 1;")
	_, tmp, e := snapshot(dir, b)
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(tmp)
	os.WriteFile(filepath.Join(dir, "sources", "00-application", "001_table.up.sql"), []byte("SELECT 2;"), 0600)
	data, e := os.ReadFile(filepath.Join(tmp, "00-application", "001_table.up.sql"))
	if e != nil || string(data) != "SELECT 1;" {
		t.Fatal("verified snapshot changed")
	}
}

func TestConnectionIsExplicitAndPasswordless(t *testing.T) {
	_, p, b := packageFixture(t, "SELECT 1;")
	for _, dsn := range []string{"postgres://bootstrap_owner:secret@127.0.0.1/bootstrap_proof?sslmode=disable", "postgres://bootstrap_owner@127.0.0.1/bootstrap_proof?password=secret&sslmode=disable", "postgres://other@127.0.0.1/bootstrap_proof?sslmode=disable", "postgres://bootstrap_owner@127.0.0.1/wrong?sslmode=disable", "postgres://bootstrap_owner@127.0.0.1/bootstrap_proof?sslmode=disable&options=secret", "postgres://bootstrap_owner@127.0.0.1/bootstrap_proof?sslmode=disable&sslmode=require"} {
		_, e := connection(Options{Binding: b, Connection: dsn}, p)
		if e == nil || strings.Contains(e.Error(), "secret") {
			t.Fatal("accepted or exposed invalid connection")
		}
	}
	_, e := Run(context.Background(), Options{Timeout: time.Second, LockTimeout: time.Hour})
	if e == nil {
		t.Fatal("invalid budgets accepted")
	}
}
