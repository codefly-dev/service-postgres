package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/codefly-dev/service-postgres/libs/go/bootstrap"
)

// The owner's password is taken out of the URL Run receives: Run supplies it at
// connect time and to the migrate child's environment, never in an argument.
func TestOwnerConnectionKeepsThePasswordOutOfTheURL(t *testing.T) {
	for name, environment := range map[string]map[string]string{
		"owner url": {"CODEFLY_POSTGRES_MIGRATION_CONNECTION": "postgresql://owner:s3cret@store.svc:5432/runtime?sslmode=disable"},
		"libpq environment": {"CODEFLY_POSTGRES_OWNER_FROM_LIBPQ_ENVIRONMENT": "true", "PGHOST": "store.svc", "PGPORT": "5432",
			"PGDATABASE": "runtime", "PGUSER": "owner", "PGPASSWORD": "s3cret", "PGSSLMODE": "disable"},
	} {
		t.Run(name, func(t *testing.T) {
			for key, value := range environment {
				t.Setenv(key, value)
			}
			connection, owner, password, err := ownerConnection()
			if err != nil {
				t.Fatal(err)
			}
			if connection != "postgres://owner@store.svc:5432/runtime?sslmode=disable" || owner != "owner" || password != "s3cret" {
				t.Fatalf("got %q %q %q", connection, owner, password)
			}
		})
	}
	t.Run("libpq's default sslmode when none is pinned", func(t *testing.T) {
		t.Setenv("CODEFLY_POSTGRES_MIGRATION_CONNECTION", "postgresql://owner:s3cret@store.svc:5432/runtime")
		if connection, _, _, err := ownerConnection(); err != nil || connection != "postgres://owner@store.svc:5432/runtime?sslmode=prefer" {
			t.Fatalf("got %q %v", connection, err)
		}
	})
	t.Run("no password is refused", func(t *testing.T) {
		t.Setenv("CODEFLY_POSTGRES_MIGRATION_CONNECTION", "postgresql://owner@store.svc:5432/runtime")
		if _, _, _, err := ownerConnection(); err == nil {
			t.Fatal("accepted an owner connection without a password")
		}
	})
}

// A self-hosted run binds the image's own plan, and each declared login's
// password comes from the variable the package names.
func TestSelfHostedReadsThePackageAndTheEnvironment(t *testing.T) {
	directory := t.TempDir()
	plan := []byte(`{"digest":"sha256:abc"}`)
	os.WriteFile(filepath.Join(directory, "plan.json"), plan, 0o644)
	pkg, _ := json.Marshal(bootstrap.SelfHostedPackage{ReadinessSeconds: 90, Logins: []bootstrap.SelfHostedLogin{{Role: "store_maintenance", PasswordVariable: "POSTGRES_MAINTENANCE_PASSWORD", ReadWriteRoles: []string{"app"}}}})
	os.WriteFile(filepath.Join(directory, bootstrap.SelfHostedFile), pkg, 0o644)
	t.Setenv("CODEFLY_POSTGRES_MIGRATION_CONNECTION", "postgresql://owner:s3cret@store.svc:5432/runtime?sslmode=disable")
	t.Setenv("POSTGRES_READ_ONLY_PASSWORD", "ro")
	t.Setenv("POSTGRES_READ_WRITE_PASSWORD", "rw")
	t.Setenv("POSTGRES_MAINTENANCE_PASSWORD", "maintenance")
	o := bootstrap.Options{Directory: directory}
	if err := selfHosted(&o, ""); err != nil {
		t.Fatal(err)
	}
	if o.Binding.OwnerRole != "owner" || o.Binding.PlanDigest != "sha256:abc" || len(o.Binding.PlanSHA256) != 64 || o.ReadinessTimeout.Seconds() != 90 {
		t.Fatalf("binding %+v readiness %s", o.Binding, o.ReadinessTimeout)
	}
	if p := o.Password; p.Owner != "s3cret" || p.ReadOnly != "ro" || p.ReadWrite != "rw" || len(p.Logins) != 1 || p.Logins[0].Password != "maintenance" || p.Logins[0].ReadWriteRoles[0] != "app" {
		t.Fatalf("password %+v", p)
	}
}
