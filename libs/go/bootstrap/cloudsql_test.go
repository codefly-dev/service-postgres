package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	postgres "github.com/codefly-dev/service-postgres/libs/go"
)

// A Cloud SQL instance is reached by the connector alone. Each other way of
// stating the server or the credential beside it is refused before anything
// connects.
func TestCloudSQLInstanceRefusesASecondAnswer(t *testing.T) {
	dir, _, binding := packageFixture(t, "CREATE TABLE fixture(id int);")
	migrate := filepath.Join(t.TempDir(), "migrate")
	if err := os.WriteFile(migrate, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	base := Options{Directory: dir, Binding: binding, MigrateExecutable: migrate, Timeout: time.Minute, LockTimeout: time.Second, StatementTimeout: time.Second,
		CloudSQLInstance: "obin-test-data:us-east1:obin-test-shared", ExternalIdentity: postgres.IssuerGCPCloudSQL}
	for name, mutate := range map[string]func(*Options){
		"a connection":       func(o *Options) { o.Connection = "postgres://owner@/fixture?host=/tmp&sslmode=disable" },
		"a server authority": func(o *Options) { o.ServerTrustAnchorPEM = "-----BEGIN CERTIFICATE-----" },
		"no identity":        func(o *Options) { o.ExternalIdentity = "" },
		"another identity":   func(o *Options) { o.ExternalIdentity = postgres.IssuerAzureEntra },
	} {
		t.Run(name, func(t *testing.T) {
			o := base
			mutate(&o)
			_, err := Run(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), "connector alone") {
				t.Fatalf("accepted %s beside the instance: %v", name, err)
			}
		})
	}
}

func TestBindingIsAcceptedAsAValue(t *testing.T) {
	var b Binding
	if err := ReadJSONValue(`{"plan-sha256":"a","plan-digest":"b","owner-role":"o","read-only-principals":[],"read-write-principals":["w"]}`, &b); err != nil {
		t.Fatal(err)
	}
	if b.OwnerRole != "o" || len(b.ReadWritePrincipals) != 1 {
		t.Fatalf("decoded %+v", b)
	}
	for _, refused := range []string{"", `{"owner-role":"o","unknown":1}`, `{} {}`, strings.Repeat(" ", 4<<20+1)} {
		if err := ReadJSONValue(refused, &Binding{}); err == nil {
			t.Fatalf("accepted %.40q", refused)
		}
	}
}
