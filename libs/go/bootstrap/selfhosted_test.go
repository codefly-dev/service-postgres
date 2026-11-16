package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A self-hosted plan binds no external principal: its logins are the plan's own.
func TestSelfHostedBindingRefusesExternalPrincipals(t *testing.T) {
	dir, _, b := packageFixture(t, "CREATE TABLE example(id integer);")
	if _, tmp, e := snapshot(dir, b, true); e == nil {
		os.RemoveAll(tmp)
		t.Fatal("accepted external principals in self-hosted mode")
	}
	b.ReadOnlyPrincipals, b.ReadWritePrincipals = nil, nil
	_, tmp, e := snapshot(dir, b, true)
	if e != nil {
		t.Fatal(e)
	}
	os.RemoveAll(tmp)
	if _, tmp, e = snapshot(dir, b, false); e == nil {
		os.RemoveAll(tmp)
		t.Fatal("managed mode accepted a binding with no principal")
	}
}

// The owner password is the self-hosted credential, so a cloud identity beside
// it, or its absence, is refused before anything connects.
func TestSelfHostedRefusesMixedOrMissingCredentials(t *testing.T) {
	dir, _, b := packageFixture(t, "CREATE TABLE example(id integer);")
	b.ReadOnlyPrincipals, b.ReadWritePrincipals = nil, nil
	migrate := filepath.Join(t.TempDir(), "migrate")
	os.WriteFile(migrate, []byte("#!/bin/sh\n"), 0o755)
	base := Options{Directory: dir, Binding: b, Connection: "postgres://bootstrap_owner@127.0.0.1:1/bootstrap_proof?sslmode=disable",
		MigrateExecutable: migrate, Timeout: time.Minute, LockTimeout: time.Second, StatementTimeout: time.Second,
		Password: &Password{Owner: "owner", ReadOnly: "ro", ReadWrite: "rw"}}
	for name, amend := range map[string]func(o *Options){
		"no owner password":  func(o *Options) { o.Password = &Password{ReadOnly: "ro", ReadWrite: "rw"} },
		"cloud sql instance": func(o *Options) { o.CloudSQLInstance = "project:region:instance" },
		"external identity":  func(o *Options) { o.ExternalIdentity = "gcp-cloud-sql" },
		"readiness > budget": func(o *Options) { o.ReadinessTimeout = 2 * time.Minute },
	} {
		t.Run(name, func(t *testing.T) {
			o := base
			amend(&o)
			if _, e := Run(context.Background(), o); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("unreachable server is bounded by readiness", func(t *testing.T) {
		o := base
		o.ReadinessTimeout = 3 * time.Second
		started := time.Now()
		if _, e := Run(context.Background(), o); e == nil || e.Error() != "database did not accept connections within 3s" {
			t.Fatalf("got %v", e)
		}
		if elapsed := time.Since(started); elapsed < 3*time.Second || elapsed > 20*time.Second {
			t.Fatalf("readiness wait took %s", elapsed)
		}
	})
}
