package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// TestNewService_EmbedsBase locks the struct contract: Service must
// carry a non-nil Base (for Wool/Logger/Location/Identity promotion)
// and a non-nil Settings pointer. If either breaks, every Runtime RPC
// on postgres panics.
func TestNewService_EmbedsBase(t *testing.T) {
	svc := NewService()
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.Base == nil {
		t.Fatal("Service.Base is nil — services.Base embedding broken")
	}
	if svc.Settings == nil {
		t.Fatal("Service.Settings is nil")
	}
}

// TestSettings_YAMLRoundTrip covers the config fields documented in
// agent.codefly.yaml. Drift here means user service.codefly.yaml files
// stop populating settings silently.
func TestSettings_YAMLRoundTrip(t *testing.T) {
	src := []byte(`
database-name: myapp
hot-reload: true
without-ssl: false
no-migration: true
`)
	var s Settings
	if err := yaml.Unmarshal(src, &s); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	if s.DatabaseName != "myapp" {
		t.Errorf("DatabaseName: got %q", s.DatabaseName)
	}
	if !s.HotReload {
		t.Error("HotReload not populated")
	}
	if !s.NoMigration {
		t.Error("NoMigration not populated")
	}
	if s.WithoutSSL {
		t.Error("WithoutSSL should be false")
	}
}
