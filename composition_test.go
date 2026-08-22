package main

import (
	"context"
	"math"
	"slices"
	"strings"
	"testing"

	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/resources"
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
runtime-schemas:
  - app
  - audit
runtime-read-write-roles:
  - app_tenant
  - app_worker
wal-budget:
  max-size-mb: 2048
  checkpoint-timeout-seconds: 600
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
	if len(s.RuntimeSchemas) != 2 || s.RuntimeSchemas[0] != "app" || s.RuntimeSchemas[1] != "audit" {
		t.Errorf("RuntimeSchemas: got %v", s.RuntimeSchemas)
	}
	if len(s.RuntimeReadWriteRoles) != 2 || s.RuntimeReadWriteRoles[0] != "app_tenant" || s.RuntimeReadWriteRoles[1] != "app_worker" {
		t.Errorf("RuntimeReadWriteRoles: got %v", s.RuntimeReadWriteRoles)
	}
	if s.WALBudget.MaxSizeMB != 2048 || s.WALBudget.CheckpointTimeoutSeconds != 600 {
		t.Errorf("WALBudget: got %+v", s.WALBudget)
	}
}

func TestEffectiveWALBudget(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		budget, err := (&Settings{}).effectiveWALBudget()
		if err != nil {
			t.Fatal(err)
		}
		if budget.maxSizeMB != 4096 || budget.checkpointTimeoutSeconds != 900 {
			t.Fatalf("default budget = %+v", budget)
		}
	})

	t.Run("explicit", func(t *testing.T) {
		settings := &Settings{WALBudget: WALBudgetSettings{MaxSizeMB: 8192, CheckpointTimeoutSeconds: 600}}
		budget, err := settings.effectiveWALBudget()
		if err != nil {
			t.Fatal(err)
		}
		if budget.maxSizeMB != 8192 || budget.checkpointTimeoutSeconds != 600 {
			t.Fatalf("explicit budget = %+v", budget)
		}
	})
}

func TestEffectiveWALBudgetRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name     string
		settings WALBudgetSettings
		want     string
	}{
		{name: "max size below supported minimum", settings: WALBudgetSettings{MaxSizeMB: 79}, want: "must be at least 80"},
		{name: "max size cannot convert to bytes", settings: WALBudgetSettings{MaxSizeMB: int(math.MaxUint64/bytesPerMiB) + 1}, want: "cannot be represented as bytes"},
		{name: "checkpoint timeout too short", settings: WALBudgetSettings{CheckpointTimeoutSeconds: 29}, want: "must be between 30 and 86400"},
		{name: "checkpoint timeout too long", settings: WALBudgetSettings{CheckpointTimeoutSeconds: 86401}, want: "must be between 30 and 86400"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := (&Settings{WALBudget: test.settings}).effectiveWALBudget()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestValidateWALBudgetStorageUsesLiveCapacityAndAvailability(t *testing.T) {
	tests := []struct {
		name      string
		budgetMB  int
		totalMB   uint64
		freeMB    uint64
		wantError string
	}{
		{name: "larger filesystem admits larger budget", budgetMB: 8192, totalMB: 32 * 1024, freeMB: 20 * 1024},
		{name: "capacity reserve rejects oversized budget", budgetMB: 8192, totalMB: 16 * 1024, freeMB: 12 * 1024, wantError: "exceeds 40% of storage capacity"},
		{name: "current usage rejects unavailable budget", budgetMB: 4096, totalMB: 32 * 1024, freeMB: 4095, wantError: "exceeds currently available storage 4095MB"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateWALBudgetStorage(
				postgresWALBudget{maxSizeMB: test.budgetMB},
				resources.StorageFilesystem{
					TotalBytes:     test.totalMB * bytesPerMiB,
					AvailableBytes: test.freeMB * bytesPerMiB,
				},
			)
			if test.wantError == "" && err != nil {
				t.Fatalf("validate storage: %v", err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}

func TestPostgresCommandCarriesWALBudgetAndLogSettings(t *testing.T) {
	budget := postgresWALBudget{maxSizeMB: 2048, checkpointTimeoutSeconds: 600}
	got := postgresCommand(budget, "NOTICE")
	want := []string{
		"postgres",
		"-c", "max_wal_size=2048MB",
		"-c", "checkpoint_timeout=600s",
		"-c", "log_min_messages=notice",
		"-c", "log_statement=none",
		"-c", "log_connections=off",
		"-c", "log_disconnections=off",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("postgres command = %q, want %q", got, want)
	}
}

func TestWALBudgetEvidenceReportsEffectiveValues(t *testing.T) {
	w, captured := newCaptureWool()
	reportWALBudget(w, postgresWALBudget{maxSizeMB: 4096, checkpointTimeoutSeconds: 900})
	if len(captured.logs) != 1 {
		t.Fatalf("evidence logs = %d, want 1", len(captured.logs))
	}
	if captured.logs[0].Message != "effective postgres WAL budget" {
		t.Fatalf("evidence message = %q", captured.logs[0].Message)
	}
	if value, ok := fieldValue(captured.logs[0], "max_wal_size_mb"); !ok || value != 4096 {
		t.Fatalf("max_wal_size_mb = %v, present = %t", value, ok)
	}
	if value, ok := fieldValue(captured.logs[0], "checkpoint_timeout_seconds"); !ok || value != 900 {
		t.Fatalf("checkpoint_timeout_seconds = %v, present = %t", value, ok)
	}
}

func TestRuntimeInitRejectsInvalidWALBudgetBeforeResolvingStartupInputs(t *testing.T) {
	runtime := NewRuntime()
	runtime.WALBudget.MaxSizeMB = 79
	response, err := runtime.Init(context.Background(), &runtimev0.InitRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetStatus().GetState() != runtimev0.InitStatus_ERROR {
		t.Fatalf("init status = %s", response.GetStatus().GetState())
	}
	if !strings.Contains(response.GetStatus().GetMessage(), "must be at least 80") {
		t.Fatalf("init message = %q", response.GetStatus().GetMessage())
	}
}
