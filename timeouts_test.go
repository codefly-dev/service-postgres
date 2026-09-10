package main

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestTimeoutsYAMLRoundTripAndDefaults(t *testing.T) {
	var configured Settings
	if err := yaml.Unmarshal([]byte(`
database-name: app
timeouts:
  connect-seconds: 3
  readiness-seconds: 45
  migration-lock-seconds: 10
  migration-statement-seconds: 120
  bootstrap-readiness-seconds: 60
  bootstrap-job-seconds: 240
`), &configured); err != nil {
		t.Fatal(err)
	}
	if err := configured.Timeouts.validate(); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name string
		got  any
		want any
	}{
		{name: "connect", got: configured.Timeouts.connect(), want: 3 * time.Second},
		{name: "readiness", got: configured.Timeouts.readiness(), want: 45 * time.Second},
		{name: "migration lock", got: configured.Timeouts.migrationLock(), want: 10 * time.Second},
		{name: "migration statement", got: configured.Timeouts.migrationStatement(), want: 120 * time.Second},
		{name: "bootstrap readiness", got: configured.Timeouts.BootstrapReadinessSeconds(), want: 60},
		{name: "bootstrap job", got: configured.Timeouts.BootstrapJobSeconds(), want: 240},
	} {
		if check.got != check.want {
			t.Errorf("%s budget = %v, want %v", check.name, check.got, check.want)
		}
	}

	// An omitted block is how a service that never thought about budgets is
	// configured, and it must still get finite ones.
	var omitted Settings
	if err := yaml.Unmarshal([]byte("database-name: app\n"), &omitted); err != nil {
		t.Fatal(err)
	}
	if err := omitted.Timeouts.validate(); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name string
		got  any
		want any
	}{
		{name: "connect", got: omitted.Timeouts.connect(), want: time.Duration(defaultConnectSeconds) * time.Second},
		{name: "readiness", got: omitted.Timeouts.readiness(), want: time.Duration(defaultReadinessSeconds) * time.Second},
		{name: "migration lock", got: omitted.Timeouts.migrationLock(), want: time.Duration(defaultMigrationLockSeconds) * time.Second},
		{name: "migration statement", got: omitted.Timeouts.migrationStatement(), want: time.Duration(defaultMigrationStatementSeconds) * time.Second},
		{name: "bootstrap readiness", got: omitted.Timeouts.BootstrapReadinessSeconds(), want: defaultBootstrapReadinessSeconds},
		{name: "bootstrap job", got: omitted.Timeouts.BootstrapJobSeconds(), want: defaultBootstrapJobSeconds},
	} {
		if check.got != check.want {
			t.Errorf("default %s budget = %v, want %v", check.name, check.got, check.want)
		}
	}
}

func TestTimeoutsRejectBudgetsThatCannotDescribeAFiniteWait(t *testing.T) {
	tests := []struct {
		name     string
		timeouts Timeouts
		want     string
	}{
		{
			name:     "negative connect",
			timeouts: Timeouts{Connect: -1},
			want:     "timeouts.connect-seconds must be positive",
		},
		{
			name:     "negative readiness",
			timeouts: Timeouts{Readiness: -30},
			want:     "timeouts.readiness-seconds must be positive",
		},
		{
			name:     "migration lock beyond the maximum",
			timeouts: Timeouts{MigrationLock: maxTimeoutSeconds + 1},
			want:     "timeouts.migration-lock-seconds must not exceed 86400 seconds",
		},
		{
			name:     "migration statement overflow",
			timeouts: Timeouts{MigrationStatement: 1 << 40},
			want:     "timeouts.migration-statement-seconds must not exceed 86400 seconds",
		},
		{
			name:     "bootstrap readiness beyond the maximum",
			timeouts: Timeouts{BootstrapReadiness: maxTimeoutSeconds + 1, BootstrapJob: maxTimeoutSeconds},
			want:     "timeouts.bootstrap-readiness-seconds must not exceed 86400 seconds",
		},
		{
			// A Job killed by its own deadline reports DeadlineExceeded and
			// nothing else, so the readiness wait must be able to finish first.
			name:     "job deadline below the readiness wait it contains",
			timeouts: Timeouts{BootstrapReadiness: 600, BootstrapJob: 60},
			want:     "timeouts.bootstrap-job-seconds (60) must not be below timeouts.bootstrap-readiness-seconds (600)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.timeouts.validate()
			if err == nil {
				t.Fatalf("%+v was accepted", test.timeouts)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to contain %q", err, test.want)
			}
		})
	}
}

func TestDefaultTimeoutsAreConsistent(t *testing.T) {
	if err := (Timeouts{}).validate(); err != nil {
		t.Fatalf("the shipped defaults do not validate: %v", err)
	}
}
