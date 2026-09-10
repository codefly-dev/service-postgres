package main

import (
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Timeouts are the operation budgets that bound every wait this agent performs
// or renders into an artifact. Each value is a whole number of seconds; zero
// selects the documented default, so an omitted `timeouts:` block keeps the
// shipped behavior.
//
//	timeouts:
//	  connect-seconds: 5
//	  readiness-seconds: 90
//	  migration-lock-seconds: 30
//	  migration-statement-seconds: 600
//	  bootstrap-readiness-seconds: 300
//	  bootstrap-job-seconds: 1800
type Timeouts struct {
	// Connect bounds ONE connection establishment — dial, TLS, and the startup
	// handshake — for every connection the agent opens against its own
	// database. It is libpq's connect_timeout, so it also covers a TCP peer
	// that accepts the connection and then never speaks the wire protocol.
	Connect int `yaml:"connect-seconds"`

	// Readiness bounds the whole "postgres answers queries" wait in Init and
	// Start, retries included.
	Readiness int `yaml:"readiness-seconds"`

	// MigrationLock bounds reaching a usable migration handle for one lineage.
	// The driver handshake takes golang-migrate's advisory lock, so this is
	// both the session lock_timeout and the budget for the handshake retries.
	MigrationLock int `yaml:"migration-lock-seconds"`

	// MigrationStatement bounds ONE statement inside a migration, as the
	// session statement_timeout and the driver's own statement budget.
	MigrationStatement int `yaml:"migration-statement-seconds"`

	// BootstrapReadiness bounds the deployed bootstrap container's wait for the
	// database to accept connections before it exits nonzero.
	BootstrapReadiness int `yaml:"bootstrap-readiness-seconds"`

	// BootstrapJob is the bootstrap Job's activeDeadlineSeconds: the elapsed
	// wall clock the whole Job gets, retries included. backoffLimit counts
	// failures and cannot stop a container that is still running.
	BootstrapJob int `yaml:"bootstrap-job-seconds"`
}

const (
	defaultConnectSeconds            = 5
	defaultReadinessSeconds          = 90
	defaultMigrationLockSeconds      = 30
	defaultMigrationStatementSeconds = 600
	defaultBootstrapReadinessSeconds = 300
	defaultBootstrapJobSeconds       = 1800

	// maxTimeoutSeconds is one day: longer than any budget a database bootstrap
	// justifies, and small enough that every derived value — nanosecond
	// durations, millisecond GUCs, the shell arithmetic rendered into the
	// bootstrap image — stays far inside its own range.
	maxTimeoutSeconds = 86400
)

// validate rejects a configured budget that cannot describe a finite wait.
// Zero is not rejected: it is how an unset YAML field asks for the default.
func (t Timeouts) validate() error {
	for _, budget := range []struct {
		name    string
		seconds int
	}{
		{name: "connect-seconds", seconds: t.Connect},
		{name: "readiness-seconds", seconds: t.Readiness},
		{name: "migration-lock-seconds", seconds: t.MigrationLock},
		{name: "migration-statement-seconds", seconds: t.MigrationStatement},
		{name: "bootstrap-readiness-seconds", seconds: t.BootstrapReadiness},
		{name: "bootstrap-job-seconds", seconds: t.BootstrapJob},
	} {
		if budget.seconds < 0 {
			return fmt.Errorf("timeouts.%s must be positive, got %d", budget.name, budget.seconds)
		}
		if budget.seconds > maxTimeoutSeconds {
			return fmt.Errorf("timeouts.%s must not exceed %d seconds, got %d", budget.name, maxTimeoutSeconds, budget.seconds)
		}
	}
	// A Job killed by its own deadline reports "DeadlineExceeded" and nothing
	// else; the readiness loop's message only survives if the loop is allowed
	// to finish first.
	if t.BootstrapJobSeconds() < t.BootstrapReadinessSeconds() {
		return fmt.Errorf("timeouts.bootstrap-job-seconds (%d) must not be below timeouts.bootstrap-readiness-seconds (%d)",
			t.BootstrapJobSeconds(), t.BootstrapReadinessSeconds())
	}
	return nil
}

func (t Timeouts) connect() time.Duration { return budget(t.Connect, defaultConnectSeconds) }

func (t Timeouts) readiness() time.Duration { return budget(t.Readiness, defaultReadinessSeconds) }

func (t Timeouts) migrationLock() time.Duration {
	return budget(t.MigrationLock, defaultMigrationLockSeconds)
}

func (t Timeouts) migrationStatement() time.Duration {
	return budget(t.MigrationStatement, defaultMigrationStatementSeconds)
}

// BootstrapReadinessSeconds and BootstrapJobSeconds are rendered into the
// bootstrap image and the bootstrap Job, which speak seconds rather than Go
// durations.
func (t Timeouts) BootstrapReadinessSeconds() int {
	return seconds(t.BootstrapReadiness, defaultBootstrapReadinessSeconds)
}

func (t Timeouts) BootstrapJobSeconds() int {
	return seconds(t.BootstrapJob, defaultBootstrapJobSeconds)
}

func budget(configured, fallback int) time.Duration {
	return time.Duration(seconds(configured, fallback)) * time.Second
}

func seconds(configured, fallback int) int {
	if configured == 0 {
		return fallback
	}
	return configured
}

// withConnectTimeout returns dsn carrying libpq's connect_timeout, so every
// connection the agent opens gives up on establishment within one budget
// instead of parking on a peer that accepts TCP and never completes startup.
func withConnectTimeout(dsn string, budget time.Duration) (string, error) {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("cannot parse postgres connection string: %w", err)
	}
	query := parsed.Query()
	query.Set("connect_timeout", strconv.Itoa(int(budget/time.Second)))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
