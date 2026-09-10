package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
)

// A database that refuses connections is the easy case. The hard one is a peer
// that completes the TCP handshake and then says nothing: libpq blocks reading
// the startup response, so a readiness wait that is not bounded and not
// cancellable parks there forever. These drive that peer for real.
func TestWaitForReadyEndsWhenBudgetExpires(t *testing.T) {
	runtime := readinessRuntime(t, Timeouts{Readiness: 2, Connect: 1})

	started := time.Now()
	err := runtime.WaitForReady(context.Background())
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("readiness reported success against a peer that never spoke Postgres")
	}
	if elapsed > 8*time.Second {
		t.Fatalf("readiness took %s to spend a 2s budget", elapsed)
	}
	if !strings.Contains(err.Error(), "readiness budget of 2s expired") {
		t.Fatalf("failure does not name the phase and budget: %v", err)
	}
	// The budget expiring must not erase what the database last did: an
	// operator needs the probe failure, not just "time ran out".
	if strings.Contains(err.Error(), "last probe: <nil>") {
		t.Fatalf("failure dropped the last probe error: %v", err)
	}
	if strings.Contains(err.Error(), "s3cr3tpassword") {
		t.Fatalf("failure leaked the connection password: %v", err)
	}
}

func TestWaitForReadyReturnsWhenCallerCancels(t *testing.T) {
	// A readiness budget far longer than the test: only the cancellation can
	// end this wait.
	runtime := readinessRuntime(t, Timeouts{Readiness: 600, Connect: 600})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	started := time.Now()
	err := runtime.WaitForReady(ctx)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("readiness reported success after the caller gave up")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("cancellation took %s to be observed", elapsed)
	}
	if !strings.Contains(err.Error(), "readiness wait cancelled") {
		t.Fatalf("failure does not report the cancellation: %v", err)
	}
}

// A readiness failure has to reach the caller as a lifecycle status: the
// deferred panic-recovery helper wrapping every RPC must not turn a cancelled
// wait into a response that looks like a healthy start.
func TestStartReportsACancelledReadinessWaitAsAnError(t *testing.T) {
	runtime := readinessRuntime(t, Timeouts{Readiness: 600, Connect: 600})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	response, err := runtime.Start(ctx, &runtimev0.StartRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetStatus().GetState() != runtimev0.StartStatus_ERROR {
		t.Fatalf("start state = %s, want ERROR", response.GetStatus().GetState())
	}
	if !strings.Contains(response.GetStatus().GetMessage(), "readiness wait cancelled") {
		t.Fatalf("start status does not carry the cancellation: %q", response.GetStatus().GetMessage())
	}
}

// readinessRuntime points a Runtime at a listener that accepts connections and
// then holds them open without ever answering the startup handshake.
func readinessRuntime(t *testing.T, timeouts Timeouts) *Runtime {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			t.Cleanup(func() { _ = connection.Close() })
		}
	}()

	runtime := NewRuntime()
	runtime.Settings.DatabaseName = "app"
	runtime.Settings.Timeouts = timeouts
	connection, err := withConnectTimeout(
		postgresConnectionString(listener.Addr().String(), "app", "owner", "s3cr3tpassword", false, false),
		timeouts.connect(),
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime.connection = connection
	return runtime
}

func TestWithConnectTimeoutBoundsEstablishment(t *testing.T) {
	dsn := postgresConnectionString("db.example.com:5432", "app", "owner", "secret", true, false)
	bounded, err := withConnectTimeout(dsn, 7*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bounded, "connect_timeout=7") {
		t.Fatalf("connection string is not bounded: %s", bounded)
	}
	if !strings.Contains(bounded, "owner:secret@db.example.com:5432/app") {
		t.Fatalf("connection string lost its target: %s", bounded)
	}

	if _, err = withConnectTimeout("postgresql://%zz", time.Second); err == nil {
		t.Fatal("an unparseable connection string was accepted")
	}
}
