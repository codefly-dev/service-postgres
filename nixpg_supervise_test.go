package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/codefly-dev/core/agents/services"
	runtimev1 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v1"
)

// awaitCallback returns the error Supervise reported, or (nil,false) if nothing
// fired within the timeout. Supervise runs its watch in a goroutine, so tests
// synchronize through this channel rather than sleeping.
func awaitCallback(t *testing.T, fired <-chan error, timeout time.Duration) (error, bool) {
	t.Helper()
	select {
	case err := <-fired:
		return err, true
	case <-time.After(timeout):
		return nil, false
	}
}

func TestSuperviseReportsCrash(t *testing.T) {
	exit := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := &nixPostgres{serverExit: exit, serverCtx: ctx}

	fired := make(chan error, 1)
	n.Supervise(func(err error) { fired <- err })

	// The postmaster dies mid-run without anyone calling Stop.
	crash := errors.New("postgres: terminated by signal 9")
	exit <- crash

	got, ok := awaitCallback(t, fired, 2*time.Second)
	if !ok {
		t.Fatal("Supervise did not report an unexpected exit")
	}
	if !errors.Is(got, crash) {
		t.Fatalf("reported error = %v, want %v", got, crash)
	}
}

func TestSuperviseReportsCleanExit(t *testing.T) {
	exit := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := &nixPostgres{serverExit: exit, serverCtx: ctx}

	fired := make(chan error, 1)
	n.Supervise(func(err error) { fired <- err })

	// A clean exit mid-run (nil error) is still unexpected: nobody asked
	// postgres to stop, yet it is gone. It must be reported.
	exit <- nil

	got, ok := awaitCallback(t, fired, 2*time.Second)
	if !ok {
		t.Fatal("Supervise did not report a clean mid-run exit")
	}
	if got != nil {
		t.Fatalf("reported error = %v, want nil", got)
	}
}

func TestSuperviseIgnoresDeliberateStop(t *testing.T) {
	exit := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	n := &nixPostgres{serverExit: exit, serverCtx: ctx}

	fired := make(chan error, 1)
	n.Supervise(func(err error) { fired <- err })

	// Stop cancels serverCtx BEFORE the process terminates, then the process
	// exit lands on the channel. The cancelled context must suppress the report.
	cancel()
	exit <- errors.New("postgres: shutting down")

	if _, ok := awaitCallback(t, fired, 500*time.Millisecond); ok {
		t.Fatal("Supervise reported a deliberate Stop as an unexpected exit")
	}
}

func TestSuperviseNilChannelIsNoop(t *testing.T) {
	// Before startServer (e.g. Docker runtime) serverExit is nil. Supervise must
	// not spawn a goroutine or panic.
	n := &nixPostgres{}
	n.Supervise(func(error) { t.Fatal("callback fired with no server to watch") })
	time.Sleep(50 * time.Millisecond)
}

// startStatusState reads the observable StartStatus the same way the
// Information RPC does — through the RuntimeWrapper's lock.
func startStatusState(rt *services.RuntimeWrapper) runtimev1.StartStatus_Status {
	rt.RLock()
	defer rt.RUnlock()
	if rt.StartStatus == nil {
		return runtimev1.StartStatus_UNKNOWN
	}
	return rt.StartStatus.State
}

// TestStartTailReportsDeathBufferedBeforeStartResponse pins the ordering fix in
// (*Runtime).Start: the death-reporting supervisor must be armed only AFTER
// StartResponse commits StartStatus=STARTED.
//
// The failure this guards against: the postmaster dies in the window between
// waitReady succeeding (inside Init) and Start returning, so its exit is already
// buffered in serverExit by the time Start runs. If Supervise is armed before
// StartResponse (the original bug), the watcher goroutine flips StartStatus to
// ERROR and StartResponse then clobbers it back to STARTED — the death is masked
// and codefly's Follow loop never tears down (codefly-dev/cli#380).
//
// The two sub-cases run the same two operations in the two possible orders and
// assert the observable final state, so the masking mechanism — and why the
// production order is respond-then-arm — is locked in.
func TestStartTailReportsDeathBufferedBeforeStartResponse(t *testing.T) {
	crash := errors.New("postgres: terminated by signal 9")

	// newDeadServer builds a nixPostgres whose postmaster has already exited:
	// the exit sits in the buffered channel exactly as it would after a crash in
	// the Init->Start window.
	newDeadServer := func() *nixPostgres {
		exit := make(chan error, 1)
		exit <- crash
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		return &nixPostgres{serverExit: exit, serverCtx: ctx}
	}

	arm := func(rt *services.RuntimeWrapper, n *nixPostgres) <-chan struct{} {
		done := make(chan struct{})
		n.Supervise(func(err error) {
			rt.MarkRunnerExited(err)
			close(done)
		})
		return done
	}

	t.Run("respond then arm (production order) reports ERROR", func(t *testing.T) {
		rt := &services.RuntimeWrapper{}
		n := newDeadServer()

		if _, err := rt.StartResponse(); err != nil {
			t.Fatalf("StartResponse: %v", err)
		}
		done := arm(rt, n)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("supervisor never reported the buffered death")
		}
		if got := startStatusState(rt); got != runtimev1.StartStatus_ERROR {
			t.Fatalf("final StartStatus = %v, want ERROR (buffered death must not be masked)", got)
		}
	})

	t.Run("arm then respond (original bug) masks the death as STARTED", func(t *testing.T) {
		rt := &services.RuntimeWrapper{}
		n := newDeadServer()

		done := arm(rt, n)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("supervisor never reported the buffered death")
		}
		// StartResponse running after the watcher has reported ERROR overwrites
		// it with STARTED. This is the masking the production order avoids.
		if _, err := rt.StartResponse(); err != nil {
			t.Fatalf("StartResponse: %v", err)
		}
		if got := startStatusState(rt); got != runtimev1.StartStatus_STARTED {
			t.Fatalf("final StartStatus = %v, want STARTED (demonstrates the masking)", got)
		}
	})
}
