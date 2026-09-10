package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestControlPlaneLockSerializes is the baseline: the lock still does the job a
// sync.Mutex did, so making it context-aware did not cost mutual exclusion.
func TestControlPlaneLockSerializes(t *testing.T) {
	var lock controlPlaneLock

	release, err := lock.acquire(context.Background())
	require.NoError(t, err)

	second := make(chan struct{})
	go func() {
		innerRelease, innerErr := lock.acquire(context.Background())
		require.NoError(t, innerErr)
		innerRelease()
		close(second)
	}()

	select {
	case <-second:
		t.Fatal("a second holder entered the control plane while it was held")
	case <-time.After(250 * time.Millisecond):
	}

	release()
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Fatal("releasing the control plane did not admit the waiter")
	}
}

// TestControlPlaneLockRefusesCancelledCaller is the property sync.Mutex could
// not offer and the reason for the change. Lock() cannot be cancelled, so a
// caller whose RPC deadline had already passed would still queue behind an
// in-flight replay and then run DDL on behalf of a request that returned long
// ago. Here the caller must be turned away instead.
func TestControlPlaneLockRefusesCancelledCaller(t *testing.T) {
	var lock controlPlaneLock

	release, err := lock.acquire(context.Background())
	require.NoError(t, err)
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = lock.acquire(ctx)
	require.ErrorIs(t, err, context.Canceled,
		"a cancelled caller must be refused, not queued behind the holder")
}

// TestControlPlaneLockRefusesCancelledCallerWhenFree pins the precheck. With the
// lock FREE and ctx already done, both select cases are ready and Go chooses
// between them at random — so without an explicit ctx check this would admit an
// expired caller a fraction of the time. Repeated so a random-choice regression
// cannot pass by luck.
func TestControlPlaneLockRefusesCancelledCallerWhenFree(t *testing.T) {
	var lock controlPlaneLock
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for range 200 {
		_, err := lock.acquire(ctx)
		require.ErrorIs(t, err, context.Canceled,
			"an expired caller must never enter a free control plane")
	}

	// Refusal must not have consumed a slot: the lock is still usable.
	release, err := lock.acquire(context.Background())
	require.NoError(t, err)
	release()
}

// TestControlPlaneLockRespectsDeadline covers the waiting case: a caller that
// times out while queued gives up rather than executing late.
func TestControlPlaneLockRespectsDeadline(t *testing.T) {
	var lock controlPlaneLock

	release, err := lock.acquire(context.Background())
	require.NoError(t, err)
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = lock.acquire(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 5*time.Second, "acquire must return at its deadline, not hang")
}

// TestControlPlaneLockZeroValueIsUsable pins the lazy init: Runtime embeds this
// by value and NewRuntime does not initialize it, so the zero value has to work.
func TestControlPlaneLockZeroValueIsUsable(t *testing.T) {
	var lock controlPlaneLock
	release, err := lock.acquire(context.Background())
	require.NoError(t, err)
	release()

	again, err := lock.acquire(context.Background())
	require.NoError(t, err)
	again()
}
