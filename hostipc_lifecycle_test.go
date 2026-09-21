package main

import (
	"context"
	"testing"

	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/shared"
	"github.com/stretchr/testify/require"
)

// stubHostResourceRecovery replaces the host sweep for one test. Without it a
// wiring test would reap the developer's real IPC tables to prove a call was
// made.
func stubHostResourceRecovery(t *testing.T, stub func(context.Context) (hostResourceRecovery, error)) {
	t.Helper()
	previous := recoverHostResources
	recoverHostResources = stub
	t.Cleanup(func() { recoverHostResources = previous })
}

// TestNativeLifecycleRecoversHostResources is the regression for the wiring
// itself, and it is the point of the whole change: recovery that is never
// invoked is indistinguishable from recovery that was deleted. Deleting the
// three call sites leaves every other test in this package passing, including
// the ones that boot a real postgres, because they assert on the database and
// never on the host resources around it.
//
// Init is driven against the nix runtime context but does not need nix
// installed: the claim under test is that recovery has already happened by the
// time anything touches a cluster, so an Init that then fails for want of nix
// still answers the question.
func TestNativeLifecycleRecoversHostResources(t *testing.T) {
	ctx := context.Background()
	fixture := newPostgresFixture(t, ctx, resources.NewRuntimeContextNix())

	runtime := NewRuntime()
	_, err := runtime.Load(ctx, &runtimev0.LoadRequest{
		Identity:     fixture.identity,
		Environment:  shared.Must(fixture.environment.Proto()),
		DisableCatch: true,
	})
	require.NoError(t, err)

	var calls int
	var adoptedClusterAtRecovery bool
	stubHostResourceRecovery(t, func(context.Context) (hostResourceRecovery, error) {
		calls++
		adoptedClusterAtRecovery = runtime.nixRuntime != nil
		return hostResourceRecovery{}, nil
	})

	// Init's own outcome is not the subject: on a host without nix it fails
	// materializing the environment, which is already past the ordering claim.
	_, _ = runtime.Init(ctx, &runtimev0.InitRequest{
		RuntimeContext:          fixture.runtimeContext,
		Configuration:           fixture.configuration,
		ProposedNetworkMappings: fixture.networkMappings,
	})
	require.Equal(t, 1, calls, "native init must recover host resources")
	require.False(t, adoptedClusterAtRecovery,
		"recovery must run before this invocation adopts a cluster, or it sweeps around a server it just started")

	// Stop and Destroy release a postmaster, which is the moment its System V
	// resources become collectable. A bare handle stands in for a started
	// cluster so the teardown wiring is covered on hosts without nix too.
	runtime.nixRuntime = &nixPostgres{}
	_, err = runtime.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Equal(t, 2, calls, "stopping a native cluster must recover the host resources it released")

	runtime.nixRuntime = &nixPostgres{}
	_, err = runtime.Destroy(ctx, &runtimev0.DestroyRequest{})
	require.NoError(t, err)
	require.Equal(t, 3, calls, "destroying a native cluster must recover the host resources it released")
}

// TestLifecycleSurvivesUnrecoverableHostResources keeps a sweep failure from
// becoming a lifecycle failure. These resources belong to runs this invocation
// does not own and several agents reach for the same ones at once, so losing
// that race must not be what fails a start or a teardown that otherwise
// succeeded — the authenticated command is where the error is raised instead.
func TestLifecycleSurvivesUnrecoverableHostResources(t *testing.T) {
	ctx := context.Background()
	fixture := newPostgresFixture(t, ctx, resources.NewRuntimeContextNix())

	runtime := NewRuntime()
	_, err := runtime.Load(ctx, &runtimev0.LoadRequest{
		Identity:     fixture.identity,
		Environment:  shared.Must(fixture.environment.Proto()),
		DisableCatch: true,
	})
	require.NoError(t, err)

	stubHostResourceRecovery(t, func(context.Context) (hostResourceRecovery, error) {
		return hostResourceRecovery{}, context.DeadlineExceeded
	})

	runtime.nixRuntime = &nixPostgres{}
	stopped, err := runtime.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.StopStatus_SUCCESS, stopped.GetStatus().GetState(),
		stopped.GetStatus().GetMessage())
}
