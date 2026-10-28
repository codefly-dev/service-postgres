package main

import (
	"testing"

	"github.com/codefly-dev/core/agents/contract"
	agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/stretchr/testify/require"
)

// InitRequest.runtime_image is a host claim about which image the postmaster
// runs. This agent resolves its own image, so there is no absent-image case for
// the handoff to serve, and the single recipe its builder emits is the migration
// bootstrap image — an alpine image whose CMD runs bootstrap.sh. A host that
// mistakes that recipe for the runtime image and supplies it would, if the field
// were ignored, believe the database runs the image it built while the
// postmaster runs the managed digest. These tests hold the refusal that keeps
// that divergence from being silent, and keep the advertisement its one source.
//
// Init reports a refusal in its status rather than as a transport error, so the
// status is what a host reads and what these tests assert. Neither test starts a
// postmaster: Init refuses before it reads a network mapping.
func TestInitRefusesAHostSuppliedRuntimeImageWhileUnadvertised(t *testing.T) {
	require.False(t, implementsCapability(contract.RuntimeInitImage),
		"adopting the handoff means implementing image selection and its reference refusals, then revisiting this test")

	runtime := NewRuntime()
	response, err := runtime.Init(t.Context(), &runtimev0.InitRequest{
		RuntimeImage: "codefly-local/runtime@sha256:" +
			"0000000000000000000000000000000000000000000000000000000000000001",
	})
	require.NoError(t, err)
	require.Equal(t, runtimev0.InitStatus_ERROR, response.GetStatus().GetState())
	require.Contains(t, response.GetStatus().GetMessage(), contract.RuntimeInitImage)
	require.Contains(t, response.GetStatus().GetMessage(), "migration bootstrap image")
}

// An empty field is the deployed and ordinary local case and carries no claim,
// so it must pass this guard untouched. Init still refuses afterwards — nothing
// here supplies an endpoint — but on the mapping, not on the image.
func TestInitLeavesAnAbsentRuntimeImageToOrdinaryResolution(t *testing.T) {
	runtime := NewRuntime()
	response, err := runtime.Init(t.Context(), &runtimev0.InitRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.InitStatus_ERROR, response.GetStatus().GetState())
	require.NotContains(t, response.GetStatus().GetMessage(), contract.RuntimeInitImage)
}

// The refusal reads the advertisement rather than restating it, so the two
// cannot drift: a declared capability lifts the guard with no second edit.
func TestTheRuntimeImageGuardFollowsTheAdvertisedContract(t *testing.T) {
	information, err := NewService().GetAgentInformation(t.Context(), &agentv0.AgentInformationRequest{})
	require.NoError(t, err)

	require.NotEmpty(t, information.GetContract().GetCapabilities())
	for _, capability := range information.GetContract().GetCapabilities() {
		require.True(t, implementsCapability(capability),
			"advertised capability %q is not visible to the runtime's own checks", capability)
	}
	require.False(t, implementsCapability("runtime-image-handoff-that-does-not-exist/v1"))
}
