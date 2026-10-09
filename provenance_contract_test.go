package main

import (
	"context"
	"slices"
	"testing"

	"github.com/codefly-dev/core/agents/contract"
	agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"
)

// TestAdvertisementAdoptsDeploymentCompositionProvenance: the host requires the
// live contract capability before it trusts this agent to judge a deployment's
// dependency edges with the request's composition provenance (core#752). The
// deployment path here is core's DeployKustomize, which does; the
// advertisement must say so, and keep the base contract it extends.
func TestAdvertisementAdoptsDeploymentCompositionProvenance(t *testing.T) {
	info, err := NewService().GetAgentInformation(context.Background(), &agentv0.AgentInformationRequest{})
	if err != nil {
		t.Fatalf("GetAgentInformation: %v", err)
	}
	if !slices.Contains(info.GetContract().GetCapabilities(), contract.DeploymentCompositionProvenance) {
		t.Fatalf("contract capabilities %v do not advertise %s", info.GetContract().GetCapabilities(), contract.DeploymentCompositionProvenance)
	}
	if err := contract.Check(info.GetContract(), contract.ContainerRecoveryScope); err != nil {
		t.Fatalf("the base contract is no longer satisfied: %v", err)
	}
}
