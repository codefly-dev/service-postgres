package main

import (
	"testing"

	"github.com/codefly-dev/core/agents/contract"
	agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"
	"github.com/stretchr/testify/require"
)

// TestDeclaredContractCarriesTheSharedPromisesForward guards the cost of
// declaring a contract explicitly. The shared server supplies its own contract
// only while a handler leaves it absent, so the moment this agent declares one
// to add a capability, every promise that server was making on its behalf
// becomes this agent's to restate — and a host reads a dropped capability as
// an agent that cannot do the thing, not as an oversight.
func TestDeclaredContractCarriesTheSharedPromisesForward(t *testing.T) {
	information, err := NewService().GetAgentInformation(t.Context(), &agentv0.AgentInformationRequest{})
	require.NoError(t, err)

	declared := information.GetContract()
	require.NotNil(t, declared, "an absent contract is undeclared, and discovery rejects it")
	require.Equal(t, contract.Current().GetProtocolVersion(), declared.GetProtocolVersion())
	require.Equal(t, uint32(contract.StartupProtocolVersion), declared.GetStartupProtocolVersion())
	require.Subset(t, declared.GetCapabilities(), contract.Current().GetCapabilities())
	require.NoError(t, contract.Check(declared, contract.ContainerRecoveryScope))
}

// TestAdvertisedHostResourceRecoveryIsServedByACommand binds the advertisement
// to the thing it promises. A host requires the capability and then invokes the
// command generically; advertising one without registering the other answers
// that call with "unknown command" after the host has already committed to
// recovery being this agent's job.
func TestAdvertisedHostResourceRecoveryIsServedByACommand(t *testing.T) {
	service := NewService()

	information, err := service.GetAgentInformation(t.Context(), &agentv0.AgentInformationRequest{})
	require.NoError(t, err)
	require.NoError(t, contract.Check(information.GetContract(), hostResourceRecoveryCapability))

	commands, err := service.ListCommands(t.Context(), &agentv0.ListCommandsRequest{})
	require.NoError(t, err)

	var recovery *agentv0.CommandDefinition
	for _, command := range commands.GetCommands() {
		if command.GetName() == recoverHostResourcesCommandName {
			recovery = command
		}
	}
	require.NotNil(t, recovery, "capability %q is advertised with no command serving it", hostResourceRecoveryCapability)

	// The command removes host resources. A policy or auto-approval layer reads
	// this flag to decide what it may run unattended, so mislabelling it hands
	// out unattended destruction of IPC state.
	require.True(t, recovery.GetDestructive())
}

// TestUnknownCommandIsRefused keeps the generic surface honest: a host that
// asks for a command this agent does not serve has to be told so, rather than
// reading an empty success as a completed recovery.
func TestUnknownCommandIsRefused(t *testing.T) {
	response, err := NewService().RunPluginCommand(t.Context(), &agentv0.RunPluginCommandRequest{
		Command: "not-a-command",
	})
	require.NoError(t, err)
	require.False(t, response.GetSuccess())
	require.Contains(t, response.GetError(), "unknown command")
}

// TestHostResourceRecoverySummaryDistinguishesAQuietPass checks that the
// command's output tells an operator which resources were destroyed, without
// pinning the wording — a caller reads this to know what happened on the host,
// so the counts have to survive, but the prose is free to change.
func TestHostResourceRecoverySummaryDistinguishesAQuietPass(t *testing.T) {
	require.True(t, hostResourceRecovery{}.empty())
	require.NotContains(t, hostResourceRecovery{}.summary(), "removed")

	busy := hostResourceRecovery{SharedSegments: 1, SemaphoreSets: 4}
	require.False(t, busy.empty())
	require.Contains(t, busy.summary(), "1")
	require.Contains(t, busy.summary(), "4")
}
