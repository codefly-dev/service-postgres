package main

import agentv1 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v1"

// validationCapabilities is the contract this agent will advertise, held back
// from AgentInformation until a caller can schedule it without regressing.
//
// A present message is authoritative for every operation, including the ones it
// omits, and that is what blocks it today. This agent runs no test suite, so the
// message declares test unsupported, and a caller reads that as an instruction
// to fail rather than to skip: it aborts the run outright instead of moving on.
// Lint and compile degrade to a skip in the same situation and source_package
// reports a clean unsupported error, so test is the only operation whose absence
// cannot currently be expressed. Advertising anything therefore turns a passing
// test phase into a failing one for every service this agent serves, while
// leaving it unadvertised keeps the caller probing the RPCs as it does now.
// Runtime.Test cannot answer UNSUPPORTED instead: callers treat every non-
// SUCCESS test status as a test failure, which fails the same run by a
// different route.
//
// image_sbom is omitted for a second, independent reason. ciinputs.Required
// emits TASK_PHASE_IMAGE_SBOM (9) for it, while validKey in every released core
// still bounds phases at TASK_PHASE_SOURCE_PACKAGE (8), so declaring it makes
// discovery reject the whole inventory and drop every other phase with it.
//
// Both gates are held by tests rather than by this comment:
// TestAgentRemainsLegacyUntilTestsAreSchedulable fails if this message is
// advertised while test is unsupported, and TestAdvertisedPhasesAreSchedulable
// fails if a declared phase cannot survive the core in use.
func validationCapabilities() *agentv1.ValidationCapabilities {
	return &agentv1.ValidationCapabilities{
		Audit:         workspaceOperation(),
		ArtifactBuild: workspaceOperation(),
		Sbom:          workspaceOperation(),
		// There is no derived source to regenerate: everything the build writes
		// into the service tree is ignored by the .gitignore the agent scaffolds
		// and by the one it stages beside the bootstrap tree. Sync therefore
		// reports the same authoritative absence of drift in either mode.
		Sync: workspaceOperation(),
	}
}

// workspaceOperation validates the whole service tree. Postgres owns migrations
// and its service manifest, not language packages or independently checkable
// files, so no narrower scope has a meaning this agent could honour.
func workspaceOperation() *agentv1.ValidationOperationCapability {
	return &agentv1.ValidationOperationCapability{
		Supported: true,
		Scopes:    []agentv1.ValidationScope{agentv1.ValidationScope_VALIDATION_SCOPE_WORKSPACE},
	}
}
