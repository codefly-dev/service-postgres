package main

import agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"

// validationCapabilities is authoritative: a present message declares every
// operation it omits unsupported, so an operation this agent serves has to
// appear here or callers stop scheduling it entirely.
//
// Runtime.Lint and Runtime.Build are not implemented, and neither is
// Builder.Package: postgres ships a stock image rather than compiled source.
// Runtime.Test is implemented, but only as the empty success the base wrapper
// returns — there is no suite to name, and a supported test capability without
// a suite inventory is a phase that passes without running anything.
//
// image_sbom is absent even though Builder.SBOM serves image scope.
// ciinputs.Required emits TASK_PHASE_IMAGE_SBOM (9) for it, while validKey in
// every released core still bounds phases at TASK_PHASE_SOURCE_PACKAGE (8), so
// advertising it makes discovery reject the whole inventory and fail every
// phase this agent does serve. Advertise it once the cores evaluating this
// agent carry the wider bound; TestAdvertisedPhasesAreSchedulable holds the
// line meanwhile.
func validationCapabilities() *agentv0.ValidationCapabilities {
	return &agentv0.ValidationCapabilities{
		Audit:         workspaceOperation(),
		ArtifactBuild: workspaceOperation(),
		Sbom:          workspaceOperation(),
		// There is no derived source to regenerate, so Sync reports the same
		// authoritative absence of drift whether or not the caller asks for a
		// dry run.
		Sync: workspaceOperation(),
	}
}

// workspaceOperation validates the whole service tree. Postgres owns migrations
// and its service manifest, not language packages or independently checkable
// files, so no narrower scope has a meaning this agent could honour.
func workspaceOperation() *agentv0.ValidationOperationCapability {
	return &agentv0.ValidationOperationCapability{
		Supported: true,
		Scopes:    []agentv0.ValidationScope{agentv0.ValidationScope_VALIDATION_SCOPE_WORKSPACE},
	}
}
