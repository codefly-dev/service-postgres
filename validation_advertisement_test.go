package main

import (
	"context"
	"testing"

	"github.com/codefly-dev/core/ciinputs"
	agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestAgentRemainsLegacyUntilTestsAreSchedulable is the gate on the whole
// contract. An advertised message is authoritative for the operations it omits
// too, and a caller answers an unsupported test operation by failing the run
// rather than skipping it, so advertising this message while no suite exists
// turns a passing test phase into a failing one for every service this agent
// serves. Leaving the advertisement absent keeps callers probing the RPCs.
func TestAgentRemainsLegacyUntilTestsAreSchedulable(t *testing.T) {
	information, err := NewService().GetAgentInformation(t.Context(), &agentv0.AgentInformationRequest{})
	require.NoError(t, err)

	test := validationCapabilities().GetTest()
	if !test.GetSupported() {
		require.Nil(t, information.GetValidation(),
			"advertising a contract that declares test unsupported fails the test phase instead of skipping it")
		return
	}
	// Once a suite exists the gate releases, but an inventory is what makes the
	// declaration schedulable at all.
	require.NotEmpty(t, test.GetSuites())
	require.NotNil(t, information.GetValidation())
}

// answered reports whether an RPC serves an operation at all. Two different
// answers mean it does not: an RPC this agent never implemented is promoted
// from the embedded core server and reports Unimplemented, while one that
// exists only to decline reports an UNSUPPORTED status and a nil error. A
// declared method is therefore not evidence of a capability, which is why this
// reads the answer rather than the method set.
func answered(err error, unsupported bool) bool {
	return status.Code(err) != codes.Unimplemented && !unsupported
}

// TestAdvertisedValidationMatchesImplementedOperations measures what each RPC
// answers instead of whether a method is declared. A declared method can still
// decline with UNSUPPORTED, and an RPC promoted from the embedded *Service is
// served without being declared on Builder or Runtime at all, so only the
// answer separates an operation this agent implements from one it inherits.
//
// The probes run on a cancelled context: an unimplemented RPC answers
// Unimplemented before looking at it, while an implemented one abandons its
// scanner or its cache lock and reports an ordinary failure, so nothing here
// builds an image or runs a vulnerability scan.
func TestAdvertisedValidationMatchesImplementedOperations(t *testing.T) {
	capabilities := validationCapabilities()
	builder := newBuildTestBuilder(t)
	runtime := NewRuntime()

	for _, operation := range []struct {
		name       string
		advertised bool
		rpc        string
		probe      func(context.Context) bool
	}{
		// Runtime.Lint and Runtime.Build carry no UNSUPPORTED status, so
		// Unimplemented is the only way they can decline.
		{"lint", capabilities.GetLint().GetSupported(), "Runtime.Lint", func(ctx context.Context) bool {
			_, err := runtime.Lint(ctx, &runtimev0.LintRequest{})
			return answered(err, false)
		}},
		{"compile", capabilities.GetCompile().GetSupported(), "Runtime.Build", func(ctx context.Context) bool {
			_, err := runtime.Build(ctx, &runtimev0.BuildRequest{})
			return answered(err, false)
		}},
		{"audit", capabilities.GetAudit().GetSupported(), "Builder.Audit", func(ctx context.Context) bool {
			response, err := builder.Audit(ctx, &builderv0.AuditRequest{})
			return answered(err, response.GetState().GetState() == builderv0.AuditStatus_UNSUPPORTED)
		}},
		{"artifact_build", capabilities.GetArtifactBuild().GetSupported(), "Builder.Build", func(ctx context.Context) bool {
			_, err := builder.Build(ctx, &builderv0.BuildRequest{})
			return answered(err, false)
		}},
		{"sbom", capabilities.GetSbom().GetSupported(), "Builder.SBOM", func(ctx context.Context) bool {
			response, err := builder.SBOM(ctx, &builderv0.SBOMRequest{})
			return answered(err, response.GetState().GetState() == builderv0.SBOMStatus_UNSUPPORTED)
		}},
		{"sync", capabilities.GetSync().GetSupported(), "Builder.Sync", func(ctx context.Context) bool {
			response, err := builder.Sync(ctx, &builderv0.SyncRequest{})
			return answered(err, response.GetState().GetState() == builderv0.SyncStatus_UNSUPPORTED)
		}},
		{"source_package", capabilities.GetSourcePackage().GetSupported(), "Builder.Package", func(ctx context.Context) bool {
			response, err := builder.Package(ctx, &builderv0.PackageRequest{})
			return answered(err, response.GetState().GetState() == builderv0.PackageStatus_UNSUPPORTED)
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			served := operation.probe(ctx)
			require.Equal(t, served, operation.advertised,
				"%s is advertised as %v but %s answers as served=%v",
				operation.name, operation.advertised, operation.rpc, served)
		})
	}

	// Runtime.Test is implemented, so the probes above would read it as a
	// served operation. It answers an empty success rather than running
	// anything, and Required refuses a supported test capability carrying no
	// suites, so naming one here would schedule a phase that reports success
	// without executing a single test.
	require.False(t, capabilities.GetTest().GetSupported())
	require.Empty(t, capabilities.GetTest().GetSuites())
}

// TestAdvertisedPhasesAreSchedulable derives the task inventory the way a
// caller does and puts it back through evaluation. A phase this agent declares
// that the evaluating core cannot represent does not degrade to a skipped
// phase: Evaluate rejects the whole inventory, so every other phase stops being
// scheduled too.
func TestAdvertisedPhasesAreSchedulable(t *testing.T) {
	required, err := ciinputs.Required(validationCapabilities())
	require.NoError(t, err)
	require.NotEmpty(t, required)

	_, err = ciinputs.Evaluate(nil, &agentv0.GetEffectiveInputsRequest{
		SchemaVersion: ciinputs.Version,
		Snapshot:      "advertisement",
	}, required)
	require.NoError(t, err)
}

// TestSyncProvesNoDriftInDryRun binds the sync capability to the behaviour it
// claims. Declaring sync supported tells a caller this agent detects generated
// drift without mutating the tree, and a caller reads a successful dry run
// carrying no changed files as proof that none exists — so the claim is only
// honest while the agent regenerates nothing that is tracked.
func TestSyncProvesNoDriftInDryRun(t *testing.T) {
	require.True(t, validationCapabilities().GetSync().GetSupported())

	builder := newBuildTestBuilder(t)
	response, err := builder.Sync(t.Context(), &builderv0.SyncRequest{DryRun: true})
	require.NoError(t, err)
	require.Equal(t, builderv0.SyncStatus_SUCCESS, response.GetState().GetState(),
		response.GetState().GetMessage())
	require.Empty(t, response.GetChangedFiles())
}
