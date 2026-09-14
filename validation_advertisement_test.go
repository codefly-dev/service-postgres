package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/codefly-dev/core/ciinputs"
	agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// TestAdvertisedValidationMatchesImplementedOperations ties each advertised
// operation to the RPC that serves it. A present validation message is
// authoritative, so an operation added to this plugin without being advertised
// is one callers never schedule, and one advertised without an implementation
// is an RPC that answers Unimplemented.
func TestAdvertisedValidationMatchesImplementedOperations(t *testing.T) {
	implemented := declaredPluginMethods(t)
	capabilities := validationCapabilities()

	for _, operation := range []struct {
		name       string
		advertised bool
		rpc        string
	}{
		{"lint", capabilities.GetLint().GetSupported(), "Runtime.Lint"},
		{"compile", capabilities.GetCompile().GetSupported(), "Runtime.Build"},
		{"audit", capabilities.GetAudit().GetSupported(), "Builder.Audit"},
		{"artifact_build", capabilities.GetArtifactBuild().GetSupported(), "Builder.Build"},
		{"sbom", capabilities.GetSbom().GetSupported(), "Builder.SBOM"},
		{"sync", capabilities.GetSync().GetSupported(), "Builder.Sync"},
		{"source_package", capabilities.GetSourcePackage().GetSupported(), "Builder.Package"},
	} {
		require.Equal(t, implemented[operation.rpc], operation.advertised,
			"%s is advertised as %v but %s is implemented as %v",
			operation.name, operation.advertised, operation.rpc, implemented[operation.rpc])
	}

	// Runtime.Test exists, so the table above cannot speak for it: it returns
	// the base empty success rather than running a suite. Required refuses a
	// supported test capability with no suites, and a named suite here would
	// schedule a phase that reports success without executing anything.
	require.False(t, capabilities.GetTest().GetSupported())
	require.Empty(t, capabilities.GetTest().GetSuites())
}

// TestAdvertisedPhasesAreSchedulable derives the task inventory the way a
// caller does and puts it back through evaluation. A phase this agent
// advertises that the evaluating core cannot represent does not degrade to a
// skipped phase: Evaluate rejects the whole inventory, so every other phase
// stops being scheduled too.
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

// TestAgentInformationCarriesValidationContract keeps the contract on the wire.
// Without it the advertisement falls back to nil, which reads as a legacy agent
// rather than as an agent supporting nothing, and the inventory above never
// reaches a caller.
func TestAgentInformationCarriesValidationContract(t *testing.T) {
	information, err := NewService().GetAgentInformation(t.Context(), &agentv0.AgentInformationRequest{})
	require.NoError(t, err)
	require.True(t, proto.Equal(information.GetValidation(), validationCapabilities()))
}

// declaredPluginMethods collects the methods this package declares on its
// plugin types. Unimplemented RPCs are promoted from the embedded core servers,
// so a method named here is one this agent actually serves.
func declaredPluginMethods(t *testing.T) map[string]bool {
	t.Helper()

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	methods := map[string]bool{}
	fileSet := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, name, nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || len(function.Recv.List) != 1 {
				continue
			}
			pointer, ok := function.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			receiver, ok := pointer.X.(*ast.Ident)
			if !ok {
				continue
			}
			methods[receiver.Name+"."+function.Name.Name] = true
		}
	}
	return methods
}
