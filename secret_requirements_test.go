package main

import (
	"context"
	"strings"
	"testing"

	coreservices "github.com/codefly-dev/core/agents/services"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/stretchr/testify/require"
)

// The probe answers what a render needs before anything is built, and it
// answers under the operation contract — without which a host reads the empty
// list as "requires nothing" and renders 25 images before the refusal.
func TestBuildCapabilitiesDeclaresWhatARenderRequires(t *testing.T) {
	builder, _ := newDeploymentTestBuilder(t)

	capabilities, err := builder.BuildCapabilities(context.Background(), &builderv0.BuildCapabilitiesRequest{})
	require.NoError(t, err)
	require.True(t, capabilities.GetBuildxSelection())
	require.Contains(t, capabilities.GetExecutionContracts(), coreservices.SecretRequirementsContract)
	require.Len(t, capabilities.GetRequiredSecretConfigurations(), 1)

	required := capabilities.GetRequiredSecretConfigurations()[0]
	require.Equal(t, "postgres", required.GetConfiguration())
	require.Equal(t, []string{
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
		"POSTGRES_READ_ONLY_PASSWORD",
		"POSTGRES_READ_WRITE_PASSWORD",
	}, required.GetKeys())
	require.Equal(t,
		[]builderv0.KubernetesOutputProfile{builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1},
		required.GetProfiles(),
	)
}

// The declaration and the refusal are the same set: every key the probe names
// is a key the restricted render refuses on when it is absent, and no other key
// is. A render that passed the probe's set must not then refuse.
func TestTheDeclarationIsExactlyWhatTheRenderRefusesOn(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	capabilities, err := builder.BuildCapabilities(context.Background(), &builderv0.BuildCapabilitiesRequest{})
	require.NoError(t, err)
	declared := capabilities.GetRequiredSecretConfigurations()[0].GetKeys()

	complete := map[string]*builderv0.KubernetesSecretKeyReference{}
	for _, key := range declared {
		configurationKey := resources.ServiceSecretConfigurationKeyFromUnique("module/postgres", "postgres", key)
		complete[configurationKey] = &builderv0.KubernetesSecretKeyReference{Name: "postgres-secrets", Key: configurationKey}
	}

	// Delivering exactly the declared set renders.
	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(t.TempDir(), networkMappings, complete))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	// Dropping any one of them is refused, by the configuration key the probe
	// named — the exact string the doctor can now hand an operator.
	for _, key := range declared {
		missing := map[string]*builderv0.KubernetesSecretKeyReference{}
		for configurationKey, reference := range complete {
			if strings.HasSuffix(configurationKey, "__"+key) {
				continue
			}
			missing[configurationKey] = reference
		}
		refused, deployErr := builder.Deploy(context.Background(), promotableDeploymentRequest(t.TempDir(), networkMappings, missing))
		require.NoError(t, deployErr)
		require.Equal(t, builderv0.DeploymentStatus_ERROR, refused.GetState().GetState(), "dropping %s must be refused", key)
		require.Contains(t, refused.GetState().GetMessage(),
			resources.ServiceSecretConfigurationKeyFromUnique("module/postgres", "postgres", key))
	}
}

// External-identity logins hold no password, so a render requires no
// credential — and the probe must not demand one, or a readiness check reports
// a failure the render would never hit.
func TestExternalIdentityRequiresNoSecretConfiguration(t *testing.T) {
	builder, _ := newDeploymentTestBuilder(t)
	builder.AuthMode = authModeExternalIdentity

	capabilities, err := builder.BuildCapabilities(context.Background(), &builderv0.BuildCapabilitiesRequest{})
	require.NoError(t, err)
	require.Contains(t, capabilities.GetExecutionContracts(), coreservices.SecretRequirementsContract)
	require.Empty(t, capabilities.GetRequiredSecretConfigurations())
}

// A mistyped auth mode is a declaration failure, and the probe is the first
// place a host can learn it: it refuses rather than answering for a mode it
// does not support.
func TestAnUnsupportedAuthModeIsRefusedByTheProbe(t *testing.T) {
	builder, _ := newDeploymentTestBuilder(t)
	builder.AuthMode = "external-idenity" // typo

	_, err := builder.BuildCapabilities(context.Background(), &builderv0.BuildCapabilitiesRequest{})
	require.ErrorContains(t, err, `unsupported postgres auth mode "external-idenity"`)
}

// The host-side comparison reads the probe's declaration and names every
// missing key at once, in the spelling the agent's own refusal uses.
func TestAHostReadsTheDeclarationAsTheMissingSet(t *testing.T) {
	builder, _ := newDeploymentTestBuilder(t)
	capabilities, err := builder.BuildCapabilities(context.Background(), &builderv0.BuildCapabilitiesRequest{})
	require.NoError(t, err)

	missing, err := coreservices.MissingServiceSecretConfigurations(
		"module/postgres",
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1,
		capabilities,
		[]string{resources.ServiceSecretConfigurationKeyFromUnique("module/postgres", "postgres", "POSTGRES_USER")},
	)
	require.NoError(t, err)
	require.Len(t, missing, 1)
	require.Equal(t, []string{"POSTGRES_PASSWORD", "POSTGRES_READ_ONLY_PASSWORD", "POSTGRES_READ_WRITE_PASSWORD"}, missing[0].Keys)
}

// A local apply carries the value inline, so nothing is required of the host.
func TestALocalApplyRequiresNothingOfTheHost(t *testing.T) {
	builder, _ := newDeploymentTestBuilder(t)
	capabilities, err := builder.BuildCapabilities(context.Background(), &builderv0.BuildCapabilitiesRequest{})
	require.NoError(t, err)

	missing, err := coreservices.MissingServiceSecretConfigurations(
		"module/postgres",
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1,
		capabilities,
		nil,
	)
	require.NoError(t, err)
	require.Empty(t, missing)
}
