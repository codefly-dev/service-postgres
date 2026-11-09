package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	coreservices "github.com/codefly-dev/core/agents/services"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
)

// postgresSecretConfiguration is the one secret configuration group this agent
// reads a service's credentials from, and the group a host must have delivered
// before a secret-free render can reference them.
const postgresSecretConfiguration = "postgres"

// managedSecretConfigurationKeys are the four primitives this agent initializes
// the server with and bootstraps its roles from. They are authored outside this
// agent — the factory scaffolds them into the service's own secret
// configuration, and `codefly config generate` mints them for an environment
// that has none — which is why a render reaching the reference selection
// without one is a service the host has not finished composing.
var managedSecretConfigurationKeys = []string{
	"POSTGRES_USER",
	"POSTGRES_PASSWORD",
	"POSTGRES_READ_ONLY_PASSWORD",
	"POSTGRES_READ_WRITE_PASSWORD",
}

// requiredSecretConfigurationKeys names every key of the service's own postgres
// secret configuration that a secret-free render requires the host to have
// delivered, for a deployment bound to an external instance or not.
//
// This is the single statement of that set. BuildCapabilities declares it to
// the host before any image is built, and selectPromotableSecretReferences and
// selectExternalSecretReferences refuse on it at render time — so what the
// probe promises and what the render demands cannot drift.
//
// A declared login's password is deliberately absent: this agent names that key
// itself and derives its reference into the render's own Secret when the service
// does not author one (loginPasswordSecretReference), so it is never something
// a host must deliver first.
func (s *Service) requiredSecretConfigurationKeys(external bool) []string {
	// External-identity logins authenticate through a cloud identity provider,
	// so the service holds no password and a render requires no credential.
	if s.externalIdentity() {
		return nil
	}
	keys := slices.Clone(managedSecretConfigurationKeys)
	if external {
		// An external binding's reader and writer reach a server this agent did
		// not initialize, over a connection the host delivers rather than one
		// assembled from the primitives above.
		keys = append(keys, readOnlyConnectionKey, readWriteConnectionKey)
	}
	return keys
}

// BuildCapabilities answers what this agent guarantees, and what a render of
// the requested environment needs from the host, without running a build. Every
// answer comes from the loaded service's own settings: this probe reaches no
// cluster, no registry and no database.
func (s *Builder) BuildCapabilities(_ context.Context, req *builderv0.BuildCapabilitiesRequest) (*builderv0.BuildCapabilitiesResponse, error) {
	response := &builderv0.BuildCapabilitiesResponse{
		BuildxSelection:    true,
		ExecutionContracts: []string{coreservices.SecretRequirementsContract},
	}
	required, err := s.requiredSecretConfiguration(req.GetEnvironment())
	if err != nil {
		return nil, err
	}
	if required != nil {
		response.RequiredSecretConfigurations = []*builderv0.RequiredSecretConfiguration{required}
	}
	return response, nil
}

// requiredSecretConfiguration states the postgres group a secret-free render of
// environment requires, or nothing when this service's auth mode holds no
// credential at all.
//
// An unnamed environment is answered with what holds in every environment: the
// managed primitives. Whether a deployment binds an external instance is a fact
// of the service's own external-instances settings, per environment, so naming
// the environment is what makes the answer exact — and an environment the
// settings declare external instances for but do not bind is reported as the
// refusal it will be at render time, rather than silently narrowed.
func (s *Builder) requiredSecretConfiguration(environment string) (*builderv0.RequiredSecretConfiguration, error) {
	if err := s.validateAuthMode(); err != nil {
		return nil, err
	}
	external := false
	if strings.TrimSpace(environment) != "" {
		binding, err := s.externalInstance(environment)
		if err != nil {
			return nil, err
		}
		external = binding != nil
	}
	keys := s.requiredSecretConfigurationKeys(external)
	if len(keys) == 0 {
		return nil, nil
	}
	required := &builderv0.RequiredSecretConfiguration{
		Configuration: postgresSecretConfiguration,
		Keys:          keys,
		// Only the secret-free contract references a credential through a
		// secretKeyRef the host must have filled; a local apply carries the
		// value inline, from the same configuration flow that runs the service.
		Profiles: []builderv0.KubernetesOutputProfile{
			builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1,
		},
	}
	if err := coreservices.ValidateRequiredSecretConfiguration(required); err != nil {
		return nil, fmt.Errorf("postgres secret requirement: %w", err)
	}
	return required, nil
}
