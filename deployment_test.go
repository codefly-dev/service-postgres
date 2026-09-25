package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codefly-dev/core/agents/services"
	agenttesting "github.com/codefly-dev/core/agents/testing"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDeploymentTemplatesWithMigration(t *testing.T) {
	dir := agenttesting.AssertKustomizeTemplates(t, deploymentFS, DeploymentTemplateParameters{
		WithBootstrap:               true,
		ManagedImage:                image.FullName(),
		BootstrapJobName:            "postgres-aaaaaaaaaaaa",
		BootstrapJobDeadlineSeconds: 240,
	})
	assertMigrationResource(t, dir, true)
	assertEphemeralSecret(t, dir)
	assertBootstrapJobDeadline(t, dir, 240)
	// No allocated port: the Service stays on the container port and headless,
	// the rendering every deployment produced before the port was read from the
	// network mapping.
	service := parseRenderedService(t, dir)
	require.Equal(t, []renderedServicePort{{Name: "postgres", Port: 5432, TargetPort: 5432}}, service.Spec.Ports)
	require.Equal(t, "None", service.Spec.ClusterIP, "a Service that translates nothing stays headless")
}

// Core allocates the tcp endpoint its canonical in-cluster port (80, not 5432)
// and hands that to every consumer, so the Service has to publish it and fold
// it onto 5432. A headless Service cannot: clients resolve it straight to pod
// IPs and dial the published port themselves.
func TestDeploymentTemplatesPublishAllocatedServicePort(t *testing.T) {
	dir := agenttesting.AssertKustomizeTemplates(t, deploymentFS, DeploymentTemplateParameters{
		WithBootstrap:               true,
		ManagedImage:                image.FullName(),
		BootstrapJobName:            "postgres-aaaaaaaaaaaa",
		BootstrapJobDeadlineSeconds: 240,
		ServicePort:                 80,
	})
	service := parseRenderedService(t, dir)
	require.Equal(t, []renderedServicePort{{Name: "postgres", Port: 80, TargetPort: 5432}}, service.Spec.Ports)
	require.NotEqual(t, "None", service.Spec.ClusterIP, "publishing a translated port needs a ClusterIP")
	statefulSet := readDeploymentFile(t, dir, "base", "stateful-set.yaml")
	require.Contains(t, statefulSet, "containerPort: 5432")
	require.NotContains(t, statefulSet, "containerPort: 80")
}

// The Deploy path reads the port from the mapping the CLI hands it for the
// store's own endpoint — the same instance whose address it advertises to
// consumers and dials from the bootstrap Job.
func TestDeployedServicePublishesAllocatedPort(t *testing.T) {
	builder, _ := newDeploymentTestBuilder(t)
	allocated := resources.NewNetworkInstance("postgres.codefly-test.svc.cluster.local", 80)
	allocated.Access = resources.NewPublicNetworkAccess()
	networkMappings := []*basev0.NetworkMapping{{
		Endpoint:  builder.TcpEndpoint,
		Instances: []*basev0.NetworkInstance{allocated},
	}}
	destination := t.TempDir()

	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(
		destination,
		networkMappings,
		promotablePostgresSecretReferences(),
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	service := parseRenderedService(t, destination)
	require.Equal(t, []renderedServicePort{{Name: "postgres", Port: 80, TargetPort: 5432}}, service.Spec.Ports)
	require.NotEqual(t, "None", service.Spec.ClusterIP)
	require.Contains(t, readDeploymentFile(t, destination, "base", "stateful-set.yaml"), "containerPort: 5432")
}

// A mapping on the container port needs no translation and renders the Service
// byte-for-byte as before.
func TestNativePortDeploymentRendersUnchangedService(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	destination := t.TempDir()

	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(
		destination,
		networkMappings,
		promotablePostgresSecretReferences(),
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	want := `
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: "codefly-test"
spec:
  selector:
    app: postgres
  ports:
    - name: postgres
      port: 5432
      targetPort: 5432
  # Headless — clients reach postgres via the StatefulSet pod's stable
  # DNS (<svc>-0.<svc>.<ns>.svc).
  clusterIP: None
`
	require.Equal(t, want, readDeploymentFile(t, destination, "base", "service.yaml"))
}

type renderedServicePort struct {
	Name       string `yaml:"name"`
	Port       uint32 `yaml:"port"`
	TargetPort uint32 `yaml:"targetPort"`
}

type renderedService struct {
	Spec struct {
		ClusterIP string                `yaml:"clusterIP"`
		Ports     []renderedServicePort `yaml:"ports"`
	} `yaml:"spec"`
}

func parseRenderedService(t *testing.T, destination string) renderedService {
	t.Helper()
	var service renderedService
	require.NoError(t, yaml.Unmarshal([]byte(readDeploymentFile(t, destination, "base", "service.yaml")), &service))
	return service
}

func TestDeploymentTemplatesWithoutBootstrap(t *testing.T) {
	dir := agenttesting.AssertKustomizeTemplates(t, deploymentFS, DeploymentTemplateParameters{
		ManagedImage:                image.FullName(),
		BootstrapJobName:            "postgres-aaaaaaaaaaaa",
		BootstrapJobDeadlineSeconds: 240,
	})
	assertMigrationResource(t, dir, false)
}

func TestPromotableDeploymentUsesTypedSecretReferencesWithoutValues(t *testing.T) {
	ctx := context.Background()
	builder := NewBuilder()
	identity := &basev0.ServiceIdentity{
		Workspace: "workspace",
		Module:    "module",
		Name:      "store",
		Version:   "1.2.3",
	}
	if err := builder.HeadlessLoad(ctx, identity); err != nil {
		t.Fatal(err)
	}
	builder.DatabaseName = "users"
	builder.Information = &services.Information{
		Service: resources.ToServiceWithCase(builder.Identity),
		Module:  resources.ToModuleWithCase(builder.Identity),
	}
	builder.TcpEndpoint = &basev0.Endpoint{
		Name:    "tcp",
		Module:  identity.Module,
		Service: identity.Name,
		Api:     "tcp",
	}
	instance := resources.NewNetworkInstance("store.platform.svc.cluster.local", 5432)
	instance.Access = resources.NewPublicNetworkAccess()
	secretReferences := make(map[string]*builderv0.KubernetesSecretKeyReference)
	for _, key := range []string{
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
		"POSTGRES_READ_ONLY_PASSWORD",
		"POSTGRES_READ_WRITE_PASSWORD",
	} {
		configurationKey := resources.ServiceSecretConfigurationKeyFromUnique(builder.Unique(), "postgres", key)
		secretReferences[configurationKey] = &builderv0.KubernetesSecretKeyReference{
			Name: "store-secrets",
			Key:  configurationKey,
		}
	}
	destination := t.TempDir()

	response, err := builder.Deploy(ctx, &builderv0.DeploymentRequest{
		Environment: &basev0.Environment{Name: "local"},
		NetworkMappings: []*basev0.NetworkMapping{{
			Endpoint:  builder.TcpEndpoint,
			Instances: []*basev0.NetworkInstance{instance},
		}},
		Deployment: &builderv0.Deployment{Kind: &builderv0.Deployment_Kubernetes{
			Kubernetes: &builderv0.KubernetesDeployment{
				Namespace:        "platform",
				Destination:      destination,
				Profile:          builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1,
				SecretReferences: secretReferences,
				BuildContext: &builderv0.DockerBuildContext{
					DockerRepository: "registry.example.com",
					ImageDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetState().GetState() != builderv0.DeploymentStatus_SUCCESS {
		t.Fatalf("deployment failed: %s", response.GetState().GetMessage())
	}
	if !response.GetDeployment().GetKubernetes().GetValidation().GetRestricted() {
		t.Fatal("deployment is not restricted")
	}
	for _, value := range response.GetConfiguration().GetInfos()[0].GetConfigurationValues() {
		if !value.GetSecret() || value.GetValue() != "" {
			t.Fatalf("exported connection contains a value: %+v", value)
		}
	}

	tree := ""
	for _, file := range []string{"stateful-set.yaml", "job.yaml"} {
		content, readErr := os.ReadFile(filepath.Join(destination, "base", file))
		if readErr != nil {
			t.Fatal(readErr)
		}
		tree += string(content)
	}
	for _, expected := range []string{
		"name: POSTGRES_USER",
		"name: POSTGRES_PASSWORD",
		"name: POSTGRES_READ_ONLY_PASSWORD",
		"name: POSTGRES_READ_WRITE_PASSWORD",
		"name: PGUSER",
		"name: PGPASSWORD",
		"name: PGHOST",
		`value: "store.platform.svc.cluster.local"`,
		"name: store-secrets",
		`value: "users"`,
	} {
		if !strings.Contains(tree, expected) {
			t.Errorf("manifest tree missing %q:\n%s", expected, tree)
		}
	}
	for configurationKey := range secretReferences {
		if strings.Contains(tree, "name: "+configurationKey) {
			t.Errorf("manifest exposed configuration key %q as a runtime variable", configurationKey)
		}
	}
}

func TestEphemeralDeploymentRetainsValueBasedConfigurationAndSecret(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	builder.DatabaseName = "accounts"
	destination := t.TempDir()
	request := promotableDeploymentRequest(destination, networkMappings, nil)
	request.GetDeployment().GetKubernetes().Profile = builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1
	request.GetDeployment().GetKubernetes().BuildContext.ImageDigest = ""
	request.Configuration = testPostgresConfiguration("migration-owner", "owner-secret", "reader-secret", "writer-secret")

	response, err := builder.Deploy(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	require.False(t, response.GetDeployment().GetKubernetes().GetValidation().GetRestricted())
	require.NotEmpty(t, configurationValue(t, response.GetConfiguration(), ownerConnectionKey))

	secret := readDeploymentFile(t, destination, "overlays", "test", "secret.yaml")
	require.Contains(t, secret, "kind: Secret")
	require.Contains(t, secret, "POSTGRES_PASSWORD: b3duZXItc2VjcmV0")
	require.Contains(t, secret, "POSTGRES_READ_ONLY_PASSWORD: cmVhZGVyLXNlY3JldA==")
	require.Contains(t, secret, "POSTGRES_READ_WRITE_PASSWORD: d3JpdGVyLXNlY3JldA==")

	job := readDeploymentFile(t, destination, "base", "job.yaml")
	require.Contains(t, job, "registry.example.com/module/postgres")
	require.Regexp(t, `^postgres-[0-9a-f]{12}$`, bootstrapJobResourceName(t, job))
	// A service that configures no budget still deploys a Job bounded in
	// elapsed time.
	require.Contains(t, job, fmt.Sprintf("activeDeadlineSeconds: %d", defaultBootstrapJobSeconds))
}

func TestExternalInstanceDeploymentUsesBindingAndOmitsOwnedServer(t *testing.T) {
	builder, _ := newDeploymentTestBuilder(t)
	builder.DatabaseName = "accounts"
	builder.RuntimeReadWriteRoles = []string{"app_tenant", "app_worker"}
	builder.ExternalInstances = map[string]ExternalInstance{"test": {
		Host:                  "managed.postgres.example.com",
		Port:                  6432,
		DatabaseName:          "accounts",
		RuntimeReadWriteRoles: []string{"app_tenant", "app_worker"},
	}}
	destination := t.TempDir()
	request := promotableDeploymentRequest(destination, nil, nil)
	request.GetDeployment().GetKubernetes().Profile = builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1
	request.GetDeployment().GetKubernetes().BuildContext.ImageDigest = ""
	request.Configuration = testPostgresConfiguration("migration-owner", "owner-secret", "reader-secret", "writer-secret")

	response, err := builder.Deploy(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	readWriteConnection := configurationValue(t, response.GetConfiguration(), readWriteConnectionKey)
	require.Contains(t, readWriteConnection, "@managed.postgres.example.com:6432/accounts")

	baseKustomization := readDeploymentFile(t, destination, "base", "kustomization.yaml")
	require.NotContains(t, baseKustomization, "stateful-set.yaml")
	require.NotContains(t, baseKustomization, "service.yaml")
	require.Contains(t, baseKustomization, "job.yaml")
	requireNoDeploymentFile(t, destination, "base", "stateful-set.yaml")
	requireNoDeploymentFile(t, destination, "base", "service.yaml")
	require.Contains(t, readDeploymentFile(t, destination, "base", "job.yaml"), "kind: Job")
}

func TestRestrictedExternalInstanceTargetsBindingAndChangesBootstrapIdentity(t *testing.T) {
	render := func(host string) string {
		t.Helper()
		builder, _ := newDeploymentTestBuilder(t)
		builder.DatabaseName = "accounts"
		builder.RuntimeReadWriteRoles = []string{"app_tenant"}
		builder.ExternalInstances = map[string]ExternalInstance{"test": {
			Host:                  host,
			Port:                  6432,
			DatabaseName:          "accounts",
			RuntimeReadWriteRoles: []string{"app_tenant"},
		}}
		destination := t.TempDir()
		response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(
			destination,
			nil,
			promotablePostgresSecretReferences(),
		))
		require.NoError(t, err)
		require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
		requireNoDeploymentFile(t, destination, "base", "stateful-set.yaml")
		requireNoDeploymentFile(t, destination, "base", "service.yaml")
		job := readDeploymentFile(t, destination, "base", "job.yaml")
		require.Contains(t, job, `value: "`+host+`"`)
		require.Contains(t, job, `value: "6432"`)
		require.Contains(t, job, "name: PGHOST")
		require.Contains(t, job, "name: PGPASSWORD")
		require.Contains(t, job, "name: "+externalReadOnlyConnectionKey)
		require.Contains(t, job, "name: "+externalReadWriteConnectionKey)
		require.NotContains(t, job, "name: "+migrationConnectionEnvironmentKey)
		return job
	}

	first := render("primary.postgres.example.com")
	second := render("replacement.postgres.example.com")
	require.NotEqual(t, bootstrapJobResourceName(t, first), bootstrapJobResourceName(t, second))
}

func TestExternalInstanceRejectsUnboundEnvironment(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	builder.ExternalInstances = map[string]ExternalInstance{"production": {
		Host:         "production.postgres.example.com",
		DatabaseName: "test",
	}}
	destination := t.TempDir()

	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(
		destination,
		networkMappings,
		promotablePostgresSecretReferences(),
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
	require.Contains(t, response.GetState().GetMessage(), `external-instances has no binding for deployment environment "test"`)
	require.NoDirExists(t, filepath.Join(destination, "base"))
}

func TestExternalIdentityExternalInstanceFailsBeforeRendering(t *testing.T) {
	builder, _ := newDeploymentTestBuilder(t)
	builder.AuthMode = authModeExternalIdentity
	builder.ExternalInstances = map[string]ExternalInstance{"test": {
		Host:         "managed.postgres.example.com",
		DatabaseName: "test",
	}}
	destination := t.TempDir()

	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(destination, nil, nil))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
	require.Contains(t, response.GetState().GetMessage(), "external-instance deployment does not support auth-mode")
	require.NoDirExists(t, filepath.Join(destination, "base"))
}

func TestExternalInstanceDeploymentRejectsContractDrift(t *testing.T) {
	tests := []struct {
		name     string
		binding  ExternalInstance
		expected string
	}{
		{
			name: "database name",
			binding: ExternalInstance{
				Host:                  "managed.postgres.example.com",
				DatabaseName:          "billing",
				RuntimeReadWriteRoles: []string{"app_tenant", "app_worker"},
			},
			expected: `external-instance database-name "billing" does not match declared database-name "accounts"`,
		},
		{
			name: "runtime roles",
			binding: ExternalInstance{
				Host:                  "managed.postgres.example.com",
				DatabaseName:          "accounts",
				RuntimeReadWriteRoles: []string{"app_worker", "app_tenant"},
			},
			expected: "external-instance runtime-read-write-roles [app_worker app_tenant] do not match declared runtime-read-write-roles [app_tenant app_worker]",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder, _ := newDeploymentTestBuilder(t)
			builder.DatabaseName = "accounts"
			builder.RuntimeReadWriteRoles = []string{"app_tenant", "app_worker"}
			builder.ExternalInstances = map[string]ExternalInstance{"test": test.binding}

			response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(
				t.TempDir(),
				nil,
				promotablePostgresSecretReferences(),
			))
			require.NoError(t, err)
			require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
			require.Contains(t, response.GetState().GetMessage(), test.expected)
		})
	}
}

// assertBootstrapJobDeadline pins the elapsed-time bound on the Job itself.
// backoffLimit counts failed pods and cannot stop a container that is still
// running, so it is not a substitute.
func assertBootstrapJobDeadline(t *testing.T, dir string, expected int) {
	t.Helper()
	content := readDeploymentFile(t, dir, "base", "job.yaml")
	var job struct {
		Spec struct {
			ActiveDeadlineSeconds *int `yaml:"activeDeadlineSeconds"`
			BackoffLimit          *int `yaml:"backoffLimit"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(content), &job); err != nil {
		t.Fatal(err)
	}
	if job.Spec.ActiveDeadlineSeconds == nil {
		t.Fatalf("bootstrap Job has no activeDeadlineSeconds:\n%s", content)
	}
	if *job.Spec.ActiveDeadlineSeconds != expected {
		t.Fatalf("activeDeadlineSeconds = %d, want %d", *job.Spec.ActiveDeadlineSeconds, expected)
	}
	if job.Spec.BackoffLimit == nil {
		t.Fatalf("bootstrap Job lost its backoffLimit:\n%s", content)
	}
}

func assertMigrationResource(t *testing.T, dir string, expected bool) {
	t.Helper()
	content := readDeploymentFile(t, dir, "base", "kustomization.yaml")
	if got := strings.Contains(content, "- job.yaml"); got != expected {
		t.Fatalf("migration resource present = %t, want %t:\n%s", got, expected, content)
	}
}

func TestPromotableGitOpsDeploymentReturnsReferenceOnlyConfigurationAndScopesSecrets(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	destination := t.TempDir()

	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(
		destination,
		networkMappings,
		promotablePostgresSecretReferences(),
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	output := response.GetDeployment().GetKubernetes()
	require.Equal(t, builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1, output.GetProfile())
	require.Equal(t, services.KubernetesManifestContractVersion, output.GetContractVersion())
	require.Equal(t, builderv0.KubernetesManifestValidation_STATUS_PASSED, output.GetValidation().GetStaticValidation())
	require.Equal(t, builderv0.KubernetesManifestValidation_STATUS_NOT_RUN, output.GetValidation().GetServerSideValidation())
	require.True(t, output.GetValidation().GetRestricted())

	configuration := response.GetConfiguration()
	require.Equal(t, builder.Unique(), configuration.GetOrigin())
	require.Equal(t, resources.RuntimeContextFree, configuration.GetRuntimeContext().GetKind())
	require.Len(t, configuration.GetInfos(), 1)
	require.Equal(t, "postgres", configuration.GetInfos()[0].GetName())
	values := configuration.GetInfos()[0].GetConfigurationValues()
	require.Len(t, values, 2)
	for _, key := range []string{readOnlyConnectionKey, readWriteConnectionKey} {
		var matched *basev0.ConfigurationValue
		for _, value := range values {
			if value.GetKey() == key {
				matched = value
				break
			}
		}
		require.NotNil(t, matched, "missing configuration value %q", key)
		require.True(t, matched.GetSecret(), "configuration value %q is not secret", key)
		require.Empty(t, matched.GetValue(), "configuration value %q leaked data", key)
	}
	for _, value := range values {
		require.NotEqual(t, ownerConnectionKey, value.GetKey())
	}

	baseKustomization := readDeploymentFile(t, destination, "base", "kustomization.yaml")
	require.NotContains(t, baseKustomization, "namespace.yaml")
	overlayKustomization := readDeploymentFile(t, destination, "overlays", "test", "kustomization.yaml")
	require.NotContains(t, overlayKustomization, "secret.yaml")
	requireNoDeploymentFile(t, destination, "base", "namespace.yaml")
	requireNoDeploymentFile(t, destination, "overlays", "test", "secret.yaml")

	statefulSet := readDeploymentFile(t, destination, "base", "stateful-set.yaml")
	for _, expected := range []string{
		image.FullName(),
		"name: PGDATA",
		"value: /var/lib/postgresql/data/pgdata",
		"name: POSTGRES_USER",
		"name: POSTGRES_PASSWORD",
		"name: POSTGRES_DB",
		`value: "test"`,
		"optional: false",
	} {
		require.Contains(t, statefulSet, expected)
	}
	for _, unexpected := range []string{
		"envFrom:",
		"subPath: pgdata",
		"name: POSTGRES_READ_ONLY_PASSWORD",
		"name: POSTGRES_READ_WRITE_PASSWORD",
		"name: " + migrationConnectionEnvironmentKey,
		"name: UNRELATED_SECRET",
	} {
		require.NotContains(t, statefulSet, unexpected)
	}
	require.Equal(t, 3, strings.Count(
		statefulSet,
		`command: ["/bin/sh", "-ec", "exec pg_isready -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\""]`,
	))

	job := readDeploymentFile(t, destination, "base", "job.yaml")
	for _, expected := range []string{
		"registry.example.com/module/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"name: POSTGRES_USER",
		"name: POSTGRES_READ_ONLY_PASSWORD",
		"name: POSTGRES_READ_WRITE_PASSWORD",
		"name: POSTGRES_DB",
		`value: "test"`,
		"name: CODEFLY_POSTGRES_OWNER_FROM_LIBPQ_ENVIRONMENT",
		"name: PGHOST",
		`value: "postgres.example.com"`,
		"name: PGPORT",
		`value: "5432"`,
		"name: PGDATABASE",
		"name: PGUSER",
		"name: PGPASSWORD",
		"optional: false",
	} {
		require.Contains(t, job, expected)
	}
	require.Equal(t, 2, strings.Count(job, "codefly.dev/bootstrap-service: postgres"))
	require.NotContains(t, job, "app: postgres")
	require.NotContains(t, job, "ttlSecondsAfterFinished")
	for _, unexpected := range []string{
		"envFrom:",
		"name: POSTGRES_PASSWORD",
		"name: UNRELATED_SECRET",
		// The owner connection string is assembled by nobody: the Job reads
		// the primitives the server is initialized with.
		"name: " + migrationConnectionEnvironmentKey,
		"key: " + migrationConnectionEnvironmentKey,
		// The server pins no sslmode unless without-ssl says so.
		"name: PGSSLMODE",
	} {
		require.NotContains(t, job, unexpected)
	}
	require.Regexp(t, `^postgres-[0-9a-f]{12}$`, bootstrapJobResourceName(t, job))
}

func TestPromotableBootstrapJobIdentityChangesWithImageDigest(t *testing.T) {
	render := func(digest string) string {
		t.Helper()
		builder, networkMappings := newDeploymentTestBuilder(t)
		destination := t.TempDir()
		request := promotableDeploymentRequest(destination, networkMappings, promotablePostgresSecretReferences())
		request.GetDeployment().GetKubernetes().BuildContext.ImageDigest = digest

		response, err := builder.Deploy(context.Background(), request)
		require.NoError(t, err)
		require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
		return readDeploymentFile(t, destination, "base", "job.yaml")
	}

	first := render("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	second := render("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	require.NotEqual(t, bootstrapJobResourceName(t, first), bootstrapJobResourceName(t, second))
}

func TestPromotableBootstrapJobIdentityChangesWithImmutablePodTemplate(t *testing.T) {
	render := func(configure func(*Builder, *builderv0.DeploymentRequest)) string {
		t.Helper()
		builder, networkMappings := newDeploymentTestBuilder(t)
		destination := t.TempDir()
		request := promotableDeploymentRequest(destination, networkMappings, promotablePostgresSecretReferences())
		if configure != nil {
			configure(builder, request)
		}
		response, err := builder.Deploy(context.Background(), request)
		require.NoError(t, err)
		require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
		return readDeploymentFile(t, destination, "base", "job.yaml")
	}

	baseline := bootstrapJobResourceName(t, render(nil))
	require.Equal(t, baseline, bootstrapJobResourceName(t, render(nil)))
	for name, configure := range map[string]func(*Builder, *builderv0.DeploymentRequest){
		"image repository": func(_ *Builder, request *builderv0.DeploymentRequest) {
			request.GetDeployment().GetKubernetes().BuildContext.DockerRepository = "mirror.example.com"
		},
		"Secret references": func(_ *Builder, request *builderv0.DeploymentRequest) {
			for _, reference := range request.GetDeployment().GetKubernetes().SecretReferences {
				if reference.GetName() == "postgres-secrets" {
					reference.Name = "renamed-postgres-secrets"
				}
			}
		},
		"database name": func(builder *Builder, _ *builderv0.DeploymentRequest) {
			builder.DatabaseName = "accounts"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := bootstrapJobResourceName(t, render(configure))
			require.NotEqual(t, baseline, changed)
		})
	}
}

func TestPromotableGitOpsDeploymentReportsExplicitValidationContext(t *testing.T) {
	useSuccessfulKubectl(t)
	builder, networkMappings := newDeploymentTestBuilder(t)
	request := promotableDeploymentRequest(
		t.TempDir(),
		networkMappings,
		promotablePostgresSecretReferences(),
	)
	kubernetes := request.GetDeployment().GetKubernetes()
	kubernetes.ValidateServerSide = true
	kubernetes.ValidationKubeconfig = "/tmp/codefly-test-kubeconfig"
	kubernetes.ValidationContext = "k3d-codefly-test"

	response, err := builder.Deploy(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	validation := response.GetDeployment().GetKubernetes().GetValidation()
	require.Equal(t, builderv0.KubernetesManifestValidation_STATUS_PASSED, validation.GetServerSideValidation())
	require.Equal(t, "k3d-codefly-test", validation.GetValidatedContext())
	require.True(t, validation.GetRestricted())
}

func TestPromotableGitOpsDeploymentRejectsMissingOrOptionalRequiredSecretReferences(t *testing.T) {
	required := []string{
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
		"POSTGRES_READ_ONLY_PASSWORD",
		"POSTGRES_READ_WRITE_PASSWORD",
	}
	for _, environmentVariable := range required {
		t.Run("missing/"+environmentVariable, func(t *testing.T) {
			builder, networkMappings := newDeploymentTestBuilder(t)
			references := promotablePostgresSecretReferences()
			configurationKey := resources.ServiceSecretConfigurationKeyFromUnique(
				builder.Unique(),
				"postgres",
				environmentVariable,
			)
			delete(references, configurationKey)

			response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(
				t.TempDir(),
				networkMappings,
				references,
			))
			require.NoError(t, err)
			require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
			require.Contains(t, response.GetState().GetMessage(), "requires a typed Kubernetes Secret reference for "+configurationKey)
			require.Nil(t, response.GetConfiguration())
		})

		t.Run("optional/"+environmentVariable, func(t *testing.T) {
			builder, networkMappings := newDeploymentTestBuilder(t)
			references := promotablePostgresSecretReferences()
			configurationKey := resources.ServiceSecretConfigurationKeyFromUnique(
				builder.Unique(),
				"postgres",
				environmentVariable,
			)
			references[configurationKey].Optional = true

			response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(
				t.TempDir(),
				networkMappings,
				references,
			))
			require.NoError(t, err)
			require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
			require.Contains(t, response.GetState().GetMessage(), configurationKey+" Kubernetes Secret reference must not be optional")
			require.Nil(t, response.GetConfiguration())
		})
	}
}

func TestPromotableExternalIdentityDeploymentPromotesNoCredentialSecrets(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	builder.AuthMode = authModeExternalIdentity
	destination := t.TempDir()

	// External-identity mode requires no configured Secret references at all.
	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(
		destination,
		networkMappings,
		nil,
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	values := response.GetConfiguration().GetInfos()[0].GetConfigurationValues()
	require.Len(t, values, 2)
	for _, value := range values {
		require.Contains(t, []string{readOnlyConnectionKey, readWriteConnectionKey}, value.GetKey())
		require.True(t, value.GetSecret())
		require.Empty(t, value.GetValue())
	}

	statefulSet := readDeploymentFile(t, destination, "base", "stateful-set.yaml")
	job := readDeploymentFile(t, destination, "base", "job.yaml")
	for _, manifest := range []string{statefulSet, job} {
		require.NotContains(t, manifest, "secretKeyRef")
		for _, credential := range []string{
			"POSTGRES_PASSWORD",
			"POSTGRES_READ_ONLY_PASSWORD",
			"POSTGRES_READ_WRITE_PASSWORD",
			migrationConnectionEnvironmentKey,
		} {
			require.NotContains(t, manifest, "name: "+credential)
		}
	}
	requireNoDeploymentFile(t, destination, "overlays", "test", "secret.yaml")
}

func TestPromotableDeploymentRejectsUnsupportedAuthMode(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	builder.AuthMode = "external-idenity" // typo

	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(
		t.TempDir(),
		networkMappings,
		promotablePostgresSecretReferences(),
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
	require.Contains(t, response.GetState().GetMessage(), `unsupported postgres auth mode "external-idenity"`)
	require.Nil(t, response.GetConfiguration())
}

func newDeploymentTestBuilder(t *testing.T) (*Builder, []*basev0.NetworkMapping) {
	t.Helper()
	ctx := context.Background()
	builder := NewBuilder()
	identity := &basev0.ServiceIdentity{
		Workspace: "workspace",
		Module:    "module",
		Name:      "postgres",
		Version:   "1.2.3",
	}
	require.NoError(t, builder.HeadlessLoad(ctx, identity))
	builder.Information = &services.Information{
		Service: resources.ToServiceWithCase(builder.Identity),
		Module:  resources.ToModuleWithCase(builder.Identity),
	}
	builder.EnvironmentVariables.SetIdentity(identity)
	builder.DatabaseName = "test"
	builder.TcpEndpoint = &basev0.Endpoint{
		Name:    "tcp",
		Module:  identity.Module,
		Service: identity.Name,
		Api:     "tcp",
	}
	instance := resources.NewNetworkInstance("postgres.example.com", 5432)
	instance.Access = resources.NewPublicNetworkAccess()
	return builder, []*basev0.NetworkMapping{{
		Endpoint:  builder.TcpEndpoint,
		Instances: []*basev0.NetworkInstance{instance},
	}}
}

func promotableDeploymentRequest(
	destination string,
	networkMappings []*basev0.NetworkMapping,
	secretReferences map[string]*builderv0.KubernetesSecretKeyReference,
) *builderv0.DeploymentRequest {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return &builderv0.DeploymentRequest{
		Environment:     &basev0.Environment{Name: "test"},
		NetworkMappings: networkMappings,
		Deployment: &builderv0.Deployment{
			Kind: &builderv0.Deployment_Kubernetes{
				Kubernetes: &builderv0.KubernetesDeployment{
					Namespace:        "codefly-test",
					Destination:      destination,
					BuildContext:     &builderv0.DockerBuildContext{DockerRepository: "registry.example.com", ImageDigest: digest},
					Profile:          builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1,
					SecretReferences: secretReferences,
				},
			},
		},
	}
}

func promotablePostgresSecretReferences() map[string]*builderv0.KubernetesSecretKeyReference {
	references := map[string]*builderv0.KubernetesSecretKeyReference{
		"UNRELATED_SECRET": {Name: "unrelated-secret", Key: "token"},
	}
	for _, environmentVariable := range []string{
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
		"POSTGRES_READ_ONLY_PASSWORD",
		"POSTGRES_READ_WRITE_PASSWORD",
		readOnlyConnectionKey,
		readWriteConnectionKey,
	} {
		configurationKey := resources.ServiceSecretConfigurationKeyFromUnique(
			"module/postgres",
			"postgres",
			environmentVariable,
		)
		references[configurationKey] = &builderv0.KubernetesSecretKeyReference{
			Name: "postgres-secrets",
			Key:  configurationKey,
		}
	}
	return references
}

func useSuccessfulKubectl(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	kubectl := filepath.Join(bin, "kubectl")
	require.NoError(t, os.WriteFile(kubectl, []byte("#!/bin/sh\ncat >/dev/null\n"), 0o755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func assertEphemeralSecret(t *testing.T, dir string) {
	t.Helper()
	require.Contains(t, readDeploymentFile(t, dir, "base", "kustomization.yaml"), "- namespace.yaml")
	require.Contains(t, readDeploymentFile(t, dir, "base", "namespace.yaml"), "kind: Namespace")
	require.Contains(t, readDeploymentFile(t, dir, "overlays", "test", "kustomization.yaml"), "- secret.yaml")
	secret := readDeploymentFile(t, dir, "overlays", "test", "secret.yaml")
	require.Contains(t, secret, "kind: Secret")
	require.Contains(t, secret, "CODEFLY_TEST_SECRET: c2VjcmV0")
}

func bootstrapJobResourceName(t *testing.T, manifest string) string {
	t.Helper()
	var job struct {
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(manifest), &job))
	require.NotEmpty(t, job.Metadata.Name)
	return job.Metadata.Name
}

func readDeploymentFile(t *testing.T, directory string, elements ...string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(append([]string{directory}, elements...)...))
	require.NoError(t, err)
	return string(content)
}

func requireNoDeploymentFile(t *testing.T, directory string, elements ...string) {
	t.Helper()
	_, err := os.Stat(filepath.Join(append([]string{directory}, elements...)...))
	require.ErrorIs(t, err, os.ErrNotExist)
}
