package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/service-postgres/libs/go/bootstrap"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	testManagedInstance = "obin-test-data:us-east1:obin-test-shared"
	testOwner           = "obin-test-0a0a0a@obin-test-data.iam.gserviceaccount.com"
	testRuntime         = "obin-test-1b1b1b@obin-test-data.iam.gserviceaccount.com"
)

func managedServiceConfiguration(values map[string]string) *basev0.Configuration {
	information := &basev0.ConfigurationInformation{Name: managedServiceInformation}
	for key, value := range values {
		information.ConfigurationValues = append(information.ConfigurationValues, &basev0.ConfigurationValue{Key: key, Value: value})
	}
	return &basev0.Configuration{Infos: []*basev0.ConfigurationInformation{information}}
}

func completeManagedValues() map[string]string {
	return map[string]string{
		managedAuthModeKey: authModeExternalIdentity,
		managedInstanceKey: testManagedInstance,
		managedOwnerKey:    testOwner,
		managedRuntimeKey:  testRuntime,
	}
}

// inClusterServiceConfiguration is the environment's explicit statement that
// this store's server runs in the cluster.
func inClusterServiceConfiguration() *basev0.Configuration {
	return &basev0.Configuration{Infos: []*basev0.ConfigurationInformation{{Name: inClusterServiceInformation}}}
}

// The mode is explicit in both directions: an environment that says nothing
// about the store is refused by name, never answered with a server, and one
// that says both is refused too.
func TestAnEnvironmentDeclaresManagedOrInClusterAndNothingIsRefused(t *testing.T) {
	managed, err := storeDeploymentOf(inClusterServiceConfiguration(), "blue")
	require.NoError(t, err)
	require.Nil(t, managed)

	for name, configuration := range map[string]*basev0.Configuration{
		"nothing":            nil,
		"only own values":    {Infos: []*basev0.ConfigurationInformation{{Name: "postgres"}}},
		"a misspelled block": {Infos: []*basev0.ConfigurationInformation{{Name: "in-cluster-services"}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := storeDeploymentOf(configuration, "blue")
			require.ErrorContains(t, err, `environment "blue" declares nothing about this store`)
			require.ErrorContains(t, err, "declare it managed (a managed-services entry) or in-cluster (an in-cluster-services entry)")
		})
	}

	both := managedServiceConfiguration(completeManagedValues())
	both.Infos = append(both.Infos, inClusterServiceConfiguration().Infos...)
	_, err = storeDeploymentOf(both, "blue")
	require.ErrorContains(t, err, "both managed")
}

// Declared managed but incomplete is refused by name: never a fallback to a
// server in the cluster.
func TestManagedDeclarationMissingAValueIsRefused(t *testing.T) {
	for _, key := range []string{managedAuthModeKey, managedInstanceKey, managedOwnerKey, managedRuntimeKey} {
		for _, blank := range []string{"", "  "} {
			values := completeManagedValues()
			values[key] = blank
			_, err := storeDeploymentOf(managedServiceConfiguration(values), "test")
			require.ErrorContains(t, err, key)
			require.ErrorContains(t, err, "refused rather than deployed in the cluster")
		}
	}
	for name, mutate := range map[string]func(map[string]string){
		"password mode":           func(v map[string]string) { v[managedAuthModeKey] = "password" },
		"an address":              func(v map[string]string) { v[managedInstanceKey] = "10.87.0.7" },
		"an owner that is a user": func(v map[string]string) { v[managedOwnerKey] = "someone@example.com" },
		"the owner as runtime":    func(v map[string]string) { v[managedRuntimeKey] = testOwner },
		"a runtime login twice":   func(v map[string]string) { v[managedRuntimeKey] = testRuntime + "," + testRuntime },
	} {
		t.Run(name, func(t *testing.T) {
			values := completeManagedValues()
			mutate(values)
			_, err := storeDeploymentOf(managedServiceConfiguration(values), "test")
			require.Error(t, err)
		})
	}
	twice := managedServiceConfiguration(completeManagedValues())
	twice.Infos = append(twice.Infos, twice.Infos[0])
	_, err := storeDeploymentOf(twice, "test")
	require.ErrorContains(t, err, "twice")
}

// The structural half of the owner's rule: the managed template set contains
// the migration Job and nothing that could deploy Postgres.
func TestManagedTemplateSetCannotDeployPostgres(t *testing.T) {
	var files []string
	require.NoError(t, fs.WalkDir(managedDeploymentFS, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		files = append(files, path)
		content, readErr := fs.ReadFile(managedDeploymentFS, path)
		require.NoError(t, readErr)
		text := string(content)
		for _, forbidden := range []string{"kind: StatefulSet", "kind: PersistentVolumeClaim", "volumeClaimTemplates", "kind: Service\n", "kind: Secret", "secretKeyRef", "envFrom", "ManagedImage", "stateful-set", "service.yaml", "secret.yaml"} {
			require.NotContains(t, text, forbidden, "%s can deploy Postgres", path)
		}
		return nil
	}))
	require.ElementsMatch(t, []string{
		"templates/deployment/kustomize/base/job.yaml.tmpl",
		"templates/deployment/kustomize/base/kustomization.yaml.tmpl",
		"templates/deployment/kustomize/overlays/environment/kustomization.yaml.tmpl",
	}, files)
}

// managedTestBuilder is a builder with one migration, the store a managed
// render stages and binds.
func managedTestBuilder(t *testing.T) (*Builder, []*basev0.NetworkMapping) {
	t.Helper()
	builder, networkMappings := newDeploymentTestBuilder(t)
	builder.Location = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(builder.Location, "migrations"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(builder.Location, "migrations", "1_init.up.sql"), []byte("CREATE TABLE t(id int);\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(builder.Location, "migrations", "1_init.down.sql"), []byte("DROP TABLE t;\n"), 0o644))
	return builder, networkMappings
}

// managedJob is what the managed Job template renders, as a test reads it.
type managedJob struct {
	Spec struct {
		Template struct {
			Spec struct {
				ServiceAccountName string           `yaml:"serviceAccountName"`
				AutomountToken     *bool            `yaml:"automountServiceAccountToken"`
				Volumes            []map[string]any `yaml:"volumes"`
				Containers         []struct {
					Image   string           `yaml:"image"`
					Command []string         `yaml:"command"`
					EnvFrom []any            `yaml:"envFrom"`
					Env     []map[string]any `yaml:"env"`
				} `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type renderedServiceAccount struct {
	Metadata struct {
		Name        string            `yaml:"name"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
}

// renderedManagedObjects walks a managed render: every object kind it emits,
// its Job, and its ServiceAccount, refusing any file naming the server image.
func renderedManagedObjects(t *testing.T, destination string) (kinds []string, job managedJob, account renderedServiceAccount) {
	t.Helper()
	require.NoError(t, filepath.WalkDir(destination, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		content, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		decoder := yaml.NewDecoder(strings.NewReader(string(content)))
		for {
			var document map[string]any
			if decoder.Decode(&document) != nil {
				break
			}
			kind, _ := document["kind"].(string)
			if kind == "" || kind == "Kustomization" {
				continue
			}
			kinds = append(kinds, kind)
			switch kind {
			case "Job":
				require.NoError(t, yaml.Unmarshal(content, &job))
			case "ServiceAccount":
				require.NoError(t, yaml.Unmarshal(content, &account))
			}
		}
		require.NotContains(t, string(content), image.FullName(), "%s names the Postgres server image", path)
		return nil
	}))
	return kinds, job, account
}

// managedJobEnvironment is the managed Job's container environment, every
// entry of which must be a value.
func managedJobEnvironment(t *testing.T, job managedJob) map[string]string {
	t.Helper()
	containers := job.Spec.Template.Spec.Containers
	require.Len(t, containers, 1)
	require.Empty(t, containers[0].EnvFrom)
	env := map[string]string{}
	for _, entry := range containers[0].Env {
		require.NotContains(t, entry, "valueFrom", "every managed input is a value")
		env[entry["name"].(string)] = entry["value"].(string)
	}
	return env
}

// A managed Deploy, end to end: the manifest set is the migration Job and the
// ServiceAccount it runs as, bound to the owner principal — nothing that could
// deploy Postgres — running the managed runner from the migration image with
// every input a value, and dependents are handed the database and nothing else.
func TestManagedRenderIsTheMigrationJobAlone(t *testing.T) {
	builder, networkMappings := managedTestBuilder(t)
	destination := t.TempDir()
	request := promotableDeploymentRequest(destination, networkMappings, nil)
	request.Configuration = managedServiceConfiguration(completeManagedValues())

	response, err := builder.Deploy(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	kinds, job, account := renderedManagedObjects(t, destination)
	require.ElementsMatch(t, []string{"Job", "ServiceAccount"}, kinds, "a managed render emits the migration Job, the account it runs as, and nothing else")

	// The Job runs as the owner principal: its pod is bound to a ServiceAccount
	// annotated with it, and mounts no token (the cloud identity comes from the
	// node's metadata server).
	require.NotEmpty(t, account.Metadata.Name)
	require.Equal(t, account.Metadata.Name, job.Spec.Template.Spec.ServiceAccountName, "the Job is not bound to the ServiceAccount the render emits")
	require.Equal(t, testOwner, account.Metadata.Annotations[workloadIdentityAnnotation])
	require.NotNil(t, job.Spec.Template.Spec.AutomountToken)
	require.False(t, *job.Spec.Template.Spec.AutomountToken)

	containers := job.Spec.Template.Spec.Containers
	require.Equal(t, "/usr/local/bin/managed-bootstrap", containers[0].Command[0])
	env := managedJobEnvironment(t, job)
	require.Equal(t, testManagedInstance, env["CODEFLY_POSTGRES_CLOUD_SQL_INSTANCE"])
	require.Equal(t, "gcp-cloud-sql", env["CODEFLY_POSTGRES_EXTERNAL_IDENTITY"])
	var binding bootstrap.Binding
	require.NoError(t, bootstrap.ReadJSONValue(env["CODEFLY_POSTGRES_MANAGED_BINDING"], &binding))
	require.Equal(t, strings.TrimSuffix(testOwner, ".gserviceaccount.com"), binding.OwnerRole)
	require.Equal(t, []string{strings.TrimSuffix(testRuntime, ".gserviceaccount.com")}, binding.ReadWritePrincipals)
	require.Len(t, binding.PlanSHA256, 64)
	require.NotEmpty(t, binding.PlanDigest)
	for _, volume := range job.Spec.Template.Spec.Volumes {
		require.Contains(t, volume, "emptyDir", "the only volume is scratch: nothing mounts configuration or credentials")
	}

	handed := map[string]string{}
	for _, information := range response.GetConfiguration().GetInfos() {
		for _, value := range information.GetConfigurationValues() {
			handed[value.GetKey()] = value.GetValue()
		}
	}
	require.Equal(t, "postgres:///test", handed[readWriteConnectionKey])
	require.Equal(t, "postgres:///test", handed[readOnlyConnectionKey])
}

// The binding names the plan the image carries: the same bytes Build stages.
func TestManagedBindingNamesThePlanBuildStages(t *testing.T) {
	builder, _ := newDeploymentTestBuilder(t)
	builder.Location = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(builder.Location, "migrations"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(builder.Location, "migrations", "1_init.up.sql"), []byte("CREATE TABLE t(id int);\n"), 0o644))
	encoded, err := builder.managedBinding(&managedDeployment{Instance: testManagedInstance, OwnerLogin: "o", RuntimeLogins: []string{"w"}})
	require.NoError(t, err)
	var binding bootstrap.Binding
	require.NoError(t, json.Unmarshal([]byte(encoded), &binding))

	prerequisites, err := builder.resolveSchemaPrerequisites()
	require.NoError(t, err)
	plan, err := buildSchemaPlan(prerequisites, builder.Settings)
	require.NoError(t, err)
	require.NoError(t, plan.attest())
	staged := t.TempDir()
	require.NoError(t, builder.stageBootstrapContext(context.Background(), plan, DockerTemplating{}, staged))
	stagedPlan, err := os.ReadFile(filepath.Join(staged, bootstrapDirectory, "plan.json"))
	require.NoError(t, err)
	digest := sha256.Sum256(stagedPlan)
	require.Equal(t, hex.EncodeToString(digest[:]), binding.PlanSHA256, "the managed Job's binding does not name the plan the image stages")
	require.Equal(t, plan.artifact().Digest, binding.PlanDigest)
}

// A refused declaration refuses through Deploy, and writes nothing: no file
// reaches the destination that a later apply could pick up.
func TestARefusedDeclarationWritesNothingThroughDeploy(t *testing.T) {
	for name, configuration := range map[string]*basev0.Configuration{
		"nothing declared": nil,
		"a managed store missing its instance": managedServiceConfiguration(map[string]string{
			managedAuthModeKey: authModeExternalIdentity, managedOwnerKey: testOwner, managedRuntimeKey: testRuntime,
		}),
	} {
		t.Run(name, func(t *testing.T) {
			builder, networkMappings := managedTestBuilder(t)
			destination := t.TempDir()
			request := promotableDeploymentRequest(destination, networkMappings, nil)
			request.Configuration = configuration

			response, err := builder.Deploy(context.Background(), request)
			require.NoError(t, err)
			require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
			require.Contains(t, response.GetState().GetMessage(), "store")
			entries, readErr := os.ReadDir(destination)
			require.NoError(t, readErr)
			require.Empty(t, entries, "a refused render wrote into its destination")
		})
	}
}

// The cross-module proof that the render and the runner agree: the binding the
// Job carries, run by the runner against the bootstrap tree the image stages,
// is accepted — the runner's refusal comes from the connector it then starts,
// never from the binding. Without this, Deploy can emit a binding the runner
// refuses before it connects (as it did: an empty reader list), and every Job
// exits 1 with nothing in this repo's tests saying so.
func TestEmittedManagedBindingIsAcceptedByTheRunner(t *testing.T) {
	builder, networkMappings := managedTestBuilder(t)
	destination := t.TempDir()
	request := promotableDeploymentRequest(destination, networkMappings, nil)
	request.Configuration = managedServiceConfiguration(completeManagedValues())
	response, err := builder.Deploy(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	_, job, _ := renderedManagedObjects(t, destination)
	env := managedJobEnvironment(t, job)
	var binding bootstrap.Binding
	require.NoError(t, bootstrap.ReadJSONValue(env["CODEFLY_POSTGRES_MANAGED_BINDING"], &binding))
	require.Empty(t, binding.ReadOnlyPrincipals, "the declaration names no reader, so the binding carries none")

	// The tree the image carries at /app/bootstrap, staged the way Build does.
	prerequisites, err := builder.resolveSchemaPrerequisites()
	require.NoError(t, err)
	plan, err := buildSchemaPlan(prerequisites, builder.Settings)
	require.NoError(t, err)
	require.NoError(t, plan.attest())
	staged := t.TempDir()
	require.NoError(t, builder.stageBootstrapContext(context.Background(), plan, DockerTemplating{}, staged))
	migrate := filepath.Join(t.TempDir(), "migrate")
	require.NoError(t, os.WriteFile(migrate, []byte("#!/bin/sh\nexit 1\n"), 0o755))
	// No cloud credential here: the connector must fail to start, which is the
	// first thing the runner does after it has accepted the binding.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent.json"))

	_, err = bootstrap.Run(context.Background(), bootstrap.Options{
		Directory:         filepath.Join(staged, bootstrapDirectory),
		Binding:           binding,
		MigrateExecutable: migrate,
		Timeout:           time.Minute,
		LockTimeout:       time.Second,
		StatementTimeout:  time.Second,
		ExternalIdentity:  env["CODEFLY_POSTGRES_EXTERNAL_IDENTITY"],
		CloudSQLInstance:  env["CODEFLY_POSTGRES_CLOUD_SQL_INSTANCE"],
	})
	require.ErrorContains(t, err, "managed bootstrap connector:", "the runner stopped before the connector: it refused what the render emitted")
}
