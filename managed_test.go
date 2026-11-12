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

func TestAbsentManagedDeclarationIsTheInClusterStore(t *testing.T) {
	managed, err := managedDeploymentOf(&basev0.Configuration{Infos: []*basev0.ConfigurationInformation{{Name: "postgres"}}})
	require.NoError(t, err)
	require.Nil(t, managed)
}

// Declared managed but incomplete is refused by name: never a fallback to a
// server in the cluster.
func TestManagedDeclarationMissingAValueIsRefused(t *testing.T) {
	for _, key := range []string{managedAuthModeKey, managedInstanceKey, managedOwnerKey, managedRuntimeKey} {
		for _, blank := range []string{"", "  "} {
			values := completeManagedValues()
			values[key] = blank
			_, err := managedDeploymentOf(managedServiceConfiguration(values))
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
			_, err := managedDeploymentOf(managedServiceConfiguration(values))
			require.Error(t, err)
		})
	}
	twice := managedServiceConfiguration(completeManagedValues())
	twice.Infos = append(twice.Infos, twice.Infos[0])
	_, err := managedDeploymentOf(twice)
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

// A managed Deploy, end to end: the manifest set is the migration Job alone,
// running the managed runner from the migration image with every input a
// value, and dependents are handed the database and nothing else.
func TestManagedRenderIsTheMigrationJobAlone(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	builder.Location = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(builder.Location, "migrations"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(builder.Location, "migrations", "1_init.up.sql"), []byte("CREATE TABLE t(id int);\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(builder.Location, "migrations", "1_init.down.sql"), []byte("DROP TABLE t;\n"), 0o644))
	destination := t.TempDir()
	request := promotableDeploymentRequest(destination, networkMappings, nil)
	request.Configuration = managedServiceConfiguration(completeManagedValues())

	response, err := builder.Deploy(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	var kinds []string
	var job struct {
		Spec struct {
			Template struct {
				Spec struct {
					Volumes    []map[string]any `yaml:"volumes"`
					Containers []struct {
						Image   string           `yaml:"image"`
						Command []string         `yaml:"command"`
						EnvFrom []any            `yaml:"envFrom"`
						Env     []map[string]any `yaml:"env"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
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
			if kind == "Job" {
				require.NoError(t, yaml.Unmarshal(content, &job))
			}
		}
		require.NotContains(t, string(content), image.FullName(), "%s names the Postgres server image", path)
		return nil
	}))
	require.Equal(t, []string{"Job"}, kinds, "a managed render emits the migration Job and nothing else")

	containers := job.Spec.Template.Spec.Containers
	require.Len(t, containers, 1)
	require.Equal(t, "/usr/local/bin/managed-bootstrap", containers[0].Command[0])
	require.Empty(t, containers[0].EnvFrom)
	env := map[string]string{}
	for _, entry := range containers[0].Env {
		require.NotContains(t, entry, "valueFrom", "every managed input is a value")
		env[entry["name"].(string)] = entry["value"].(string)
	}
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
