package main

import (
	"context"
	"fmt"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/network"
	"github.com/codefly-dev/core/resources"
	runners "github.com/codefly-dev/core/runners/base"
	"github.com/codefly-dev/core/shared"
	"github.com/codefly-dev/core/wool"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"testing"
	"time"
)

// TODO: Add tests
// - migrations: up/down

// TestCreateToRunDocker runs the full agent lifecycle against the Docker
// runtime (the default container backend).
func TestCreateToRunDocker(t *testing.T) {
	testCreateToRun(t, resources.NewRuntimeContextFree())
}

// TestCreateToRunNix runs the SAME full lifecycle against the nix runtime —
// the third backend in the native/docker/nix matrix. Requires nix.
func TestCreateToRunNix(t *testing.T) {
	if !runners.CheckNixInstalled() || !runners.IsNixSupported() {
		t.Skip("nix not installed/supported on this host")
	}
	testCreateToRun(t, resources.NewRuntimeContextNix())
}

// testCreateToRun drives Load → Init → Start → connect → SELECT 1 for one
// runtime context, so docker and nix exercise the identical agent path.
func testCreateToRun(t *testing.T, runtimeContext *basev0.RuntimeContext) {
	wool.SetGlobalLogLevel(wool.DEBUG)
	ctx := context.Background()

	workspace := &resources.Workspace{Name: "test"}

	tmpDir := t.TempDir()
	defer func(path string) {
		err := os.RemoveAll(path)
		require.NoError(t, err)
	}(tmpDir)

	serviceName := fmt.Sprintf("svc-%v", time.Now().UnixMilli())
	service := resources.Service{Name: serviceName, Version: "test-me"}
	err := service.SaveAtDir(ctx, path.Join(tmpDir, "mod", service.Name))

	require.NoError(t, err)

	identity := &basev0.ServiceIdentity{
		Name:                service.Name,
		Module:              "mod",
		Workspace:           workspace.Name,
		WorkspacePath:       tmpDir,
		RelativeToWorkspace: fmt.Sprintf("mod/%s", service.Name),
	}
	builder := NewBuilder()

	resp, err := builder.Load(ctx, &builderv0.LoadRequest{DisableCatch: true, Identity: identity, CreationMode: &builderv0.CreationMode{Communicate: false}})
	require.NoError(t, err)
	require.NotNil(t, resp)

	_, err = builder.Create(ctx, &builderv0.CreateRequest{})
	require.NoError(t, err)

	// Now run it
	runtime := NewRuntime()

	// Create temporary network mappings
	networkManager, err := network.NewRuntimeManager(ctx, nil)
	require.NoError(t, err)
	networkManager.WithTemporaryPorts()

	env := resources.LocalEnvironment()

	_, err = runtime.Load(ctx, &runtimev0.LoadRequest{
		Identity:     identity,
		Environment:  shared.Must(env.Proto()),
		DisableCatch: true})
	require.NoError(t, err)

	require.Equal(t, 1, len(runtime.Endpoints))

	networkMappings, err := networkManager.GenerateNetworkMappings(ctx, env, workspace, runtime.Identity, runtime.Endpoints)
	require.NoError(t, err)
	require.Equal(t, 1, len(networkMappings))

	// Configurations are passed in
	conf := &basev0.Configuration{
		Origin:         fmt.Sprintf("mod/%s", service.Name),
		RuntimeContext: resources.NewRuntimeContextFree(),
		Infos: []*basev0.ConfigurationInformation{
			{Name: "postgres",
				ConfigurationValues: []*basev0.ConfigurationValue{
					{Key: "POSTGRES_USER", Value: "postgres"},
					{Key: "POSTGRES_PASSWORD", Value: "owner-password"},
					{Key: "POSTGRES_READ_ONLY_PASSWORD", Value: "read-only-password"},
					{Key: "POSTGRES_READ_WRITE_PASSWORD", Value: "read-write-password"},
				},
			},
		},
	}

	init, err := runtime.Init(ctx, &runtimev0.InitRequest{
		RuntimeContext:          runtimeContext,
		Configuration:           conf,
		ProposedNetworkMappings: networkMappings,
	})
	require.NoError(t, err)
	require.NotNil(t, init)

	defer func() {
		_, err = runtime.Destroy(ctx, &runtimev0.DestroyRequest{})
	}()

	// Extract logs

	_, err = runtime.Start(ctx, &runtimev0.StartRequest{})
	require.NoError(t, err)

	// Get the configuration and connect to postgres
	configurationOut, err := resources.ExtractConfiguration(init.RuntimeConfigurations, resources.NewRuntimeContextNative())
	require.NoError(t, err)

	readOnlyConnection, err := resources.GetConfigurationValue(ctx, configurationOut, "postgres", readOnlyConnectionKey)
	require.NoError(t, err)
	readWriteConnection, err := resources.GetConfigurationValue(ctx, configurationOut, "postgres", readWriteConnectionKey)
	require.NoError(t, err)

	reader, err := openPostgresCapabilityProbe(ctx, readOnlyConnection)
	require.NoError(t, err)
	defer reader.Close()
	writer, err := openPostgresCapabilityProbe(ctx, readWriteConnection)
	require.NoError(t, err)
	defer writer.Close()

	fixtureID := "00000000-0000-0000-0000-000000000001"
	require.NoError(t, writer.AppendFixture(ctx, serviceName, fixtureID), "writer must mutate migrated application relations")
	found, err := reader.HasFixture(ctx, serviceName, fixtureID)
	require.NoError(t, err, "reader must query migrated application relations")
	require.True(t, found)
	require.Error(t, reader.AppendFixture(ctx, serviceName, "00000000-0000-0000-0000-000000000002"), "reader must not mutate data")
	require.Error(t, reader.CreateRelation(ctx, "reader_escape"), "reader must not create schema objects")
	require.Error(t, writer.CreateRelation(ctx, "writer_escape"), "writer must not create schema objects")
	require.Error(t, writer.CreateLoginRole(ctx, "writer_escape_role"), "writer must not create roles")
	require.Error(t, writer.AssumeRole(ctx, "postgres"), "writer must not assume the migration owner")

	owner, err := openPostgresCapabilityProbe(ctx, runtime.connection)
	require.NoError(t, err)
	defer owner.Close()
	tenantRelation := serviceName + "_tenant_scope"
	require.NoError(t, owner.InstallTenantFixture(ctx, tenantRelation))

	// An omitted authenticated scope fails closed at RLS, even with a valid
	// runtime credential.
	unscoped, err := reader.HasFixture(ctx, tenantRelation, fixtureID)
	require.NoError(t, err)
	require.False(t, unscoped)
	require.Error(t, writer.AppendTenantFixture(ctx, tenantRelation, fixtureID, "unscoped"))

	repository, closeRepository, err := newScopedFixtureRepository(ctx, readOnlyConnection, readWriteConnection, tenantRelation)
	require.NoError(t, err)
	defer closeRepository()
	tenantA := contextWithDatabasePrincipal(ctx, "tenant-a", "user-a")
	tenantB := contextWithDatabasePrincipal(ctx, "tenant-b", "user-b")
	require.NoError(t, repository.Put(tenantA, "shared-id", "tenant-a-value"))
	require.NoError(t, repository.Put(tenantB, "shared-id", "tenant-b-value"))
	value, found, err := repository.Get(tenantA, "shared-id")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "tenant-a-value", value)
	value, found, err = repository.Get(tenantB, "shared-id")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "tenant-b-value", value)
	_, _, err = repository.Get(ctx, "shared-id")
	require.Error(t, err, "repository access without an authenticated principal must fail before querying")
}
