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
	scoped "github.com/codefly-dev/service-postgres/libs/go"
	migrationtest "github.com/codefly-dev/service-postgres/libs/go/migrationtest"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"testing"
	"time"
)

// TODO: Add tests
// - migrations: up/down

// TestCreateToRunDocker runs the full agent lifecycle against the explicitly
// selected container backend. Using free here would only test backend
// auto-selection and could silently fall back to Nix.
func TestCreateToRunDocker(t *testing.T) {
	testCreateToRun(t, resources.NewRuntimeContextContainer())
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
	// The reusable migration control plane is exercised against this actual
	// plugin instance, including isolated database lifecycle, runtime-access
	// reconciliation, physical cloning, and reversible transactional DDL.
	migrationControl, err := migrationtest.OpenControlPlane(ctx, runtime.connection)
	require.NoError(t, err)
	defer migrationControl.Close()
	isolate, err := migrationControl.Create(ctx, "service_postgres_migration_test")
	require.NoError(t, err)
	defer isolate.Drop(context.Background())
	isolateMigrations := []migrationtest.Migration{{
		Version: 1,
		Name:    "fixture",
		UpSQL:   `CREATE TABLE migration_control_fixture (id UUID PRIMARY KEY);`,
		DownSQL: `DROP TABLE migration_control_fixture;`,
	}}
	require.NoError(t, migrationtest.ApplyUp(ctx, isolate.DB, isolateMigrations))
	require.NoError(t, isolate.ReconcileRuntimeAccess(ctx, readOnlyConnection, readWriteConnection))
	require.NoError(t, isolate.Close())
	clone, err := migrationControl.Clone(ctx, isolate.Name, "service_postgres_migration_clone")
	require.NoError(t, err)
	defer clone.Drop(context.Background())
	var relationExists bool
	require.NoError(t, clone.DB.QueryRowContext(ctx, `SELECT to_regclass('public.migration_control_fixture') IS NOT NULL`).Scan(&relationExists))
	require.True(t, relationExists)
	require.NoError(t, migrationtest.ApplyDown(ctx, clone.DB, isolateMigrations))
	require.NoError(t, clone.DB.QueryRowContext(ctx, `SELECT to_regclass('public.migration_control_fixture') IS NOT NULL`).Scan(&relationExists))
	require.False(t, relationExists)
	// Migration ownership remains inside the plugin. A hot-reload migration is
	// rolled down and back up here without ever exporting the owner connection
	// to a dependent service.
	migrationRelation := serviceName + "_migration_replay"
	migrationDirectory := path.Join(tmpDir, "mod", service.Name, "migrations")
	migrationUp := path.Join(migrationDirectory, "2_replay.up.sql")
	migrationDown := path.Join(migrationDirectory, "2_replay.down.sql")
	quotedMigrationRelation := pq.QuoteIdentifier(migrationRelation)
	require.NoError(t, os.WriteFile(migrationUp, []byte("CREATE TABLE "+quotedMigrationRelation+" (id UUID PRIMARY KEY);"), 0o600))
	require.NoError(t, os.WriteFile(migrationDown, []byte("DROP TABLE IF EXISTS "+quotedMigrationRelation+";"), 0o600))
	require.NoError(t, runtime.updateMigration(ctx, migrationUp))
	exists, err := owner.RelationExists(ctx, migrationRelation)
	require.NoError(t, err)
	require.True(t, exists)
	replayFixtureID := "00000000-0000-0000-0000-000000000003"
	require.NoError(t, owner.AppendFixture(ctx, migrationRelation, replayFixtureID))
	require.NoError(t, runtime.updateMigration(ctx, migrationUp))
	exists, err = owner.RelationExists(ctx, migrationRelation)
	require.NoError(t, err)
	require.True(t, exists)
	found, err = owner.HasFixture(ctx, migrationRelation, replayFixtureID)
	require.NoError(t, err)
	require.False(t, found, "hot reload must execute down then up, rebuilding the migration-owned relation")
	require.NoError(t, runtime.ensureRuntimeAccess(ctx))
	found, err = reader.HasFixture(ctx, migrationRelation, replayFixtureID)
	require.NoError(t, err, "reader grants must be reconciled after migration replay")
	require.False(t, found)
	tenantRelation := serviceName + "_tenant_scope"
	require.NoError(t, owner.InstallTenantFixture(ctx, tenantRelation))

	// An omitted authenticated scope fails closed at RLS, even with a valid
	// runtime credential.
	unscoped, err := reader.HasFixture(ctx, tenantRelation, fixtureID)
	require.NoError(t, err)
	require.False(t, unscoped)
	require.Error(t, writer.AppendTenantFixture(ctx, tenantRelation, fixtureID, "unscoped"))

	workloadIssuer, err := scoped.NewWorkloadIssuer(contextAuthenticator{})
	require.NoError(t, err)
	repository, closeRepository, err := newScopedFixtureRepository(ctx, readOnlyConnection, readWriteConnection, tenantRelation, workloadIssuer)
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

	workloadA, err := workloadIssuer.Issue("tenant-a", "fixture-writer", true)
	require.NoError(t, err)
	workloadB, err := workloadIssuer.Issue("tenant-b", "fixture-reader", false)
	require.NoError(t, err)
	require.NoError(t, repository.Put(workloadA.Context(ctx), "workload-id", "tenant-a-workload"))
	value, found, err = repository.Get(workloadA.Context(ctx), "workload-id")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "tenant-a-workload", value)
	_, found, err = repository.Get(workloadB.Context(ctx), "workload-id")
	require.NoError(t, err)
	require.False(t, found, "tenant-b workload must not see tenant-a data")
	require.Error(t, repository.Put(workloadB.Context(ctx), "blocked", "value"), "read-only workload must not obtain a writer")
}
