package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/codefly-dev/core/agents/services"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/stretchr/testify/require"
)

// newBuildTestBuilder loads a builder whose Location points at a temporary
// service directory seeded with a migrations tree, so Build can render its
// recipe against a real filesystem.
func newBuildTestBuilder(t *testing.T) *Builder {
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
	builder.DatabaseName = "test"

	location := t.TempDir()
	builder.Location = location
	require.NoError(t, os.MkdirAll(filepath.Join(location, "migrations"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(location, "migrations", "1_create_table.up.sql"),
		[]byte("CREATE TABLE example ();\n"), 0o644))
	require.NoError(t, os.WriteFile(
		filepath.Join(location, "migrations", "1_create_table.down.sql"),
		[]byte("DROP TABLE example;\n"), 0o644))
	return builder
}

func buildRequest(outputDirectory string) *builderv0.BuildRequest {
	return &builderv0.BuildRequest{
		BuildContext: &builderv0.BuildContext{
			Kind: &builderv0.BuildContext_DockerBuildContext{
				DockerBuildContext: &builderv0.DockerBuildContext{DockerRepository: "registry.example.com"},
			},
		},
		OutputDirectory: outputDirectory,
	}
}

func TestBuildEmitsRecipeToOutputDirectory(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	outputDirectory := t.TempDir()

	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	plan := response.GetResult().GetDockerBuildPlan()
	require.NotNil(t, plan, "recipe build must return a DockerBuildPlan, not a legacy DockerBuildResult")
	require.Equal(t, services.DockerBuildRecipeContractVersion, plan.GetContractVersion())

	require.Len(t, plan.GetRecipes(), 1)
	recipe := plan.GetRecipes()[0]
	require.Equal(t, "builder/Dockerfile", recipe.GetDockerfile())
	require.Equal(t, ".", recipe.GetContext())
	require.Equal(t, "registry.example.com/module/postgres", recipe.GetImage())
	require.Equal(t, []string{"linux/amd64", "linux/arm64"}, recipe.GetPlatforms())

	// The rendered tree is a self-contained context: a consumer with no codefly
	// toolchain can build it from the emitted files alone.
	require.FileExists(t, filepath.Join(outputDirectory, "builder", "Dockerfile"))
	require.FileExists(t, filepath.Join(outputDirectory, "builder", "runtime-access.sql"))
	require.FileExists(t, filepath.Join(outputDirectory, "migrations", "1_create_table.up.sql"))
	require.FileExists(t, filepath.Join(outputDirectory, "migrations", "1_create_table.down.sql"))

	// The plan the agent emits verifies against the tree it wrote, so the CLI
	// builds it without the recipe drifting from the inventory.
	require.NoError(t, services.VerifyDockerBuildPlan(outputDirectory, plan))
}

func TestBuildRecipeOmitsMigrationsWhenDisabled(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	builder.Settings.NoMigration = true
	outputDirectory := t.TempDir()

	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	require.NoDirExists(t, filepath.Join(outputDirectory, "migrations"))
	require.NotNil(t, response.GetResult().GetDockerBuildPlan())
	require.NoError(t, services.VerifyDockerBuildPlan(outputDirectory, response.GetResult().GetDockerBuildPlan()))
}

// TestBuildRecipePurgesPreexistingOutputDirectory covers a caller that reuses or
// pre-populates the output directory: stale and foreign content must not survive
// into the emitted tree, the plan inventory, or (via COPY .) the image.
func TestBuildRecipePurgesPreexistingOutputDirectory(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	outputDirectory := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(outputDirectory, "migrations"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(outputDirectory, "migrations", "9_stale.up.sql"),
		[]byte("SELECT 'stale';\n"), 0o644))
	require.NoError(t, os.WriteFile(
		filepath.Join(outputDirectory, "stale-root.txt"),
		[]byte("foreign\n"), 0o644))

	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	require.NoFileExists(t, filepath.Join(outputDirectory, "stale-root.txt"))
	require.NoFileExists(t, filepath.Join(outputDirectory, "migrations", "9_stale.up.sql"))
	require.FileExists(t, filepath.Join(outputDirectory, "migrations", "1_create_table.up.sql"))

	plan := response.GetResult().GetDockerBuildPlan()
	require.NotNil(t, plan)
	for _, file := range plan.GetFiles() {
		require.NotContains(t, file.GetPath(), "stale", "stale content leaked into the plan inventory")
	}
	require.NoError(t, services.VerifyDockerBuildPlan(outputDirectory, plan))
}

// TestBuildRecipeCreatesEmptyMigrationsDirectory covers migrations enabled with
// none authored yet: the recipe must still carry a migrations directory so the
// Dockerfile's COPY migrations resolves, matching the legacy in-agent build.
func TestBuildRecipeCreatesEmptyMigrationsDirectory(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	require.NoError(t, os.RemoveAll(builder.Local("migrations")))
	require.NoError(t, os.MkdirAll(builder.Local("migrations"), 0o755))
	outputDirectory := t.TempDir()

	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	require.DirExists(t, filepath.Join(outputDirectory, "migrations"))
	require.NoError(t, services.VerifyDockerBuildPlan(outputDirectory, response.GetResult().GetDockerBuildPlan()))
}
