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
	require.FileExists(t, filepath.Join(outputDirectory, "migrations", "1_create_table.up.sql"))
	require.FileExists(t, filepath.Join(outputDirectory, "migrations", "1_create_table.down.sql"))

	// The CLI resolves the recipe's "." context to the service directory, so the
	// runtime-access.sql the Dockerfile COPYs root-relative must sit at the service
	// directory root beside the committed migrations/ — otherwise the COPY the CLI
	// runs against that context fails to resolve.
	require.FileExists(t, filepath.Join(builder.Location, "runtime-access.sql"))

	// It is also rendered into the recipe tree (never under builder/) so the emitted
	// artifact stays a self-contained context a consumer can build directly.
	require.FileExists(t, filepath.Join(outputDirectory, "runtime-access.sql"))
	require.NoFileExists(t, filepath.Join(outputDirectory, "builder", "runtime-access.sql"))

	// The plan the agent emits verifies against the tree it wrote, so the CLI
	// builds it without the recipe drifting from the inventory.
	require.NoError(t, services.VerifyDockerBuildPlan(outputDirectory, plan))
}

// TestFactoryScaffoldsGitignoreForGeneratedRuntimeAccess covers the file the
// build writes into the service directory on every run: Create must scaffold a
// .gitignore that keeps the generated runtime-access.sql out of version control,
// so a consumer's `codefly build service` does not leave untracked noise beside
// the committed migrations/. This also guards the `all:` embed — a plain
// //go:embed drops the .gitignore dotfile and the render would silently produce
// nothing.
func TestFactoryScaffoldsGitignoreForGeneratedRuntimeAccess(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)

	require.NoError(t, builder.Templates(ctx,
		create{DatabaseName: "test", TableName: "postgres"},
		services.WithFactory(factoryFS)))

	data, err := os.ReadFile(filepath.Join(builder.Location, ".gitignore"))
	require.NoError(t, err, "Create must scaffold a .gitignore at the service root")
	require.Contains(t, string(data), "/runtime-access.sql")
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

// TestBuildRecipeLocksBootstrapInputs covers the recipe a consumer builds without
// the agent: the Dockerfile pins the base by digest and the recipe's typed build
// arguments record every resolved bootstrap identity, including the lock digest.
func TestBuildRecipeLocksBootstrapInputs(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	outputDirectory := t.TempDir()

	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	recipe := response.GetResult().GetDockerBuildPlan().GetRecipes()[0]
	require.Equal(t, bootstrapLock.RecipeBuildArgs(), recipe.GetBuildArgs())
	require.Equal(t, bootstrapLock.LockDigest, recipe.GetBuildArgs()["CODEFLY_BOOTSTRAP_LOCK_DIGEST"])

	dockerfile, err := os.ReadFile(filepath.Join(outputDirectory, "builder", "Dockerfile"))
	require.NoError(t, err)
	require.Contains(t, string(dockerfile), "FROM "+bootstrapLock.Base.Reference())
}

// TestBuildRecipeResolvesIdenticalInputsAcrossEmissions builds the recipe twice
// from independent builders and output directories: the resolved inputs, and the
// aggregate digest over the tree they produce, must not depend on the emitting run.
func TestBuildRecipeResolvesIdenticalInputsAcrossEmissions(t *testing.T) {
	ctx := context.Background()

	emit := func() (*builderv0.DockerBuildPlan, []byte) {
		builder := newBuildTestBuilder(t)
		outputDirectory := t.TempDir()
		response, err := builder.Build(ctx, buildRequest(outputDirectory))
		require.NoError(t, err)
		require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
		dockerfile, err := os.ReadFile(filepath.Join(outputDirectory, "builder", "Dockerfile"))
		require.NoError(t, err)
		return response.GetResult().GetDockerBuildPlan(), dockerfile
	}

	firstPlan, firstDockerfile := emit()
	secondPlan, secondDockerfile := emit()

	require.Equal(t, firstDockerfile, secondDockerfile)
	require.Equal(t, firstPlan.GetRecipes()[0].GetBuildArgs(), secondPlan.GetRecipes()[0].GetBuildArgs())
	require.NotEmpty(t, firstPlan.GetDigest())
	require.Equal(t, firstPlan.GetDigest(), secondPlan.GetDigest())
}
