package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/codefly-dev/core/agents/services"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/wool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

// TestBuildRejectsUnresolvableSchemaDeclaration proves the build fails on a
// declaration the runtime would also reject, rather than emitting a bootstrap
// image that quietly omits the declared schema.
func TestBuildRejectsUnresolvableSchemaDeclaration(t *testing.T) {
	ctx := context.Background()
	for name, declared := range map[string][]MigrationSource{
		"missing directory": {{Name: "api", Path: "../nowhere/migrations"}},
		"duplicate lineage": {{Name: "api"}, {Name: "api", Path: "../other/migrations"}},
	} {
		t.Run(name, func(t *testing.T) {
			builder := newBuildTestBuilder(t)
			builder.Settings.MigrationSources = declared

			response, err := builder.Build(ctx, buildRequest(t.TempDir()))
			require.NoError(t, err)
			require.Equal(t, builderv0.BuildStatus_ERROR, response.GetState().GetState(),
				"a declaration the runtime rejects must fail the build")
		})
	}
}

// TestBuildDoesNotClaimSchemaItDoesNotPackage locks the other half: the build
// validates declared sources but packages only this service's own migrations,
// so reporting the resolved plan here would tell an operator the bootstrap
// TestBuildPackagesTheSchemaItReports inverts a constraint this build used to
// carry: it packaged only the service's own migrations, so reporting a resolved
// plan would have claimed image content that did not exist. The build now stages
// every resolved source, so the report is truthful — and the assertion is that
// the sibling's migration is actually in the tree, not merely mentioned.
func TestBuildPackagesTheSchemaItReports(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	sibling := filepath.Join(filepath.Dir(builder.Location), "api", "migrations")
	require.NoError(t, os.MkdirAll(sibling, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sibling, "1_init.up.sql"), []byte("SELECT 1;"), 0o600))
	builder.Settings.MigrationSources = []MigrationSource{{Name: "api", Path: sibling}}

	sink := &capturingLogger{}
	builder.Wool.WithLogger(sink)
	// The run plan is reported at DEBUG; without this the assertion would pass
	// against a line the level filter dropped rather than one never emitted.
	builder.Wool.WithLoglevel(wool.DEBUG)

	outputDirectory := t.TempDir()
	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	require.True(t, sink.saw("schema prerequisites resolved"),
		"the build no longer reports what it resolved")
	require.FileExists(t, filepath.Join(outputDirectory, "bootstrap", "sources", "01-api", "1_init.up.sql"),
		"the build reported a declared source it did not package")
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
	require.FileExists(t, filepath.Join(outputDirectory, "bootstrap", "bootstrap.sh"))
	require.FileExists(t, filepath.Join(outputDirectory, "bootstrap", "extensions.sql"))
	require.FileExists(t, filepath.Join(outputDirectory, "bootstrap", "plan.json"))
	require.FileExists(t, filepath.Join(outputDirectory, "bootstrap", "sources.sha256"))
	require.Equal(t, "bootstrap/dockerignore", recipe.GetDockerignore(),
		"the build context is the service directory, so the recipe must declare an ignore that keeps local secrets out of it")
	require.FileExists(t, filepath.Join(outputDirectory, "bootstrap", "sources", "00-store", "1_create_table.up.sql"))
	require.FileExists(t, filepath.Join(outputDirectory, "bootstrap", "sources", "00-store", "1_create_table.down.sql"))

	// The CLI resolves the recipe's "." context to the service directory, so
	// everything the Dockerfile COPYs root-relative must also sit at the service
	// directory root — otherwise the COPY the CLI runs fails to resolve.
	require.FileExists(t, filepath.Join(builder.Location, "runtime-access.sql"))
	require.FileExists(t, filepath.Join(builder.Location, "bootstrap", "bootstrap.sh"))
	require.FileExists(t, filepath.Join(builder.Location, "bootstrap", "sources", "00-store", "1_create_table.up.sql"))

	// runtime-access.sql is also rendered into the recipe tree (never under
	// builder/) so the emitted artifact stays a self-contained context.
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
	require.Contains(t, string(data), "/bootstrap.sql")
}

func TestBuildRecipeOmitsMigrationsWhenDisabled(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	builder.Settings.NoMigration = true
	outputDirectory := t.TempDir()

	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	// Extension-only bootstrap: the artifact is still emitted and the image
	// still reconciles runtime grants, but no lineage is staged or applied.
	require.NoDirExists(t, filepath.Join(outputDirectory, "bootstrap", "sources"))
	require.FileExists(t, filepath.Join(outputDirectory, "bootstrap", "extensions.sql"))
	require.FileExists(t, filepath.Join(outputDirectory, "runtime-access.sql"))
	program, err := os.ReadFile(filepath.Join(outputDirectory, "bootstrap", "bootstrap.sh"))
	require.NoError(t, err)
	require.NotContains(t, readRendered(t, outputDirectory, "bootstrap.sql"), "/usr/local/bin/migrate")
	require.Contains(t, string(program), "/app/bootstrap.sql")

	require.Empty(t, readPlanArtifact(t, outputDirectory).Lineages)

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
	require.FileExists(t, filepath.Join(outputDirectory, "bootstrap", "sources", "00-store", "1_create_table.up.sql"))

	plan := response.GetResult().GetDockerBuildPlan()
	require.NotNil(t, plan)
	for _, file := range plan.GetFiles() {
		require.NotContains(t, file.GetPath(), "stale", "stale content leaked into the plan inventory")
	}
	require.NoError(t, services.VerifyDockerBuildPlan(outputDirectory, plan))
}

// TestBuildRecipeTreatsOwnSourceAbsenceAndEmptinessAlike covers the two ways a
// service can carry no own migrations. Both must bootstrap identically, and
// neither may emit a migrate invocation: golang-migrate reports an empty source
// as a missing first version, not as "no change", so applying one would fail the
// bootstrap Job.
func TestBuildRecipeTreatsOwnSourceAbsenceAndEmptinessAlike(t *testing.T) {
	ctx := context.Background()
	programs := map[string]string{}
	for name, prepare := range map[string]func(*Builder){
		"absent": func(builder *Builder) {
			require.NoError(t, os.RemoveAll(builder.Local("migrations")))
		},
		"empty": func(builder *Builder) {
			require.NoError(t, os.RemoveAll(builder.Local("migrations")))
			require.NoError(t, os.MkdirAll(builder.Local("migrations"), 0o755))
		},
	} {
		builder := newBuildTestBuilder(t)
		prepare(builder)
		outputDirectory := t.TempDir()

		response, err := builder.Build(ctx, buildRequest(outputDirectory))
		require.NoError(t, err)
		require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

		program, err := os.ReadFile(filepath.Join(outputDirectory, "bootstrap", "bootstrap.sh"))
		require.NoError(t, err)
		require.NotContains(t, readRendered(t, outputDirectory, "bootstrap.sql"), "/usr/local/bin/migrate", name)
		require.Contains(t, string(program), "/app/bootstrap.sql", name)
		require.NoError(t, services.VerifyDockerBuildPlan(outputDirectory, response.GetResult().GetDockerBuildPlan()))
		require.Empty(t, readPlanArtifact(t, outputDirectory).Lineages, name)
		programs[name] = string(program)
	}
	require.Equal(t, programs["absent"], programs["empty"],
		"an absent and an empty own migrations directory must bootstrap identically")
}

// TestBuildStagesSiblingSourcesIntoTheBuildContext is the packaging half of the
// local multi-source contract: a service whose tables come from sibling
// directories must ship those bytes, since a Dockerfile COPY cannot reach
// outside its context.
func TestBuildStagesSiblingSourcesIntoTheBuildContext(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	writeMigration(t, filepath.Join(filepath.Dir(builder.Location), "api", "migrations"), "1_api.up.sql")
	writeMigration(t, filepath.Join(filepath.Dir(builder.Location), "billing", "migrations"), "1_billing.up.sql")
	builder.Settings.MigrationSources = []MigrationSource{{Name: "api"}, {Name: "billing"}}
	outputDirectory := t.TempDir()

	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	for _, contextRoot := range []string{builder.Location, outputDirectory} {
		require.FileExists(t, filepath.Join(contextRoot, "bootstrap", "sources", "00-store", "1_create_table.up.sql"))
		require.FileExists(t, filepath.Join(contextRoot, "bootstrap", "sources", "01-api", "1_api.up.sql"))
		require.FileExists(t, filepath.Join(contextRoot, "bootstrap", "sources", "02-billing", "1_billing.up.sql"))
	}

	// The migrate invocations live in the locked psql session, one per lineage.
	bootstrapSQL := readRendered(t, outputDirectory, "bootstrap.sql")
	require.Contains(t, bootstrapSQL, `-path /app/bootstrap/sources/01-api`)
	require.Contains(t, bootstrapSQL, `x-migrations-table=schema_migrations_api`)
	require.Contains(t, bootstrapSQL, `-path /app/bootstrap/sources/02-billing`)
	require.Contains(t, bootstrapSQL, `x-migrations-table=schema_migrations_billing`)

	artifact := readPlanArtifact(t, outputDirectory)
	require.Len(t, artifact.Lineages, 3)
	require.Equal(t,
		[]string{"schema_migrations", "schema_migrations_api", "schema_migrations_billing"},
		[]string{artifact.Lineages[0].Ledger, artifact.Lineages[1].Ledger, artifact.Lineages[2].Ledger})
	// The artifact must stay machine-independent so its digest is reproducible.
	require.NotContains(t, string(mustReadFile(t, filepath.Join(outputDirectory, "bootstrap", "plan.json"))), builder.Location)

	require.NoError(t, services.VerifyDockerBuildPlan(outputDirectory, response.GetResult().GetDockerBuildPlan()))
}

// TestBuildRejectsUnresolvedDeclaredSource covers the required-declaration rule:
// local development tolerates a sibling that has not shipped migrations yet, but
// a build that cannot stage the bytes must fail rather than emit an image that
// silently leaves those tables out.
func TestBuildRejectsUnresolvedDeclaredSource(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	builder.Settings.MigrationSources = []MigrationSource{{Name: "api"}}
	outputDirectory := t.TempDir()

	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_ERROR, response.GetState().GetState())
	require.Contains(t, response.GetState().GetMessage(), "api")
}

// TestBuildPlanDigestTracksMigrationContent proves the emitted evidence follows
// the bytes: mutating one migration changes the plan digest, the staged content,
// and the recipe digest the Job identity is derived from.
func TestBuildPlanDigestTracksMigrationContent(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	outputDirectory := t.TempDir()

	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	before := readPlanArtifact(t, outputDirectory)
	recipeDigestBefore := response.GetResult().GetDockerBuildPlan().GetDigest()

	require.NoError(t, os.WriteFile(
		filepath.Join(builder.Location, "migrations", "1_create_table.up.sql"),
		[]byte("CREATE TABLE example (id UUID PRIMARY KEY);\n"), 0o644))

	response, err = builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	after := readPlanArtifact(t, outputDirectory)

	require.NotEqual(t, before.Digest, after.Digest)
	require.NotEqual(t, before.Lineages[0].Files[1].Digest, after.Lineages[0].Files[1].Digest)
	require.NotEqual(t, recipeDigestBefore, response.GetResult().GetDockerBuildPlan().GetDigest())
	require.Contains(t,
		string(mustReadFile(t, filepath.Join(outputDirectory, "bootstrap", "sources", "00-store", "1_create_table.up.sql"))),
		"id UUID PRIMARY KEY")
}

// TestBuildRecipeCarriesNoSecrets guards the emitted artifact and the image
// contents: the build context is the whole service directory, which holds the
// generated local secret file every scaffolded service carries.
func TestBuildRecipeCarriesNoSecrets(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	secretDirectory := filepath.Join(builder.Location, "configurations", "local")
	require.NoError(t, os.MkdirAll(secretDirectory, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(secretDirectory, "postgres.secret.env"),
		[]byte("POSTGRES_PASSWORD=super-secret\n"), 0o600))
	outputDirectory := t.TempDir()

	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	require.NoError(t, filepath.WalkDir(outputDirectory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		require.NotContains(t, string(mustReadFile(t, path)), "super-secret", path)
		return nil
	}))

	dockerfile := string(mustReadFile(t, filepath.Join(outputDirectory, "builder", "Dockerfile")))
	require.NotContains(t, dockerfile, "COPY . .",
		"a wholesale copy would bake the service directory's local secrets into the image")
}

func readPlanArtifact(t *testing.T, contextRoot string) schemaPlanArtifact {
	t.Helper()
	var artifact schemaPlanArtifact
	require.NoError(t, json.Unmarshal(mustReadFile(t, filepath.Join(contextRoot, "bootstrap", "plan.json")), &artifact))
	require.Equal(t, schemaPlanContractVersion, artifact.ContractVersion)
	return artifact
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return content
}

// TestBuildRefusesToReplaceAForeignBootstrapDirectory covers the staging root
// living in the user's service directory: "bootstrap" is a plausible name for
// hand-authored seed SQL, and staging deletes the directory it claims.
func TestBuildRefusesToReplaceAForeignBootstrapDirectory(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	handAuthored := filepath.Join(builder.Location, "bootstrap", "seed.sql")
	require.NoError(t, os.MkdirAll(filepath.Dir(handAuthored), 0o755))
	require.NoError(t, os.WriteFile(handAuthored, []byte("INSERT INTO example VALUES (1);\n"), 0o644))

	response, err := builder.Build(ctx, buildRequest(t.TempDir()))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_ERROR, response.GetState().GetState())
	require.FileExists(t, handAuthored, "the build destroyed a directory it did not generate")

	// A directory the agent generated is replaced without complaint.
	require.NoError(t, os.RemoveAll(filepath.Join(builder.Location, "bootstrap")))
	response, err = builder.Build(ctx, buildRequest(t.TempDir()))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	response, err = builder.Build(ctx, buildRequest(t.TempDir()))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
}

// TestBuildStagesTreeThatGitIgnoresItself covers services that already exist:
// they never re-render the factory .gitignore, so the staged tree — which is
// regenerated every build and holds copies of sibling migrations — has to carry
// its own ignore rule or it gets committed as a second source of truth.
func TestBuildStagesTreeThatGitIgnoresItself(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)

	response, err := builder.Build(ctx, buildRequest(t.TempDir()))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	ignore := string(mustReadFile(t, filepath.Join(builder.Location, "bootstrap", ".gitignore")))
	require.Contains(t, ignore, "*")
	require.Contains(t, ignore, "codefly-generated postgres bootstrap")
}

// TestBuildStagesModesIndependentOfUmask covers two failures with one cause: the
// recipe digest covers each file's mode, so a umask would otherwise make the
// published digest machine-dependent, and the bootstrap Job reads this tree as
// uid 65534, which cannot read a 0600 root-owned file.
func TestBuildStagesModesIndependentOfUmask(t *testing.T) {
	ctx := context.Background()
	previous := syscall.Umask(0o077)
	builder := newBuildTestBuilder(t)
	outputDirectory := t.TempDir()
	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	syscall.Umask(previous)
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	require.NoError(t, filepath.WalkDir(filepath.Join(outputDirectory, "bootstrap"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, infoErr := entry.Info()
		require.NoError(t, infoErr)
		expected := os.FileMode(0o644)
		if entry.IsDir() {
			expected = 0o755
		}
		require.Equal(t, expected, info.Mode().Perm(), path)
		return nil
	}))
	runtimeAccess, err := os.Stat(filepath.Join(outputDirectory, "runtime-access.sql"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), runtimeAccess.Mode().Perm())
}

// TestBuildArtifactIsIdenticalAcrossCheckouts covers the published identity: two
// machines building one commit must emit the same plan and the same recipe
// digest, or every deploy from a different machine churns the bootstrap Job.
// An absolutely declared source is the case that breaks it.
func TestBuildArtifactIsIdenticalAcrossCheckouts(t *testing.T) {
	ctx := context.Background()
	emit := func() (string, string) {
		t.Helper()
		builder := newBuildTestBuilder(t)
		external := filepath.Join(t.TempDir(), "external", "migrations")
		writeMigration(t, external, "1_external.up.sql")
		builder.Settings.MigrationSources = []MigrationSource{{Name: "external", Path: external}}
		outputDirectory := t.TempDir()
		response, err := builder.Build(ctx, buildRequest(outputDirectory))
		require.NoError(t, err)
		require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
		return string(mustReadFile(t, filepath.Join(outputDirectory, "bootstrap", "plan.json"))),
			response.GetResult().GetDockerBuildPlan().GetDigest()
	}

	firstPlan, firstDigest := emit()
	secondPlan, secondDigest := emit()
	require.Equal(t, firstPlan, secondPlan, "the published plan carries the emitting machine's paths")
	require.Equal(t, firstDigest, secondDigest, "the recipe digest depends on where the sources happen to live")
	require.NotContains(t, firstPlan, t.TempDir())
	require.NotContains(t, firstPlan, "declared-path")
}

// TestBuildChecksumManifestCoversEveryStagedSource is what makes a drifted or
// partly written context loud: the bootstrap program verifies this manifest
// before it applies anything.
func TestBuildChecksumManifestCoversEveryStagedSource(t *testing.T) {
	ctx := context.Background()
	builder := newBuildTestBuilder(t)
	writeMigration(t, filepath.Join(filepath.Dir(builder.Location), "api", "migrations"), "1_api.up.sql")
	builder.Settings.MigrationSources = []MigrationSource{{Name: "api"}}
	outputDirectory := t.TempDir()

	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	manifest := string(mustReadFile(t, filepath.Join(outputDirectory, "bootstrap", "sources.sha256")))
	for _, staged := range []string{
		"sources/00-store/1_create_table.up.sql",
		"sources/00-store/1_create_table.down.sql",
		"sources/01-api/1_api.up.sql",
	} {
		require.Contains(t, manifest, staged)
	}
	for _, line := range strings.Split(strings.TrimSpace(manifest), "\n") {
		digest, path, found := strings.Cut(line, "  ")
		require.True(t, found, line)
		require.Len(t, digest, 64, "sha256sum -c expects a bare hex digest")
		require.Equal(t, "sha256:"+digest, mustFileDigest(t, filepath.Join(outputDirectory, "bootstrap", path)))
	}
}

func mustFileDigest(t *testing.T, path string) string {
	t.Helper()
	digest, err := fileDigest(path)
	require.NoError(t, err)
	return digest
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

func TestBuildRecipeContractOverGRPC(t *testing.T) {
	for _, selection := range []string{"default", "explicit", "cache-selected"} {
		for _, output := range []string{"recipe", "missing", "relative"} {
			t.Run(selection+"/"+output, func(t *testing.T) {
				builder := newBuildTestBuilder(t)
				marker := filepath.Join(builder.Location, "builder", "Dockerfile")
				require.NoError(t, os.MkdirAll(filepath.Dir(marker), 0o755))
				require.NoError(t, os.WriteFile(marker, []byte("caller-owned"), 0o644))
				server := grpc.NewServer()
				builderv0.RegisterBuilderServer(server, builder)
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				go func() { _ = server.Serve(listener) }()
				t.Cleanup(server.Stop)
				conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, conn.Close()) })
				client := services.NewBuilderAgentClient(conn)
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()

				t.Setenv("PATH", t.TempDir())
				for _, executable := range []string{"docker", "buildx"} {
					_, err := exec.LookPath(executable)
					require.ErrorIs(t, err, exec.ErrNotFound)
				}
				capabilities, err := client.BuildCapabilities(ctx, &builderv0.BuildCapabilitiesRequest{})
				require.NoError(t, err)
				require.True(t, capabilities.GetBuildxSelection())

				directory := t.TempDir()
				request := buildRequest(directory)
				docker := request.GetBuildContext().GetDockerBuildContext()
				if selection != "default" {
					docker.BuildxBuilder = "cli-owned-builder"
				}
				if selection == "cache-selected" {
					docker.Cache = &builderv0.BuildCacheOptions{
						Backend: "registry", Scope: "postgres",
						Imports: []string{"registry.example.com/cache/import"},
						Exports: []string{"registry.example.com/cache/export"},
					}
				}
				switch output {
				case "missing":
					request.OutputDirectory = ""
				case "relative":
					request.OutputDirectory = "relative-output"
				}
				response, err := client.Build(ctx, request)
				if output == "relative" {
					require.ErrorContains(t, err, "must be absolute")
				} else {
					require.NoError(t, err)
					if output == "missing" {
						require.Equal(t, builderv0.BuildStatus_ERROR, response.GetState().GetState())
						require.Contains(t, response.GetState().GetMessage(), "output_directory is required")
						require.Nil(t, response.GetResult())
					} else {
						require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
						plan := response.GetResult().GetDockerBuildPlan()
						require.NotNil(t, plan)
						require.NoError(t, services.VerifyDockerBuildPlan(directory, plan))
						require.Len(t, plan.GetRecipes(), 1)
						require.Equal(t, "registry.example.com/module/postgres", plan.GetRecipes()[0].GetImage())
						require.Nil(t, response.GetResult().GetDockerBuildResult())
						require.Empty(t, response.GetBuildxBuilder())
						require.Empty(t, response.GetCacheContractVersion())
					}
				}
				require.Equal(t, "caller-owned", string(mustReadFile(t, marker)))
				if output != "recipe" {
					require.NoDirExists(t, filepath.Join(builder.Location, "bootstrap"))
					require.NoFileExists(t, filepath.Join(builder.Location, "runtime-access.sql"))
					entries, err := os.ReadDir(directory)
					require.NoError(t, err)
					require.Empty(t, entries)
				}
			})
		}
	}
}
