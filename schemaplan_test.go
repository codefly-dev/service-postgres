package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codefly-dev/core/resources"
	"github.com/stretchr/testify/require"
)

// writeMigration creates a migrations directory holding one named migration.
func writeMigration(t *testing.T, dir, name string) {
	t.Helper()
	mustMkdir(t, dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("SELECT 1;\n"), 0o644))
}

// newPlanFixture lays out a service with its own migrations and two sibling
// sources, the shape the shared-database contract is written for.
func newPlanFixture(t *testing.T) *Service {
	t.Helper()
	root := t.TempDir()
	location := filepath.Join(root, "store")
	writeMigration(t, filepath.Join(location, "migrations"), "1_store.up.sql")
	writeMigration(t, filepath.Join(root, "api", "migrations"), "1_api.up.sql")
	writeMigration(t, filepath.Join(root, "billing", "db", "migrations"), "1_billing.up.sql")
	return newPlanService(t, location, &Settings{
		DatabaseName: "app",
		Extensions:   []Extension{{Name: "hstore"}},
		MigrationSources: []MigrationSource{
			{Name: "api"},
			{Name: "billing", Path: "../billing/db/migrations"},
		},
	})
}

func newPlanService(t *testing.T, location string, settings *Settings) *Service {
	t.Helper()
	service := NewService()
	service.Identity = &resources.ServiceIdentity{Name: "store", Module: "test"}
	service.Settings = settings
	service.Location = location
	return service
}

// planFor packages what the shared resolver returned, the way Build does.
func planFor(t *testing.T, service *Service) *schemaPlan {
	t.Helper()
	prerequisites, err := service.resolveSchemaPrerequisites()
	require.NoError(t, err)
	plan, err := buildSchemaPlan(prerequisites, service.Settings)
	require.NoError(t, err)
	return plan
}

func TestSchemaPlanStagesEveryLineageInACollisionFreeDirectory(t *testing.T) {
	plan := planFor(t, newPlanFixture(t))
	require.NoError(t, plan.attest())

	require.Equal(t,
		[]string{"00-store", "01-api", "02-billing"},
		[]string{plan.lineages[0].stage, plan.lineages[1].stage, plan.lineages[2].stage})
	require.Equal(t,
		[]string{"schema_migrations", "schema_migrations_api", "schema_migrations_billing"},
		[]string{plan.lineages[0].trackingTable(), plan.lineages[1].trackingTable(), plan.lineages[2].trackingTable()})
	for _, lineage := range plan.lineages {
		require.Len(t, lineage.files, 1)
		require.True(t, strings.HasPrefix(lineage.files[0].digest, "sha256:"))
	}
}

// TestSchemaPlanIdentityIsMachineIndependent keeps the emitted evidence
// reproducible: two checkouts of the same sources at different absolute paths
// must agree on the plan digest — including a source declared by absolute path,
// which is where provenance would otherwise leak into the identity — while
// changing a byte must not.
func TestSchemaPlanIdentityIsMachineIndependent(t *testing.T) {
	attested := func() (*schemaPlan, *Service) {
		t.Helper()
		service := newPlanFixture(t)
		external := filepath.Join(t.TempDir(), "external", "migrations")
		writeMigration(t, external, "1_external.up.sql")
		service.Settings.MigrationSources = append(service.Settings.MigrationSources,
			MigrationSource{Name: "external", Path: external})
		plan := planFor(t, service)
		require.NoError(t, plan.attest())
		return plan, service
	}

	first, firstService := attested()
	second, secondService := attested()

	require.NotEqual(t, firstService.Location, secondService.Location)
	require.Equal(t, first.digest(), second.digest())

	require.NoError(t, os.WriteFile(
		filepath.Join(secondService.Location, "migrations", "1_store.up.sql"),
		[]byte("SELECT 2;\n"), 0o644))
	mutated := planFor(t, secondService)
	require.NoError(t, mutated.attest())
	require.NotEqual(t, first.digest(), mutated.digest())
}

// TestSchemaPlanRejectsSymlinkEscapingSourceRoot covers the escape a lexical
// path check cannot see: staging copies bytes, so this would pull content from
// an arbitrary path into the image with no record of where it came from.
func TestSchemaPlanRejectsSymlinkEscapingSourceRoot(t *testing.T) {
	service := newPlanFixture(t)
	outside := filepath.Join(t.TempDir(), "9_outside.up.sql")
	require.NoError(t, os.WriteFile(outside, []byte("SELECT 'outside';\n"), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(service.Location, "migrations", "9_outside.up.sql")))

	prerequisites, err := service.resolveSchemaPrerequisites()
	require.NoError(t, err)
	_, err = buildSchemaPlan(prerequisites, service.Settings)
	require.ErrorContains(t, err, "links outside")
	require.ErrorContains(t, err, "migration source")
}

// TestSchemaPlanFollowsSymlinkInsideSourceRoot covers a layout that runs fine
// locally — golang-migrate reads through a symlink — so packaging must not turn
// it into a build failure. Its content is staged, never the link.
func TestSchemaPlanFollowsSymlinkInsideSourceRoot(t *testing.T) {
	service := newPlanFixture(t)
	migrations := filepath.Join(service.Location, "migrations")
	require.NoError(t, os.Symlink(
		filepath.Join(migrations, "1_store.up.sql"),
		filepath.Join(migrations, "2_store.up.sql")))

	plan := planFor(t, service)
	require.NoError(t, plan.attest())
	require.Len(t, plan.lineages[0].files, 2)

	staged := t.TempDir()
	require.NoError(t, stageLineage(context.Background(), plan.lineages[0], staged))
	linked, err := os.Lstat(filepath.Join(staged, "2_store.up.sql"))
	require.NoError(t, err)
	require.Zero(t, linked.Mode()&os.ModeSymlink, "a symlink in the recipe tree is rejected by the inventory")
	require.Equal(t, "SELECT 1;\n", string(mustReadFile(t, filepath.Join(staged, "2_store.up.sql"))))
}

// TestSchemaPlanStagesOnlyMigrationFiles pins packaging to the one runtime
// filename definition: an editor backup parses as the same version and direction
// as the file it shadows, so shipping one would make migrate reject the lineage.
func TestSchemaPlanStagesOnlyMigrationFiles(t *testing.T) {
	service := newPlanFixture(t)
	migrations := filepath.Join(service.Location, "migrations")
	for _, name := range []string{
		"1_store.up.sql~", "1_store.up.sql.bak", "1_store.up.sql.orig",
		".1_store.up.sql.swp", "README.md", "2_flavored.up.pgsql",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(migrations, name), []byte("SELECT 1;\n"), 0o644))
	}

	plan := planFor(t, service)
	staged := make([]string, 0, len(plan.lineages[0].files))
	for _, file := range plan.lineages[0].files {
		staged = append(staged, file.name)
	}
	require.Equal(t, []string{"1_store.up.sql", "2_flavored.up.pgsql"}, staged)
}

// TestSchemaPlanPackagesNothingWithoutMigrations mirrors applySchema: a
// no-migration service still creates extensions and reconciles grants, and must
// not ship a lineage the runtime would refuse to apply.
func TestSchemaPlanPackagesNothingWithoutMigrations(t *testing.T) {
	service := newPlanFixture(t)
	service.Settings.NoMigration = true

	plan := planFor(t, service)
	require.Empty(t, plan.lineages)
	require.NotEmpty(t, plan.extensions)
	require.NotEmpty(t, plan.access.readWriteRole)
}

// TestSchemaPlanPackagesNoEmptyLineage checks the packaging consequence of the
// resolver excluding a lineage with no migration: the staged tree and the
// numbering start at the first lineage that actually has one, so the image never
// carries a source golang-migrate would reject as a missing first version.
func TestSchemaPlanPackagesNoEmptyLineage(t *testing.T) {
	root := t.TempDir()
	location := filepath.Join(root, "store")
	mustMkdir(t, filepath.Join(location, "migrations"))
	writeMigration(t, filepath.Join(root, "api", "migrations"), "1_api.up.sql")
	service := newPlanService(t, location, &Settings{
		DatabaseName:     "app",
		MigrationSources: []MigrationSource{{Name: "api"}},
	})

	plan := planFor(t, service)
	require.Len(t, plan.lineages, 1)
	require.Equal(t, "api", plan.lineages[0].label())
	require.Equal(t, "00-api", plan.lineages[0].stage)
}

// TestSchemaPlanCarriesRuntimeAccessInputs keeps grant reconciliation on the
// same packaging as migrations, so the bootstrap image and the local runtime
// reconcile identical roles.
func TestSchemaPlanCarriesRuntimeAccessInputs(t *testing.T) {
	service := newPlanFixture(t)
	service.Settings.RuntimeSchemas = []string{"public", "audit"}
	service.Settings.RuntimeReadWriteRoles = []string{"app_tenant"}

	plan := planFor(t, service)
	readOnlyRole, readWriteRole := runtimeRoleNames("app")
	require.Equal(t, readOnlyRole, plan.access.readOnlyRole)
	require.Equal(t, readWriteRole, plan.access.readWriteRole)
	require.Equal(t, []string{"public", "audit"}, plan.access.schemas)
	require.Equal(t, []string{"app_tenant"}, plan.access.readWriteRoles)
}

// TestSchemaPlanCarriesRequiredExtensions is the deployed half of the required
// contract: a declared extension must be packaged as required so the image fails
// on it exactly as the runtime fails readiness.
func TestSchemaPlanCarriesRequiredExtensions(t *testing.T) {
	service := newPlanFixture(t)
	service.Settings.Extensions = []Extension{{Name: "hstore"}, {Name: "postgis", Optional: true}}

	plan := planFor(t, service)
	required := map[string]bool{}
	for _, extension := range plan.extensions {
		required[extension.name] = extension.required
	}
	require.True(t, required["hstore"], "a declared extension is required by default")
	require.False(t, required["postgis"], "an explicitly optional extension stays best-effort")
	require.False(t, required["vector"], "the convenience defaults stay best-effort")
}
