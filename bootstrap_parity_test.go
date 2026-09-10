package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/core/agents/services"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/stretchr/testify/require"
)

const (
	parityOwnerUser        = "postgres"
	parityOwnerPassword    = "owner-secret"
	parityReadOnlyPassword = "read-only-secret"
	parityReadWritePasword = "read-write-secret"
	parityDatabase         = "store"
)

// TestBootstrapImageMatchesLocalRuntimeSchema is the acceptance test for the
// local/deployed schema contract: the same fixture is applied by the local
// runtime and by the built bootstrap image, against two fresh Postgres
// clusters, and the resulting tables, migration ledgers, extensions, and
// runtime-role grants must be identical. Each path runs twice, so the
// comparison also proves both are idempotent.
func TestBootstrapImageMatchesLocalRuntimeSchema(t *testing.T) {
	requireDocker(t)

	scenarios := map[string]func(t *testing.T, location string) *Settings{
		"sibling sources without own migrations": func(t *testing.T, location string) *Settings {
			writeFixtureMigration(t, filepath.Join(location, "..", "api", "migrations"), "1_api",
				`CREATE TABLE api_widget (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), attributes HSTORE NOT NULL DEFAULT ''::hstore);`,
				`DROP TABLE api_widget;`)
			writeFixtureMigration(t, filepath.Join(location, "..", "billing", "db", "migrations"), "1_billing",
				`CREATE TABLE billing_invoice (id UUID PRIMARY KEY, cents BIGINT NOT NULL);`,
				`DROP TABLE billing_invoice;`)
			return &Settings{
				DatabaseName: parityDatabase,
				Extensions:   []Extension{{Name: "hstore"}},
				MigrationSources: []MigrationSource{
					{Name: "api"},
					{Name: "billing", Path: "../billing/db/migrations"},
				},
			}
		},
		"own and sibling sources": func(t *testing.T, location string) *Settings {
			writeFixtureMigration(t, filepath.Join(location, "migrations"), "1_store",
				`CREATE TABLE store_item (id UUID PRIMARY KEY);`,
				`DROP TABLE store_item;`)
			writeFixtureMigration(t, filepath.Join(location, "..", "api", "migrations"), "1_api",
				`CREATE TABLE api_widget (id UUID PRIMARY KEY, attributes HSTORE NOT NULL DEFAULT ''::hstore);`,
				`DROP TABLE api_widget;`)
			writeFixtureMigration(t, filepath.Join(location, "..", "api", "migrations"), "2_api_index",
				`CREATE INDEX api_widget_attributes ON api_widget USING GIN (attributes);`,
				`DROP INDEX api_widget_attributes;`)
			return &Settings{
				DatabaseName:     parityDatabase,
				Extensions:       []Extension{{Name: "hstore"}},
				MigrationSources: []MigrationSource{{Name: "api"}},
			}
		},
		"extension-only bootstrap": func(t *testing.T, location string) *Settings {
			writeFixtureMigration(t, filepath.Join(location, "migrations"), "1_ignored",
				`CREATE TABLE never_applied (id UUID PRIMARY KEY);`,
				`DROP TABLE never_applied;`)
			return &Settings{
				DatabaseName: parityDatabase,
				NoMigration:  true,
				Extensions:   []Extension{{Name: "hstore"}},
			}
		},
	}

	for name, fixture := range scenarios {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			location := filepath.Join(t.TempDir(), "module", "store")
			require.NoError(t, os.MkdirAll(location, 0o755))
			settings := fixture(t, location)

			network := startParityNetwork(t)
			local := startParityPostgres(t, network, "local")
			deployed := startParityPostgres(t, network, "deployed")

			applyLocally(ctx, t, location, settings, local.hostDSN)
			applyLocally(ctx, t, location, settings, local.hostDSN)

			bootstrapImage := buildBootstrapImage(ctx, t, location, settings)
			runBootstrapImage(t, network, bootstrapImage, deployed.networkDSN)
			runBootstrapImage(t, network, bootstrapImage, deployed.networkDSN)

			readOnlyRole, readWriteRole := runtimeRoleNames(parityDatabase)
			localSchema := snapshotSchema(ctx, t, local.hostDSN, readOnlyRole, readWriteRole)
			deployedSchema := snapshotSchema(ctx, t, deployed.hostDSN, readOnlyRole, readWriteRole)
			require.Equal(t, localSchema, deployedSchema,
				"the bootstrap image and the local runtime disagree on the schema contract")

			// The comparison is only meaningful if both actually did the work.
			require.Contains(t, localSchema, "extension: hstore")
			require.Contains(t, localSchema, "role: "+readOnlyRole+" login=t super=f bypassrls=f")
			switch name {
			case "extension-only bootstrap":
				require.NotContains(t, strings.Join(localSchema, "\n"), "ledger:")
				require.NotContains(t, strings.Join(localSchema, "\n"), "table: never_applied")
			case "sibling sources without own migrations":
				require.Contains(t, localSchema, "table: api_widget")
				require.Contains(t, localSchema, "table: billing_invoice")
				require.Contains(t, localSchema, "ledger: schema_migrations_api version=1 dirty=f")
				require.Contains(t, localSchema, "ledger: schema_migrations_billing version=1 dirty=f")
				require.NotContains(t, strings.Join(localSchema, "\n"), "ledger: schema_migrations ")
			case "own and sibling sources":
				require.Contains(t, localSchema, "table: store_item")
				require.Contains(t, localSchema, "ledger: schema_migrations version=1 dirty=f")
				require.Contains(t, localSchema, "ledger: schema_migrations_api version=2 dirty=f")
			}
		})
	}
}

// applyLocally runs the local half of the contract: the plan is resolved once
// and then executed exactly as Init does.
func applyLocally(ctx context.Context, t *testing.T, location string, settings *Settings, dsn string) {
	t.Helper()
	runtime := NewRuntime()
	runtime.Location = location
	runtime.Settings = settings
	runtime.postgresUser = parityOwnerUser
	runtime.postgresPassword = parityOwnerPassword
	runtime.readOnlyPassword = parityReadOnlyPassword
	runtime.readWritePassword = parityReadWritePasword
	runtime.connection = dsn

	prerequisites, err := runtime.resolveSchemaPrerequisites()
	require.NoError(t, err)
	require.NoError(t, runtime.applySchema(ctx, prerequisites))
	require.NoError(t, runtime.ensureRuntimeAccess(ctx))
}

// buildBootstrapImage emits the CLI-owned build recipe and builds it exactly as
// the CLI would: from the recipe tree, which must be a self-contained context.
func buildBootstrapImage(ctx context.Context, t *testing.T, location string, settings *Settings) string {
	t.Helper()
	builder := NewBuilder()
	require.NoError(t, builder.HeadlessLoad(ctx, &basev0.ServiceIdentity{
		Workspace: "workspace", Module: "module", Name: "store", Version: "1.2.3",
	}))
	builder.Information = &services.Information{
		Service: resources.ToServiceWithCase(builder.Identity),
		Module:  resources.ToModuleWithCase(builder.Identity),
	}
	builder.Location = location
	builder.Settings = settings

	outputDirectory := t.TempDir()
	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	require.NoError(t, services.VerifyDockerBuildPlan(outputDirectory, response.GetResult().GetDockerBuildPlan()))

	tag := fmt.Sprintf("service-postgres-parity:%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "--force", tag).Run() })
	runDocker(t, "build", "--file", filepath.Join(outputDirectory, "builder", "Dockerfile"),
		"--tag", tag, outputDirectory)
	return tag
}

func runBootstrapImage(t *testing.T, network, tag, dsn string) {
	t.Helper()
	runDocker(t, "run", "--rm", "--network", network,
		"--env", migrationConnectionEnvironmentKey+"="+dsn,
		"--env", "POSTGRES_USER="+parityOwnerUser,
		"--env", "POSTGRES_READ_ONLY_PASSWORD="+parityReadOnlyPassword,
		"--env", "POSTGRES_READ_WRITE_PASSWORD="+parityReadWritePasword,
		tag)
}

// snapshotSchema renders every externally visible part of the schema contract
// as sorted text, so a mismatch between the two paths reads as a diff.
func snapshotSchema(ctx context.Context, t *testing.T, dsn, readOnlyRole, readWriteRole string) []string {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()

	var snapshot []string
	snapshot = append(snapshot, queryLines(ctx, t, db,
		`SELECT format('table: %s', table_name) FROM information_schema.tables
		 WHERE table_schema = 'public' ORDER BY table_name`)...)
	snapshot = append(snapshot, queryLines(ctx, t, db,
		`SELECT format('extension: %s', extname) FROM pg_extension ORDER BY extname`)...)
	snapshot = append(snapshot, queryLines(ctx, t, db,
		`SELECT format('role: %s login=%s super=%s bypassrls=%s', rolname, rolcanlogin, rolsuper, rolbypassrls)
		 FROM pg_roles WHERE rolname IN ($1, $2) ORDER BY rolname`, readOnlyRole, readWriteRole)...)
	snapshot = append(snapshot, queryLines(ctx, t, db,
		`SELECT format('grant: %s on %s %s', grantee, table_name, privilege_type)
		 FROM information_schema.role_table_grants WHERE grantee IN ($1, $2)
		 ORDER BY grantee, table_name, privilege_type`, readOnlyRole, readWriteRole)...)

	// Every migration ledger the plan may own, whichever path created it.
	ledgers := queryLines(ctx, t, db,
		`SELECT table_name FROM information_schema.tables
		 WHERE table_schema = 'public' AND table_name LIKE 'schema_migrations%' ORDER BY table_name`)
	for _, ledger := range ledgers {
		snapshot = append(snapshot, queryLines(ctx, t, db,
			`SELECT format('ledger: `+ledger+` version=%s dirty=%s', version, dirty) FROM "`+ledger+`"`)...)
	}
	return snapshot
}

func queryLines(ctx context.Context, t *testing.T, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, query, args...)
	require.NoError(t, err)
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		lines = append(lines, line)
	}
	require.NoError(t, rows.Err())
	return lines
}

type parityPostgres struct {
	hostDSN    string
	networkDSN string
}

// startParityPostgres runs one disposable cluster on the shared network. The
// local runtime reaches it through the published host port and the bootstrap
// container through the network alias, mirroring how each really connects.
func startParityPostgres(t *testing.T, network, role string) parityPostgres {
	t.Helper()
	alias := fmt.Sprintf("postgres-%s-%d", role, time.Now().UnixNano())
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "--force", alias).Run() })
	runDocker(t, "run", "--detach", "--name", alias,
		"--network", network, "--network-alias", alias,
		"--publish", "127.0.0.1::5432",
		"--env", "POSTGRES_USER="+parityOwnerUser,
		"--env", "POSTGRES_PASSWORD="+parityOwnerPassword,
		"--env", "POSTGRES_DB="+parityDatabase,
		image.FullName())

	published := strings.TrimSpace(runDocker(t, "port", alias, "5432/tcp"))
	published = strings.TrimSpace(strings.Split(published, "\n")[0])
	port := published[strings.LastIndex(published, ":")+1:]

	postgres := parityPostgres{
		hostDSN:    fmt.Sprintf("postgresql://%s:%s@127.0.0.1:%s/%s?sslmode=disable", parityOwnerUser, parityOwnerPassword, port, parityDatabase),
		networkDSN: fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable", parityOwnerUser, parityOwnerPassword, alias, parityDatabase),
	}
	waitForParityPostgres(t, alias, postgres.hostDSN)
	return postgres
}

func waitForParityPostgres(t *testing.T, container, dsn string) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	deadline := time.Now().Add(90 * time.Second)
	for {
		if err = db.Ping(); err == nil {
			return
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "40", container).CombinedOutput()
			t.Fatalf("postgres %s never became ready: %v\n%s", container, err, logs)
		}
		time.Sleep(time.Second)
	}
}

func startParityNetwork(t *testing.T) string {
	t.Helper()
	network := fmt.Sprintf("codefly-postgres-parity-%d", time.Now().UnixNano())
	runDocker(t, "network", "create", network)
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", network).Run() })
	return network
}

func runDocker(t *testing.T, args ...string) string {
	t.Helper()
	output, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func writeFixtureMigration(t *testing.T, dir, name, up, down string) {
	t.Helper()
	mustMkdir(t, dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, name+".up.sql"), []byte(up+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name+".down.sql"), []byte(down+"\n"), 0o644))
}

// TestBootstrapImageRefusesDriftedStagedSources is the behavioral half of the
// staging guarantee. The image is built from the service directory by a
// separate process, long after the plan was emitted, so staged content can
// drift or be only partly written. Without verification the run applies fewer
// migrations and exits successfully — a silently under-migrated database. The
// check runs before the database is even contacted, so no cluster is needed.
func TestBootstrapImageRefusesDriftedStagedSources(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	location := filepath.Join(t.TempDir(), "module", "store")
	require.NoError(t, os.MkdirAll(location, 0o755))
	writeFixtureMigration(t, filepath.Join(location, "migrations"), "1_store",
		`CREATE TABLE store_item (id UUID PRIMARY KEY);`, `DROP TABLE store_item;`)
	settings := &Settings{DatabaseName: parityDatabase}

	builder := NewBuilder()
	require.NoError(t, builder.HeadlessLoad(ctx, &basev0.ServiceIdentity{
		Workspace: "workspace", Module: "module", Name: "store", Version: "1.2.3",
	}))
	builder.Information = &services.Information{
		Service: resources.ToServiceWithCase(builder.Identity),
		Module:  resources.ToModuleWithCase(builder.Identity),
	}
	builder.Location = location
	builder.Settings = settings

	outputDirectory := t.TempDir()
	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	// Exactly what a concurrent build, a stray editor write, or a partly copied
	// context leaves behind.
	drifted := filepath.Join(outputDirectory, "bootstrap", "sources", "00-store", "1_store.up.sql")
	require.NoError(t, os.WriteFile(drifted, []byte("CREATE TABLE something_else (id UUID PRIMARY KEY);\n"), 0o644))

	tag := fmt.Sprintf("service-postgres-drift:%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "--force", tag).Run() })
	runDocker(t, "build", "--file", filepath.Join(outputDirectory, "builder", "Dockerfile"),
		"--tag", tag, outputDirectory)

	// A reachable database, so the run gets past the readiness gate and the
	// verification is what stops it.
	database := startBootstrapPostgres(t)
	output, err := exec.Command("docker", "run", "--rm",
		"--network", "container:"+database,
		"--env", migrationConnectionEnvironmentKey+"=postgres://postgres:bootstrap-test@127.0.0.1:5432/postgres?sslmode=disable",
		"--env", "POSTGRES_USER=postgres",
		"--env", "POSTGRES_READ_ONLY_PASSWORD=read-only-secret",
		"--env", "POSTGRES_READ_WRITE_PASSWORD=read-write-secret",
		tag).CombinedOutput()
	require.Error(t, err, "the bootstrap applied drifted migration content instead of failing:\n%s", output)
	require.Contains(t, string(output), "1_store.up.sql")

	// Nothing may reach the database: not the drifted statement, not the
	// migration it replaced.
	for _, relation := range []string{"public.something_else", "public.store_item"} {
		require.Equal(t, "f",
			queryBootstrapPostgres(t, database, fmt.Sprintf("SELECT to_regclass('%s') IS NOT NULL", relation)),
			"a drifted staged source reached the database")
	}
}

// TestBootstrapImageBuildsTheWayTheCLIBuildsIt exercises the recipe the way the
// CLI consumes it: the build context is the service directory, not the recipe
// tree, and the recipe's declared ignore is staged next to the Dockerfile
// first. Building only from the recipe tree would never apply that ignore, so
// an ignore that excluded something the Dockerfile copies would break every
// deploy while the suite stayed green.
func TestBootstrapImageBuildsTheWayTheCLIBuildsIt(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	location := filepath.Join(t.TempDir(), "module", "store")
	require.NoError(t, os.MkdirAll(location, 0o755))
	writeFixtureMigration(t, filepath.Join(location, "migrations"), "1_store",
		`CREATE TABLE store_item (id UUID PRIMARY KEY);`, `DROP TABLE store_item;`)
	secrets := filepath.Join(location, "configurations", "local")
	require.NoError(t, os.MkdirAll(secrets, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(secrets, "postgres.secret.env"),
		[]byte("POSTGRES_PASSWORD=super-secret\n"), 0o600))

	builder := NewBuilder()
	require.NoError(t, builder.HeadlessLoad(ctx, &basev0.ServiceIdentity{
		Workspace: "workspace", Module: "module", Name: "store", Version: "1.2.3",
	}))
	builder.Information = &services.Information{
		Service: resources.ToServiceWithCase(builder.Identity),
		Module:  resources.ToModuleWithCase(builder.Identity),
	}
	builder.Location = location
	builder.Settings = &Settings{DatabaseName: parityDatabase}

	outputDirectory := t.TempDir()
	response, err := builder.Build(ctx, buildRequest(outputDirectory))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	recipe := response.GetResult().GetDockerBuildPlan().GetRecipes()[0]
	require.NotEmpty(t, recipe.GetDockerignore())
	dockerfile := filepath.Join(outputDirectory, filepath.FromSlash(recipe.GetDockerfile()))
	ignore := filepath.Join(outputDirectory, filepath.FromSlash(recipe.GetDockerignore()))
	require.NoError(t, os.WriteFile(dockerfile+".dockerignore", mustReadFile(t, ignore), 0o644))

	tag := fmt.Sprintf("service-postgres-cli-shape:%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "--force", tag).Run() })
	runDocker(t, "build", "--file", dockerfile, "--tag", tag, location)

	listing := runDocker(t, "run", "--rm", "--entrypoint", "/bin/sh", tag,
		"-c", "ls -A /app && ls -A /app/bootstrap")
	require.Contains(t, listing, "runtime-access.sql")
	require.Contains(t, listing, "sources.sha256")
	require.NotContains(t, listing, "configurations")

	// /app is the whole of what this build adds to the base image, so scanning it
	// is exhaustive for content the build could have leaked. Scanning from / would
	// descend into /proc and /dev and block on their pseudo-files.
	secretSearch := runDocker(t, "run", "--rm", "--entrypoint", "/bin/sh", tag,
		"-c", "grep -rl super-secret /app 2>/dev/null; exit 0")
	require.Empty(t, strings.TrimSpace(secretSearch), "the image carries the service directory's local secret")
}
