package main

import (
	"context"
	"database/sql"
	"fmt"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/resources"
	runners "github.com/codefly-dev/core/runners/base"
	"github.com/codefly-dev/core/wool"
	scoped "github.com/codefly-dev/service-postgres/libs/go"
	pgcontrol "github.com/codefly-dev/service-postgres/libs/go/controlplane"
	migrationtest "github.com/codefly-dev/service-postgres/libs/go/migrationtest"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
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

	fixture := newPostgresFixture(t, ctx, runtimeContext)
	serviceName := fixture.serviceName

	runtime, init := fixture.start(t, ctx)
	assertMigrationConnectionsAreOwned(t, ctx, runtime)

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
	// Migration ownership remains inside the plugin. Hot reload applies a NEW
	// forward migration without ever exporting the owner connection to a
	// dependent service, and re-saving that migration once it is applied
	// neither re-runs its SQL nor touches the rows it now holds.
	migrationRelation := serviceName + "_migration_replay"
	migrationDirectory := path.Join(fixture.workspaceDir, "mod", serviceName, "migrations")
	migrationUp := path.Join(migrationDirectory, "2_replay.up.sql")
	migrationDown := path.Join(migrationDirectory, "2_replay.down.sql")
	quotedMigrationRelation := pq.QuoteIdentifier(migrationRelation)
	require.NoError(t, os.WriteFile(migrationUp, []byte("CREATE TABLE "+quotedMigrationRelation+" (id UUID PRIMARY KEY);"), 0o600))
	require.NoError(t, os.WriteFile(migrationDown, []byte("DROP TABLE IF EXISTS "+quotedMigrationRelation+";"), 0o600))
	applied, err := runtime.applyMigrationChange(ctx, migrationUp)
	require.NoError(t, err)
	require.True(t, applied)
	exists, err := owner.RelationExists(ctx, migrationRelation)
	require.NoError(t, err)
	require.True(t, exists)
	replayFixtureID := "00000000-0000-0000-0000-000000000003"
	require.NoError(t, owner.AppendFixture(ctx, migrationRelation, replayFixtureID))
	applied, err = runtime.applyMigrationChange(ctx, migrationUp)
	require.ErrorIs(t, err, errAppliedMigrationEdited)
	require.False(t, applied)
	exists, err = owner.RelationExists(ctx, migrationRelation)
	require.NoError(t, err)
	require.True(t, exists)
	found, err = owner.HasFixture(ctx, migrationRelation, replayFixtureID)
	require.NoError(t, err)
	require.True(t, found, "re-saving an applied migration must not replay it or drop its rows")
	require.NoError(t, runtime.ensureRuntimeAccess(ctx))
	found, err = reader.HasFixture(ctx, migrationRelation, replayFixtureID)
	require.NoError(t, err, "reader grants must be reconciled after a forward migration")
	require.True(t, found)
	assertStrayMigrationFilesDoNotBlockLineage(t, ctx, runtime, owner, migrationDirectory, migrationUp, migrationRelation)
	assertHotReloadPreservesAppliedHistory(t, ctx, migrationControl, runtime.connection)
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

	runtime.RuntimeReadWriteRoles = []string{"missing_app_writer"}
	require.ErrorContains(
		t,
		runtime.ensureRuntimeAccess(ctx),
		`configured runtime read-write role "missing_app_writer" does not exist`,
	)
	require.NoError(
		t,
		writer.AppendFixture(ctx, serviceName, "00000000-0000-0000-0000-000000000006"),
		"failed delegated-role reconciliation must preserve the writer's prior authority",
	)

	const delegatedWriter = "app_writer"
	require.NoError(t, owner.InstallDelegatedWriteRole(ctx, delegatedWriter, serviceName))
	runtime.RuntimeReadWriteRoles = []string{delegatedWriter}
	require.NoError(t, runtime.ensureRuntimeAccess(ctx))
	require.Error(
		t,
		writer.AppendFixture(ctx, serviceName, "00000000-0000-0000-0000-000000000004"),
		"delegated writer must not retain direct table authority",
	)
	require.NoError(
		t,
		writer.AppendFixtureAsRole(ctx, delegatedWriter, serviceName, "00000000-0000-0000-0000-000000000005"),
		"delegated writer must mutate through an explicitly configured role",
	)

	// #94: the exported credential must write with nothing asked of the consumer.
	// A fresh connection is the observable unit — the default role is applied at
	// login, so `writer`'s pooled connections predate the reconciliation above.
	_, managedReadWriteRole := runtimeRoleNames(runtime.DatabaseName)
	delegatedWriterProbe, err := openPostgresCapabilityProbe(ctx, readWriteConnection)
	require.NoError(t, err)
	defer delegatedWriterProbe.Close()
	require.NoError(
		t,
		delegatedWriterProbe.AppendFixture(ctx, serviceName, "00000000-0000-0000-0000-000000000007"),
		"a connection opened after reconciliation must write without the consumer selecting a role",
	)

	// A default role the principal cannot assume must degrade to a denied write on
	// a working connection, never to a connection the consumer cannot open at all:
	// consumers race the bootstrap Job that grants the membership, and a refused
	// connection takes their reads and health checks down with their writes.
	require.NoError(t, owner.RevokeRoleMembership(ctx, delegatedWriter, managedReadWriteRole))
	unassumableProbe, err := openPostgresCapabilityProbe(ctx, readWriteConnection)
	require.NoError(t, err, "an unassumable default role must not make the credential unconnectable")
	require.Error(
		t,
		unassumableProbe.AppendFixture(ctx, serviceName, "00000000-0000-0000-0000-000000000008"),
		"an unassumable default role must leave the session as the unprivileged principal",
	)
	require.NoError(t, unassumableProbe.Close())

	// Reconciliation restores it, and dropping the delegated roles clears the
	// default rather than leaving the principal pointed at a role it has lost.
	require.NoError(t, runtime.ensureRuntimeAccess(ctx))
	restoredProbe, err := openPostgresCapabilityProbe(ctx, readWriteConnection)
	require.NoError(t, err)
	require.NoError(
		t,
		restoredProbe.AppendFixture(ctx, serviceName, "00000000-0000-0000-0000-000000000009"),
		"reconciliation must restore the delegated writer's default role",
	)
	require.NoError(t, restoredProbe.Close())

	runtime.RuntimeReadWriteRoles = nil
	require.NoError(t, runtime.ensureRuntimeAccess(ctx))
	genericProbe, err := openPostgresCapabilityProbe(ctx, readWriteConnection)
	require.NoError(t, err)
	require.NoError(
		t,
		genericProbe.AppendFixture(ctx, serviceName, "00000000-0000-0000-0000-00000000000a"),
		"removing the delegated roles must restore direct write authority",
	)
	require.NoError(t, genericProbe.Close())
	runtime.RuntimeReadWriteRoles = []string{delegatedWriter}
	require.NoError(t, runtime.ensureRuntimeAccess(ctx))

	maintenance, closeMaintenance, err := scoped.OpenMaintenance(ctx, readWriteConnection, delegatedWriter, scoped.WithOperationTimeout(5*time.Second))
	require.NoError(t, err)
	maintenanceWriter, err := maintenance.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, maintenanceWriter.InTransaction(ctx, func(ctx context.Context, tx scoped.WriteTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO "+pq.QuoteIdentifier(serviceName)+" (id) VALUES ($1)", "10000000-0000-0000-0000-000000000001")
		return err
	}))
	require.Error(t, maintenanceWriter.InTransaction(ctx, func(ctx context.Context, tx scoped.WriteTx) error {
		_, err := tx.Exec(ctx, "CREATE TABLE forbidden_maintenance(id integer)")
		return err
	}))
	closeMaintenance()
	closeMaintenance()
	_, closeOwner, err := scoped.OpenMaintenance(ctx, runtime.connection, delegatedWriter, scoped.WithOperationTimeout(5*time.Second))
	if err == nil {
		closeOwner()
	}
	require.Error(t, err, "maintenance must not accept the migration owner")

	assertExternalIdentityReconciliation(t, ctx, migrationControl)
	assertExternalIdentityTokenAuthentication(t, ctx, readOnlyConnection, readWriteConnection)
	assertSchemaPrerequisitesFailClosed(t, ctx, migrationControl, runtime.connection, readWriteConnection)

	if runtimeContext.Kind == resources.RuntimeContextContainer {
		assertDockerStateSurvivesContainerRecreation(t, ctx, fixture, runtime, serviceName, fixtureID)
	}
}

// assertMigrationConnectionsAreOwned proves the real golang-migrate boundary
// does not retain a backend after startup or after an explicit handle close.
// It runs inside the existing Docker/Nix lifecycle, so no fake database or
// second infrastructure harness is needed.
func assertMigrationConnectionsAreOwned(t *testing.T, ctx context.Context, runtime *Runtime) {
	t.Helper()
	probePool, err := sql.Open("postgres", runtime.connection)
	require.NoError(t, err)
	defer probePool.Close()
	probe, err := probePool.Conn(ctx)
	require.NoError(t, err)
	defer probe.Close()

	countOtherBackends := func() int {
		var count int
		err := probe.QueryRowContext(ctx, `
			SELECT count(*)
			FROM pg_stat_activity
			WHERE datname = current_database()
			  AND pid <> pg_backend_pid()
		`).Scan(&count)
		require.NoError(t, err)
		return count
	}
	require.Zero(t, countOtherBackends(), "startup migrations retained database backends")

	handle, err := runtime.openMigration(ctx, migrationSource{dir: runtime.Local("migrations")})
	require.NoError(t, err)
	require.Equal(t, 1, countOtherBackends(), "one migration handle must own exactly one backend")
	require.NoError(t, handle.Close())

	deadline := time.Now().Add(2 * time.Second)
	for countOtherBackends() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("closed migration handle retained a database backend")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// assertStrayMigrationFilesDoNotBlockLineage exercises the editor-leftover case
// against the real database. A backup keeping a migration's own prefix parses as
// the same version and direction as the file it shadows, which used to make the
// source driver refuse every migration path — startup and hot reload alike. A
// genuine version collision must still fail, naming both files.
//
// Hot reload is forward-only, so the leftovers are visible here at two distinct
// layers and both must hold: a change event naming one is not a migration event
// at all, and a leftover merely SITTING beside a migration must not stop the
// lineage being read. The second is what proves the directory is filtered —
// before that filter the apply died on "duplicate migration file" instead of
// reaching its forward-only verdict.
func assertStrayMigrationFilesDoNotBlockLineage(
	t *testing.T,
	ctx context.Context,
	runtime *Runtime,
	owner *postgresCapabilityProbe,
	migrationDirectory string,
	migrationUp string,
	relation string,
) {
	t.Helper()

	const strayRelation = "stray_must_not_apply"
	for _, stray := range []string{
		"2_replay.up.sql~",
		"2_replay.up.sql.bak",
		"2_replay.up.sql.orig",
		".2_replay.up.sql.swp",
	} {
		strayPath := path.Join(migrationDirectory, stray)
		require.NoError(t, os.WriteFile(
			strayPath,
			[]byte("CREATE TABLE "+pq.QuoteIdentifier(strayRelation)+" (id UUID PRIMARY KEY);"),
			0o600,
		))
		defer os.Remove(strayPath)
	}

	require.NoError(t, applyMigrations(t, ctx, runtime), "startup migrations must ignore editor leftovers")

	// A save that writes a backup emits a change event for that file too. Acting
	// on it would replay the version it shadows — down then up — and destroy the
	// rows in the table that migration owns.
	survivorID := "00000000-0000-0000-0000-000000000010"
	require.NoError(t, owner.AppendFixture(ctx, relation, survivorID))
	applied, err := runtime.applyMigrationChange(ctx, path.Join(migrationDirectory, "2_replay.up.sql.bak"))
	require.NoError(t, err, "a change event for a non-migration file must be ignored")
	require.False(t, applied, "an ignored file must not reach the database at all")
	survived, err := owner.HasFixture(ctx, relation, survivorID)
	require.NoError(t, err)
	require.True(t, survived, "an editor backup must not trigger a destructive migration replay")

	// Re-saving migration 2 while the leftovers sit beside it: the lineage is
	// read (the leftovers are filtered out of the source), and the event is then
	// declined because version 2 is already applied — not because the directory
	// could not be parsed.
	applied, err = runtime.applyMigrationChange(ctx, migrationUp)
	require.ErrorIs(t, err, errAppliedMigrationEdited, "hot reload must ignore editor leftovers")
	require.False(t, applied)
	exists, err := owner.RelationExists(ctx, relation)
	require.NoError(t, err)
	require.True(t, exists, "the migration the leftovers shadow must stay applied")
	exists, err = owner.RelationExists(ctx, strayRelation)
	require.NoError(t, err)
	require.False(t, exists, "no SQL from an ignored file may reach the database")

	conflictPath := path.Join(migrationDirectory, "2_conflict.up.sql")
	require.NoError(t, os.WriteFile(conflictPath, []byte("SELECT 1;"), 0o600))
	defer os.Remove(conflictPath)
	err = applyMigrations(t, ctx, runtime)
	require.ErrorContains(t, err, "2_conflict.up.sql")
	require.ErrorContains(t, err, "2_replay.up.sql")
}

func assertDockerStateSurvivesContainerRecreation(
	t *testing.T,
	ctx context.Context,
	fixture *postgresFixture,
	initial *Runtime,
	relation string,
	fixtureID string,
) {
	t.Helper()

	_, err := initial.Destroy(ctx, &runtimev0.DestroyRequest{})
	require.NoError(t, err)

	restarted, init := fixture.start(t, ctx)

	nativeConfiguration, err := resources.ExtractConfiguration(
		init.RuntimeConfigurations,
		resources.NewRuntimeContextNative(),
	)
	require.NoError(t, err)
	readOnlyConnection, err := resources.GetConfigurationValue(
		ctx,
		nativeConfiguration,
		"postgres",
		readOnlyConnectionKey,
	)
	require.NoError(t, err)
	reader, err := openPostgresCapabilityProbe(ctx, readOnlyConnection)
	require.NoError(t, err)
	defer reader.Close()

	found, err := reader.HasFixture(ctx, relation, fixtureID)
	require.NoError(t, err)
	require.True(t, found, "data written before container recreation must remain available")
	require.NotEmpty(t, restarted.retainedDataPath)
}

// assertExternalIdentityReconciliation drives the runtime role reconciler in
// external-identity mode against an isolated real database: the login
// principals are created out-of-band, codefly creates only the _ro/_rw NOLOGIN
// group roles, and reconciles the principals into exactly their group role
// without ever issuing a password.
func assertExternalIdentityReconciliation(t *testing.T, ctx context.Context, control *migrationtest.ControlPlane) {
	t.Helper()
	isolate, err := control.Create(ctx, "service_postgres_external_identity")
	require.NoError(t, err)
	defer isolate.Drop(context.Background())

	readOnlyGroup, readWriteGroup := runtimeRoleNames(isolate.Name)
	readerPrincipal := readOnlyGroup + "_p"
	writerPrincipal := readWriteGroup + "_p"

	base := pgcontrol.RuntimeAccess{
		Database:                          isolate.Name,
		OwnerRole:                         "postgres",
		ReadOnlyRole:                      readOnlyGroup,
		ReadWriteRole:                     readWriteGroup,
		Schemas:                           []string{"public"},
		AuthMode:                          pgcontrol.AuthModeExternalIdentity,
		ReconcileReadWriteRoleMemberships: true,
	}
	reconcile := func(access pgcontrol.RuntimeAccess) error {
		tx, err := isolate.DB.BeginTx(ctx, nil)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback() }()
		if err := pgcontrol.ReconcileRuntimeAccess(ctx, tx, access); err != nil {
			return err
		}
		return tx.Commit()
	}

	// An external principal that the cloud has not created fails loud.
	missing := base
	missing.ReadWritePrincipals = []string{writerPrincipal}
	require.ErrorContains(t, reconcile(missing), "does not exist")

	for _, principal := range []string{readerPrincipal, writerPrincipal} {
		_, err = isolate.DB.ExecContext(ctx, "CREATE ROLE "+pq.QuoteIdentifier(principal)+" LOGIN")
		require.NoError(t, err)
	}
	_, err = isolate.DB.ExecContext(ctx, "CREATE TABLE ext_fixture (id integer)")
	require.NoError(t, err)

	full := base
	full.ReadOnlyPrincipals = []string{readerPrincipal}
	full.ReadWritePrincipals = []string{writerPrincipal}
	require.NoError(t, reconcile(full))

	// The managed group roles are NOLOGIN and never received a password.
	for _, group := range []string{readOnlyGroup, readWriteGroup} {
		var canLogin, hasPassword bool
		require.NoError(t, isolate.DB.QueryRowContext(ctx,
			"SELECT rolcanlogin, rolpassword IS NOT NULL FROM pg_authid WHERE rolname = $1", group,
		).Scan(&canLogin, &hasPassword))
		require.Falsef(t, canLogin, "managed group role %q must be NOLOGIN in external-identity mode", group)
		require.Falsef(t, hasPassword, "managed group role %q must not carry a password", group)
	}

	require.ElementsMatch(t, []string{readOnlyGroup}, principalGroupMemberships(t, ctx, isolate.DB, readerPrincipal))
	require.ElementsMatch(t, []string{readWriteGroup}, principalGroupMemberships(t, ctx, isolate.DB, writerPrincipal))

	// The group membership confers effective privilege by inheritance: the
	// writer principal can write, the reader principal can read but not write.
	assertPrincipalInsert := func(principal string, wantOK bool) {
		conn, err := isolate.DB.Conn(ctx)
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.ExecContext(ctx, "SET ROLE "+pq.QuoteIdentifier(principal))
		require.NoError(t, err)
		_, insertErr := conn.ExecContext(ctx, "INSERT INTO ext_fixture (id) VALUES (1)")
		_, _ = conn.ExecContext(ctx, "RESET ROLE")
		if wantOK {
			require.NoError(t, insertErr, "writer principal must inherit write access via its group role")
		} else {
			require.Error(t, insertErr, "reader principal must not inherit write access")
		}
	}
	assertPrincipalInsert(writerPrincipal, true)
	assertPrincipalInsert(readerPrincipal, false)
	readerConn, err := isolate.DB.Conn(ctx)
	require.NoError(t, err)
	defer readerConn.Close()
	_, err = readerConn.ExecContext(ctx, "SET ROLE "+pq.QuoteIdentifier(readerPrincipal))
	require.NoError(t, err)
	var readable int
	require.NoError(t, readerConn.QueryRowContext(ctx, "SELECT count(*) FROM ext_fixture").Scan(&readable),
		"reader principal must inherit read access via its group role")
	_, _ = readerConn.ExecContext(ctx, "RESET ROLE")

	// A membership the principal holds outside the managed group is not touched:
	// the reconciler owns the group's membership, not the cloud principal's.
	strayRole := readWriteGroup + "_stray"
	_, err = isolate.DB.ExecContext(ctx, "CREATE ROLE "+pq.QuoteIdentifier(strayRole)+" NOLOGIN")
	require.NoError(t, err)
	_, err = isolate.DB.ExecContext(ctx, "GRANT "+pq.QuoteIdentifier(strayRole)+" TO "+pq.QuoteIdentifier(writerPrincipal))
	require.NoError(t, err)
	require.NoError(t, reconcile(full))
	require.ElementsMatch(t, []string{readWriteGroup, strayRole}, principalGroupMemberships(t, ctx, isolate.DB, writerPrincipal))

	// A principal dropped from the configured set is revoked from the group,
	// idempotently, without disturbing the principals still configured.
	retiredPrincipal := readWriteGroup + "_retired"
	_, err = isolate.DB.ExecContext(ctx, "CREATE ROLE "+pq.QuoteIdentifier(retiredPrincipal)+" LOGIN")
	require.NoError(t, err)
	withRetired := full
	withRetired.ReadWritePrincipals = []string{writerPrincipal, retiredPrincipal}
	require.NoError(t, reconcile(withRetired))
	require.ElementsMatch(t, []string{readWriteGroup}, principalGroupMemberships(t, ctx, isolate.DB, retiredPrincipal))
	require.NoError(t, reconcile(full))
	require.Empty(t, principalGroupMemberships(t, ctx, isolate.DB, retiredPrincipal))
	require.NoError(t, reconcile(full))
	require.Empty(t, principalGroupMemberships(t, ctx, isolate.DB, retiredPrincipal))
	require.ElementsMatch(t, []string{readWriteGroup, strayRole}, principalGroupMemberships(t, ctx, isolate.DB, writerPrincipal))
}

// assertExternalIdentityTokenAuthentication proves the passwordless DSN + token
// contract end to end through the real consumer entrypoint: the reader/writer
// login roles authenticate with a per-principal token supplied via
// WithAccessTokenProvider (pgx BeforeConnect), with no password in the DSN.
func assertExternalIdentityTokenAuthentication(t *testing.T, ctx context.Context, readOnlyConnection, readWriteConnection string) {
	t.Helper()
	readerUser, readerPassword, readerPasswordless := splitConnectionPassword(t, readOnlyConnection)
	writerUser, writerPassword, writerPasswordless := splitConnectionPassword(t, readWriteConnection)
	require.NotContains(t, readerPasswordless, readerPassword, "passwordless DSN still carried the reader password")
	require.NotContains(t, writerPasswordless, writerPassword, "passwordless DSN still carried the writer password")

	tokens := map[string]string{readerUser: readerPassword, writerUser: writerPassword}
	provider := func(_ context.Context, principal string) (string, error) {
		token, ok := tokens[principal]
		if !ok {
			return "", fmt.Errorf("no token minted for principal %q", principal)
		}
		return token, nil
	}
	_, closeFactory, err := scoped.Open(
		ctx,
		readerPasswordless,
		writerPasswordless,
		contextAuthenticator{},
		scoped.WithAccessTokenProvider(provider),
	)
	require.NoError(t, err, "passwordless reader/writer DSNs must authenticate with per-principal tokens")
	closeFactory()

	// A provider that cannot mint a token fails the connection loudly instead of
	// falling back to an unauthenticated or password path.
	_, _, err = scoped.Open(
		ctx,
		readerPasswordless,
		writerPasswordless,
		contextAuthenticator{},
		scoped.WithAccessTokenProvider(func(context.Context, string) (string, error) {
			return "", fmt.Errorf("token unavailable")
		}),
	)
	require.Error(t, err, "a failed token acquisition must abort connection")
}

// assertSchemaPrerequisitesFailClosed proves the declared schema contract
// against a real Postgres. A declaration that cannot resolve fails before any
// migration side effect — a sentinel ledger stays untouched and no new tracking
// table appears. A required extension the server cannot install fails readiness
// with an actionable diagnostic, whether the library is absent or the principal
// lacks the privilege; the same declaration marked optional reports a skip.
func assertSchemaPrerequisitesFailClosed(
	t *testing.T,
	ctx context.Context,
	control *migrationtest.ControlPlane,
	ownerConnection string,
	unprivilegedConnection string,
) {
	t.Helper()
	isolate, err := control.Create(ctx, "service_postgres_schema_prerequisites")
	require.NoError(t, err)
	defer isolate.Drop(context.Background())

	_, err = isolate.DB.ExecContext(ctx,
		`CREATE TABLE schema_migrations_sentinel (version bigint not null primary key, dirty boolean not null)`)
	require.NoError(t, err)
	_, err = isolate.DB.ExecContext(ctx, `INSERT INTO schema_migrations_sentinel (version, dirty) VALUES (7, false)`)
	require.NoError(t, err)

	requireNoMigrationSideEffect := func() {
		t.Helper()
		var version int64
		var dirty bool
		require.NoError(t, isolate.DB.QueryRowContext(ctx,
			`SELECT version, dirty FROM schema_migrations_sentinel`).Scan(&version, &dirty))
		require.EqualValues(t, 7, version, "a rejected declaration moved an existing ledger")
		require.False(t, dirty, "a rejected declaration dirtied an existing ledger")
		var ledgers int
		require.NoError(t, isolate.DB.QueryRowContext(ctx, `
			SELECT count(*) FROM pg_tables
			WHERE schemaname = 'public'
			  AND tablename LIKE 'schema\_migrations%'
			  AND tablename <> 'schema_migrations_sentinel'`).Scan(&ledgers))
		require.Zero(t, ledgers, "a rejected declaration created a migration ledger")
	}

	overlength := strings.Repeat("a", maxIdentifierBytes-len(migrationTablePrefix)+1)
	for name, declared := range map[string][]MigrationSource{
		"missing explicit path": {{Name: "api", Path: "../nowhere/migrations"}},
		"empty name":            {{Name: "  "}},
		"duplicate name":        {{Name: "api"}, {Name: "api", Path: "../other/migrations"}},
		"overlength name":       {{Name: overlength}},
	} {
		candidate := newRuntimeForDatabase(t, ownerConnection, isolate.Name)
		candidate.Settings.MigrationSources = declared
		_, resolveErr := candidate.resolveSchemaPrerequisites()
		require.Errorf(t, resolveErr, "declaration %q must be rejected", name)
		requireNoMigrationSideEffect()
	}

	// A resolvable declaration applies: the own lineage keeps the legacy default
	// ledger and the declared source gets its own.
	accepted := newRuntimeForDatabase(t, ownerConnection, isolate.Name)
	writeMigrationDirectory(t, filepath.Join(accepted.Location, "..", "api", "migrations"),
		"CREATE TABLE IF NOT EXISTS prerequisite_api (id integer);")
	accepted.Settings.MigrationSources = []MigrationSource{{Name: "api"}}
	prerequisites, err := accepted.resolveSchemaPrerequisites()
	require.NoError(t, err)
	require.NoError(t, accepted.applySchema(ctx, prerequisites))
	for _, ledger := range []string{"schema_migrations", "schema_migrations_api"} {
		var present bool
		require.NoError(t, isolate.DB.QueryRowContext(ctx,
			`SELECT to_regclass('public.' || $1) IS NOT NULL`, ledger).Scan(&present))
		require.Truef(t, present, "lineage ledger %q was not created", ledger)
	}

	const absentExtension = "codefly-absent-extension"

	unavailable := newRuntimeForDatabase(t, ownerConnection, isolate.Name)
	unavailable.Settings.Extensions = []Extension{{Name: absentExtension}}
	prerequisites, err = unavailable.resolveSchemaPrerequisites()
	require.NoError(t, err)
	require.ErrorContains(t, unavailable.applySchema(ctx, prerequisites),
		`cannot create required extension "`+absentExtension+`"`)

	optional := newRuntimeForDatabase(t, ownerConnection, isolate.Name)
	optional.Settings.Extensions = []Extension{{Name: absentExtension, Optional: true}}
	prerequisites, err = optional.resolveSchemaPrerequisites()
	require.NoError(t, err)
	require.NoError(t, optional.applySchema(ctx, prerequisites))
	require.Contains(t, skippedPrerequisiteNames(prerequisites, prerequisiteExtension), absentExtension,
		"an explicitly optional extension must report a structured skipped result")

	// A principal without the privilege to install extensions fails readiness
	// rather than reporting a database that silently lacks the extension.
	unprivileged := newRuntimeForDatabase(t, unprivilegedConnection, isolate.Name)
	unprivileged.Settings.Extensions = []Extension{{Name: "hstore"}}
	prerequisites, err = unprivileged.resolveSchemaPrerequisites()
	require.NoError(t, err)
	require.ErrorContains(t, unprivileged.applySchema(ctx, prerequisites),
		`cannot create required extension "hstore"`)
}

// newRuntimeForDatabase points a runtime at one isolated database, with a
// service directory that owns a single valid migration.
func newRuntimeForDatabase(t *testing.T, connection, database string) *Runtime {
	t.Helper()
	parsed, err := url.Parse(connection)
	require.NoError(t, err)
	parsed.Path = "/" + database

	runtime := NewRuntime()
	runtime.Location = filepath.Join(t.TempDir(), "store")
	runtime.Settings.DatabaseName = database
	runtime.connection = parsed.String()
	writeMigrationDirectory(t, filepath.Join(runtime.Location, "migrations"),
		"CREATE TABLE IF NOT EXISTS prerequisite_store (id integer);")
	return runtime
}

func writeMigrationDirectory(t *testing.T, directory, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(directory, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "1_init.up.sql"), []byte(body), 0o600))
}

func skippedPrerequisiteNames(prerequisites *schemaPrerequisites, kind string) []string {
	var names []string
	for _, skipped := range prerequisites.skipped {
		if skipped.kind == kind {
			names = append(names, skipped.name)
		}
	}
	return names
}

func splitConnectionPassword(t *testing.T, connection string) (user, password, passwordless string) {
	t.Helper()
	parsed, err := url.Parse(connection)
	require.NoError(t, err)
	user = parsed.User.Username()
	password, _ = parsed.User.Password()
	require.NotEmpty(t, password, "test fixture connection must carry a password to strip")
	parsed.User = url.User(user)
	return user, password, parsed.String()
}

func principalGroupMemberships(t *testing.T, ctx context.Context, db *sql.DB, principal string) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		SELECT granted.rolname
		FROM pg_auth_members membership
		JOIN pg_roles granted ON granted.oid = membership.roleid
		JOIN pg_roles member ON member.oid = membership.member
		WHERE member.rolname = $1`, principal)
	require.NoError(t, err)
	defer rows.Close()
	var memberships []string
	for rows.Next() {
		var role string
		require.NoError(t, rows.Scan(&role))
		memberships = append(memberships, role)
	}
	require.NoError(t, rows.Err())
	return memberships
}
