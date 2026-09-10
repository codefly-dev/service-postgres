package main

import (
	"context"
	"net/url"
	"strings"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/stretchr/testify/require"
)

// The delegated read-write principal is NOINHERIT and holds its write authority
// only through the configured application role, so the credential must arrive
// already running as that role. It is set as the login's session default
// server-side; nothing about it is encoded in the DSN.
func TestExportedReadWriteConnectionCarriesNoRoleStartupParameter(t *testing.T) {
	for _, roles := range [][]string{nil, {"app_documents"}, {"app_documents", "app_worker"}} {
		svc := newTestPostgresService()
		svc.DatabaseName = "accounts"
		svc.RuntimeReadWriteRoles = roles

		configuration, err := svc.CreateConnectionConfiguration(
			context.Background(),
			testPostgresConfiguration("migration-owner", "owner-secret", "reader-secret", "writer-secret"),
			&basev0.NetworkInstance{Address: "database.internal:5432", Access: resources.NewNativeNetworkAccess()},
			true,
		)
		require.NoError(t, err)

		readWrite := configurationValue(t, configuration, readWriteConnectionKey)
		parsed, err := url.Parse(readWrite)
		require.NoError(t, err)

		// A `role` startup parameter turns a role the principal cannot yet assume
		// into a FATAL that refuses the connection outright, taking reads and
		// health checks down with it, and it never reaches the restricted deploy
		// profile, which exports these keys without values.
		require.Empty(t, parsed.Query().Get("options"),
			"roles=%v: the read-write DSN must not encode a role", roles)
		require.NotContains(t, readWrite, "role", "roles=%v", roles)

		_, readWriteRole := runtimeRoleNames(svc.DatabaseName)
		assertConnectionIdentity(t, readWrite, readWriteRole, "writer-secret")
	}
}

// Keying the default to the first entry rather than to "there is exactly one"
// is what keeps appending a role from silently dropping every consumer back to
// "permission denied" on its first write.
func TestDefaultRuntimeReadWriteRoleIsStableWhenRolesAreAppended(t *testing.T) {
	require.Equal(t, "", defaultRuntimeReadWriteRole(nil), "no configured role selects none")
	require.Equal(t, "app_documents", defaultRuntimeReadWriteRole([]string{"app_documents"}))
	require.Equal(t, "app_documents", defaultRuntimeReadWriteRole([]string{"app_documents", "app_worker"}),
		"appending a role must not change the session default")
	require.Equal(t, "app_documents",
		defaultRuntimeReadWriteRole([]string{"app_documents", "app_worker", "app_backfill"}))
	require.Equal(t, "app_worker", defaultRuntimeReadWriteRole([]string{"app_worker", "app_documents"}),
		"reordering the list is the way to change the default")
}

// The bootstrap Job runs runtime-access.sql in every deploy profile, including
// the restricted one whose connection strings this agent never authors, so the
// default role has to be established there too.
func TestRuntimeAccessTemplateSetsTheDefaultReadWriteRole(t *testing.T) {
	base := DockerTemplating{
		MigrationConnectionKeyHolder: "{" + migrationConnectionEnvironmentKey + "}",
		ReadOnlyRole:                 "codefly_app_ro",
		ReadWriteRole:                "codefly_app_rw",
		Schemas:                      []string{"public"},
	}

	delegated := base
	delegated.ReadWriteRoles = []string{"app_documents", "app_worker"}
	delegated.DefaultReadWriteRole = defaultRuntimeReadWriteRole(delegated.ReadWriteRoles)
	accessSQL := renderRuntimeAccessTemplate(t, delegated)
	require.Contains(t, accessSQL,
		"SELECT format('ALTER ROLE %I SET role = %L', 'codefly_app_rw', 'app_documents')",
		"the delegated login must default to the first configured role")
	require.NotContains(t, accessSQL, "RESET role")
	// The default is established after the memberships it depends on.
	require.Greater(t, strings.Index(accessSQL, "SET role = %L"), strings.Index(accessSQL, "GRANT %I TO %I"),
		"the default role must be set after the membership GRANTs")

	generic := base
	genericSQL := renderRuntimeAccessTemplate(t, generic)
	require.Contains(t, genericSQL, "SELECT format('ALTER ROLE %I RESET role', 'codefly_app_rw')",
		"without delegated roles the login must carry no default role")
	require.NotContains(t, genericSQL, "SET role = %L")
}
