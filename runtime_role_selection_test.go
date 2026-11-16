package main

import (
	"context"
	"net/url"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	pgcontrol "github.com/codefly-dev/service-postgres/libs/go/controlplane"
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
	require.Equal(t, "", pgcontrol.DefaultReadWriteRole(nil), "no configured role selects none")
	require.Equal(t, "app_documents", pgcontrol.DefaultReadWriteRole([]string{"app_documents"}))
	require.Equal(t, "app_documents", pgcontrol.DefaultReadWriteRole([]string{"app_documents", "app_worker"}),
		"appending a role must not change the session default")
	require.Equal(t, "app_documents",
		pgcontrol.DefaultReadWriteRole([]string{"app_documents", "app_worker", "app_backfill"}))
	require.Equal(t, "app_worker", pgcontrol.DefaultReadWriteRole([]string{"app_worker", "app_documents"}),
		"reordering the list is the way to change the default")
}
