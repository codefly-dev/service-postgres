package main

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// The read-write principal is NOINHERIT and holds its write authority only
// through the configured application role, so the credential handed out must
// already select that role — as a `role` startup parameter — or a consumer that
// uses the secret as-is fails its first query with "permission denied" (#94).
func TestWithSelectedRoleAppendsStartupParameter(t *testing.T) {
	base := postgresConnectionString("localhost:4180", "documents", "codefly_documents_rw", "pw", false, false)
	got := withSelectedRole(base, "app_documents")

	// The space is percent-encoded, never `+`: libpq takes `+` literally in a URI
	// query, while both libpq and pgx decode %20.
	require.Contains(t, got, "options=-c%20role%3Dapp_documents")
	require.NotContains(t, got, "+")

	parsed, err := url.Parse(got)
	require.NoError(t, err)
	require.Equal(t, "-c role=app_documents", parsed.Query().Get("options"))
	// The existing query survives.
	require.Equal(t, "disable", parsed.Query().Get("sslmode"))
	require.Equal(t, "codefly_documents_rw", parsed.User.Username())
	require.Equal(t, "/documents", parsed.Path)
}

func TestWithSelectedRoleOnBareConnection(t *testing.T) {
	got := withSelectedRole("postgresql://rw:pw@db.example:5432/app", "app_role")
	parsed, err := url.Parse(got)
	require.NoError(t, err)
	require.Equal(t, "-c role=app_role", parsed.Query().Get("options"))
}

func TestSelectedRuntimeReadWriteRole(t *testing.T) {
	require.Equal(t, "", selectedRuntimeReadWriteRole(nil), "no configured role selects none")
	require.Equal(t, "app_documents", selectedRuntimeReadWriteRole([]string{"app_documents"}), "exactly one is selected")
	require.Equal(t, "", selectedRuntimeReadWriteRole([]string{"app_a", "app_b"}), "several select none; consumers SET ROLE")
}
