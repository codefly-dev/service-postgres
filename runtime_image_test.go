package main

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRuntimeImageLock(t *testing.T) {
	got, err := parseRuntimeImageLock([]byte(`{
		"name": "ghcr.io/codefly-dev/service-postgres",
		"tag": "postgres-17.10-pgvector-0.8.5-alpine3.24",
		"digest": "sha256:a5bb05518fd2f054884282f389577028c6304337bcf9d65363810ef1ad9e8c6c",
		"platforms": ["linux/amd64", "linux/arm64"]
	}`))
	require.NoError(t, err)
	require.Equal(t,
		"ghcr.io/codefly-dev/service-postgres@sha256:a5bb05518fd2f054884282f389577028c6304337bcf9d65363810ef1ad9e8c6c",
		got.FullName(),
	)
	require.Equal(t, "postgres-17.10-pgvector-0.8.5-alpine3.24", got.Tag)
	require.Equal(t, []string{"linux/amd64", "linux/arm64"}, got.Platforms)
}

func TestParseRuntimeImageLockRejectsIncompleteReference(t *testing.T) {
	_, err := parseRuntimeImageLock([]byte(`{
		"name": "ghcr.io/codefly-dev/service-postgres",
		"tag": "postgres-17.10-pgvector-0.8.5-alpine3.24"
	}`))
	require.EqualError(t, err, "runtime image digest is required")
}

// Image evidence describes one platform each, so a lock that names none leaves
// the shipped platforms to whatever a scan happens to pick.
func TestParseRuntimeImageLockRejectsUnknownPlatforms(t *testing.T) {
	for _, test := range []struct {
		name      string
		platforms string
		error     string
	}{
		{name: "absent", platforms: `[]`, error: "runtime image platforms are required"},
		{name: "architecture only", platforms: `["amd64"]`, error: `runtime image platform "amd64" must be os/arch`},
		{name: "empty architecture", platforms: `["linux/"]`, error: `runtime image platform "linux/" must be os/arch`},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseRuntimeImageLock([]byte(`{
				"name": "ghcr.io/codefly-dev/service-postgres",
				"tag": "postgres-17.10-pgvector-0.8.5-alpine3.24",
				"digest": "sha256:a5bb05518fd2f054884282f389577028c6304337bcf9d65363810ef1ad9e8c6c",
				"platforms": ` + test.platforms + `
			}`))
			require.EqualError(t, err, test.error)
		})
	}
}

func TestDefaultImageMatchesRuntimeImageLock(t *testing.T) {
	lock, err := os.ReadFile("runtime-image.json")
	require.NoError(t, err)
	expected, err := parseRuntimeImageLock(lock)
	require.NoError(t, err)
	require.Equal(t, expected, image)
}

// The platforms the lock declares are the platforms image evidence is produced
// for, so they must be the ones CI proves the published manifest actually
// ships. A lock that claimed a platform the image does not carry would turn
// into evidence nobody could bind to a real manifest.
func TestRuntimeImageLockPlatformsMatchThePublishedManifest(t *testing.T) {
	verify := findWorkflowStep(t, readWorkflow(t, ".github/workflows/ci.yml").Jobs["image"],
		"Verify published runtime image")

	quoted := make([]string, 0, len(image.Platforms))
	for _, platform := range image.Platforms {
		quoted = append(quoted, strconv.Quote(platform))
	}
	require.Contains(t, verify.Run, "["+strings.Join(quoted, ", ")+"]")
}
