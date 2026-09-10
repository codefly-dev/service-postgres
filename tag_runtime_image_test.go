package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	taggedImage  = "ghcr.io/codefly-dev/service-postgres@sha256:d8847e56"
	taggedDigest = "sha256:d8847e56"
	taggedTag    = "ghcr.io/codefly-dev/service-postgres:postgres-17.10-pgvector-0.8.5-alpine3.24"
)

func TestTagRuntimeImageRetriesUntilTheTagResolves(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log, 2, taggedDigest)

	require.NoErrorf(t, err, "output: %s", output)
	calls := readCalls(t, log)
	require.Equal(t, "buildx imagetools create --tag "+taggedTag+" "+taggedImage+" ", calls[0])
	require.Len(t, calls, 4)
}

func TestTagRuntimeImageFailsWhenTheTagNeverResolves(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log, 5, taggedDigest)

	require.Error(t, err)
	require.Contains(t, output, taggedTag+" was published but did not resolve to a digest")
	require.Len(t, readCalls(t, log), 6)
}

func TestTagRuntimeImageFailsWhenTheTagHoldsAnotherDigest(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log, 0, "sha256:0ther")

	require.Error(t, err)
	require.Contains(t, output, "tagged digest sha256:0ther does not match "+taggedDigest)
	require.Len(t, readCalls(t, log), 2)
}

// runTagRuntimeImage runs the tagging script against a docker whose reads of the
// tag fail the first inspectFailures times, standing in for a registry that has
// not propagated the tag yet.
func runTagRuntimeImage(t *testing.T, log string, inspectFailures int, digest string) (string, error) {
	t.Helper()
	command := exec.Command("bash", ".github/scripts/tag-runtime-image.sh")
	command.Env = append(os.Environ(),
		"PATH="+fakeDocker(t)+string(os.PathListSeparator)+os.Getenv("PATH"),
		"DOCKER_LOG="+log,
		"DOCKER_INSPECT_DIGEST="+digest,
		"DOCKER_INSPECT_FAILURES="+strconv.Itoa(inspectFailures),
		"EXPECTED_DIGEST="+taggedDigest,
		"RUNTIME_IMAGE="+taggedImage,
		"RUNTIME_TAG="+taggedTag,
	)
	output, err := command.CombinedOutput()
	return string(output), err
}

// fakeDocker also shadows sleep so the backoff does not slow the test down.
func fakeDocker(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	for name, source := range map[string]string{
		"docker": `#!/usr/bin/env bash
set -euo pipefail
printf '%s ' "$@" >>"$DOCKER_LOG"
printf '\n' >>"$DOCKER_LOG"
if [[ "$3" != inspect ]]; then
  exit 0
fi
if (($(grep -c 'imagetools inspect' "$DOCKER_LOG") <= DOCKER_INSPECT_FAILURES)); then
  echo "ERROR: unexpected status from HEAD request to $4: 404 Not Found" >&2
  exit 1
fi
printf 'Name:      %s\nDigest:    %s\n' "$4" "$DOCKER_INSPECT_DIGEST"
`,
		"sleep": "#!/usr/bin/env bash\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(source), 0o755))
	}
	return bin
}
