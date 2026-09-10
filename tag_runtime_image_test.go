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
	staleDigest  = "sha256:5731ed01"
	taggedTag    = "ghcr.io/codefly-dev/service-postgres:postgres-17.10-pgvector-0.8.5-alpine3.24"
	releaseTag   = "ghcr.io/codefly-dev/service-postgres:v0.0.130"
)

// readBackBudget is the number of reads the script spends before it rules on
// the tag: one per propagation delay, plus the first read.
const readBackBudget = 8

// registry describes how ghcr.io answers reads of a tag just written: some
// reads failing outright, then some serving whatever digest the tag held
// before the push, then digest. The counts apply to each tag separately,
// because propagation is per tag.
type registry struct {
	failedReads int
	staleReads  int
	digest      string
	// unreadableTag never resolves, however many times it is read.
	unreadableTag string
}

func TestTagRuntimeImagePublishesTheTagBeforeReadingItBack(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log, registry{digest: taggedDigest}, taggedTag)

	require.NoErrorf(t, err, "output: %s", output)
	calls := readCalls(t, log)
	require.Equal(t, "buildx imagetools create --tag "+taggedTag+" "+taggedImage+" ", calls[0])
	require.Len(t, calls, 2, "a tag that reads back correctly costs one read")
}

func TestTagRuntimeImageRetriesWhileTheTagCannotBeRead(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log, registry{failedReads: 2, digest: taggedDigest}, taggedTag)

	require.NoErrorf(t, err, "output: %s", output)
	require.Len(t, readCalls(t, log), 4)
}

// A propagation lag can serve the digest the tag held before the push just as
// easily as it can fail the read, so a mismatch is no more final than an
// unreadable tag until the budget is spent.
func TestTagRuntimeImageRetriesWhileTheTagServesAStaleDigest(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log, registry{staleReads: 2, digest: taggedDigest}, taggedTag)

	require.NoErrorf(t, err, "output: %s", output)
	require.Len(t, readCalls(t, log), 4)
}

func TestTagRuntimeImageFailsWhenTheTagNeverBecomesReadable(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log, registry{failedReads: readBackBudget + 1}, taggedTag)

	require.Error(t, err)
	require.Contains(t, output, taggedTag+" was published but did not resolve to a digest")
	require.Len(t, readCalls(t, log), readBackBudget+1)
}

// The retry must still terminate: a tag that genuinely holds another digest —
// a concurrent build moved it — has to redden the job, naming what it found.
func TestTagRuntimeImageFailsWhenTheTagKeepsAnotherDigest(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log, registry{digest: staleDigest}, taggedTag)

	require.Error(t, err)
	require.Contains(t, output, taggedTag+" resolves to "+staleDigest+", want "+taggedDigest)
	require.Len(t, readCalls(t, log), readBackBudget+1)
}

// Without timeout every read fails, and the retry would report that as a tag
// that never resolved rather than as the missing dependency it is.
func TestTagRuntimeImageFailsLoudlyWithoutTimeout(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	command := tagRuntimeImageCommand(t, log, registry{digest: taggedDigest}, taggedTag)
	command.Env = append(command.Env, "PATH="+t.TempDir())
	output, err := command.CombinedOutput()

	require.Error(t, err)
	require.Contains(t, string(output), "timeout is required to bound registry reads")
}

// The release publishes the version tag and the runtime tag together, so one
// create has to carry both — and both have to be read back.
func TestTagRuntimeImagePublishesEveryTagInOneCreate(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log, registry{digest: taggedDigest}, releaseTag, taggedTag)

	require.NoErrorf(t, err, "output: %s", output)
	calls := readCalls(t, log)
	require.Equal(t,
		"buildx imagetools create --tag "+releaseTag+" --tag "+taggedTag+" "+taggedImage+" ",
		calls[0],
	)
	require.Len(t, calls, 3, "every tag is read back, not just the first")
}

// The first tag having propagated by the time it is read says nothing about the
// second, which is read later but lags on its own schedule.
func TestTagRuntimeImageSpendsTheReadBackBudgetOnEveryTag(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log, registry{failedReads: 2, digest: taggedDigest}, releaseTag, taggedTag)

	require.NoErrorf(t, err, "output: %s", output)
	require.Len(t, readCalls(t, log), 7, "one create, then three reads of each tag")
}

func TestTagRuntimeImageNamesTheLaterTagThatNeverResolves(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log,
		registry{digest: taggedDigest, unreadableTag: taggedTag}, releaseTag, taggedTag)

	require.Error(t, err)
	require.Contains(t, output, taggedTag+" was published but did not resolve to a digest")
	require.NotContains(t, output, releaseTag+" was published")
	require.Len(t, readCalls(t, log), readBackBudget+2,
		"one create, one read of the tag that resolved, then the full budget on the one that did not")
}

func TestTagRuntimeImageRefusesToPublishNothing(t *testing.T) {
	log := filepath.Join(t.TempDir(), "docker.log")
	output, err := runTagRuntimeImage(t, log, registry{digest: taggedDigest})

	require.Error(t, err)
	require.Contains(t, output, "at least one tag is required")
	require.NoFileExists(t, log, "a caller without tags must publish nothing")
}

func runTagRuntimeImage(t *testing.T, log string, ghcr registry, tags ...string) (string, error) {
	t.Helper()
	output, err := tagRuntimeImageCommand(t, log, ghcr, tags...).CombinedOutput()
	return string(output), err
}

func tagRuntimeImageCommand(t *testing.T, log string, ghcr registry, tags ...string) *exec.Cmd {
	t.Helper()
	command := exec.Command("bash", append([]string{".github/scripts/tag-runtime-image.sh"}, tags...)...)
	command.Env = append(os.Environ(),
		"PATH="+fakeDocker(t)+string(os.PathListSeparator)+os.Getenv("PATH"),
		"DOCKER_LOG="+log,
		"DOCKER_FAILED_READS="+strconv.Itoa(ghcr.failedReads),
		"DOCKER_STALE_READS="+strconv.Itoa(ghcr.staleReads),
		"DOCKER_STALE_DIGEST="+staleDigest,
		"DOCKER_DIGEST="+ghcr.digest,
		"DOCKER_UNREADABLE_TAG="+ghcr.unreadableTag,
		"EXPECTED_DIGEST="+taggedDigest,
		"RUNTIME_IMAGE="+taggedImage,
	)
	return command
}

// fakeDocker also shadows sleep, so the propagation budget does not become the
// test's runtime. Reads are counted per tag, the way a registry propagates them.
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
read_number=$(grep -cF "imagetools inspect $4 " "$DOCKER_LOG")
if [[ "$4" == "$DOCKER_UNREADABLE_TAG" ]] || ((read_number <= DOCKER_FAILED_READS)); then
  echo "ERROR: unexpected status from HEAD request to $4: 404 Not Found" >&2
  exit 1
fi
digest=$DOCKER_DIGEST
if ((read_number <= DOCKER_FAILED_READS + DOCKER_STALE_READS)); then
  digest=$DOCKER_STALE_DIGEST
fi
printf 'Name:      %s\nDigest:    %s\n' "$4" "$digest"
`,
		"sleep": "#!/usr/bin/env bash\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(source), 0o755))
	}
	return bin
}
