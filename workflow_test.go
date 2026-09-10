package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type workflowDefinition struct {
	Permissions map[string]string      `yaml:"permissions"`
	Concurrency workflowConcurrency    `yaml:"concurrency"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowConcurrency struct {
	Group            string `yaml:"group"`
	CancelInProgress bool   `yaml:"cancel-in-progress"`
}

type workflowJob struct {
	Permissions    map[string]string `yaml:"permissions"`
	TimeoutMinutes int               `yaml:"timeout-minutes"`
	Steps          []workflowStep    `yaml:"steps"`
	Uses           string            `yaml:"uses"`
}

type workflowStep struct {
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

// TestCIWorkflowEnforcesMigrationRegression locks the wiring that keeps the
// dirty-migration fail-closed regression actually running in CI. It must run
// unconditionally, after the runtime image is built locally (so it needs no
// registry credentials, which this job only acquires later), and it must declare
// SERVICE_POSTGRES_TEST_IMAGE — the flag that turns a missing docker daemon into
// a failure instead of a skip. Without these, the regression can silently stop
// enforcing anything while the build stays green.
func TestCIWorkflowEnforcesMigrationRegression(t *testing.T) {
	imageJob := readWorkflow(t, ".github/workflows/ci.yml").Jobs["image"]

	buildIndex, _ := findWorkflowStepAt(t, imageJob, "Build runtime image")
	regressionIndex, regression := findWorkflowStepAt(t, imageJob, "Migration fail-closed regression")
	require.Less(t, buildIndex, regressionIndex, "the regression must run after the image it uses is built")

	require.Empty(t, regression.If, "the regression must never be conditionally skipped")
	require.Equal(t, "service-postgres:test", regression.Env["SERVICE_POSTGRES_TEST_IMAGE"],
		"the regression must run against the locally built image, which also makes the prerequisite mandatory")
	require.Contains(t, regression.Run, "TestDirtyMigrationFailsClosed")

	// The unit-test step deliberately carries no container-booting test; the
	// regression must therefore be excluded there and present here, not neither.
	unitTests := findWorkflowStep(t, imageJob, "Run unit tests")
	require.Contains(t, unitTests.Run, "TestDirtyMigrationFailsClosed",
		"the unit-test step must exclude the container-booting regression")
}

func TestCIWorkflowValidatesLockedImageForEveryPullRequest(t *testing.T) {
	workflow := readWorkflow(t, ".github/workflows/ci.yml")
	require.Equal(t, map[string]string{"contents": "read"}, workflow.Permissions)
	require.Equal(t, map[string]string{"contents": "read"}, workflow.Jobs["ci"].Permissions)
	require.Equal(t, map[string]string{
		"contents": "read",
		"packages": "write",
	}, workflow.Jobs["image"].Permissions)
	require.Regexp(t, `@[0-9a-f]{40}$`, workflow.Jobs["ci"].Uses)

	unitTests := findWorkflowStep(t, workflow.Jobs["image"], "Run unit tests")
	require.Empty(t, unitTests.If)
	// The lifecycle contract drives a real agent against the LOCKED runtime
	// image, so it cannot run in the pre-publish unit-test step: a commit that
	// relocks the digest would send it pulling an image this job has not pushed
	// yet. It runs unconditionally once that image is verified present.
	require.Contains(t, unitTests.Run, "TestLifecycleContractDocker")
	lifecycle := findWorkflowStep(t, workflow.Jobs["image"], "Run runtime lifecycle tests")
	require.Empty(t, lifecycle.If)
	require.Contains(t, lifecycle.Run, "^TestLifecycleContractDocker$")

	smoke := findWorkflowStep(t, workflow.Jobs["image"], "Smoke test runtime image")
	require.Contains(t, smoke.Run, "--read-only")
	require.Contains(t, smoke.Run, "--tmpfs /var/run/postgresql:uid=70,gid=70")
	require.Contains(t, smoke.Run, "--tmpfs /tmp:uid=70,gid=70")

	verify := findWorkflowStep(t, workflow.Jobs["image"], "Verify published runtime image")
	require.Contains(t, verify.Run, `--config "$anonymous_docker_config"`)
	require.Contains(t, verify.Run, `"$RUNTIME_IMAGE"`)
	require.Contains(t, verify.Run, `"linux/amd64"`)
	require.Contains(t, verify.Run, `"linux/arm64"`)

	imageJob := workflow.Jobs["image"]
	candidateIndex, candidate := findWorkflowStepAt(t, imageJob, "Publish runtime image candidate")
	verifyCandidateIndex, verifyCandidate := findWorkflowStepAt(t, imageJob, "Verify runtime image candidate")
	publishedIndex, _ := findWorkflowStepAt(t, imageJob, "Verify published runtime image")
	lifecycleIndex, _ := findWorkflowStepAt(t, imageJob, "Run runtime lifecycle tests")
	scanIndex, scan := findWorkflowStepAt(t, imageJob, "Scan published runtime image")
	tagIndex, tag := findWorkflowStepAt(t, imageJob, "Tag verified runtime image")
	require.Less(t, candidateIndex, verifyCandidateIndex)
	require.Less(t, verifyCandidateIndex, publishedIndex)
	require.Less(t, publishedIndex, lifecycleIndex)
	require.Less(t, lifecycleIndex, scanIndex)
	require.Less(t, scanIndex, tagIndex)
	require.Equal(t,
		"type=image,name=${{ steps.runtime.outputs.name }},push-by-digest=true,name-canonical=true,push=true,rewrite-timestamp=true",
		candidate.With["outputs"],
	)
	require.Equal(t, false, candidate.With["provenance"])
	require.Equal(t, false, candidate.With["sbom"])
	require.Contains(t, verifyCandidate.Run, `"$ACTUAL_DIGEST" != "$EXPECTED_DIGEST"`)
	require.Contains(t, scan.Run, `docker save --output /tmp/service-postgres-image.tar "$RUNTIME_IMAGE"`)
	require.Equal(t, `.github/scripts/tag-runtime-image.sh "$RUNTIME_TAG"`, strings.TrimSpace(tag.Run))
	require.Equal(t, map[string]string{
		"EXPECTED_DIGEST": "${{ steps.runtime.outputs.digest }}",
		"RUNTIME_IMAGE":   "${{ steps.runtime.outputs.reference }}",
		"RUNTIME_TAG":     "${{ steps.runtime.outputs.tag_reference }}",
	}, tag.Env)

	buildx := findWorkflowAction(t, imageJob, "docker/setup-buildx-action")
	require.Equal(t,
		"image=moby/buildkit@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
		buildx.With["driver-opts"],
	)
}

// The runtime tag string is read from runtime-image.json, so every branch
// resolves the same one and the ref-keyed concurrency group does not serialize
// branches against each other. Only a push may move it: a PR build that did
// would race every other PR on that single tag, and would repoint what releases
// consume before merging. The candidate publish keeps the wider guard — it
// pushes by digest, moves no tag, and the verification below it needs that push
// for a same-repo PR that relocks the digest.
func TestCIWorkflowMovesTheSharedRuntimeTagOnlyOnPush(t *testing.T) {
	imageJob := readWorkflow(t, ".github/workflows/ci.yml").Jobs["image"]

	tag := findWorkflowStep(t, imageJob, "Tag verified runtime image")
	require.Equal(t, "github.event_name == 'push'", tag.If)

	candidate := findWorkflowStep(t, imageJob, "Publish runtime image candidate")
	require.Contains(t, candidate.If,
		"github.event.pull_request.head.repo.full_name == github.repository")
}

func TestReleaseWorkflowRetagsLockedImageWithLeastPrivilege(t *testing.T) {
	workflow := readWorkflow(t, ".github/workflows/releaser.yml")
	require.Equal(t, map[string]string{"contents": "read"}, workflow.Permissions)
	require.Equal(t, map[string]string{
		"contents": "read",
		"packages": "write",
	}, workflow.Jobs["image"].Permissions)
	require.Equal(t, map[string]string{"contents": "read"}, workflow.Jobs["release"].Permissions)
	require.Equal(t, map[string]string{"contents": "read"}, workflow.Jobs["backfill"].Permissions)
	require.Regexp(t, `@[0-9a-f]{40}$`, workflow.Jobs["release"].Uses)

	imageJob := workflow.Jobs["image"]
	for _, step := range imageJob.Steps {
		require.NotContains(t, step.Uses, "docker/build-push-action")
	}
	// The release publishes two tags and reads both back, which is the same
	// propagation race the CI step hit, so it has to go through the same
	// retrying script rather than its own create-then-inspect.
	publish := findWorkflowStep(t, imageJob, "Publish release image tags")
	require.NotContains(t, publish.Run, "docker buildx imagetools",
		"the release must not read a tag back on its own")
	require.Equal(t, "${{ github.ref_name }}", publish.Env["RELEASE_TAG"])

	// Two releases publishing at once each see the other's digest on the shared
	// runtime tag, and the read-back retry holds that window open for minutes.
	require.Equal(t, "${{ github.workflow }}", workflow.Concurrency.Group)
	require.False(t, workflow.Concurrency.CancelInProgress,
		"cancelling would abandon a half-published release")
	require.NotZero(t, imageJob.TimeoutMinutes,
		"a hung registry read must not run to GitHub's six-hour default")
	buildx := findWorkflowAction(t, imageJob, "docker/setup-buildx-action")
	require.Equal(t,
		"image=moby/buildkit@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
		buildx.With["driver-opts"],
	)

	for _, step := range workflow.Jobs["backfill"].Steps {
		if step.Uses != "" {
			require.Regexp(t, `@[0-9a-f]{40}$`, step.Uses)
		}
	}
}

func TestRuntimeDockerfilePinsReproducibleBuildInputs(t *testing.T) {
	content, err := os.ReadFile("Dockerfile")
	require.NoError(t, err)
	dockerfile := string(content)
	require.Contains(t, dockerfile, "# syntax=docker/dockerfile:1.7@sha256:")
	require.Contains(t, dockerfile, "ARG POSTGRES_IMAGE=postgres:17.10-alpine3.24@sha256:")
	require.Contains(t, dockerfile, "ARG SOURCE_DATE_EPOCH=0")
	require.Contains(t, dockerfile, "build-base=0.5-r4")
	require.Contains(t, dockerfile, "clang21=21.1.8-r3")
	require.Contains(t, dockerfile, "llvm21-dev=21.1.8-r1")
	require.Contains(t, dockerfile, "libcrypto3=3.5.8-r0")
	require.Contains(t, dockerfile, "libssl3=3.5.8-r0")
	require.Contains(t, dockerfile, "libuuid=2.42.3-r1")
	require.Contains(t, dockerfile, "su-exec=0.3-r0")
	require.Contains(t, dockerfile, "RUN rm /usr/local/bin/gosu")
	require.Contains(t, dockerfile, "ln -s /sbin/su-exec /usr/local/bin/gosu")
	require.Contains(t, dockerfile, "rm /var/log/apk.log")
	require.NotContains(t, dockerfile, "FROM scratch")
	require.NotContains(t, dockerfile, "COPY --from=runtime / /")
}

func readWorkflow(t *testing.T, path string) workflowDefinition {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var workflow workflowDefinition
	require.NoError(t, yaml.Unmarshal(content, &workflow))
	return workflow
}

func findWorkflowStep(t *testing.T, job workflowJob, name string) workflowStep {
	t.Helper()
	_, step := findWorkflowStepAt(t, job, name)
	return step
}

func findWorkflowStepAt(t *testing.T, job workflowJob, name string) (int, workflowStep) {
	t.Helper()
	for index, step := range job.Steps {
		if step.Name == name {
			return index, step
		}
	}
	var names []string
	for _, step := range job.Steps {
		names = append(names, step.Name)
	}
	t.Fatalf("workflow step %q not found in %s", name, strings.Join(names, ", "))
	return -1, workflowStep{}
}

func findWorkflowAction(t *testing.T, job workflowJob, action string) workflowStep {
	t.Helper()
	for _, step := range job.Steps {
		if strings.Contains(step.Uses, action) {
			return step
		}
	}
	t.Fatalf("workflow action %q not found", action)
	return workflowStep{}
}

// releaser.yml's image job only runs on a v* tag push, so nothing else exercises
// this step before a real release. Running its own shell against a fake registry
// covers the wiring the string assertions cannot: that the tags it derives from
// the lock are the ones published, that a lagging read is retried rather than
// fatal, and that the script is invoked the way the step actually invokes it.
func TestReleaseStepPublishesBothLockedTagsPastALaggingRead(t *testing.T) {
	var lock struct {
		Name   string `json:"name"`
		Tag    string `json:"tag"`
		Digest string `json:"digest"`
	}
	content, err := os.ReadFile("runtime-image.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(content, &lock))

	imageJob := readWorkflow(t, ".github/workflows/releaser.yml").Jobs["image"]
	publish := findWorkflowStep(t, imageJob, "Publish release image tags")
	log := filepath.Join(t.TempDir(), "docker.log")
	command := exec.Command("bash", "-c", publish.Run)
	command.Env = append(os.Environ(),
		"PATH="+fakeDocker(t)+string(os.PathListSeparator)+os.Getenv("PATH"),
		"DOCKER_LOG="+log,
		"DOCKER_FAILED_READS=1",
		"DOCKER_STALE_READS=0",
		"DOCKER_STALE_DIGEST="+staleDigest,
		"DOCKER_DIGEST="+lock.Digest,
		"DOCKER_UNREADABLE_TAG=",
		"RELEASE_TAG=v0.0.130",
	)
	output, err := command.CombinedOutput()

	require.NoErrorf(t, err, "output: %s", output)
	calls := readCalls(t, log)
	require.Equal(t,
		"buildx imagetools create --tag "+lock.Name+":v0.0.130 --tag "+lock.Name+":"+lock.Tag+
			" "+lock.Name+"@"+lock.Digest+" ",
		calls[0],
		"the release publishes exactly the two references the lock describes",
	)
	require.Len(t, calls, 5, "one create, then each tag read past its 404")
}
