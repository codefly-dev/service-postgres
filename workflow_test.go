package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type workflowDefinition struct {
	Permissions map[string]string      `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
	Uses        string            `yaml:"uses"`
}

type workflowStep struct {
	Name string         `yaml:"name"`
	If   string         `yaml:"if"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
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
	qualification := findWorkflowStep(t, workflow.Jobs["image"], "Qualify sustained WAL budget")
	require.Empty(t, qualification.If)
	require.Contains(t, qualification.Run, "-run '^TestSustainedWALBudgetDocker$'")
	require.Contains(t, qualification.Run, "-count=1")

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
	scanIndex, scan := findWorkflowStepAt(t, imageJob, "Scan published runtime image")
	tagIndex, tag := findWorkflowStepAt(t, imageJob, "Tag verified runtime image")
	require.Less(t, candidateIndex, verifyCandidateIndex)
	require.Less(t, verifyCandidateIndex, publishedIndex)
	require.Less(t, publishedIndex, scanIndex)
	require.Less(t, scanIndex, tagIndex)
	require.Equal(t,
		"type=image,name=${{ steps.runtime.outputs.name }},push-by-digest=true,name-canonical=true,push=true,rewrite-timestamp=true",
		candidate.With["outputs"],
	)
	require.Equal(t, false, candidate.With["provenance"])
	require.Equal(t, false, candidate.With["sbom"])
	require.Contains(t, verifyCandidate.Run, `"$ACTUAL_DIGEST" != "$EXPECTED_DIGEST"`)
	require.Contains(t, scan.Run, `docker save --output /tmp/service-postgres-image.tar "$RUNTIME_IMAGE"`)
	require.Contains(t, tag.Run, `docker buildx imagetools create --tag "$RUNTIME_TAG" "$RUNTIME_IMAGE"`)

	buildx := findWorkflowAction(t, imageJob, "docker/setup-buildx-action")
	require.Equal(t,
		"image=moby/buildkit@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
		buildx.With["driver-opts"],
	)
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
	publish := findWorkflowStep(t, imageJob, "Publish release image tags")
	require.Contains(t, publish.Run, `"$RUNTIME_IMAGE"`)
	require.Contains(t, publish.Run, "docker buildx imagetools create")
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
