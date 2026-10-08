package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestReleaseWorkflowRoutesDevTagsWithoutTheSharedGate(t *testing.T) {
	payload, err := os.ReadFile(".github/workflows/releaser.yml")
	require.NoError(t, err)
	var trigger struct {
		On struct {
			Push struct{ Tags []string }
		}
	}
	require.NoError(t, yaml.Unmarshal(payload, &trigger))
	require.Equal(t, []string{"v*"}, trigger.On.Push.Tags, "excluding dev tags removes their publisher")

	workflow := readWorkflow(t, ".github/workflows/releaser.yml")
	release := workflow.Jobs["release"]
	require.Equal(t, "github.event_name == 'push' && !contains(github.ref_name, '-dev.')", release.If)
	require.Equal(t, "image", release.Needs)
	require.Equal(t, "codefly-dev/core/.github/workflows/go-service-release.yml@e54bc852f3d40cd1aeafc0ced2369a8c13a51bb8", release.Uses,
		"core v0.16.0 enforces default-branch reachability for real releases")
	for _, name := range []string{"dev-build", "dev-publish"} {
		require.Equal(t, "github.event_name == 'push' && contains(github.ref_name, '-dev.')", workflow.Jobs[name].If)
		require.Empty(t, workflow.Jobs[name].Uses, "dev tags must not enter core's default-branch gate")
	}
	require.Equal(t, "github.event_name == 'workflow_dispatch'", workflow.Jobs["backfill"].If)
}

func TestDevReleaseBuildAndPublishAreSeparate(t *testing.T) {
	workflow := readWorkflow(t, ".github/workflows/releaser.yml")
	build := workflow.Jobs["dev-build"]
	publish := workflow.Jobs["dev-publish"]
	require.Equal(t, "image", build.Needs)
	require.Equal(t, "dev-build", publish.Needs)
	require.Equal(t, map[string]string{"contents": "read"}, build.Permissions)
	require.Equal(t, map[string]string{"contents": "write"}, publish.Permissions)
	checkout := findWorkflowAction(t, build, "actions/checkout")
	require.Equal(t, 0, checkout.With["fetch-depth"])
	require.Equal(t, false, checkout.With["persist-credentials"])
	qemu := -1
	for i, step := range build.Steps {
		if strings.HasPrefix(step.Uses, "docker/setup-qemu-action@") {
			qemu = i
		}
		for _, value := range step.Env {
			require.NotContains(t, value, "secrets.")
			require.NotContains(t, value, "github.token")
		}
	}
	testIndex, test := findWorkflowStepAt(t, build, "Test")
	require.GreaterOrEqual(t, qemu, 0)
	require.Less(t, qemu, testIndex)
	require.Equal(t, "go test -v ./...", test.Run)
	syftIndex, syft := findWorkflowStepAt(t, build, "Install Syft for archive SBOMs")
	buildIndex, goreleaser := findWorkflowStepAt(t, build, "Build dev release")
	uploadIndex, upload := findWorkflowStepAt(t, build, "Upload dev release")
	require.Less(t, testIndex, buildIndex)
	require.Less(t, syftIndex, buildIndex)
	require.Less(t, buildIndex, uploadIndex)
	require.Equal(t, "v1.44.0", syft.With["syft-version"])
	require.Equal(t, "release --clean --skip=publish,announce", goreleaser.With["args"])
	require.Equal(t, "error", upload.With["if-no-files-found"])
	require.Equal(t, "dist/*.tar.gz\ndist/*.tar.gz.sbom.json\ndist/*_checksums.txt\ndist/CHANGELOG.md\n", upload.With["path"])
	require.Len(t, publish.Steps, 2, "the publishing runner only downloads and uploads data")
	download := findWorkflowAction(t, publish, "actions/download-artifact")
	require.Equal(t, upload.With["name"], download.With["name"])
	require.Equal(t, "dist", download.With["path"])
	step := findWorkflowStep(t, publish, "Publish dev prerelease")
	require.Equal(t, "${{ github.token }}", step.Env["GH_TOKEN"])
	require.Equal(t, "${{ github.repository }}", step.Env["GH_REPO"])
	require.Equal(t, "${{ github.ref_name }}", step.Env["RELEASE_TAG"])
}

// Run the actual upload shell against a fake gh. Extra files must never become
// assets, and a missing SBOM must fail before creating a partial prerelease.
func TestDevPublisherRequiresAllSevenAssetsAndNeverPublishesStable(t *testing.T) {
	const devTag = "v0.0.139-dev.93280f407cc4"
	for _, tc := range []struct {
		name, tag, missing string
		wantSuccess        bool
	}{
		{name: "complete dev release", tag: devTag, wantSuccess: true},
		{name: "missing SBOM", tag: devTag, missing: "darwin_arm64.tar.gz.sbom.json"},
		{name: "missing archive", tag: devTag, missing: "linux_amd64.tar.gz"},
		{name: "missing checksums", tag: devTag, missing: "checksums.txt"},
		{name: "missing notes", tag: devTag, missing: "CHANGELOG.md"},
		{name: "stable", tag: "v0.0.141"},
		{name: "other prerelease", tag: "v0.0.141-rc.1"},
		{name: "malformed dev", tag: "v0.0.141-dev.not-a-sha"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(dir, "dist"), 0o755))
			assets := []string{"service-postgres_" + strings.TrimPrefix(tc.tag, "v") + "_checksums.txt"}
			for _, platform := range []string{"darwin_amd64", "darwin_arm64", "linux_amd64"} {
				archive := fmt.Sprintf("service-postgres_%s_%s.tar.gz", strings.TrimPrefix(tc.tag, "v"), platform)
				assets = append(assets, archive, archive+".sbom.json")
			}
			for _, name := range append(append([]string{}, assets...), "CHANGELOG.md", "unrelated.tar.gz", "hook.sh") {
				if tc.missing != "" && strings.HasSuffix(name, tc.missing) {
					continue
				}
				require.NoError(t, os.WriteFile(filepath.Join(dir, "dist", name), []byte("fixture"), 0o644))
			}
			log := filepath.Join(dir, "gh.log")
			step := findWorkflowStep(t, readWorkflow(t, ".github/workflows/releaser.yml").Jobs["dev-publish"], "Publish dev prerelease")
			command := exec.Command("bash", "-c", step.Run)
			command.Dir = dir
			command.Env = append(os.Environ(),
				"PATH="+fakeGitHubCLI(t)+string(os.PathListSeparator)+os.Getenv("PATH"),
				"GH_LOG="+log, "GH_TOKEN=test-token", "GH_REPO=codefly-dev/service-postgres", "RELEASE_TAG="+tc.tag)
			output, err := command.CombinedOutput()
			if !tc.wantSuccess {
				require.Error(t, err, string(output))
				_, err = os.Stat(log)
				require.True(t, os.IsNotExist(err), "no GitHub write may happen on invalid input")
				return
			}
			require.NoError(t, err, string(output))
			calls := readCalls(t, log)
			require.Len(t, calls, 1)
			want := "release create " + tc.tag
			for _, asset := range assets {
				want += " dist/" + asset
			}
			want += " --verify-tag --prerelease --latest=false --title " + tc.tag + " --notes-file dist/CHANGELOG.md"
			require.Equal(t, want, calls[0])
		})
	}
}

func TestDevTagValidationAcceptsOffMainAndUsesExactTag(t *testing.T) {
	dir := t.TempDir()
	runTestCommand(t, dir, nil, "git", "init", "--quiet", "--initial-branch=main")
	runTestCommand(t, dir, nil, "git", "config", "user.name", "Test")
	runTestCommand(t, dir, nil, "git", "config", "user.email", "test@example.com")
	runTestCommand(t, dir, nil, "git", "config", "commit.gpgsign", "false")
	runTestCommand(t, dir, nil, "git", "config", "tag.gpgsign", "false")
	runTestCommand(t, dir, nil, "git", "commit", "--quiet", "--allow-empty", "-m", "main")
	runTestCommand(t, dir, nil, "git", "checkout", "--quiet", "--detach")
	runTestCommand(t, dir, nil, "git", "commit", "--quiet", "--allow-empty", "-m", "off-main iteration")
	sha := strings.TrimSpace(runTestCommand(t, dir, nil, "git", "rev-parse", "HEAD"))
	tag := "v0.0.139-dev." + sha[:12]
	runTestCommand(t, dir, nil, "git", "tag", tag)
	// An annotated tag wins git describe over the lightweight dev tag.
	runTestCommand(t, dir, nil, "git", "tag", "-a", "v0.0.140", "-m", "another tag")
	require.Equal(t, "v0.0.140", strings.TrimSpace(runTestCommand(t, dir, nil, "git", "describe", "--tags", "--exact-match")))
	gate := exec.Command("git", "merge-base", "--is-ancestor", "HEAD", "main")
	gate.Dir = dir
	require.Error(t, gate.Run(), "fixture must be rejected by a default-branch reachability gate")

	script, err := os.ReadFile(".github/scripts/release-backfill.sh")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".github", "scripts"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".github", "scripts", "release-backfill.sh"), script, 0o755))
	envFile := filepath.Join(t.TempDir(), "github-env")
	step := findWorkflowStep(t, readWorkflow(t, ".github/workflows/releaser.yml").Jobs["dev-build"], "Validate dev tag")
	runTestCommand(t, dir, []string{"RELEASE_TAG=" + tag, "GITHUB_ENV=" + envFile}, "bash", "-c", step.Run)
	environment, err := os.ReadFile(envFile)
	require.NoError(t, err)
	require.Equal(t, "GORELEASER_CURRENT_TAG="+tag+"\n", string(environment))

	// A valid dev tag pointing at a different commit must still be rejected.
	runTestCommand(t, dir, nil, "git", "checkout", "--quiet", "main")
	command := exec.Command("bash", "-c", step.Run)
	command.Dir = dir
	command.Env = append(os.Environ(), "RELEASE_TAG="+tag, "GITHUB_ENV="+envFile)
	output, err := command.CombinedOutput()
	require.Error(t, err)
	require.Contains(t, string(output), "does not point at the checked-out commit")
}
