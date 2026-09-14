package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/core/agents/services/sbom"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/stretchr/testify/require"
)

// The scanner resolves a manifest list to one child digest per platform, so the
// evidence a platform carries must be the child's digest and never the list's.
var (
	runtimeAMD64Digest   = testImageDigest("a11")
	runtimeARM64Digest   = testImageDigest("a22")
	bootstrapAMD64Digest = testImageDigest("b11")
	bootstrapARM64Digest = testImageDigest("b22")
)

func testImageDigest(seed string) string {
	return "sha256:" + seed + strings.Repeat("0", 64-len(seed))
}

// TestImageSBOMCoversEveryShippedImageAndPlatform drives the whole contract the
// way the CLI does: build the recipe, derive the subjects the build plan
// declares, ask for image scope, and measure the answer with the shared
// conformance check rather than with assertions of this test's own invention.
func TestImageSBOMCoversEveryShippedImageAndPlatform(t *testing.T) {
	builder := newBuildTestBuilder(t)
	log := stubScanner(t, scanner{})

	response, err := builder.Build(t.Context(), buildRequest(t.TempDir()))
	require.NoError(t, err)
	plan := response.GetResult().GetDockerBuildPlan()
	expected := sbom.ExpectedFromBuildPlan(builder.Unique(), plan)
	require.Len(t, expected, 2, "the bootstrap recipe ships two platforms")

	sbomResponse, err := builder.SBOM(t.Context(), &builderv0.SBOMRequest{
		Scope:    builderv0.SBOMScope_SBOM_SCOPE_IMAGE,
		Subjects: expected,
	})
	require.NoError(t, err)
	require.Equal(t, builderv0.SBOMStatus_COMPLETE, sbomResponse.GetState().GetState(),
		sbomResponse.GetState().GetMessage())
	require.Equal(t, builderv0.SBOMScope_SBOM_SCOPE_IMAGE, sbomResponse.GetScope())
	require.Equal(t, builderv0.NoImageReason_NO_IMAGE_REASON_UNSPECIFIED, sbomResponse.GetNoImageReason())
	require.NoError(t, sbom.ValidateCoverage(expected, sbomResponse))

	covered := map[string]*builderv0.ImageSBOM{}
	for _, evidence := range sbomResponse.GetImages() {
		require.NotEmpty(t, evidence.GetSha256(), "evidence must carry its own document checksum")
		covered[evidence.GetDigest()] = evidence
	}
	require.Equal(t,
		[]string{runtimeAMD64Digest, runtimeARM64Digest, bootstrapAMD64Digest, bootstrapARM64Digest},
		sortedKeys(covered),
		"every shipped image and platform is bound to the digest it was scanned from")

	// The postgres image is deployed rather than built, so it appears in no
	// build plan: the agent is the only party that can name it.
	runtime := covered[runtimeAMD64Digest]
	require.Equal(t, "linux/amd64", runtime.GetPlatform())
	require.Len(t, runtime.GetSubjects(), 1)
	require.Equal(t, image.FullName(), runtime.GetSubjects()[0].GetReference())
	require.Equal(t, runtimeImageRole, runtime.GetSubjects()[0].GetRole())
	require.Equal(t, builder.Unique(), runtime.GetSubjects()[0].GetService())

	for digest, evidence := range covered {
		architecture := "amd64"
		if strings.HasSuffix(evidence.GetPlatform(), "arm64") {
			architecture = "arm64"
		}
		require.Contains(t, purls(evidence.GetBom()), "pkg:apk/alpine/musl@1.2.5-r9?arch="+architecture,
			"%s must inventory the OS packages of the platform it describes", digest)
		require.Contains(t, purls(evidence.GetBom()), "pkg:generic/pgvector@0.8.5",
			"%s must inventory installed application dependencies", digest)
	}

	// Four subjects, four scans: the list is resolved once per platform and the
	// inventory is pinned to the child digest that resolution returned.
	require.Equal(t, []string{
		"registry:" + image.Name + "@" + runtimeAMD64Digest,
		"registry:" + image.Name + "@" + runtimeARM64Digest,
		"registry:" + bootstrapImageName + "@" + bootstrapAMD64Digest,
		"registry:" + bootstrapImageName + "@" + bootstrapARM64Digest,
	}, sortedScans(t, log))
}

// An agent that cannot name every image it ships must fail the request rather
// than answer for the subset it happens to know.
func TestImageSBOMWithoutSubjectsRefusesToClaimCoverage(t *testing.T) {
	builder := newBuildTestBuilder(t)
	log := stubScanner(t, scanner{})

	response, err := builder.SBOM(t.Context(), &builderv0.SBOMRequest{
		Scope: builderv0.SBOMScope_SBOM_SCOPE_IMAGE,
	})
	require.NoError(t, err)
	require.Equal(t, builderv0.SBOMStatus_ERROR, response.GetState().GetState())
	require.Equal(t, builderv0.SBOMScope_SBOM_SCOPE_IMAGE, response.GetScope())
	require.Equal(t, basev0.FailureCode_FAILURE_CODE_PRECONDITION_FAILED,
		response.GetState().GetFailure().GetCode())
	require.Empty(t, response.GetImages())
	require.Equal(t, builderv0.NoImageReason_NO_IMAGE_REASON_UNSPECIFIED, response.GetNoImageReason(),
		"a service that does ship images must never claim a no-image reason")
	require.ErrorContains(t,
		sbom.ValidateCoverage([]*builderv0.ImageSubject{{
			Reference: bootstrapImageName, Platform: "linux/amd64", Role: "bootstrap", Service: builder.Unique(),
		}}, response),
		"does not build its own images")
	require.NoFileExists(t, log, "nothing may be scanned once the request is refused")
}

// A failed scan is reported with the cause the scanner gave, under image scope
// so the caller can tell which request failed.
func TestImageSBOMReportsAFailedScanRatherThanPartialCoverage(t *testing.T) {
	builder := newBuildTestBuilder(t)
	stubScanner(t, scanner{failure: "syft exited 1: no space left on device"})

	response, err := builder.SBOM(t.Context(), &builderv0.SBOMRequest{
		Scope: builderv0.SBOMScope_SBOM_SCOPE_IMAGE,
		Subjects: []*builderv0.ImageSubject{{
			Reference: bootstrapImageName, Platform: "linux/amd64", Role: "bootstrap", Service: builder.Unique(),
		}},
	})
	require.NoError(t, err)
	require.Equal(t, builderv0.SBOMStatus_ERROR, response.GetState().GetState())
	require.Equal(t, builderv0.SBOMScope_SBOM_SCOPE_IMAGE, response.GetScope())
	require.Empty(t, response.GetImages())
	require.Contains(t, response.GetState().GetMessage(), "no space left on device")
}

// One scan answers for every service that runs that exact image: the digest is
// inventoried once and keeps both associations.
func TestImageSBOMDeduplicatesASharedDigestWithoutLosingSubjects(t *testing.T) {
	builder := newBuildTestBuilder(t)
	log := stubScanner(t, scanner{})
	neighbour := &builderv0.ImageSubject{
		Reference: image.FullName(),
		Platform:  "linux/amd64",
		Role:      runtimeImageRole,
		Service:   "module/other-postgres",
	}

	response, err := builder.SBOM(t.Context(), &builderv0.SBOMRequest{
		Scope:    builderv0.SBOMScope_SBOM_SCOPE_IMAGE,
		Subjects: []*builderv0.ImageSubject{neighbour},
	})
	require.NoError(t, err)
	require.Equal(t, builderv0.SBOMStatus_COMPLETE, response.GetState().GetState(),
		response.GetState().GetMessage())

	require.Len(t, response.GetImages(), 2, "the shared digest is reported once, not once per subject")
	shared := evidenceFor(t, response, runtimeAMD64Digest)
	require.Equal(t, []string{builder.Unique(), "module/other-postgres"}, subjectServices(shared))
	require.Equal(t, image.FullName(), shared.GetSubjects()[1].GetReference())
	require.NotEmpty(t, scans(t, log))
}

// The source inventory this agent has always served is preserved, and is still
// rejected as image coverage.
func TestSourceScopeStillInventoriesTheConfiguredImage(t *testing.T) {
	builder := newBuildTestBuilder(t)
	log := stubScanner(t, scanner{})

	response, err := builder.SBOM(t.Context(), &builderv0.SBOMRequest{})
	require.NoError(t, err)
	require.Equal(t, builderv0.SBOMStatus_COMPLETE, response.GetState().GetState(),
		response.GetState().GetMessage())
	require.Equal(t, builderv0.SBOMScope_SBOM_SCOPE_SOURCE, response.GetScope())
	require.Equal(t, []string{"registry:" + image.FullName()}, scans(t, log))
	require.ErrorContains(t,
		sbom.ValidateCoverage([]*builderv0.ImageSubject{{
			Reference: image.FullName(), Role: runtimeImageRole, Service: builder.Unique(),
		}}, response),
		"not image coverage")
}

func TestRuntimeImageSubjectsFollowTheLockedPlatformsAndTheOverride(t *testing.T) {
	builder := newBuildTestBuilder(t)

	locked := builder.runtimeImageSubjects()
	require.Len(t, locked, len(image.Platforms))
	for index, subject := range locked {
		require.Equal(t, image.FullName(), subject.GetReference())
		require.Equal(t, image.Platforms[index], subject.GetPlatform())
		require.Equal(t, runtimeImageRole, subject.GetRole())
		require.Equal(t, builder.Unique(), subject.GetService())
		require.Empty(t, subject.GetDigest(),
			"evidence binds to the platform's child manifest, not to the manifest list")
	}

	builder.Settings.Image = "postgis/postgis:17-3.5"
	overridden := builder.runtimeImageSubjects()
	require.Len(t, overridden, 1)
	require.Equal(t, "postgis/postgis:17-3.5", overridden[0].GetReference())
	require.Empty(t, overridden[0].GetPlatform(),
		"an override's platforms are not locked here, so the scanner resolves them")
}

// bootstrapImageName is the image the recipe emitted by newBuildTestBuilder's
// build context names.
const bootstrapImageName = "registry.example.com/module/postgres"

type scanner struct {
	// failure is the stderr a failing scan reports; empty means every scan
	// succeeds.
	failure string
}

// stubScanner puts a docker and a syft on PATH that answer like the real ones:
// docker resolves a manifest list to per-platform children, syft emits a
// CycloneDX inventory carrying OS packages and installed application
// dependencies for the platform it was pointed at. It returns the path of the
// log both write, which is also how a test proves nothing was scanned.
func stubScanner(t *testing.T, options scanner) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "scanner.log")
	for name, source := range map[string]string{
		"docker": `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$SCANNER_LOG"
case "$4" in
  "$RUNTIME_IMAGE_NAME"*) amd64=$RUNTIME_AMD64_DIGEST; arm64=$RUNTIME_ARM64_DIGEST ;;
  *) amd64=$BOOTSTRAP_AMD64_DIGEST; arm64=$BOOTSTRAP_ARM64_DIGEST ;;
esac
cat <<JSON
{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:list","manifests":[
  {"digest":"$amd64","platform":{"architecture":"amd64","os":"linux"}},
  {"digest":"$arm64","platform":{"architecture":"arm64","os":"linux"}}]}
JSON
`,
		"syft": `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$SCANNER_LOG"
if [[ -n "${SYFT_FAILURE:-}" ]]; then
  echo "$SYFT_FAILURE" >&2
  exit 1
fi
architecture=unknown
case "$1" in
  *"$RUNTIME_AMD64_DIGEST"|*"$BOOTSTRAP_AMD64_DIGEST") architecture=amd64 ;;
  *"$RUNTIME_ARM64_DIGEST"|*"$BOOTSTRAP_ARM64_DIGEST") architecture=arm64 ;;
esac
cat <<JSON
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {"component": {"bom-ref": "${1#registry:}", "type": "container", "name": "${1#registry:}"}},
  "components": [
    {"bom-ref": "pkg:apk/alpine/musl@1.2.5-r9?arch=$architecture", "type": "library",
     "name": "musl", "version": "1.2.5-r9", "purl": "pkg:apk/alpine/musl@1.2.5-r9?arch=$architecture"},
    {"bom-ref": "pkg:generic/pgvector@0.8.5", "type": "library",
     "name": "pgvector", "version": "0.8.5", "purl": "pkg:generic/pgvector@0.8.5"}
  ]
}
JSON
`,
	} {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(source), 0o755))
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SCANNER_LOG", log)
	t.Setenv("SYFT_FAILURE", options.failure)
	t.Setenv("RUNTIME_IMAGE_NAME", image.Name)
	t.Setenv("RUNTIME_AMD64_DIGEST", runtimeAMD64Digest)
	t.Setenv("RUNTIME_ARM64_DIGEST", runtimeARM64Digest)
	t.Setenv("BOOTSTRAP_AMD64_DIGEST", bootstrapAMD64Digest)
	t.Setenv("BOOTSTRAP_ARM64_DIGEST", bootstrapARM64Digest)
	return log
}

// scans returns the targets syft was pointed at, in call order.
func scans(t *testing.T, log string) []string {
	t.Helper()
	content, err := os.ReadFile(log)
	require.NoError(t, err)
	var targets []string
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		if target, _, found := strings.Cut(line, " -o cyclonedx-json@1.5"); found {
			targets = append(targets, target)
		}
	}
	return targets
}

func sortedScans(t *testing.T, log string) []string {
	t.Helper()
	targets := scans(t, log)
	slices.Sort(targets)
	return targets
}

func sortedKeys(evidence map[string]*builderv0.ImageSBOM) []string {
	keys := make([]string, 0, len(evidence))
	for key := range evidence {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func evidenceFor(t *testing.T, response *builderv0.SBOMResponse, digest string) *builderv0.ImageSBOM {
	t.Helper()
	for _, evidence := range response.GetImages() {
		if evidence.GetDigest() == digest {
			return evidence
		}
	}
	t.Fatalf("no image evidence for digest %s", digest)
	return nil
}

func subjectServices(evidence *builderv0.ImageSBOM) []string {
	var names []string
	for _, subject := range evidence.GetSubjects() {
		names = append(names, subject.GetService())
	}
	return names
}

func purls(bom *agentv0.Bom) []string {
	var values []string
	for _, component := range bom.GetComponents() {
		values = append(values, component.GetPurl())
	}
	return values
}
