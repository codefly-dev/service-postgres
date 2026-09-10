package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBootstrapImageLockMatchesCommittedDocument(t *testing.T) {
	content, err := os.ReadFile("bootstrap-image.json")
	require.NoError(t, err)
	lock, err := parseBootstrapImageLock(content)
	require.NoError(t, err)
	require.Equal(t, lock, bootstrapLock)

	canonical, err := json.Marshal(lock)
	require.NoError(t, err)
	document := sha256.Sum256(canonical)
	require.Equal(t, "sha256:"+hex.EncodeToString(document[:]), bootstrapLock.LockDigest)
}

// TestBootstrapImageLockDigestIgnoresDocumentFormatting covers the value a consumer
// compares across two builds: reindenting the lock resolves the same inputs, so it
// must not report a different identity.
func TestBootstrapImageLockDigestIgnoresDocumentFormatting(t *testing.T) {
	document := committedBootstrapLockDocument(t)
	compact, err := json.Marshal(document)
	require.NoError(t, err)
	indented, err := json.MarshalIndent(document, "", "\t")
	require.NoError(t, err)
	require.NotEqual(t, compact, indented)

	fromCompact, err := parseBootstrapImageLock(compact)
	require.NoError(t, err)
	fromIndented, err := parseBootstrapImageLock(indented)
	require.NoError(t, err)

	require.Equal(t, bootstrapLock.LockDigest, fromCompact.LockDigest)
	require.Equal(t, bootstrapLock.LockDigest, fromIndented.LockDigest)
}

// TestBootstrapImageLockChecksumsMatchPublishedArchives is the check that makes a
// locked checksum falsifiable: it downloads each archive the lock pins and hashes
// it. Nothing else in the suite can tell a correct checksum from a plausible one —
// the template test only asserts the value is present, and the per-architecture
// build test needs emulation the host may not have.
func TestBootstrapImageLockChecksumsMatchPublishedArchives(t *testing.T) {
	for _, archive := range bootstrapLock.Migrate.Archives {
		t.Run(archive.Architecture, func(t *testing.T) {
			url := fmt.Sprintf(
				"https://github.com/golang-migrate/migrate/releases/download/%s/migrate.linux-%s.tar.gz",
				bootstrapLock.Migrate.Version, archive.Architecture,
			)
			response, err := http.Get(url)
			require.NoError(t, err, "cannot reach %s to verify the locked checksum", url)
			defer func() { require.NoError(t, response.Body.Close()) }()
			require.Equal(t, http.StatusOK, response.StatusCode, url)

			hasher := sha256.New()
			_, err = io.Copy(hasher, response.Body)
			require.NoError(t, err)
			require.Equal(t, archive.SHA256, hex.EncodeToString(hasher.Sum(nil)),
				"locked checksum does not match the archive published at %s", url)
		})
	}
}

// The bootstrap image downloads the migrate archive with curl and its command
// reconciles runtime access with psql, so both tools must stay pinned in the lock
// rather than being pulled from whatever the repository serves.
func TestBootstrapImageLockPinsBuildAndCommandTooling(t *testing.T) {
	pinned := map[string]string{}
	for _, entry := range bootstrapLock.Packages.Pinned {
		pinned[entry.Name] = entry.Version
	}
	require.Contains(t, pinned, "curl")
	require.Contains(t, pinned, "postgresql17-client")
}

func TestBootstrapProvenanceExposesEveryResolvedInput(t *testing.T) {
	provenance := bootstrapLock.Provenance()
	require.NotEmpty(t, provenance)

	arguments := map[string]bool{}
	labels := map[string]bool{}
	for _, entry := range provenance {
		require.NotEmpty(t, entry.Arg)
		require.NotEmpty(t, entry.Label)
		require.NotEmpty(t, entry.Value, entry.Arg)
		require.False(t, arguments[entry.Arg], "duplicate build argument %s", entry.Arg)
		require.False(t, labels[entry.Label], "duplicate label %s", entry.Label)
		arguments[entry.Arg] = true
		labels[entry.Label] = true
	}

	values := map[string]string{}
	for _, entry := range provenance {
		values[entry.Label] = entry.Value
	}
	require.Equal(t, bootstrapLock.LockDigest, values["dev.codefly.bootstrap.lock-digest"])
	require.Equal(t, bootstrapLock.Base.Reference(), values["dev.codefly.bootstrap.base"])
	require.Equal(t, bootstrapLock.Packages.Specs(), values["dev.codefly.bootstrap.apk-packages"])
	require.Equal(t, strings.Join(bootstrapLock.Packages.Repositories, " "), values["dev.codefly.bootstrap.apk-repositories"])
	require.Contains(t, values["dev.codefly.bootstrap.migrate-archives"], "amd64=")
	require.Contains(t, values["dev.codefly.bootstrap.migrate-archives"], "arm64=")

	buildArgs := bootstrapLock.RecipeBuildArgs()
	require.Len(t, buildArgs, len(provenance))
	for _, entry := range provenance {
		require.Equal(t, entry.Value, buildArgs[entry.Arg])
	}
}

func TestParseBootstrapImageLockRejectsUnverifiableInput(t *testing.T) {
	tests := []struct {
		name  string
		amend func(document map[string]any)
		error string
	}{
		{
			name:  "missing base digest",
			amend: func(document map[string]any) { lockBase(document)["digest"] = "" },
			error: "bootstrap base image digest must be a sha256 digest",
		},
		{
			name:  "base pinned by tag instead of digest",
			amend: func(document map[string]any) { lockBase(document)["digest"] = "3.21.7" },
			error: "bootstrap base image digest must be a sha256 digest",
		},
		{
			name:  "truncated base digest",
			amend: func(document map[string]any) { lockBase(document)["digest"] = "sha256:48b0309ca019d89d" },
			error: "bootstrap base image digest must be a sha256 digest",
		},
		{
			name:  "missing base version",
			amend: func(document map[string]any) { lockBase(document)["version"] = "" },
			error: "bootstrap base image version is required",
		},
		{
			name: "plaintext package repository",
			amend: func(document map[string]any) {
				lockPackages(document)["repositories"] = []any{"http://dl-cdn.alpinelinux.org/alpine/v3.21/main"}
			},
			error: `bootstrap apk repository must be an https URL, got "http://dl-cdn.alpinelinux.org/alpine/v3.21/main"`,
		},
		{
			name:  "package repository left on the previous release branch",
			amend: func(document map[string]any) { lockBase(document)["version"] = "3.22.1" },
			error: `bootstrap apk repository "https://dl-cdn.alpinelinux.org/alpine/v3.21/main" does not serve the locked Alpine v3.22 branch`,
		},
		{
			name: "package without an exact version",
			amend: func(document map[string]any) {
				lockPackages(document)["pinned"] = []any{map[string]any{"name": "curl", "version": ""}}
			},
			error: "bootstrap apk package curl must pin an exact version",
		},
		{
			name:  "no package repositories",
			amend: func(document map[string]any) { lockPackages(document)["repositories"] = []any{} },
			error: "bootstrap apk repositories are required",
		},
		{
			name:  "no pinned packages",
			amend: func(document map[string]any) { lockPackages(document)["pinned"] = []any{} },
			error: "bootstrap apk packages are required",
		},
		{
			name:  "migrate pinned to a moving reference",
			amend: func(document map[string]any) { lockMigrate(document)["version"] = "latest" },
			error: `bootstrap migrate version must be a release tag, got "latest"`,
		},
		{
			name: "archive without a checksum",
			amend: func(document map[string]any) {
				lockArchives(document)[0].(map[string]any)["sha256"] = ""
			},
			error: "bootstrap migrate amd64 archive checksum must be a sha256 checksum",
		},
		{
			name: "architecture locked twice",
			amend: func(document map[string]any) {
				lockArchives(document)[1].(map[string]any)["architecture"] = "amd64"
			},
			error: "bootstrap migrate archive for amd64 is locked twice",
		},
		{
			name: "unsupported architecture",
			amend: func(document map[string]any) {
				lockArchives(document)[1].(map[string]any)["architecture"] = "riscv64"
			},
			error: `bootstrap migrate archive architecture "riscv64" is not one of amd64, arm64`,
		},
		{
			name: "architecture missing from the lock",
			amend: func(document map[string]any) {
				lockMigrate(document)["archives"] = lockArchives(document)[:1]
			},
			error: "bootstrap migrate archive for arm64 is required",
		},
		{
			name: "unknown field",
			amend: func(document map[string]any) {
				lockMigrate(document)["checksums"] = map[string]any{"amd64": "unverified"}
			},
			error: `parse bootstrap image lock: json: unknown field "checksums"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := committedBootstrapLockDocument(t)
			test.amend(document)
			amended, err := json.Marshal(document)
			require.NoError(t, err)

			_, err = parseBootstrapImageLock(amended)
			require.EqualError(t, err, test.error)
		})
	}
}

func committedBootstrapLockDocument(t *testing.T) map[string]any {
	t.Helper()
	content, err := os.ReadFile("bootstrap-image.json")
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, json.Unmarshal(content, &document))
	return document
}

func lockBase(document map[string]any) map[string]any {
	return document["base"].(map[string]any)
}

func lockPackages(document map[string]any) map[string]any {
	return document["packages"].(map[string]any)
}

func lockMigrate(document map[string]any) map[string]any {
	return document["migrate"].(map[string]any)
}

func lockArchives(document map[string]any) []any {
	return lockMigrate(document)["archives"].([]any)
}

func TestBootstrapDockerfileLocksEveryInput(t *testing.T) {
	dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", DockerTemplating{
		MigrationConnectionKeyHolder: "{" + migrationConnectionEnvironmentKey + "}",
	})

	require.Contains(t, dockerfile, "FROM "+bootstrapLock.Base.Reference())
	require.NotContains(t, dockerfile, bootstrapLock.Base.Image+":", "base image must not resolve through a mutable tag")

	for _, repository := range bootstrapLock.Packages.Repositories {
		require.Contains(t, dockerfile, `"`+repository+`"`)
	}
	require.Contains(t, dockerfile, ">/etc/apk/repositories")
	require.Contains(t, dockerfile, "apk add --no-cache "+bootstrapLock.Packages.Specs())

	script := bootstrapMigrateInstallScript(t, dockerfile)
	for _, archive := range bootstrapLock.Migrate.Archives {
		require.Contains(t, script, archive.Architecture+") checksum="+archive.SHA256)
	}
	require.Contains(t, script, "/releases/download/"+bootstrapLock.Migrate.Version+"/migrate.linux-${architecture}.tar.gz")

	// The archive lands in a file that is checksum-verified before anything reads
	// it, so unverified bytes never reach tar — the shape a curl-into-tar pipe
	// cannot have.
	require.NotContains(t, script, "| tar")
	download := strings.Index(script, "-o /tmp/migrate.tar.gz")
	verification := strings.Index(script, "sha256sum -c -")
	extraction := strings.Index(script, "tar -xzf")
	installation := strings.Index(script, "install -m 0755")
	require.Positive(t, download)
	require.Greater(t, verification, download)
	require.Greater(t, extraction, verification)
	require.Greater(t, installation, extraction)

	// Literal label values, and no ARG behind them: a label that resolves a build
	// argument reports whatever the caller passed, not what built the image.
	for _, entry := range bootstrapLock.Provenance() {
		require.Contains(t, dockerfile, entry.Label+"=\""+entry.Value+"\"")
		require.NotContains(t, dockerfile, "ARG "+entry.Arg)
		require.NotContains(t, dockerfile, "$"+entry.Arg)
	}
}

// TestBootstrapDockerfileRendersFromZeroValueTemplating covers the locked inputs no
// caller passes in: they reach the template through DockerTemplating's own method,
// so a value constructed without them still renders a fully pinned image instead of
// failing at render with a nil dereference.
func TestBootstrapDockerfileRendersFromZeroValueTemplating(t *testing.T) {
	dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", DockerTemplating{})
	require.Contains(t, dockerfile, "FROM "+bootstrapLock.Base.Reference())
	require.Contains(t, dockerfile, "apk add --no-cache "+bootstrapLock.Packages.Specs())
}

// TestBootstrapImageBuildsLockedInputsPerArchitecture builds the image the
// template renders and reads back what the locked inputs actually resolved to: the
// base release, the pinned client version, and a migrate binary that executes on
// the target architecture and reports the locked version.
func TestBootstrapImageBuildsLockedInputsPerArchitecture(t *testing.T) {
	requireDocker(t)
	context := bootstrapBuildContext(t)

	machines := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}
	for _, architecture := range bootstrapArchitectures {
		t.Run(architecture, func(t *testing.T) {
			platform := "linux/" + architecture
			requireDockerPlatform(t, platform)

			tag := fmt.Sprintf("service-postgres-bootstrap-lock-test-%s:%d", architecture, time.Now().UnixNano())
			t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", tag).Run() })
			build := exec.Command("docker", "build", "--platform", platform, "--tag", tag, context)
			output, err := build.CombinedOutput()
			require.NoError(t, err, "%s build failed: %s", platform, output)

			inspect, err := exec.Command("docker", "image", "inspect", tag, "--format", "{{json .Config.Labels}}").Output()
			require.NoError(t, err)
			labels := map[string]string{}
			require.NoError(t, json.Unmarshal(inspect, &labels))
			for _, entry := range bootstrapLock.Provenance() {
				require.Equal(t, entry.Value, labels[entry.Label])
			}

			machine, named := machines[architecture]
			require.True(t, named, "no expected machine name for %s", architecture)

			resolved, err := exec.Command("docker", "run", "--rm", "--platform", platform,
				"--entrypoint", "sh", tag, "-c",
				"migrate -version; uname -m; cat /etc/alpine-release; psql --version",
			).CombinedOutput()
			require.NoError(t, err, string(resolved))
			require.Contains(t, string(resolved), strings.TrimPrefix(bootstrapLock.Migrate.Version, "v"))
			require.Contains(t, string(resolved), machine)
			require.Contains(t, string(resolved), bootstrapLock.Base.Version)
			client, _, _ := strings.Cut(bootstrapPinnedVersion(t, "postgresql17-client"), "-r")
			require.Contains(t, string(resolved), "(PostgreSQL) "+client)
		})
	}
}

// TestBootstrapImageLabelsCannotBeOverriddenAtBuildTime covers the provenance the
// image reports about itself: passing the same names the recipe carries as build
// arguments must not change a single label, or the labels are a caller's claim
// rather than evidence of what was built.
func TestBootstrapImageLabelsCannotBeOverriddenAtBuildTime(t *testing.T) {
	requireDocker(t)
	requireDockerPlatform(t, "linux/"+runtime.GOARCH)
	context := bootstrapBuildContext(t)

	arguments := []string{"build", "--tag", ""}
	for argument := range bootstrapLock.RecipeBuildArgs() {
		arguments = append(arguments, "--build-arg", argument+"=forged")
	}
	tag := fmt.Sprintf("service-postgres-bootstrap-forge-test:%d", time.Now().UnixNano())
	arguments[2] = tag
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", tag).Run() })

	output, err := exec.Command("docker", append(arguments, context)...).CombinedOutput()
	require.NoError(t, err, string(output))

	inspect, err := exec.Command("docker", "image", "inspect", tag, "--format", "{{json .Config.Labels}}").Output()
	require.NoError(t, err)
	labels := map[string]string{}
	require.NoError(t, json.Unmarshal(inspect, &labels))
	for _, entry := range bootstrapLock.Provenance() {
		require.Equal(t, entry.Value, labels[entry.Label], "%s was forged by a build argument", entry.Label)
	}
}

// TestBootstrapImageRejectsTamperedMigrateArchive runs the Dockerfile's own install
// step against a substituted archive: only the download is replaced, so the
// verification under test is the template's. The archive carries a payload that
// records its own execution, so the test can prove the tampered bytes were never
// extracted or run.
func TestBootstrapImageRejectsTamperedMigrateArchive(t *testing.T) {
	requireDocker(t)
	dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", DockerTemplating{
		MigrationConnectionKeyHolder: "{" + migrationConnectionEnvironmentKey + "}",
	})
	script := bootstrapMigrateInstallScript(t, dockerfile)

	download := regexp.MustCompile(`curl -fsSL -o /tmp/migrate\.tar\.gz "[^"]+"`)
	require.Len(t, download.FindAllString(script, -1), 1, "install step no longer downloads the archive to a file")
	script = download.ReplaceAllString(script, "cp /fixture/migrate.tar.gz /tmp/migrate.tar.gz")

	fixture := t.TempDir()
	writeTamperedMigrateArchive(t, filepath.Join(fixture, "migrate.tar.gz"))

	output, err := exec.Command("docker", "run", "--rm",
		"--volume", fixture+":/fixture",
		bootstrapLock.Base.Reference(), "sh", "-c", script,
	).CombinedOutput()
	require.Error(t, err, "tampered archive was accepted: %s", output)
	require.Contains(t, string(output), "FAILED")
	require.NoFileExists(t, filepath.Join(fixture, "executed"),
		"tampered archive was extracted and executed")
}

// bootstrapBuildContext stages a build context for the bootstrap Dockerfile: the
// rendered Dockerfile plus the runtime-access.sql it COPYs.
func bootstrapBuildContext(t *testing.T) string {
	t.Helper()
	context := t.TempDir()
	dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", DockerTemplating{
		MigrationConnectionKeyHolder: "{" + migrationConnectionEnvironmentKey + "}",
	})
	require.NoError(t, os.WriteFile(filepath.Join(context, "Dockerfile"), []byte(dockerfile), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(context, "runtime-access.sql"), []byte("SELECT 1;\n"), 0o644))
	return context
}

// bootstrapMigrateInstallScript lifts the migrate install step out of the rendered
// Dockerfile as a runnable shell script, so a test exercises the template's own
// commands instead of a re-typed copy of them.
func bootstrapMigrateInstallScript(t *testing.T, dockerfile string) string {
	t.Helper()
	var scripts []string
	lines := strings.Split(dockerfile, "\n")
	for index := 0; index < len(lines); index++ {
		script, isRun := strings.CutPrefix(lines[index], "RUN ")
		if !isRun {
			continue
		}
		for strings.HasSuffix(script, "\\") && index+1 < len(lines) {
			index++
			script = strings.TrimSuffix(script, "\\") + lines[index]
		}
		if strings.Contains(script, "sha256sum -c -") {
			scripts = append(scripts, script)
		}
	}
	require.Len(t, scripts, 1, "exactly one build step must verify the migrate archive")
	return scripts[0]
}

// writeTamperedMigrateArchive writes an archive shaped like the migrate release but
// carrying a payload that records being run, so an accepted archive is observable.
func writeTamperedMigrateArchive(t *testing.T, path string) {
	t.Helper()
	payload := []byte("#!/bin/sh\ntouch /fixture/executed\n")

	file, err := os.Create(path)
	require.NoError(t, err)
	compressor := gzip.NewWriter(file)
	archive := tar.NewWriter(compressor)
	require.NoError(t, archive.WriteHeader(&tar.Header{
		Name: "migrate",
		Mode: 0o755,
		Size: int64(len(payload)),
	}))
	_, err = archive.Write(payload)
	require.NoError(t, err)
	require.NoError(t, archive.Close())
	require.NoError(t, compressor.Close())
	require.NoError(t, file.Close())
}

func bootstrapPinnedVersion(t *testing.T, name string) string {
	t.Helper()
	for _, pinned := range bootstrapLock.Packages.Pinned {
		if pinned.Name == name {
			return pinned.Version
		}
	}
	t.Fatalf("bootstrap lock does not pin %s", name)
	return ""
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}
}

// requireDockerPlatform skips when the host cannot run images for platform, because
// a foreign architecture needs emulation a developer machine may not have. Under CI
// it fails instead: that is the run whose green result is taken as proof both
// architectures were verified, so it must not be able to quietly verify one.
func requireDockerPlatform(t *testing.T, platform string) {
	t.Helper()
	probe := exec.Command("docker", "run", "--rm", "--platform", platform, bootstrapLock.Base.Reference(), "true")
	output, err := probe.CombinedOutput()
	if err == nil {
		return
	}
	message := fmt.Sprintf("docker cannot run %s images on this host: %v\n%s", platform, err, output)
	if os.Getenv("CI") != "" {
		t.Fatal(message + "\nCI must register emulation (docker/setup-qemu-action) before running these tests")
	}
	t.Skip(message)
}
