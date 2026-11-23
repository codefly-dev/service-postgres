package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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
	require.Equal(t, bootstrapLock.Migrate.Toolchain, values["dev.codefly.bootstrap.migrate-toolchain"])
	require.Equal(t, bootstrapLock.Migrate.GoModSHA256(), values["dev.codefly.bootstrap.migrate-go-mod"])
	require.Equal(t, bootstrapLock.Migrate.GoSumSHA256(), values["dev.codefly.bootstrap.migrate-go-sum"])
	require.Equal(t, "postgres,file", values["dev.codefly.bootstrap.migrate-drivers"])

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
			// The image is FROM scratch and installs no package: a lock naming a
			// base or packages would be a second, unread source of truth.
			name:  "a base of its own",
			amend: func(document map[string]any) { document["base"] = map[string]any{"image": "alpine"} },
			error: `parse bootstrap image lock: json: unknown field "base"`,
		},
		{
			name:  "apk packages",
			amend: func(document map[string]any) { document["packages"] = map[string]any{"pinned": []any{}} },
			error: `parse bootstrap image lock: json: unknown field "packages"`,
		},
		{
			name:  "migrate pinned to a moving reference",
			amend: func(document map[string]any) { lockMigrate(document)["version"] = "latest" },
			error: `bootstrap migrate version must be a release tag, got "latest"`,
		},
		{
			name:  "toolchain without digest",
			amend: func(document map[string]any) { lockMigrate(document)["toolchain"] = "golang:1.27.3-alpine3.24" },
			error: "bootstrap migrate toolchain must pin an exact Go/Alpine tag and sha256 digest",
		},
		{
			name: "toolchain shell injection",
			amend: func(document map[string]any) {
				lockMigrate(document)["toolchain"] = "golang:1.27.3-alpine3.24@sha256:$(id)"
			},
			error: "bootstrap migrate toolchain must pin an exact Go/Alpine tag and sha256 digest",
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

func lockMigrate(document map[string]any) map[string]any {
	return document["migrate"].(map[string]any)
}

func TestBootstrapDockerfileLocksEveryInput(t *testing.T) {
	dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", DockerTemplating{})

	require.Contains(t, dockerfile, "\nFROM scratch\n")
	// Nothing resolves from a package index: an index serves only the newest
	// revision of a package, so a pin breaks the build and no pin is not a lock.
	require.NotRegexp(t, `(?m)^RUN .*\b(apk|apt-get)\b`, dockerfile)
	require.Contains(t, dockerfile, "USER 65534:65534")

	require.Contains(t, dockerfile, "FROM --platform=$BUILDPLATFORM "+bootstrapLock.Migrate.Toolchain+" AS migrate-builder")
	require.NotContains(t, dockerfile, "releases/download")
	require.Contains(t, dockerfile, "COPY --from=migrate-builder /migrate /usr/local/bin/migrate")
	require.Contains(t, dockerfile, "COPY --from=migrate-builder /bootstrap /app/bootstrap")
	require.Contains(t, dockerfile, "RUN rm -rf /bootstrap/migrate")
	script := bootstrapMigrateBuildScript(t, dockerfile)
	require.Contains(t, script, "GOTOOLCHAIN=local")
	require.Contains(t, script, "CGO_ENABLED=0 GOOS=linux GOARCH=\"$architecture\"")
	require.Contains(t, script, "go build -mod=readonly -trimpath -tags postgres,file")
	require.Less(t, strings.Index(script, "sha256sum -c -"), strings.Index(script, "go build"))

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
	require.Contains(t, dockerfile, "\nFROM scratch\n")
	require.Contains(t, dockerfile, "FROM --platform=$BUILDPLATFORM "+bootstrapLock.Migrate.Toolchain)
}

// TestBootstrapImageBuildsLockedInputsPerArchitecture builds the image the
// template renders and reads back what it carries: a migrate binary that executes
// on the target architecture and reports the locked version, the runner, and
// nothing else — no shell to run anything else with.
func TestBootstrapImageBuildsLockedInputsPerArchitecture(t *testing.T) {
	requireDocker(t)
	context := bootstrapBuildContext(t)

	for _, architecture := range bootstrapArchitectures {
		t.Run(architecture, func(t *testing.T) {
			platform := "linux/" + architecture
			requireDockerPlatform(t, platform)

			tag := uniqueDockerName("service-postgres-bootstrap-lock-test-" + architecture + ":")
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

			resolved, err := exec.Command("docker", "run", "--rm", "--platform", platform,
				"--entrypoint", "/usr/local/bin/migrate", tag, "-version").CombinedOutput()
			require.NoError(t, err, string(resolved))
			require.Contains(t, string(resolved), strings.TrimPrefix(bootstrapLock.Migrate.Version, "v"))
			inspect, err = exec.Command("docker", "image", "inspect", tag, "--format", "{{.Architecture}} {{.Config.User}}").Output()
			require.NoError(t, err)
			require.Equal(t, architecture+" 65534:65534", strings.TrimSpace(string(inspect)))
			_, err = exec.Command("docker", "run", "--rm", "--platform", platform, "--entrypoint", "/bin/sh", tag, "-c", "true").CombinedOutput()
			require.Error(t, err, "the image ships no shell")
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
	tag := uniqueDockerName("service-postgres-bootstrap-forge-test:")
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

// Verify the rendered recipe's commands on the host, with no Docker prerequisite.
// The output graph is the evidence: unrelated DB/cloud drivers must not sneak
// back into the bootstrap binary even when the parent go.mod needs them.
func TestBootstrapMigrateSourceBuildGraph(t *testing.T) {
	for _, arch := range bootstrapArchitectures {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, stageBootstrapMigrate(dir))
			output := filepath.Join(dir, "migrate-"+arch)
			script := bootstrapMigrateBuildScript(t, renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", DockerTemplating{}))
			script = strings.ReplaceAll(script, "-o /migrate", "-o "+output)
			script = strings.ReplaceAll(script, "-o /managed-bootstrap", "-o "+filepath.Join(dir, "managed-bootstrap-"+arch))
			command := exec.Command("sh", "-c", script)
			command.Dir = filepath.Join(dir, "migrate")
			// The staged image builds its own module outside the invoking workspace.
			command.Env = append(os.Environ(), "GOWORK=off", "TARGETARCH="+arch)
			log, err := command.CombinedOutput()
			require.NoError(t, err, string(log))
			info, err := buildinfo.ReadFile(output)
			require.NoError(t, err)
			require.Equal(t, "github.com/golang-migrate/migrate/v4", info.Main.Path)
			require.Equal(t, bootstrapLock.Migrate.Version, info.Main.Version)
			require.NotEmpty(t, info.Main.Sum, "upstream source must be checksum pinned")
			require.Len(t, info.Deps, 1, "only the PostgreSQL driver dependency belongs in this binary: %+v", info.Deps)
			require.Equal(t, "github.com/lib/pq", info.Deps[0].Path)
			require.Equal(t, "v1.12.3", info.Deps[0].Version)
			settings := map[string]string{}
			for _, setting := range info.Settings {
				settings[setting.Key] = setting.Value
			}
			require.Equal(t, "linux", settings["GOOS"])
			require.Equal(t, arch, settings["GOARCH"])
			require.Equal(t, "0", settings["CGO_ENABLED"])
			require.Equal(t, "postgres,file", settings["-tags"])
		})
	}
}

func TestBootstrapMigrateRejectsTamperedModuleInputs(t *testing.T) {
	for _, name := range []string{"go.mod", "go.sum"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, stageBootstrapMigrate(dir))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "migrate", name), []byte("tampered"), 0o644))
			script := bootstrapMigrateBuildScript(t, renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", DockerTemplating{}))
			output := filepath.Join(dir, "output")
			script = strings.ReplaceAll(script, "-o /migrate", "-o "+output)
			command := exec.Command("sh", "-c", script)
			command.Dir = filepath.Join(dir, "migrate")
			command.Env = append(os.Environ(), "TARGETARCH=amd64")
			log, err := command.CombinedOutput()
			require.Error(t, err, string(log))
			require.Contains(t, string(log), name+": FAILED")
			require.NoFileExists(t, output)
		})
	}
}

// bootstrapBuildContext stages a build context for the bootstrap Dockerfile: the
// rendered Dockerfile plus the staged tree it COPYs.
func bootstrapBuildContext(t *testing.T) string {
	t.Helper()
	context := t.TempDir()
	parameters := DockerTemplating{ReadinessTimeoutSeconds: defaultBootstrapReadinessSeconds}
	dockerfile := renderBuilderTemplate(t, "templates/builder/Dockerfile.tmpl", parameters)
	require.NoError(t, os.WriteFile(filepath.Join(context, "Dockerfile"), []byte(dockerfile), 0o644))
	staged := filepath.Join(context, bootstrapDirectory)
	require.NoError(t, os.MkdirAll(staged, 0o755))
	require.NoError(t, stageBootstrapMigrate(staged))
	return context
}

// bootstrapMigrateBuildScript lifts the migrate build step out of the rendered
// Dockerfile as a runnable shell script, so a test exercises the template's own
// commands instead of a re-typed copy of them.
func bootstrapMigrateBuildScript(t *testing.T, dockerfile string) string {
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
	require.Len(t, scripts, 1, "exactly one build step must verify the maintained module inputs")
	return scripts[0]
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}
}

// requireDockerPlatform skips when the host cannot build images for platform,
// because a foreign architecture needs emulation a developer machine may not have.
// Under CI it fails instead: that is the run whose green result is taken as proof
// both architectures were verified, so it must not be able to quietly verify one.
//
// The probe builds rather than runs, matching what it gates. `docker run
// --platform` against the locked base is refused outright ("cannot overwrite
// digest") whenever the requested platform is not the one the pinned index digest
// resolves to by default, so it reports a missing emulator on every host for every
// foreign architecture. A build resolves the per-platform manifest out of the index
// the way the real build does, and its RUN still needs the emulator.
func requireDockerPlatform(t *testing.T, platform string) {
	t.Helper()
	probe := exec.Command("docker", "build", "--platform", platform, "--quiet", "-")
	probe.Stdin = strings.NewReader("FROM " + bootstrapLock.Migrate.Toolchain + "\nRUN true\n")
	output, err := probe.CombinedOutput()
	if err == nil {
		return
	}
	message := fmt.Sprintf("docker cannot build %s images on this host: %v\n%s", platform, err, output)
	if os.Getenv("CI") != "" {
		t.Fatal(message + "\nCI must register emulation (docker/setup-qemu-action) before running these tests")
	}
	t.Skip(message)
}
