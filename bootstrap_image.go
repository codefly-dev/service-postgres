package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/codefly-dev/core/shared"
)

//go:embed bootstrap-image.json
var bootstrapImageLockJSON []byte

//go:embed go.mod
var bootstrapMigrateGoMod []byte

//go:embed go.sum
var bootstrapMigrateGoSum []byte

// managedBootstrapSource is the migration runner a managed store's Job runs. It
// builds beside migrate from this module's own go.mod and go.sum, so every
// migration image carries both runners and the image is the same whichever mode
// an environment declares.
//
//go:embed cmd/managed-bootstrap/main.go
var managedBootstrapSource []byte

// bootstrapArchitectures are the architectures the bootstrap image is built for,
// matching the recipe's linux/amd64 + linux/arm64 platform list. The lock must
// build a migrate binary for each of them, and the image rejects any other.
var bootstrapArchitectures = []string{"amd64", "arm64"}

// bootstrapRecipePlatforms are the buildx platforms the emitted recipe targets,
// derived from the architectures the lock resolves inputs for so a platform can
// never be advertised without a source-built migrate binary behind it.
func bootstrapRecipePlatforms() []string {
	platforms := make([]string, 0, len(bootstrapArchitectures))
	for _, architecture := range bootstrapArchitectures {
		platforms = append(platforms, "linux/"+architecture)
	}
	return platforms
}

// bootstrapLock resolves the inputs the bootstrap image builds from. The image
// is FROM scratch: the migrate binary and the migration runner, both compiled
// static from this lock's toolchain, and that toolchain image's CA bundle. No
// package index is read at build time, so nothing here can stop resolving.
var bootstrapLock = shared.Must(parseBootstrapImageLock(bootstrapImageLockJSON))

// bootstrapImageLock pins the source-build toolchain and the migrate version.
// The maintained module files are embedded separately; their hashes travel in
// provenance and are verified before compilation, so callers cannot substitute
// a different module graph behind the image labels.
type bootstrapImageLock struct {
	Migrate bootstrapMigrateBinary `json:"migrate"`

	// LockDigest identifies the JSON inputs; the embedded module-file hashes are
	// separate provenance entries. Together they enter the aggregate recipe digest.
	// Canonical encoding ignores JSON whitespace and key order.
	LockDigest string `json:"-"`
}

type bootstrapMigrateBinary struct {
	Version   string `json:"version"`
	Toolchain string `json:"toolchain"`
}

func (bootstrapMigrateBinary) GoModSHA256() string {
	return fmt.Sprintf("%x", sha256.Sum256(bootstrapMigrateGoMod))
}

func (bootstrapMigrateBinary) GoSumSHA256() string {
	return fmt.Sprintf("%x", sha256.Sum256(bootstrapMigrateGoSum))
}

func (bootstrapMigrateBinary) ManagedBootstrapSHA256() string {
	return fmt.Sprintf("%x", sha256.Sum256(managedBootstrapSource))
}

// Stage only agent-owned module inputs, never a consumer's module or credentials.
func stageBootstrapMigrate(root string) error {
	dir := filepath.Join(root, "migrate")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"go.mod": bootstrapMigrateGoMod, "go.sum": bootstrapMigrateGoSum} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	runner := filepath.Join(dir, "cmd", "managed-bootstrap")
	if err := os.MkdirAll(runner, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(runner, "main.go"), managedBootstrapSource, 0o644)
}

// bootstrapProvenance is one resolved input, exposed from the lock as a Dockerfile
// build argument, an image label, and a typed field of the emitted build recipe.
type bootstrapProvenance struct {
	Arg   string
	Label string
	Value string
}

// Provenance lists the resolved identities the image and the emitted recipe
// record, so a consumer can read what a built artifact was assembled from without
// re-resolving anything.
func (l *bootstrapImageLock) Provenance() []bootstrapProvenance {
	return []bootstrapProvenance{
		{Arg: "CODEFLY_BOOTSTRAP_LOCK_DIGEST", Label: "dev.codefly.bootstrap.lock-digest", Value: l.LockDigest},
		{Arg: "CODEFLY_BOOTSTRAP_MIGRATE_VERSION", Label: "dev.codefly.bootstrap.migrate-version", Value: l.Migrate.Version},
		{Arg: "CODEFLY_BOOTSTRAP_MIGRATE_TOOLCHAIN", Label: "dev.codefly.bootstrap.migrate-toolchain", Value: l.Migrate.Toolchain},
		{Arg: "CODEFLY_BOOTSTRAP_MIGRATE_GO_MOD", Label: "dev.codefly.bootstrap.migrate-go-mod", Value: l.Migrate.GoModSHA256()},
		{Arg: "CODEFLY_BOOTSTRAP_MIGRATE_GO_SUM", Label: "dev.codefly.bootstrap.migrate-go-sum", Value: l.Migrate.GoSumSHA256()},
		{Arg: "CODEFLY_BOOTSTRAP_MIGRATE_DRIVERS", Label: "dev.codefly.bootstrap.migrate-drivers", Value: "postgres,file"},
		{Arg: "CODEFLY_BOOTSTRAP_MANAGED_RUNNER", Label: "dev.codefly.bootstrap.managed-runner", Value: l.Migrate.ManagedBootstrapSHA256()},
	}
}

// RecipeBuildArgs exposes the same resolved identities through the build recipe's
// typed build arguments, where core folds them into the plan's aggregate digest.
// Nothing in the Dockerfile reads them: every input the build resolves, verifies
// against, or records as a label is a rendered literal, so no caller can pass an
// argument that changes what the image is or what it claims to be.
func (l *bootstrapImageLock) RecipeBuildArgs() map[string]string {
	provenance := l.Provenance()
	buildArgs := make(map[string]string, len(provenance))
	for _, entry := range provenance {
		buildArgs[entry.Arg] = entry.Value
	}
	return buildArgs
}

func parseBootstrapImageLock(content []byte) (*bootstrapImageLock, error) {
	var lock bootstrapImageLock
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse bootstrap image lock: %w", err)
	}
	if err := lock.validate(); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(lock)
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap image lock: %w", err)
	}
	document := sha256.Sum256(canonical)
	lock.LockDigest = "sha256:" + hex.EncodeToString(document[:])
	return &lock, nil
}

func (l *bootstrapImageLock) validate() error {
	return l.validateMigrate()
}

func (l *bootstrapImageLock) validateMigrate() error {
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(l.Migrate.Version) {
		return fmt.Errorf("bootstrap migrate version must be a release tag, got %q", l.Migrate.Version)
	}
	if !regexp.MustCompile(`^golang:[0-9]+\.[0-9]+\.[0-9]+-alpine[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$`).MatchString(l.Migrate.Toolchain) {
		return fmt.Errorf("bootstrap migrate toolchain must pin an exact Go/Alpine tag and sha256 digest")
	}
	return nil
}

// validateSHA256Digest accepts an "sha256:<hex>" reference, the form the runtime
// image lock pins by.
func validateSHA256Digest(field, value string) error {
	algorithm, encoded, found := strings.Cut(value, ":")
	if !found || algorithm != "sha256" || !isSHA256Hex(encoded) {
		return fmt.Errorf("%s must be a sha256 digest", field)
	}
	return nil
}

// validateSHA256Checksum accepts the bare hex a checksum file publishes.
func validateSHA256Checksum(field, value string) error {
	if !isSHA256Hex(value) {
		return fmt.Errorf("%s must be a sha256 checksum", field)
	}
	return nil
}

func isSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
