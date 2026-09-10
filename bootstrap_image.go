package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/codefly-dev/core/shared"
)

//go:embed bootstrap-image.json
var bootstrapImageLockJSON []byte

// bootstrapArchitectures are the architectures the bootstrap image is built for,
// matching the recipe's linux/amd64 + linux/arm64 platform list. The lock must
// resolve a migrate archive for each of them, and the image rejects any other.
var bootstrapArchitectures = []string{"amd64", "arm64"}

// bootstrapLock resolves the inputs the bootstrap image builds from. The runtime
// image lock covers only the managed Postgres image, so this separate image needs
// its own source of truth.
var bootstrapLock = shared.Must(parseBootstrapImageLock(bootstrapImageLockJSON))

// bootstrapImageLock is the checked-in identity of every input the bootstrap
// image consumes: the base image by digest, the apk repository with exact package
// versions, and the migrate release archive by checksum per architecture. Nothing
// the image builds from resolves against a mutable tag, and the migrate archive is
// verified before any of its bytes are extracted or executed.
//
// .github/scripts/update-bootstrap-lock.sh is the supported way to change it; it
// resolves each value from upstream (including migrate's published checksums)
// rather than accepting hand-written digests.
type bootstrapImageLock struct {
	Base     bootstrapBaseImage     `json:"base"`
	Packages bootstrapPackages      `json:"packages"`
	Migrate  bootstrapMigrateBinary `json:"migrate"`

	// LockDigest is the sha256 of the lock document, derived when it is parsed. It
	// is the single value two builds compare to prove they resolved the same
	// inputs, and it travels with the image as a label.
	LockDigest string `json:"-"`
}

type bootstrapBaseImage struct {
	Image   string `json:"image"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type bootstrapPackages struct {
	Repository string             `json:"repository"`
	Pinned     []bootstrapPackage `json:"pinned"`
}

type bootstrapPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type bootstrapMigrateBinary struct {
	Version  string                    `json:"version"`
	Archives []bootstrapMigrateArchive `json:"archives"`
}

type bootstrapMigrateArchive struct {
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
}

// Reference is the base image the Dockerfile builds FROM. The locked digest is the
// multi-platform index digest, so buildx still selects the per-architecture
// manifest for the platform it is building.
func (b bootstrapBaseImage) Reference() string {
	return b.Image + "@" + b.Digest
}

// Specs renders the locked packages as apk arguments, each pinned to an exact
// version.
func (p bootstrapPackages) Specs() string {
	specs := make([]string, 0, len(p.Pinned))
	for _, pinned := range p.Pinned {
		specs = append(specs, pinned.Name+"="+pinned.Version)
	}
	return strings.Join(specs, " ")
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
	archives := make([]string, 0, len(l.Migrate.Archives))
	for _, archive := range l.Migrate.Archives {
		archives = append(archives, archive.Architecture+"="+archive.SHA256)
	}
	return []bootstrapProvenance{
		{Arg: "CODEFLY_BOOTSTRAP_LOCK_DIGEST", Label: "dev.codefly.bootstrap.lock-digest", Value: l.LockDigest},
		{Arg: "CODEFLY_BOOTSTRAP_BASE", Label: "dev.codefly.bootstrap.base", Value: l.Base.Reference()},
		{Arg: "CODEFLY_BOOTSTRAP_BASE_VERSION", Label: "dev.codefly.bootstrap.base-version", Value: l.Base.Version},
		{Arg: "CODEFLY_BOOTSTRAP_APK_REPOSITORY", Label: "dev.codefly.bootstrap.apk-repository", Value: l.Packages.Repository},
		{Arg: "CODEFLY_BOOTSTRAP_APK_PACKAGES", Label: "dev.codefly.bootstrap.apk-packages", Value: l.Packages.Specs()},
		{Arg: "CODEFLY_BOOTSTRAP_MIGRATE_VERSION", Label: "dev.codefly.bootstrap.migrate-version", Value: l.Migrate.Version},
		{Arg: "CODEFLY_BOOTSTRAP_MIGRATE_ARCHIVES", Label: "dev.codefly.bootstrap.migrate-archives", Value: strings.Join(archives, ",")},
	}
}

// RecipeBuildArgs exposes the same resolved identities through the build recipe's
// typed build arguments. They carry the locked values the Dockerfile already
// defaults to, so the recipe records what it was built from without becoming the
// thing that decides it: the digests and checksums the build verifies against are
// literals in the Dockerfile, not arguments a caller can override.
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
	document := sha256.Sum256(content)
	lock.LockDigest = "sha256:" + hex.EncodeToString(document[:])
	return &lock, nil
}

func (l *bootstrapImageLock) validate() error {
	if l.Base.Image == "" {
		return fmt.Errorf("bootstrap base image name is required")
	}
	if l.Base.Version == "" {
		return fmt.Errorf("bootstrap base image version is required")
	}
	if err := validateBootstrapDigest("bootstrap base image digest", l.Base.Digest); err != nil {
		return err
	}
	if err := l.validatePackages(); err != nil {
		return err
	}
	return l.validateMigrate()
}

func (l *bootstrapImageLock) validatePackages() error {
	if !strings.HasPrefix(l.Packages.Repository, "https://") {
		return fmt.Errorf("bootstrap apk repository must be an https URL, got %q", l.Packages.Repository)
	}
	branch, err := alpineReleaseBranch(l.Base.Version)
	if err != nil {
		return err
	}
	// A base bumped to a new Alpine release while the package repository stays on
	// the previous branch resolves packages that were never built against that
	// base, so the lock only accepts both moving together.
	if !strings.Contains(l.Packages.Repository, "/"+branch+"/") {
		return fmt.Errorf("bootstrap apk repository %q does not serve the locked Alpine %s branch", l.Packages.Repository, branch)
	}
	if len(l.Packages.Pinned) == 0 {
		return fmt.Errorf("bootstrap apk packages are required")
	}
	for _, pinned := range l.Packages.Pinned {
		if pinned.Name == "" {
			return fmt.Errorf("bootstrap apk package name is required")
		}
		if pinned.Version == "" {
			return fmt.Errorf("bootstrap apk package %s must pin an exact version", pinned.Name)
		}
		if strings.ContainsAny(pinned.Name+pinned.Version, " =") {
			return fmt.Errorf("bootstrap apk package %s=%s is not a single apk constraint", pinned.Name, pinned.Version)
		}
	}
	return nil
}

func (l *bootstrapImageLock) validateMigrate() error {
	if !strings.HasPrefix(l.Migrate.Version, "v") {
		return fmt.Errorf("bootstrap migrate version must be a release tag, got %q", l.Migrate.Version)
	}
	locked := make(map[string]bool, len(l.Migrate.Archives))
	for _, archive := range l.Migrate.Archives {
		if !slices.Contains(bootstrapArchitectures, archive.Architecture) {
			return fmt.Errorf(
				"bootstrap migrate archive architecture %q is not one of %s",
				archive.Architecture,
				strings.Join(bootstrapArchitectures, ", "),
			)
		}
		if locked[archive.Architecture] {
			return fmt.Errorf("bootstrap migrate archive for %s is locked twice", archive.Architecture)
		}
		locked[archive.Architecture] = true
		if err := validateBootstrapChecksum(
			fmt.Sprintf("bootstrap migrate %s archive checksum", archive.Architecture),
			archive.SHA256,
		); err != nil {
			return err
		}
	}
	for _, architecture := range bootstrapArchitectures {
		if !locked[architecture] {
			return fmt.Errorf("bootstrap migrate archive for %s is required", architecture)
		}
	}
	return nil
}

func alpineReleaseBranch(version string) (string, error) {
	major, rest, found := strings.Cut(version, ".")
	minor, _, _ := strings.Cut(rest, ".")
	if !found || major == "" || minor == "" {
		return "", fmt.Errorf("bootstrap base image version %q is not an Alpine release version", version)
	}
	return "v" + major + "." + minor, nil
}

func validateBootstrapDigest(field, value string) error {
	algorithm, encoded, found := strings.Cut(value, ":")
	if !found || algorithm != "sha256" {
		return fmt.Errorf("%s must be a sha256 digest", field)
	}
	return validateBootstrapChecksum(field, encoded)
}

func validateBootstrapChecksum(field, value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("%s must be a sha256 checksum", field)
	}
	return nil
}
