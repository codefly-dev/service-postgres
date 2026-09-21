---
name: bootstrap-image-lock
description: Move bootstrap-image.json forward — the lock the bootstrap image builds from (alpine base digest, pinned apk package versions, golang-migrate archive checksums). Use when a bootstrap image build fails "unable to select packages", when the weekly bootstrap-lock-freshness check reports drift, when bumping the alpine branch or the migrate version, or when a bootstrap_image_test.go checksum assertion fails. Explains why a failing build is the intended signal and why values are never authored by hand.
---

# Moving the bootstrap image lock

`bootstrap-image.json` pins what the bootstrap image installs: the alpine base
by digest, exact apk package versions, and the golang-migrate archive sha256 per
architecture. `templates/builder/Dockerfile.tmpl` renders entirely from it.

**Never edit this file by hand.** Every value is resolved from upstream by
`.github/scripts/update-bootstrap-lock.sh` — the base digest from the registry,
package versions from inside the digest-pinned base on *both* architectures, and
the migrate checksums from the release's published `sha256sum.txt`.

```bash
.github/scripts/update-bootstrap-lock.sh            # re-resolve what the lock targets
.github/scripts/update-bootstrap-lock.sh --check    # report drift, write nothing, exit 1 if stale
ALPINE_BRANCH=v3.22 .github/scripts/update-bootstrap-lock.sh
MIGRATE_VERSION=v4.20.0 .github/scripts/update-bootstrap-lock.sh
go test ./... && git commit bootstrap-image.json
```

A plain rerun re-resolves the lock's *own* intent: the branch, migrate version
and package set are read back out of the current file, so it cannot silently
revert someone's deliberate bump. The environment variables are the only way to
change what is targeted.

## "unable to select packages" is the feature

Alpine publishes no immutable package snapshot — a release branch keeps only the
newest `-rN` of each package. Pinning exact versions trades availability for
integrity: once upstream replaces `curl` or `postgresql17-client`, the build
fails loudly instead of quietly installing different bytes.

That failure is the signal to rerun the script, and it is also how a security
fix reaches the image. Do not respond to it by loosening a version constraint or
dropping a pin — that converts a build failure into an unrecorded change of
what ships.

The signal covers pinned packages only. A base digest the branch has moved past,
and a newer migrate release, fail nothing on their own, which is why
`.github/workflows/bootstrap-lock-freshness.yml` runs `--check` on a schedule
instead of gating pull requests on unrelated upstream releases.

## What the checksums do and do not prove

The `sha256sum.txt` ships in the same GitHub release as the archives it covers.
It pins **identity** — the bytes cannot change under a fixed version, and a
mirror or CDN cannot substitute them — but it shares a trust root with the
artifact, so it is not proof of authorship. Locking the version is what bounds
that trust. Say so if a PR changes `MIGRATE_VERSION`.

## Tests that hold the lock honest

Under `go test ./...`, and several need docker with arm64 emulation:

- `TestBootstrapImageLockMatchesCommittedDocument` — the parsed lock equals the file.
- `TestBootstrapImageLockChecksumsMatchPublishedArchives` — the recorded sha256
  is what the release actually publishes.
- `TestBootstrapImageBuildsLockedInputsPerArchitecture` — the locked inputs
  install on both architectures.
- `TestBootstrapImageRejectsTamperedMigrateArchive` — a wrong checksum fails the build.

Without an arm64 emulator these skip locally and fail under `CI`. If you ran
them only on amd64, the arm64 archive checksum is unverified — say that.
