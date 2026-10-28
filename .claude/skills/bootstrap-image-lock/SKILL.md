---
name: bootstrap-image-lock
description: Resolve bootstrap-image.json from upstream — Alpine base/package pins and the source-built migrate Go toolchain. Use for bootstrap package drift, migrate/module or compiler updates, and bootstrap freshness failures. Never guess lock values.
---

# Moving the bootstrap image lock

`bootstrap-image.json` pins the Alpine base, apk packages, migrate source version
and Go builder image. The binary is built from the agent's embedded `go.mod` and
`go.sum`, with only the PostgreSQL and file drivers. The module files' hashes,
compiler image, source version and drivers are exposed in recipe/image provenance.
See `docs/bootstrap-migrate.md` for the dependency and image verification contract.

**Never edit lock values by hand.** The resolver verifies the registry manifest
bytes against its digest and requires both linux/amd64 and linux/arm64 support.

```bash
# Source/toolchain-only update: no engine. Keep the base and apk pins unchanged.
python3 .github/scripts/update-bootstrap-migrate.py
MIGRATE_GO_IMAGE=golang:1.27.3-alpine3.24 python3 .github/scripts/update-bootstrap-migrate.py

# Full refresh: requires Docker and both architectures.
.github/scripts/update-bootstrap-lock.sh
.github/scripts/update-bootstrap-lock.sh --check
ALPINE_BRANCH=v3.22 .github/scripts/update-bootstrap-lock.sh
```

To upgrade migrate or its dependencies, update the parent module through normal
Go dependency maintenance first, then resolve the lock. Do not use `go install
...@version` in the image: that ignores the maintained parent graph. The recipe
uses `go build -mod=readonly`, `GOTOOLCHAIN=local` and the exact builder digest.
The Go builder must be at least the module's Go version. Updating the parent
module changes the embedded inputs and their provenance hashes automatically.

## Package drift

Alpine's rolling repository replaces `-rN` packages. A missing pinned package
must fail the build; resolve the lock rather than loosening a constraint. The
full resolver checks package versions on both architectures. The freshness
workflow checks for registry/package drift and a newer migrate source release.
An exact Go patch pin requires an explicit compiler update when a new patch ships.

## Verification

- `TestBootstrapMigrateSourceBuildGraph` cross-compiles the rendered build command
  for both target architectures and inspects the actual binary's module graph.
- `TestBootstrapMigrateRejectsTamperedModuleInputs` refuses changed module files
  before compiling, so provenance cannot describe different input bytes.
- `TestBuildRecipeLocksBootstrapInputs` checks the staged source files and recipe
  hashes; the existing deterministic-emission tests cover the aggregate digest.
- `TestBootstrapImageBuildsLockedInputsPerArchitecture` builds and runs both
  images; the existing bootstrap parity tests exercise database migrations.

Host cross-compilation does not verify the container build or image scan. If no
engine slot is allocated, run host tests only and state that the Docker checks,
registry freshness and actual image vulnerability scan remain unverified.
