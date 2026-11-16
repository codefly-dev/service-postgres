---
name: bootstrap-image-lock
description: Resolve bootstrap-image.json from upstream — the source-built migrate version and its Go toolchain. Use for migrate/module or compiler updates and bootstrap freshness failures. Never guess lock values.
---

# Moving the bootstrap image lock

`bootstrap-image.json` pins the migrate source version and Go builder image. The
image is FROM scratch (migrate, the runner, the toolchain's CA bundle), so no
package is resolved from an index when a consumer renders. The binary is built from the agent's embedded `go.mod` and
`go.sum`, with only the PostgreSQL and file drivers. The module files' hashes,
compiler image, source version and drivers are exposed in recipe/image provenance.
See `docs/bootstrap-migrate.md` for the dependency and image verification contract.

**Never edit lock values by hand.** The resolver verifies the registry manifest
bytes against its digest and requires both linux/amd64 and linux/arm64 support.

```bash
python3 .github/scripts/update-bootstrap-migrate.py
MIGRATE_GO_IMAGE=golang:1.27.3-alpine3.24 python3 .github/scripts/update-bootstrap-migrate.py

# The same resolution, plus a newer-upstream-migrate report.
.github/scripts/update-bootstrap-lock.sh
.github/scripts/update-bootstrap-lock.sh --check
```

To upgrade migrate or its dependencies, update the parent module through normal
Go dependency maintenance first, then resolve the lock. Do not use `go install
...@version` in the image: that ignores the maintained parent graph. The recipe
uses `go build -mod=readonly`, `GOTOOLCHAIN=local` and the exact builder digest.
The Go builder must be at least the module's Go version. Updating the parent
module changes the embedded inputs and their provenance hashes automatically.

## No package drift

The image installs nothing from apk. Alpine's rolling repository keeps only the
newest `-rN` of a package, so an exact pin broke every consumer's render the day
upstream moved it (17.11-r0 -> 17.12-r0), and a loose constraint installs
different bytes on different days. Do not add a package or a shell to the
template; a capability the bootstrap needs belongs in the Go runner. The
freshness workflow checks for toolchain drift and a newer migrate source release.
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
