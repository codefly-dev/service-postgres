# Bootstrap migrate source and security maintenance

The Builder emits a bootstrap image for each database. Its `migrate` executable
is compiled from the same maintained `go.mod` and `go.sum` embedded in the agent,
using the Go builder image pinned in `bootstrap-image.json`. Only the PostgreSQL
and file drivers are enabled. Cross-compilation runs on the builder's native
platform with CGO disabled; the final image contains neither the Go toolchain nor
module manifests. No core companion supplies this executable.

This replaces the upstream all-driver v4.19.1 archives used through agent
v0.0.147. Their locked amd64 archive (`2ac648fbd1b127b69ab5a7b33cf96212178f71e22379fc50573630c6f4c7ce18`)
contains Go 1.25.4, x/crypto 0.45.0, x/net 0.47.0, pgx/v5 5.5.4, grpc 1.74.2,
go-jose/v4 4.0.5, and OpenTelemetry 1.37.0 (SDK 1.36.0). Rebuilding that recipe or
upgrading the agent's parent dependencies did not replace those binary bytes.

The initial source build uses migrate v4.19.1, lib/pq v1.12.3 and Go 1.27.3.
Actual compiled-module inspection records only migrate and lib/pq; the six
vulnerable dependency families above are absent. This is a reduction to the
required drivers, not a claim that unused modules in the parent's full module
graph have been patched by rebuilding. The upstream CLI's built-in stub driver
is also present; no additional external database or remote-source driver is
selected. Existing migration SQL, ledgers, locks, budgets and dirty-state
behavior are unchanged.

The source-stage checksum check verifies both staged module files before
`go build -mod=readonly`. The checksummed Go modules authenticate downloaded
source. `GOTOOLCHAIN=local` prevents an implicit compiler download. Literal image
labels and typed recipe arguments record the Go image digest, migrate version,
driver set and both module-file SHA256 values. Normal context hashing includes the staged source files. The build
copies only the compiled executable and cleaned bootstrap artifacts into the
runtime, so an SBOM describes shipped code rather than unused parent manifests.

The image is `FROM scratch`: the migrate executable, the migration runner
(`cmd/managed-bootstrap`, compiled static the same way), the toolchain image's CA
bundle (the Cloud SQL connector verifies Google's APIs with it), an empty `/tmp`,
and the staged `/app/bootstrap` tree. No shell, no package manager, and no
package index is read when it is built: through v0.0.150 the image installed
`postgresql17-client` at an exact `-rN` from the live Alpine index, which keeps
only the newest revision, so every consumer's render failed the day Alpine moved
it. It runs as 65534 on a read-only root filesystem.

The runner (`libs/go/bootstrap.Run`) serves both store kinds. A managed store's
Job passes its binding and reaches Cloud SQL through the connector as its own
cloud identity. An in-cluster store's Job runs the image's default and is
self-hosted: the owner connects with its password (supplied at connect time and
to the migrate child's environment, never in a URL or argument), and the
read-only, read-write and declared logins are provisioned with
`controlplane.ReconcilePasswordAccess` — the same function the local runtime
uses, so a local store and a deployed one grant identical access. Either way the
runner verifies every staged source against `plan.json`, waits for the server
(self-hosted), then holds the runtime-access lock across extensions, every
lineage and the access reconciliation. `self-hosted.json` beside the plan names
the declared logins and the variable each one's password arrives on.

Use `.github/scripts/update-bootstrap-migrate.py` to resolve the migrate portion
of the lock without Docker. It reads migrate's version from `go.mod`, retains the
existing exact compiler tag, verifies the registry manifest digest and checks
both target platforms. `MIGRATE_GO_IMAGE=golang:<patch>-alpine<release>` deliberately
selects a newer compiler. `update-bootstrap-lock.sh` calls the same resolver
and also reports a newer upstream migrate release.
No lock digest is manually authored. Dependency and toolchain changes require the
same source-build tests; the strict binary dependency inventory intentionally
fails if another module enters the binary and requires review.

Host verification:

```sh
go test . -run '^(TestBootstrapMigrate|TestBootstrapDockerfile|TestBootstrapProvenance|TestParseBootstrapImageLock|TestBootstrapImageLock|TestBuildRecipeLocksBootstrapInputs)' -count=1
go build ./...
go vet ./...
go mod tidy -diff
```

Before rollout, run the Docker bootstrap tests for both architectures and the
existing bootstrap parity tests in an allocated engine slot. Then build through
the normal released/local agent recipe, record each resulting migration image's
digest, and scan the actual images. A host binary inspection is source evidence;
it does not establish scanner clearance for the deployed
images. Old agent releases continue to emit the old archive recipe, so consumers
must adopt the corrected agent and rebuild all migration images before deployment.
