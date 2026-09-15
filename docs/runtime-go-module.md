# PostgreSQL runtime Go module

The runtime packages under `libs/go` are a separate Go module:

```text
github.com/codefly-dev/service-postgres/libs/go
```

Existing package import paths and exported APIs are unchanged. Applications can
use the connection profiles, restricted sessions, role reconciliation, schema
plans, workload attachments and migration fixtures without selecting the parent
agent module or Codefly Core. The runtime module still includes its existing
pgx, lib/pq and Azure identity dependencies. Authentication policy and schema
ownership stay with their existing callers; this packaging change adds no SQL
migrations or deployment settings.

The initial published runtime version is
`v0.0.0-20260915032422-272301033aed`. The parent agent explicitly requires this
version and retains Core for its own tooling. Local child edits do not override
that requirement: build the child independently, publish it, then update the
parent to the version returned by Go. Release tags for this child, when used,
must have the `libs/go/` prefix.

## Consumer transition

Resolve the complete consumer graph before adopting this module. Older parent
module archives contain the same `libs/go` packages. Selecting an old parent and
the new child together produces ambiguous imports, even though the source APIs
are compatible.

For applications that only import the runtime packages, replace the old parent
requirement with the child requirement, run `go mod tidy`, and verify that no
transitive dependency retains an older parent. Consumers that also need the
parent must select a published parent revision containing this split and its
explicit child requirement. Go excludes a nested module from that parent
archive. Use the actual version returned by `go mod download -json`, retain its
checksums, and build without workspace or `replace` overrides. See the
[Go module archive rules](https://go.dev/ref/mod#zip-files).

This dependency transition does not remove Core requirements introduced by
other dependencies. It also does not select application images, apply schema
migrations, or change the deployed toolchain.

## Qualification

From the repository root, run:

```sh
python3 scripts/qualify-runtime-library.py
go build ./...
```

The helper checks the child and test dependency graphs, race tests, vet,
integration-test compilation, checksum verification and tidy stability. It
rejects Core, the parent module and replacements. It also compares the packaged
workload-attachment fixture with the canonical contract example. The fixture
must live inside the child so published archives can run its tests.

Root `go test ./...` covers only the parent module. CI explicitly qualifies the
child before image publication and keeps the existing parent tests. Native
connection-profile qualification runs in the child; control-plane qualification
builds the migration and bootstrap commands from the parent, then runs child
integration tests against its disposable database fixture. A historical release
backfill runs child qualification only when that selected release contains the
child module.
