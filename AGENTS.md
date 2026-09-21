# Working in codefly-dev/service-postgres

The codefly **Postgres service agent** (`agent.codefly.yaml`: `kind:
codefly:service`, `name: postgres`) — a plugin binary the `codefly` CLI loads,
plus the runtime image and client libraries it ships. It owns the Postgres
primitive: the Builder surface that renders a bootstrap image and kustomize
output, the Runtime surface that brings a postmaster up under docker or nix,
migrations, the schema plan, and the role/grant control plane.

It does **not** own the agent framework, the protobufs, the resource model or
the reusable CI workflows — those are `codefly-dev/core`, which this module
depends on. It does not own build execution or readiness orchestration: the CLI
runs the build and dials the readiness gate. It renders workload manifests and
nothing else — no GitOps transport, no reconciler, no git or GitHub client.
`conformance_test.go` enforces that last boundary by forbidden token, import,
binary and endpoint, so a manifest carrying `argoproj.io/` fails the suite.

## How to behave

Fleet standard — [handbook#68](https://github.com/obin-ai/handbook/issues/68).
They land hard here: this repo ships a *database*, and most of what it guards is
invisible from a healthy boot. A half-applied migration, a role never granted, a
tag left on an older digest — each of those serves traffic and is still wrong.

- **A gap in the tooling is a bug in the tooling — never a reason to reach
  around it.** When the CLI cannot express what a composition needs, the answer
  is the capability fixed in whichever tool owns it, named in the PR. It is
  never a hand-written environment or a pinned port — not as a "workaround", not
  "just this once", not "until the verb lands".
- **Never hack. Provide the best fix, even when it spans repos.** The fix living
  in `codefly-dev/core` or `codefly-dev/cli` is not a reason to work around it
  here. Open the PR there and consume the reviewed result. When it genuinely
  cannot be fixed now, the deliverable is a precise issue against that owner
  plus an explicitly labelled stopgap — never an unlabelled one.
- **Classify every change that makes something work**, in the PR body: a *fix*
  at the place that owns the behaviour, or a *hack*. A hack does not become a
  fix by working, by being small, by being local, or by the real fix belonging
  elsewhere.
- **Never hardcode what the system resolves** — injected environment, derived
  ports, service addresses, credentials copied out of another component. A
  runtime missing a credential can skip registration *silently*, so the service
  boots, serves, and is simply absent. Typing the value encodes something true
  on one machine for ten minutes and buries the defect that caused it.
- **Diagnose, do not pattern-match.** "It started working when I set X" is not a
  diagnosis — set X back and confirm it breaks. Do not trust an error message
  before checking its claim.
- **Say what you did not verify.** Unverified is not working. The container
  tests *skip* on a host with no docker daemon, and a skipped test is green.

## Build and test

Derived from `.github/workflows/ci.yml` and the reusable
`codefly-dev/core/.github/workflows/go-service-ci.yml` it pins by SHA.

```bash
go build ./...
go vet ./...
go mod tidy -diff        # CI fails on any diff
go test ./... -skip '^(TestCreateToRunDocker|TestDirtyMigrationFailsClosed|TestLifecycleContractDocker|TestMigrationLockBudgetExpiresWhilePeerHoldsTheLock|TestMigrationStatementBudgetExpiresAndPreservesTheLedger)$' -timeout 20m
```

That skip list is CI's unit step, and it is the inventory of what needs a
container. Everything else is template rendering, lock parsing, workflow
assertions and unit tests. The three migration regressions run after it,
against a locally built image:

```bash
docker build --build-arg SOURCE_DATE_EPOCH=0 --tag service-postgres:test .
SERVICE_POSTGRES_TEST_IMAGE=service-postgres:test go test . \
  -run '^(TestDirtyMigrationFailsClosed|TestMigrationLockBudgetExpiresWhilePeerHoldsTheLock|TestMigrationStatementBudgetExpiresAndPreservesTheLedger)$' -timeout 20m
```

`TestLifecycleContractDocker` runs later still, against the *published* image.
`TestCreateToRunDocker` runs in no ci.yml step at all — but the release
workflow runs a plain `go test -v ./...` with no skip list, so every excluded
test gates the release. A test that only fails there fails late.

Two prerequisite gates behave differently, and the difference is the point:

- `SERVICE_POSTGRES_TEST_IMAGE` **unset** → a missing docker daemon skips;
  **set** → the same condition fails. CI sets it so the regression cannot
  quietly stop enforcing anything while the build stays green.
- `requireDockerPlatform` skips a missing arm64 emulator locally, but `Fatal`s
  when `CI` is set — an arm64 archive checksum is only really checked there.

A clean local run therefore proves less than a green CI run. Say which you did.

Two further suites own their own module or fixture:

```bash
python3 scripts/qualify-runtime-library.py                      # libs/go standalone
POSTGRES_TEST_IMAGE=postgres@sha256:… python3 scripts/qualify-controlplane.py
```

`cd libs/go && go test ./...` is green with no docker and no database: its
real-database tests sit behind the `controlplaneintegration` tag and DSN
variables only the qualify script supplies.

## Where things live

| Path | Owns |
| --- | --- |
| `main.go` | plugin entrypoint, the `Settings` YAML contract, credentials |
| `builder.go` | Builder RPCs; staging `bootstrap/` and rendering its Dockerfile |
| `runtime.go` | Runtime RPCs; postmaster lifecycle and the state-ownership contract |
| `migrations.go` | one golang-migrate lineage per source, budgets, fail-closed |
| `schema.go`, `schemaplan.go` | prerequisite resolution into `bootstrap/plan.json` |
| `runtime_access.go` | roles, grants, RLS, password vs `external-identity` |
| `nixpg.go` | the docker-free backend, from the embedded `nix/flake.*` |
| `hotreload.go` | forward-only migration reload |
| `templates/` | everything embedded into the binary; `factory/` is what `Create` scaffolds |
| `libs/go` | **separate module**: the Go client library, no core, no parent |
| `libs/rust` | the Rust parity boundary for `libs/go` |
| `cmd/managed-bootstrap` | the explicit migration-owner command |
| `contracts/workload-attachment` | the sealed attachment envelope (v1, v2) |

## Rules that bite

- **No runtime operation deletes data.** `Stop`, `keep-running` and `Destroy`
  all retain database state; the contract is the table in `runtime.go` above
  `Stop`. Keep it when adding a lifecycle path.
- **A dirty lineage fails closed** — `Init` and `Start` error, readiness never
  succeeds, and nothing is repaired automatically (`docs/dirty-migrations.md`).
- **Hot reload is forward-only.** An edit at or below the applied version is
  reported, never re-applied.
- **`libs/go` is consumed by published version, never `replace`.** The qualify
  script fails on a `replace` directive or any core/parent import.
- **The two image locks move by different mechanisms.** `bootstrap-image.json`
  is written by a script; `runtime-image.json` is hand-edited and only verified.
  Neither is a value to guess — see the skills below.
- **A pull request never moves the shared runtime tag.** It publishes by digest;
  only a push to `main` tags.
- **CI's own shape is under test.** `workflow_test.go` asserts step order and
  env, so editing `.github/workflows/ci.yml` without the test fails the suite.
- **Migrations and role reconciliation share one advisory-locked session** —
  `build_bootstrap_lock_test.go` pins that order.

## Procedures

Loaded on demand rather than carried here — `.claude/skills/`:

- `runtime-image-relock` — the Dockerfile or one of its pins changed, and the
  digest in `runtime-image.json` has to move with it.
- `bootstrap-image-lock` — a build fails "unable to select packages", or the
  weekly freshness check reports drift.
- `standalone-runtime-module` — a change touches `libs/go`, alone or together
  with the parent module.

## Workflow

- Branch and PR; never commit to `main`. Conventional Commits for the title.
- The PR body carries the fix-or-hack classification and what you did not
  verify. Both are rules above; answer them there rather than omitting them.
- `agentcontext_test.go` holds this file's length budget and each skill's
  frontmatter contract, and runs under `go test ./...`.
- Keep this file under ~150 lines (hard cap 200). Push depth into a nested
  `AGENTS.md` beside what it describes, or into `.claude/skills/`.
- `CLAUDE.md` is a pointer to this file. Keep one canonical source.
- Treat this file as code: the PR that changes a process updates it.
