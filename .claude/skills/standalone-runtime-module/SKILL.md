---
name: standalone-runtime-module
description: Change code under libs/go, the separate github.com/codefly-dev/service-postgres/libs/go module, alone or together with the parent agent module. Use when adding or editing anything in libs/go, when qualify-runtime-library.py fails, when tempted to add a replace directive or a go.work file to test a parent change against a local child edit, or when the parent needs a libs/go change that is not published yet. Covers the publish-then-bump rule, the no-core/no-parent/no-replace contract, and the two-module test split.
---

# Changing the standalone runtime module

`libs/go` is its own Go module — `github.com/codefly-dev/service-postgres/libs/go`
— with its own `go.mod` and `go.sum`. It exists so an application can use the
connection profiles, restricted sessions, role reconciliation, schema plans,
workload attachments and migration fixtures **without** dragging in the parent
agent module or Codefly Core.

That independence is a contract, and `scripts/qualify-runtime-library.py`
enforces it:

- no `codefly-dev/core` in the child's dependency graph, including test deps;
- no parent-module path;
- **no `replace` directives**;
- the packaged workload-attachment fixture is byte-identical to
  `contracts/workload-attachment/example.json`;
- then, inside `libs/go` with `GOWORK=off GOENV=off GOFLAGS=-mod=readonly`:
  `go test -race -count=1 ./...`, `go vet ./...`, integration-test compilation
  under `-tags=controlplaneintegration`, `go mod verify`, `go mod tidy -diff`.

```bash
python3 scripts/qualify-runtime-library.py
go build ./...
```

## The rule that will bite you

The parent requires the child **by published version**:

```
github.com/codefly-dev/service-postgres/libs/go v0.0.0-20260915032422-272301033aed
```

A local edit under `libs/go` does **not** reach the parent build. The loop is:
build the child independently, publish it, then update the parent to the version
Go returns. Release tags for the child carry the `libs/go/` prefix.

So when a parent change needs a child change, you cannot test them together in
one commit. The temptation is a `replace` directive or a `go.work` — both are
forbidden (`go.work*` is gitignored for this reason, and the qualify script
fails on `replace`). Reaching for either is the hack this repo names in its PR
classification. Split the work: land the child, publish, then bump the parent in
a second PR, and say in the first that the parent side is unverified until the
bump.

## Testing the two modules

Root `go test ./...` covers **only** the parent. Nothing at the root exercises
`libs/go`, so run its suite separately:

```bash
cd libs/go && go test ./...      # green with no docker and no database
```

Its real-database tests sit behind the `controlplaneintegration` build tag and
need `SERVICE_POSTGRES_CONTROLPLANE_TEST_DSN`,
`SERVICE_POSTGRES_MIGRATE_EXECUTABLE`, `SERVICE_POSTGRES_BOOTSTRAP_EXECUTABLE`
and `SERVICE_POSTGRES_FIXTURE_CONTAINER` — all supplied by
`scripts/qualify-controlplane.py`, which boots a digest-pinned official postgres
on loopback and cross-builds the two commands for the fixture's architecture:

```bash
POSTGRES_TEST_IMAGE=postgres@sha256:… python3 scripts/qualify-controlplane.py
```

Two more skip plainly without a DSN, so a green local run says nothing about
them: `connection_profile_postgres_test.go` (`CONNECTION_PROFILE_TEST_DSN`) and
`session_policy_test.go` (`SESSION_POLICY_TEST_DSN`).

## Consumer graph

An old parent archive contains the same `libs/go` packages, so selecting an old
parent together with the new child produces ambiguous imports even though the
APIs are compatible. A consumer needing both must select a published parent
revision that contains the split and its explicit child requirement. The long
form is in `docs/runtime-go-module.md`.
