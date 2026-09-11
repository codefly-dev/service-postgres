# Managed identity bootstrap preview

The `cmd/managed-bootstrap` command applies the existing schema-plan package
through the pinned `golang-migrate` executable, then calls
`controlplane.ReconcileRuntimeAccess`. It is an explicit owner operation in this
database primitive. Application services supply their domain migration files;
they do not copy this runner or the role engine.

This preview is qualified on disposable PostgreSQL 16 with a restricted
CREATEROLE migration owner and a passwordless loopback endpoint. Managed cloud
execution, identity proxies, container packaging and deployment integration are
separate qualification steps. The ordinary agent `Build` still rejects
`auth-mode: external-identity`; its password bootstrap must not be used for this
path. The new command does not remove that guard or enable runtime startup DDL.

## Inputs and ownership

Supply the builder's `bootstrap/plan.json` and `bootstrap/sources` tree, plus a
separate deployment binding. The shared `libs/go/schemaplan` package defines the
same v1 artifact and digest used by the builder. No format or existing content
identity changes in this preview.

The binding must name pre-provisioned cloud login principals and the connected
migration owner. For example, with entirely synthetic role names:

```json
{
  "plan-sha256": "<SHA-256 of the exact plan.json file>",
  "plan-digest": "sha256:<digest recorded inside that plan>",
  "owner-role": "migration_owner",
  "read-only-principals": ["external_reader"],
  "read-write-principals": ["external_writer"]
}
```

Both identities are checked. The exact file SHA additionally binds field
boundaries and inventory bytes; the v1 plan digest is retained for compatibility.
The plan supplies the database, NOLOGIN groups, schemas, delegated write roles,
extensions and independently versioned migration ledgers. The deployment owner
must review the exact plan and binding together. Group names are not inferred
from a provider identity, and the command cannot override the plan's access
policy. The connected `current_user` must equal the explicit owner so migration
ownership and default privileges agree.

Login identities must already exist. They must differ from the migration owner,
the managed groups, delegated roles and each other. A configured group that is
already a LOGIN or elevated role fails before migration. The command never
creates login identities, alters their passwords or obtains cloud credentials.
The canonical role engine owns NOLOGIN group creation and access reconciliation.
Its existing restrictions on administration authority and stable grantors apply.

The migration owner needs authority for the declared DDL, extension operations,
group administration, grants and its own default privileges. The runner also
needs permission to terminate its own child sessions, supported by PostgreSQL
14+ and qualified here on PostgreSQL 16. It never requests superuser or bypass-RLS
rights. Managed-provider SQL permissions still need separate qualification.

## Build and run

Build both executables from one reviewed, immutable checkout. The migration
executable uses the existing version in `go.mod` (currently v4.19.1):

```sh
go build -trimpath -o /tmp/managed-bootstrap ./cmd/managed-bootstrap
go build -trimpath -tags postgres -o /tmp/migrate \
  github.com/golang-migrate/migrate/v4/cmd/migrate
```

Supply `CODEFLY_POSTGRES_MIGRATION_CONNECTION` privately through the deployment
composition. This preview accepts an explicit passwordless TCP URL, for example
`postgres://migration_owner@127.0.0.1:5432/example?sslmode=disable` for a disposable
local fixture or an already authenticated local proxy. Direct network endpoints
should use their reviewed TLS mode and trust configuration. The supported query
keys are `sslmode`, `sslrootcert`, `sslcert` and `sslkey`; the runner owns connection,
lock and statement budgets. Static passwords, hidden service files, implicit
principals, alternate databases and arbitrary connection options are rejected.
Inherited password/role configuration is not forwarded to the child.

```sh
/tmp/managed-bootstrap \
  -package /mounted/bootstrap \
  -binding /mounted/binding.json \
  -migrate /tmp/migrate \
  -timeout 10m -lock-timeout 30s -statement-timeout 5m
```

The deployment owner must pin both binaries and the schema package in its own
immutable image/artifact. A local build or editable checkout is not cloud release
evidence. This change does not ship a cloud Job or automatically publish a
managed bootstrap image.

## Execution and failure semantics

The runner verifies the exact plan, lineage/file hashes and inventory before
connecting. It executes a private snapshot of those verified bytes, so a later
input edit cannot change a running migration. Changed bytes, duplicate versions,
unknown fields, path traversal, symlinks and missing identity bindings fail closed.

One owner connection holds the existing per-database `codefly-runtime-access`
advisory lock across extensions, every migration subprocess and the canonical
access transaction. Independent lineages retain their original ledgers. Concurrent
jobs serialize; reruns use `golang-migrate`'s existing no-change behavior. There
are no automatic migration retries or force/repair actions.

A failed or dirty migration prevents access reconciliation. Migrations are not
atomic with each other or with the final grants transaction: earlier completed
lineages remain committed. Use [the dirty-migration runbook](dirty-migrations.md)
to inspect and reconcile failures. Do not force a ledger clean merely to rerun.

The total execution budget cancels subprocesses; lock and statement timeouts also
bound server work. Killing a client alone is not proof that its SQL stopped, so
the runner drains only that child's uniquely named owner sessions while it still
holds the shared lock. Cleanup has a separate five-second bound. An uncertain
cleanup/commit is an operator reconciliation outcome, not safe-retry permission.
Uncatchable process loss or loss of the lock-owning connection remains a deployed
recovery qualification gap; this local test does not claim restart recovery.

Standard output is a JSON receipt containing the exact plan file SHA-256, plan digest, completed lineages,
skipped optional extensions and whether access committed. Exit zero requires
committed access. Errors omit SQL, connection URLs and subprocess output; inspect
SQL state through the privileged operator path. This receipt is not a durable
migration audit service or a substitute for the actual version ledgers.

## Qualification

With Docker running and the workflow's pinned fixture available locally:

```sh
POSTGRES_TEST_IMAGE=postgres@sha256:fe03a7605299a34ddf5e4f285dff78c3d7190a576b3c6b46f2fcff69f4bffd54 \
  python3 scripts/qualify-controlplane.py
```

The harness builds the actual command and pinned migration CLI, and exercises
concurrent jobs, command replay, one migration execution, unchanged external
passwords, reader/writer DML, denied runtime DDL, default sequence privileges,
missing-principal and LOGIN-group rejection, bounded shared-lock contention,
dirty-state preservation, cancellation and child-session cleanup. Failure tests
verify that runtime access is not reconciled and sensitive SQL is not returned.
The existing restricted-session and canonical role-engine suites also run.

The managed command still needs an immutable deployment artifact and managed
provider qualification before use against a shared endpoint. Provider IAM,
workload identity, secret/token refresh, application database clients and cloud
backup/restore are outside this runner's responsibility.
