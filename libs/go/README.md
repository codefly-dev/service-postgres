# Postgres Go library

This is the service-owned Go client library for `service-postgres`. Database-
specific capability, authentication, transaction, and RLS integration belongs
here—not in the generic Codefly SDK and not in consuming applications.

`postgres.Open` accepts Codefly's distinct read-only/read-write connections and
an application authenticator. It returns only an authenticated `Factory` plus
an idempotent closer; raw pools and migration-owner authority are never exposed.

Repositories request a scoped `Reader` or `Writer` from context and execute
through `ReadTx` or `WriteTx`. Tenant/user identity is installed as transaction-
local settings for RLS. Trusted background work uses an opaque `WorkloadIssuer`
capability fixed to one tenant, workload identity, and read/write permission.
`WriteTx.ScopedAdvisoryLock` serializes a logical resource inside that same
authenticated tenant without revealing tenant identity to repository code.

The library suite runs under `-race`, and the service root lifecycle suite
starts the actual Postgres plugin to prove separate roles, read-only enforcement,
DDL/role denial, fail-closed RLS, request/workload isolation, and private-owner
migration replay with runtime-grant reconciliation.

Privileged migration qualification is deliberately separate at
`libs/go/migrationtest`. That test-only package validates reversible numbered
migration inventories and owns isolated database create/clone/drop mechanics.
It requires the plugin-private owner connection explicitly and is never exposed
through the authenticated application `Factory`.

## Service-owned maintenance

`OpenMaintenance(ctx, connection, applicationRole, options...)` opens a separate
capability for background cleanup, queue discovery or reconciliation. It uses the
same Reader/Writer transaction implementation, clears tenant/user settings locally,
and does not invent a tenant or grant database privileges. Application migrations
own table grants and any explicit maintenance RLS policy. Every new connection
checks that the selected role cannot log in, that neither the login nor selected
role has elevated role flags, and that neither directly owns the database. These
checks do not audit inherited memberships, table grants or application policies.
Raw pools and migration APIs are not exposed. Keep Maintenance out of request
handlers; they continue to receive only the authenticated Factory.

`NewMaintenance` supports trusted preconfigured pool compositions and tests, just
as `NewFactory` does; that caller owns pool closure and privilege qualification.
`OpenMaintenance` owns an idempotent closer and accepts the existing token-provider
and operation-timeout options. Neither constructor issues a new login credential
or makes a request writer's credential less privileged. Separate process/secret
identities must be provisioned by the platform when that isolation is required.

`WithReadIsolation(pgx.RepeatableRead)` preserves a consistent snapshot across
multiple queries. It affects readers only; writers keep their existing isolation
semantics and application-owned row locking. Failed callbacks roll back as in the
existing scoped Factory. Without this option, existing read isolation is unchanged.

## Restricted sessions

`WithRestrictedSession("background_jobs")` is an optional policy for `Open` and
`OpenMaintenance`. It rejects the login or current role if either has direct or
transitive membership in a named forbidden role, a privileged role (including
BYPASSRLS, CREATEROLE or CREATEDB), or the current database owner. A missing named
role fails closed. With no arguments it still checks privileged and owner roles.
The policy uses read-only catalog queries on every new physical connection and
every pool checkout, adding a catalog round trip to checkout. A newly forbidden
connection is discarded before the application transaction begins. Errors do not
expose the denied role names or credentials.

This does not grant privileges, change RLS, audit table/function grants or replace
separate process credentials. It cannot fence a concurrent GRANT after checkout;
operators must drain affected sessions before changing role memberships. PostgreSQL
object grants, safe search paths and application RLS remain separately qualified.
Caller-owned pools passed to `NewFactory` or `NewMaintenance` are not rewired by
this option; their owners must enforce the equivalent connection policy.
Existing consumers that omit this option retain the same behavior.

The isolated regression below also exercises safe sessions, direct/transitive
membership denial, privileged/owner denial, permission changes on pooled sessions,
reconnection after revoke and composition with maintenance validation. It uses
fixture-only roles and no cloud identities.

## External-identity role administration

`controlplane.ReconcileRuntimeAccess` is the privileged role-engine boundary for
managed database compositions. Callers own the transaction and per-database
advisory lock, and must roll back on any error. Identity providers create login
principals; the engine never sets their passwords. It creates and hardens NOLOGIN
groups and reconciles runtime grants and external membership separately.

Group hardening changes only attributes that differ from the required safe
values. PostgreSQL requires elevated authority for protected `ALTER ROLE`
attributes even if their current value already matches. Avoiding those redundant
updates allows a CREATEROLE administrator to reconcile ordinary groups; it does
not authorize that administrator to repair an elevated role. Existing unsafe
attributes are still hardened when authorized, or cause the transaction to fail.
See [PostgreSQL's ALTER ROLE permission rules](https://www.postgresql.org/docs/16/sql-alterrole.html).

The administrator also needs ownership/grant authority over the selected
database, schema, existing objects and migration owner's default privileges.
On PostgreSQL 16, role administration requires the appropriate ADMIN OPTION;
the regression checks that the creator's administration-only membership remains
available over repeated reconciliation. Login IAM alone supplies none of these
SQL privileges. Exact managed-provider administration must be qualified separately.
Keep the reconciliation identity stable. Switching the grantor can encounter
dependent membership grants on PostgreSQL 16; this change does not implement
administrator rotation, cascade revocation or privilege reassignment.

Run the isolated regression with a locally available, digest-pinned official
PostgreSQL fixture (the workflow pins the tested image):

```sh
POSTGRES_TEST_IMAGE=postgres@sha256:fe03a7605299a34ddf5e4f285dff78c3d7190a576b3c6b46f2fcff69f4bffd54 \
  python3 scripts/qualify-controlplane.py
```

The harness binds a disposable, trust-authenticated container to a random
loopback port, uses temporary storage and removes only that container on exit.
It loads no cloud credentials and accepts no managed endpoint. The dedicated
`controlplaneintegration` tag fails if this fixture is missing. Tests cover
restricted-admin replay and membership replacement, existing/default table and
sequence grants, runtime DDL denial, preserved external passwords/unrelated
memberships, rollback, elevated-role rejection and authorized hardening.
