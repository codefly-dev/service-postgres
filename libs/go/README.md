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
