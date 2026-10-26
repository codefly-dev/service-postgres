# Share a local Postgres server

A local composition can run one Postgres server with a separate logical database
for each database service. This is an explicit dependency, using Codefly's existing
network/configuration handoff and lifecycle ordering. It works with an owned Nix
or Docker server. The default remains one owned server per service.

## Compose it

On the service that owns the server, set:

```yaml
spec:
  database-name: local_control
  shared-local-server: true
```

On each database service using that server, declare a normal managed service
dependency (not `kind: external`) and set `local-server` to its module/service:

```yaml
service-dependencies:
  - name: postgres
    module: storage
spec:
  database-name: accounts
  local-server: storage/postgres
```

These are excerpts of services scaffolded with `codefly add service --agent=postgres`.
Use the containing module's actual dependency identity. The server and borrowers
must use an agent containing this feature. A missing opt-in, dependency mapping or
exported configuration fails before provisioning; there is no default address.

Give each database service a **distinct `POSTGRES_USER` migration-owner name**
through its Codefly configuration. Keep its own generated owner/reader/writer
passwords. Names must fit PostgreSQL's 63-byte identifier limit. Application
principals continue to be derived from the database name, and declared delegated
roles must be unique across databases. A collision is refused before changing
another database's credentials. This matters because PostgreSQL roles are global
to a server, even though tables and migrations belong to individual databases.

Run the consuming services together with `codefly run service`; their shared
server dependency starts once. Endpoints and credentials come from the dependency's
accepted Init response. Each logical service republishes its own endpoint identity
and reader/writer configuration at that server's addresses, so application clients
continue using their existing service dependencies. No application DSN changes.
Independent naming scopes resolve separate owning servers and retained state.
There is no process-global or machine-global pool.

The server owner exports the secret `postgres.local-server-connection` only after
`shared-local-server: true` is selected. A borrower does not export it: sharing
chains are refused. This is a local administrative capability, available to the
database runtime, not a credential applications should consume. As with existing
local owned clusters, migration owners are trusted superusers. Reader/writer
logins are not; CONNECT is explicitly granted per database and revoked from PUBLIC
on both the sharing server's database and each borrowed database. Do not use an
owner connection in an application. This feature is not an isolation boundary
between mutually untrusted migration authors.

The Postgres major must match the agent's managed runtime image. Borrowers cannot
set `docker-image`, `keep-running`, or external-identity authentication: those are
server-owner decisions. Required extensions still go through normal schema
preparation and fail if unavailable. Hosted deployment still uses the existing
`external-instances` binding; these local settings do not replace that binding or
change deployed manifests.

## Lifecycle and recovery

The existing Codefly graph owns server ordering and supervision. A logical service
runs its own migrations and runtime-grant reconciliation before reporting ready.
Concurrent initializations serialize cluster-wide role allocation through an
advisory lock in the server owner's database. Durable role reservations in
`codefly_local_server.roles` survive interrupted/dirty bootstrap and prevent
another database from taking the same role name. Do not delete this schema to
resolve a collision: choose distinct declared identities instead.

Stopping or destroying a borrower stops its watchers and releases its local
lifecycle state; it never stops the dependency's server or drops data. The owning
service stops the physical server when its composition stops. Restarting uses the
same retained server directory and per-database migration ledgers. Directly
stopping the server owner while applications still use it stops their shared
server, just as stopping any other required dependency does.

## Move existing local data deliberately

Changing `local-server` does **not** import an existing service-owned cluster. It
would create an empty logical database on the shared server. Keep the old cluster
and backup until the composed application has been verified against the restored
state; none of this agent's Stop/Destroy operations delete data.

1. Quiesce application writes and make a consistent `pg_dump` custom-format
   backup of each source database, using Codefly-resolved owner connections.
   Record row counts, migration versions and representative reference identities.
2. Prove each backup restores into an isolated test composition. Resolve its
   connections through Codefly as well. Bootstrap the target service with its
   distinct owner and normal migrations, then restore the application's data
   using a reviewed restore list. Do not restore global roles from the source
   server, replace the target migration ledger blindly, or use `--clean` on an
   existing target. A schema/version mismatch must be resolved before cutover.
3. Repeat the restore into the intended fresh shared composition while writes
   remain stopped. Verify counts, relationships, application queries, permissions
   and migration ledgers; retain the original cluster for rollback.
4. Switch the application composition only after verification. Rollback means
   stopping writes and returning to the original dependency configuration; writes
   accepted after cutover require reconciliation before such a rollback.

The PR's lifecycle test proves persistence on a new shared composition. It does
not claim to have migrated any user's existing database or validated an arbitrary
application backup.

## Qualification

`go test . -run '^TestLocalServer' -count=1` includes actual Nix/Docker Postgres startup,
two simultaneous independently migrated database services, exported mappings,
reader access to own data, denied cross-database connections, role collision
refusal, borrower Stop/Destroy, and data surviving a whole-server restart.
Unavailable local runtimes are explicit skips. CI runs the Docker lifecycle
with a required locally built image; a missing daemon then fails. The pure unit
cases cover missing/ambiguous dependency handoff, mismatched addresses, missing
opt-in and incompatible settings. Run with
`-race` for concurrent-bootstrap qualification.

A standalone `codefly endpoint` invocation that cannot attach to the running flow
may fall back to the borrower's proposed port. For shared databases, consume the
accepted mappings/runtime configurations from the live composition; a deterministic
pre-run endpoint is not evidence of the actual shared listener.
