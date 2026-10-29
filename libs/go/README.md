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
connection is discarded before the application transaction begins, and the
acquisition fails with that refusal rather than retrying on fresh connections
until pgx's attempt budget is exhausted. Errors do not expose the denied role
names or credentials.

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

## Connection policies

`WithConnectionPolicies(reader, writer)` carries an application's own
connection-authority rule on the pools `Open` owns, one policy per capability.
`WithMaintenanceConnectionPolicy` does the same for the separately wired
maintenance capability. A `ConnectionPolicy` is
`func(context.Context, *pgx.Conn) error`: nil admits the connection, any error
refuses it. The policy itself stays in the application; this library owns only
the lifecycle that runs it.

Coverage is per capability and never crosses. The reader policy runs on the
read-only pool and the writer policy on the read-write pool, each with its own
login, and neither reaches maintenance; the maintenance policy reaches neither of
them. Pools a caller builds and passes to `NewFactory` or `NewMaintenance` are
not rewired by any of these options — their owner enforces the equivalent policy,
exactly as with restricted sessions.

Both lifecycle boundaries run the same ordered chain: any connection hook the
caller already set, then this library's mandatory checks (the maintenance role
qualification, on new connections only), then the restricted-session policy, then
the capability's connection policy.

A refusal by one of this library's own checks — restricted session or the
capability policy — destroys that connection and fails the acquisition with that
error, so a refused connection never serves application traffic and the reason
reaches the caller. A prior hook the caller set keeps its own verdict instead,
with pgx's `PrepareConn` semantics unchanged: returning true with an error
releases the connection to the pool and fails the query rather than destroying
it, and returning false with no error asks pgx to retry on a fresh connection
rather than failing. Only the library's refusals are destructive.

Checkout runs the policy on every transaction, so a policy costs whatever it
queries, per transaction, on top of the restricted-session round trip. Connect
runs it once per physical connection, including reconnects and background pool
refills. When `WithOperationTimeout` is set it bounds each boundary's whole chain
— one budget for the chain, not one per check, and the caller's own prior hook is
inside it. That bound matters on the connect
path: pgx deliberately lets a connection finish building after its acquire is
cancelled, so a connect-time check has no deadline of its own. The bound refuses
a check that outlives it; it cannot interrupt callback code that ignores its
context.

A policy is a point-in-time check, not a fence. A `GRANT` landing after a
connection is validated is visible only at the next boundary, so this is not a
substitute for changing authority under a controlled procedure and draining the
workloads that hold connections.

A nil policy installs nothing of its own, with one qualification: a capability
that also enables `WithRestrictedSession` gets the refusal behavior described
above either way, because both checks now share one chain. A refused checkout
fails with that refusal rather than retrying on fresh connections until pgx's
attempt budget reports a generic hook bug. A capability with neither a policy
nor a restricted session has no connection hook installed at all and is
unchanged.

The isolated regression exercises both boundaries and hook ordering, per-capability
logins, refusal at connect, a pooled connection refused after a `GRANT` with the
application callback never running, single-invocation refusal, cancelled contexts,
a blocking policy bounded on the connect path, background pool refill, failed-startup
and shutdown connection cleanup, and maintenance isolation in both directions. It
uses fixture-only roles and no cloud identities.

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

## Explicit managed schema bootstrap

The [managed bootstrap preview](../../docs/managed-bootstrap.md) composes the
shared schema-plan artifact, existing `golang-migrate` executable and canonical
role engine under the database control-plane lock. It accepts an explicit
passwordless owner endpoint and separately bound existing external principals.
Use `cmd/managed-bootstrap` for this owner operation; it is not part of the
request-scoped Store API. Its isolated PostgreSQL qualification is included in
`scripts/qualify-controlplane.py`. Managed deployment packaging and cloud
qualification remain separate, and the agent's external-identity Build guard
continues to reject password-bootstrap generation.
# Explicit connection profiles

`Open` can validate the exact parsed driver configurations it uses for its private
reader/writer pools. Opt in with `WithConnectionProfiles(readerProfile,
writerProfile)`. `OpenMaintenance` accepts the independent
`WithMaintenanceConnectionProfile(profile)` option. No profile preserves existing
driver parsing and defaults; it is a legacy compatibility mode, not a hosted TLS
guarantee. Existing scope, token-provider, isolation and restricted-session options
continue to compose with either constructor.

```go
reader := postgres.ConnectionProfile{Transport: postgres.VerifiedTLS}
writer := postgres.ConnectionProfile{
    Transport: postgres.VerifiedTLS,
    ApplicationRole: "request_writer",
}
// The writer URL must contain exactly role=request_writer; the reader URL must
// contain no role. Memberships and SQL grants remain separately provisioned.
factory, close, err := postgres.Open(ctx, readerURL, writerURL, authenticator,
    postgres.WithConnectionProfiles(reader, writer),
    postgres.WithExternalIdentity(declaredIssuer))
```

## One authenticated pool, for a service that owns its own tenancy

`OpenPool(ctx, connection, profile, options...)` opens one pool for one
capability and nothing else: the profile decides the transport and the pinned
authority, the options decide the credential, and the caller gets a pool whose
first connection has already succeeded. It grants no role, installs no session
policy and judges no privilege.

It exists because every other constructor here is opinionated. `Open` splits a
service across a reader and a writer and installs the scoped RLS factory;
`OpenMaintenance` selects an application role and refuses a privileged login. A
service with one runtime principal and its own authority over whose tenant a
call concerns fits neither, and so called `pgxpool.New` itself — which means it
also re-decided the transport, the trust anchor and the credential, each of
which this package already decides. This is the primitive underneath the other
two, exposed, so adopting the library is one call rather than a redesign.

`pgxpool` connects lazily, so `OpenPool` pings before returning: a wrong
credential, an unverifiable server or an unreachable address fails at boot,
where it is a deployment fault, rather than at the first query, where it reads
as a runtime one.

## External identity: the consuming service names no cloud

`WithExternalIdentity(declaration)` authenticates every pooled connection as the
workload's own cloud identity: the login is a cloud principal, the password is a
short-lived token minted per physical connection, and no password exists to be
seeded, projected or rotated. A capability URL must then carry its login and no
password — one beside a credential provider is refused, because the token
replaces it on every backend and the URL's would be dead config reading as the
live credential.

`declaration` is the deployment's statement of where the workload runs. The
consuming service forwards the value it was configured with and does not
interpret it: no application names a cloud, a cloud SDK or an identity endpoint,
and adding a cloud changes this library alone. Declarable values are
`azure-entra` (Entra ID on Azure Database for PostgreSQL) and `gcp-cloud-sql`
(IAM database authentication on Cloud SQL, which the instance must have on
through the `cloudsql.iam_authentication` flag). There is no default: an empty
or unrecognized declaration is refused at startup, naming the set it could have
been, because the absence of a declaration and a declaration of absence are
different states.

`gcp-cloud-sql` authenticates several distinct logins from one pod. A pod holds
one Kubernetes ServiceAccount and therefore one primary cloud identity, while
this library deliberately keeps its capabilities on separate logins. The login
each connection names decides the path: the pod's own service account uses its
ambient credential directly, and any other login is exchanged for that
principal's token through the IAM Credentials API, which requires
`roles/iam.serviceAccountTokenCreator` on exactly that account. The cloud
principal is derived from the login rather than declared twice — Cloud SQL
registers a service-account login as the email with `.gserviceaccount.com`
stripped, so appending it reverses that exactly. A login that is not a
service-account login never reaches the API. Tokens are cached per login and
retired before expiry; distinct logins never share one, which is the whole point
of keeping them distinct.

`WithExternalIdentity` and `WithAccessTokenProvider` are mutually exclusive:
both authenticate the same pools, and a deployment declaring two credentials for
one login has not said which is authoritative. `WithAccessTokenProvider` remains
for a service that mints its own credential — a projected token file rewritten
by a sidecar, say — and carries no cloud knowledge into this library.

## The server's trust anchor arrives as a value, not a file

A managed instance often presents a certificate signed by an authority private
to it: Cloud SQL's default `serverCaMode` signs with a per-instance, self-signed
CA whose root is in no system trust store, so `sslmode=verify-full` against
system trust cannot verify it at all. pgx reads an anchor from `sslrootcert`, a
file — and a file has to be mounted, which is a seam a service agent may not
have.

`ConnectionProfile.ServerTrustAnchorPEM` takes the authority as a configured
value and the library builds the trust pool itself, so the configuration plane
delivers a value and nothing delivers a file. A certificate authority is public
information: this is ordinary configuration, not a secret. Pinning it is
stronger than system trust rather than weaker — verification then means "this
instance's own authority" instead of "any authority a public trust store
carries" — and it narrows the authority only: hostname verification stays on and
`InsecureSkipVerify` stays false.

It is `VerifiedTLS` only, since no other transport verifies a certificate.
Declaring it beside `sslrootcert` in the URL is refused: two answers to one
question, one of which is the file the deployment could not deliver. An anchor
that parses to no certificate — including the empty string — is refused rather
than falling through to system trust, as are a private-key block, a server's own
leaf certificate and an expired authority, each of which a lenient parse accepts
and turns into an unverifiable connection far from its cause.

`VerifiedTLS` requires an explicit PostgreSQL URL, login, database, a single TCP
host and `sslmode=verify-full`; every effective endpoint is checked and driver
fallbacks are rejected. Explicit CA/client-certificate files and reviewed pool
settings are supported. Absent CA settings use normal system trust rather than
implicit home-directory certificates. Passfile lookup is disabled. There is no
plaintext, service-file, ambient endpoint or unverified-TLS fallback.

`LocalIdentityProxy` requires a canonical hostless URL with an absolute socket
directory, explicit numeric port, `sslmode=disable` and `passfile=/dev/null`.
Passwords, token hooks, TCP fallback and extra options are rejected. The service
may require distinct reader/writer socket directories using
`WithDistinctProxySockets()`. This checks the local binding only; the deployment
owner must attest the proxy's remote TLS, identity and isolation separately.

`MeshProtected` is a plaintext TCP connection to one named host, for a store the
platform's service mesh reaches over mutual TLS between workload identities — the
connection the Postgres agent renders for an in-cluster store. It requires
`sslmode=disable` literally, allows a password, and rejects CA/client-certificate
files, passfiles, socket hosts, pool settings and fallbacks. Selecting it is the
service's assertion that the mesh covers the hop; it is never inferred from a URL.
`LocalLoopback` is the same shape restricted to `localhost` or a literal loopback
address: what a local development run of the agent serves.

In any explicit profile, duplicate keys, case aliases, unknown options,
session-authorization injection, endpoint/login/database overrides and any `PG*`
environment variable (including an empty one) fail before pool creation. The only
accepted startup role is the exact nonempty `ApplicationRole`; empty forbids a URL
role. Optional `Host`, `Port`, `Database` and `User` fields additionally bind a
capability to a trusted projection. These fields compare the effective parsed
configuration; they do not rewrite its identity. `OpenMaintenance` retains its
separate application-role selection and live restricted-role qualification.

Explicit-profile parsing errors are `ErrConnectionProfile`; connection/token
failures during constructor startup are redacted as `ErrConnectionUnavailable`.
The legacy zero profile retains prior error behavior. `ParseConnection` is the
same single parser for an intentional trusted raw-pool composition; its returned
configuration must be used directly. Validating then discarding it and reparsing
the original string defeats the contract. Parsing creates no pool, connects to no
database and executes no SQL. Callers that mutate the returned config or install
arbitrary hooks assume responsibility for those changes.

The migration is opt-in. A consumer must explicitly choose its default transport,
startup roles and required physical bindings. URLs that relied on ambient `PG*`,
`.pgpass`, home-directory client certificates, unknown startup parameters or
multiple hosts must be replaced with a reviewed explicit binding before enabling
a profile. No database migration, role grant, schema-plan or engine/image update
is performed by this API.

Local qualification from the repository root (requires a native PostgreSQL
installation, Go and OpenSSL):

```sh
POSTGRES_BIN=/path/to/postgres/bin python3 qualification/connection-profiles/run.py \
  --output /tmp/connection-profile-evidence
```

This creates disposable TLS and Unix-socket PostgreSQL fixtures and checks actual
identity/role, RLS, maintenance separation, token reconnect, closure, wrong CA and
hostname denial, and redacted failures. It does not qualify a real identity proxy
or hosted provider. From `libs/go`, ordinary `go test ./...` also runs the parser matrix;
the native fixture requires the runner and records whether its test actually ran.
