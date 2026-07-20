# Postgres Rust library

This is the service-owned Rust client for `service-postgres`. It is the Rust
parity boundary for `../go`: consumers supply an application authenticator,
while this library privately owns Codefly's distinct read-only and read-write
connections, installs tenant/principal scope with transaction-local settings,
and never exposes a pool or raw transaction.

`Factory::reader` accepts any authenticated Principal. `Factory::writer`
additionally asks the application authenticator for an explicit write decision.
The returned reader has query-only methods; only the writer exposes `execute`
and tenant-scoped advisory locks. The database credentials and `BEGIN READ
ONLY`/`BEGIN READ WRITE` modes remain defense in depth if an API boundary is
circumvented.

Every transaction has one fixed operation deadline covering pool acquisition,
scope installation, every query, and commit. Scope setting names are validated
once at construction and values are always bound parameters.

