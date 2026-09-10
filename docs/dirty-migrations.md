# Dirty migration recovery

golang-migrate marks a lineage **dirty** when it starts applying a version and
never records the outcome — the agent process was killed, the container was
torn down, or the connection dropped mid-apply. The Postgres agent **fails
closed** on that state: `Init` and `Start` return an error, readiness never
succeeds, and no migration, drop, or version rewrite is attempted.

The error names the lineage, its tracking table, and the stuck version:

```
migration lineage "billing" is dirty at version 7 (tracking table schema_migrations_billing): ...
```

## Why the agent does not recover automatically

A dirty marker records that a migration *began*. It does not say what
happened, and every automatic recovery has to guess:

- **The SQL may have committed.** The marker is cleared in a separate
  statement from the migration body. A process killed in between leaves a
  fully applied schema behind a dirty ledger. Re-running the migration then
  fails on objects that already exist, or silently doubles a data change.
- **A migration may span several transactions.** Anything with an explicit
  `COMMIT`, a `CREATE INDEX CONCURRENTLY`, or a `VACUUM` is not atomic, so
  "dirty" can mean partially applied with no way to tell how far.
- **The interrupted operation may have been a downgrade.** A dirty marker at
  version V is written by both the up and the down direction. Forcing V−1 and
  running up again re-applies a migration the operator was deliberately
  removing.
- **Version numbers need not be consecutive.** Timestamp-style versions
  (`20260114093000_add_index.up.sql`) and deleted or squashed migrations make
  V−1 arithmetic meaningless — V−1 is usually not a version that exists.
- **`Drop` is schema-wide.** The pinned golang-migrate Postgres driver
  implements `Drop` by enumerating every base table in the current schema and
  issuing `DROP TABLE ... CASCADE`. It is not scoped to the lineage that went
  dirty, so on a database shared by several services (see
  `migration-sources` in the service settings) it deletes the other services'
  tables and their migration ledgers too.

## Recovery procedure

Run these by hand, against the affected database. Nothing here is executed by
the agent.

1. **Back up first.** `pg_dump` the whole database before touching anything —
   including the `schema_migrations*` tables.

   ```sh
   pg_dump --format=custom --file=pre-recovery.dump "$DATABASE_URL"
   ```

2. **Read the ledger.** Each lineage has its own tracking table: the service's
   own migrations use `schema_migrations`, and every entry in
   `migration-sources` uses `schema_migrations_<name>`.

   ```sql
   SELECT * FROM schema_migrations;              -- own lineage
   SELECT * FROM schema_migrations_billing;      -- a named source
   ```

   Note the `version` and `dirty` columns. Only the lineage named in the error
   is dirty; the others are untouched and must stay that way.

3. **Find the migration that was interrupted.** The dirty `version` maps to
   `<version>_<name>.up.sql` in that lineage's `migrations/` directory. Read
   it and list the objects and rows it touches.

4. **Decide whether it actually applied.** Compare the file against the live
   schema — `\d+ <table>`, `information_schema.columns`,
   `SELECT indexname FROM pg_indexes`, and row counts for any data migration.
   The three outcomes are:

   - **Fully applied.** The schema already matches the migration. Clear the
     marker without re-running anything:

     ```sql
     UPDATE schema_migrations_billing SET dirty = false WHERE version = 7;
     ```

   - **Not applied at all.** No object or row from the file is present.
     Point the ledger at the previous version *that exists in this lineage* —
     read it off the directory listing, do not assume `version - 1`:

     ```sql
     UPDATE schema_migrations_billing SET version = 6, dirty = false;
     ```

     The next startup re-applies version 7 onward.

   - **Partially applied.** Finish or undo the remainder by hand in one
     transaction, so the schema matches exactly one of the two states above,
     then apply the matching ledger update.

5. **If the interrupted run was a downgrade,** the target is the version the
   operator was moving *to*, not `version - 1`. Reconcile against that
   intended version instead.

6. **Restart the service.** With the marker cleared and the ledger consistent,
   the next `Init` runs the remaining migrations normally.

## Resetting a disposable database

There is no automatic reset, and the agent will not infer permission to delete
from a dirty marker. When the database genuinely is disposable — a local
sandbox or a CI job — drop and recreate it explicitly, outside the agent:

```sh
dropdb --force app && createdb app
```

For tests, `libs/go/migrationtest` creates and drops uniquely named throwaway
databases rather than mutating an existing one.
