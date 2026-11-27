# Codefly Postgres repositories for Python

This package gives module code transaction-scoped access to a Codefly store. The
application opens Psycopg pools using its deployment's resolved connections and
owns their lifecycle. The same API accepts pools connected through an
environment-provided Cloud SQL proxy.

Inject a `Reader` or `Writer` into the domain repository that needs it. Wire
`RequestRepository` once at the service boundary. Its `authenticate` callback
reads the verified request context and returns a Pydantic `Principal`. Its
`authorize_write` callback evaluates application permission for that principal.
Pass the store's maintenance roles as `denied_roles` and supply a separate
writer pool only to a process authorized to write.

```python
from codefly_postgres import Reader

def invoice_total(repository: Reader, invoice_id: int):
    with repository.read() as tx:
        return tx.execute(
            "SELECT total FROM invoices WHERE id = %s", (invoice_id,)
        ).fetchone()
```

Each request transaction installs the Go library's default RLS settings,
`codefly.current_tenant_id` and `codefly.current_user_id`, transaction-locally.
Read transactions also request PostgreSQL read-only mode. The database controls
table privileges and enforces the policies installed by store migrations.

Wire `MaintenanceRepository` only into the maintenance process, using its own
dedicated pool and delegated NOLOGIN role. It selects that role within each
transaction and clears request identity settings. Both repository types check
database ownership and privileged role memberships at checkout.

Run `uv sync --locked`, `uv run --locked pytest` and
`uv run --locked pyright src tests` in this directory. The integration suite uses
`initdb` and `pg_ctl` from PATH to create and stop an isolated local cluster.
