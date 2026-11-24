from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from typing import Annotated, Protocol

from psycopg import Cursor, sql
from psycopg.pq import TransactionStatus
from psycopg.rows import TupleRow, tuple_row
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, ConfigDict, StringConstraints

Identity = Annotated[
    str, StringConstraints(strict=True, strip_whitespace=True, min_length=1)
]


class Principal(BaseModel):
    """Identity resolved by the workload's authentication layer."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    tenant_id: Identity
    user_id: Identity


class Reader(Protocol):
    def read(self) -> AbstractContextManager[Cursor[TupleRow]]: ...


class Writer(Protocol):
    def write(self) -> AbstractContextManager[Cursor[TupleRow]]: ...


class AccessDenied(PermissionError):
    """The current principal or database connection fails its access policy."""


# Include transitive membership: a login which can assume the owner or a
# maintenance group cannot safely be used as a tenant-scoped request login.
_SESSION_ALLOWED = """
SELECT NOT EXISTS (
    SELECT FROM pg_catalog.pg_roles r
    WHERE (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
      AND (pg_catalog.pg_has_role(session_user, r.oid, 'MEMBER')
        OR pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER'))
) AND NOT EXISTS (
    SELECT FROM pg_catalog.pg_database d
    WHERE d.datname = current_database() AND
      (pg_catalog.pg_has_role(session_user, d.datdba, 'MEMBER')
       OR pg_catalog.pg_has_role(current_user, d.datdba, 'MEMBER'))
) AND NOT EXISTS (
    SELECT FROM pg_catalog.unnest(%s::text[]) denied(name)
    LEFT JOIN pg_catalog.pg_roles r ON r.rolname = denied.name
    WHERE r.oid IS NULL OR pg_catalog.pg_has_role(session_user, r.oid, 'MEMBER')
      OR pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')
)
"""


@contextmanager
def _transaction(
    pool: ConnectionPool,
    principal: Principal | None,
    *,
    readonly: bool,
    denied_roles: tuple[str, ...],
    maintenance_role: str | None = None,
) -> Iterator[Cursor[TupleRow]]:
    with pool.connection() as connection:
        if connection.info.transaction_status != TransactionStatus.IDLE:
            raise AccessDenied("repository requires an idle connection")
        with (
            connection.transaction(),
            connection.cursor(row_factory=tuple_row) as cursor,
        ):
            if readonly:
                cursor.execute("SET TRANSACTION READ ONLY")
            if maintenance_role is not None:
                cursor.execute(
                    sql.SQL("SET LOCAL ROLE {}").format(
                        sql.Identifier(maintenance_role)
                    )
                )
                cursor.execute(
                    "SELECT FROM pg_catalog.pg_roles WHERE rolname = current_user "
                    "AND rolname = %s AND NOT rolcanlogin",
                    (maintenance_role,),
                )
                if cursor.fetchone() is None:
                    raise AccessDenied("maintenance requires a dedicated NOLOGIN role")
            cursor.execute(_SESSION_ALLOWED, (list(denied_roles),))
            if cursor.fetchone() != (True,):
                raise AccessDenied("database session fails its restricted role policy")
            cursor.execute(
                "SELECT pg_catalog.set_config('codefly.current_tenant_id', %s, true), "
                "pg_catalog.set_config('codefly.current_user_id', %s, true)",
                (
                    principal.tenant_id if principal else "",
                    principal.user_id if principal else "",
                ),
            )
            yield cursor


class RequestRepository:
    """Supply trusted per-request authentication and write authorization callbacks."""

    def __init__(
        self,
        reader: ConnectionPool,
        writer: ConnectionPool | None,
        *,
        authenticate: Callable[[], Principal],
        authorize_write: Callable[[Principal], bool],
        denied_roles: tuple[str, ...],
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._authenticate = authenticate
        self._authorize_write = authorize_write
        self._denied_roles = denied_roles

    def _principal(self) -> Principal:
        principal = self._authenticate()
        if not isinstance(principal, Principal):
            raise AccessDenied("authenticated principal required")
        return principal

    @contextmanager
    def read(self) -> Iterator[Cursor[TupleRow]]:
        with _transaction(
            self._reader,
            self._principal(),
            readonly=True,
            denied_roles=self._denied_roles,
        ) as cursor:
            yield cursor

    @contextmanager
    def write(self) -> Iterator[Cursor[TupleRow]]:
        principal = self._principal()
        if self._writer is None or not self._authorize_write(principal):
            raise AccessDenied("write access required")
        with _transaction(
            self._writer, principal, readonly=False, denied_roles=self._denied_roles
        ) as cursor:
            yield cursor


class MaintenanceRepository:
    """Separately wired process capability with an explicit delegated application role."""

    def __init__(self, pool: ConnectionPool, *, application_role: str) -> None:
        if (
            not application_role
            or len(application_role.encode()) > 63
            or "\x00" in application_role
        ):
            raise ValueError("valid PostgreSQL application role required")
        self._pool = pool
        self._role = application_role

    def read(self) -> AbstractContextManager[Cursor[TupleRow]]:
        return _transaction(
            self._pool,
            None,
            readonly=True,
            denied_roles=(),
            maintenance_role=self._role,
        )

    def write(self) -> AbstractContextManager[Cursor[TupleRow]]:
        return _transaction(
            self._pool,
            None,
            readonly=False,
            denied_roles=(),
            maintenance_role=self._role,
        )
