import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from psycopg_pool import ConnectionPool

from codefly_postgres import (
    AccessDenied,
    MaintenanceRepository,
    Principal,
    RequestRepository,
)


@pytest.fixture(scope="module")
def database(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """An isolated real PG cluster with socket-only access and a disposable schema."""
    if not shutil.which("initdb") or not shutil.which("pg_ctl"):
        pytest.skip(
            "install PostgreSQL server tools on PATH to run repository integration tests"
        )
    cluster = tmp_path_factory.mktemp("pg") / "data"
    subprocess.run(["initdb", "-D", cluster, "-U", "owner", "-A", "trust"], check=True)
    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(
            [
                "pg_ctl",
                "-D",
                cluster,
                "-o",
                f"-k {directory} -c listen_addresses=''",
                "-l",
                Path(directory) / "server.log",
                "-w",
                "start",
            ],
            check=True,
        )
        try:
            dsn = make_conninfo(host=directory, dbname="postgres", user="owner")
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute("""
                    CREATE ROLE request LOGIN;
                    CREATE ROLE jobs NOLOGIN;
                    CREATE ROLE worker LOGIN NOINHERIT;
                    GRANT jobs TO worker;
                    CREATE TABLE ledger (tenant text, value integer);
                    ALTER TABLE ledger ENABLE ROW LEVEL SECURITY;
                    GRANT SELECT, INSERT ON ledger TO request, jobs;
                    CREATE POLICY scoped ON ledger TO request USING (
                        tenant = current_setting('codefly.current_tenant_id', true)
                    );
                    CREATE POLICY maintain ON ledger TO jobs USING (true)
                """)
            yield dsn
        finally:
            subprocess.run(["pg_ctl", "-D", cluster, "-w", "stop"], check=True)


def test_capabilities(database: str) -> None:
    with ExitStack() as stack:

        def pool(user: str) -> ConnectionPool:
            connection_pool: ConnectionPool = ConnectionPool(
                make_conninfo(database, user=user),
                min_size=1,
                max_size=1,
                open=False,
            )
            return stack.enter_context(connection_pool)

        request, worker = pool("request"), pool("worker")
        tenant = "first"
        can_write = True

        def authenticate() -> Principal:
            return Principal(tenant_id=tenant, user_id="person")

        repo = RequestRepository(
            request,
            request,
            authenticate=authenticate,
            authorize_write=lambda _: can_write,
            denied_roles=("jobs",),
        )
        with repo.write() as tx:
            tx.execute("INSERT INTO ledger VALUES ('first', 1)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege), repo.write() as tx:
            tx.execute("INSERT INTO ledger VALUES ('second', 2)")
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction), repo.read() as tx:
            tx.execute("INSERT INTO ledger VALUES ('first', 3)")
        with repo.read() as tx:
            assert tx.execute("SELECT * FROM ledger").fetchall() == [("first", 1)]
        tenant = "second"
        with repo.read() as tx:
            assert tx.execute("SELECT * FROM ledger").fetchall() == []
        with request.connection() as connection:
            assert connection.execute(
                "SELECT current_setting('codefly.current_tenant_id',true)"
            ).fetchone() == ("",)
        can_write = False
        with pytest.raises(AccessDenied), repo.write():
            pass
        for wrong_pool in (worker, pool("owner")):
            unsafe = RequestRepository(
                wrong_pool,
                None,
                authenticate=authenticate,
                authorize_write=lambda _: False,
                denied_roles=("jobs",),
            )
            with pytest.raises(AccessDenied), unsafe.read():
                pass
        maintenance = MaintenanceRepository(worker, application_role="jobs")
        with maintenance.write() as tx:
            tx.execute("INSERT INTO ledger VALUES ('second', 4)")
        with maintenance.read() as tx:
            assert tx.execute("SELECT count(*) FROM ledger").fetchone() == (2,)
            assert tx.execute(
                "SELECT current_setting('codefly.current_tenant_id')"
            ).fetchone() == ("",)
