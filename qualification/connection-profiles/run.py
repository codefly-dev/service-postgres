#!/usr/bin/env python3
"""Qualify connection profiles against one disposable native TLS PostgreSQL.

Requires POSTGRES_BIN (directory with initdb/pg_ctl), Go on PATH and openssl.
No hosted database, proxy, external identity, image or migration is touched.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
from urllib.parse import urlencode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    repo = Path(__file__).resolve().parents[2]
    child = repo / "libs" / "go"
    pg = Path(os.environ["POSTGRES_BIN"])
    work = Path(tempfile.mkdtemp(prefix="pgprofile-", dir="/tmp"))
    started = False
    result = {"passed": False, "scope": "native-loopback-TLS-and-Unix-postgres-not-a-hosted-proxy-proof"}
    def run(argv, **kwargs):
        return subprocess.run([str(x) for x in argv], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    try:
        for name in ("server", "wrong"):
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Disposable Database Fixture", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", work / (name + ".key"), "-out", work / (name + ".crt")])
            (work / (name + ".key")).chmod(0o600)
        (work / "password").write_text("fixture-admin\n")
        run([pg / "initdb", "-D", work / "data", "-U", "profile_admin", "--auth-local=trust", "--auth-host=scram-sha-256", "--pwfile", work / "password"])
        (work / "socket").mkdir()
        with socket.socket() as bound:
            bound.bind(("127.0.0.1", 0))
            port = bound.getsockname()[1]
        options = f"-h 127.0.0.1 -p {port} -k {work / 'socket'} -c ssl=on -c ssl_cert_file={work / 'server.crt'} -c ssl_key_file={work / 'server.key'}"
        run([pg / "pg_ctl", "-D", work / "data", "-l", work / "postgres.log", "-o", options, "start", "-w"])
        started = True
        env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        env.update(GOWORK="off", GOENV="off", GOFLAGS="-mod=readonly -p=2")
        env["CONNECTION_PROFILE_TEST_DSN"] = f"postgres://profile_admin:fixture-admin@127.0.0.1:{port}/postgres?" + urlencode({"sslmode": "verify-full", "sslrootcert": str(work / "server.crt")})
        env["CONNECTION_PROFILE_TEST_SOCKET"] = str(work / "socket")
        env["CONNECTION_PROFILE_TEST_WRONG_CA"] = str(work / "wrong.crt")
        command = ["go", "test", "-race", "-json", ".", "-run", "^TestConnectionProfile", "-count=1", "-timeout=2m"]
        checked = subprocess.run(command, cwd=child, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (args.output / "test.jsonl").write_bytes(checked.stdout)
        rows = []
        for line in checked.stdout.splitlines():
            try:
                rows.append(json.loads(line))
            except (ValueError, UnicodeDecodeError):
                pass
        tests = [row for row in rows if row.get("Test")]
        result.update({"command": command, "cwd": str(child), "exit_code": checked.returncode, "passed_tests": [r["Test"] for r in tests if r.get("Action") == "pass"], "failed_tests": [r["Test"] for r in tests if r.get("Action") == "fail"], "skipped_tests": [r["Test"] for r in tests if r.get("Action") == "skip"], "log_sha256": hashlib.sha256(checked.stdout).hexdigest(), "postgres": run([pg / "postgres", "--version"]).stdout.decode().strip(), "go": run(["go", "version"]).stdout.decode().strip()})
        result["passed"] = checked.returncode == 0 and not result["failed_tests"] and not result["skipped_tests"] and "TestConnectionProfilesPostgres" in result["passed_tests"]
        print(json.dumps({k: v for k, v in result.items() if k != "passed_tests"}, indent=2))
    finally:
        if started:
            run([pg / "pg_ctl", "-D", work / "data", "-m", "immediate", "stop", "-w"])
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        if (work / "postgres.log").exists():
            shutil.copyfile(work / "postgres.log", args.output / "postgres.log")
        shutil.rmtree(work)
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
