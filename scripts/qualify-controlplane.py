"""Qualify role reconciliation and session restrictions on an isolated fixture."""

import json
import os
import re
import subprocess
import time
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    image = os.environ["POSTGRES_TEST_IMAGE"]
    if not re.fullmatch(r"postgres@sha256:[0-9a-f]{64}", image):
        raise ValueError("POSTGRES_TEST_IMAGE must pin the official fixture by digest")
    container = subprocess.check_output(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--pull=never",
            "--publish",
            "127.0.0.1::5432",
            "--env",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "--tmpfs",
            "/var/lib/postgresql/data",
            image,
        ],
        text=True,
    ).strip()
    try:
        for _ in range(60):
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    container,
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    "postgres",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("fixture did not become ready")
        ports = json.loads(
            subprocess.check_output(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{json .NetworkSettings.Ports}}",
                    container,
                ],
                text=True,
            )
        )
        binding = ports["5432/tcp"][0]
        if binding["HostIp"] != "127.0.0.1":
            raise RuntimeError("fixture is not loopback-only")
        env = os.environ.copy()
        env["SERVICE_POSTGRES_CONTROLPLANE_TEST_DSN"] = (
            f"postgres://postgres@127.0.0.1:{int(binding['HostPort'])}/postgres"
        )
        env["SESSION_POLICY_TEST_DSN"] = env["SERVICE_POSTGRES_CONTROLPLANE_TEST_DSN"]
        with tempfile.TemporaryDirectory(prefix="postgres-bootstrap-tools-") as tool_dir:
            migrate = str(Path(tool_dir) / "migrate")
            bootstrap = str(Path(tool_dir) / "managed-bootstrap")
            subprocess.run(["go", "build", "-tags", "postgres", "-o", migrate,
                            "github.com/golang-migrate/migrate/v4/cmd/migrate"], cwd=ROOT, check=True, timeout=180)
            subprocess.run(["go", "build", "-o", bootstrap, "./cmd/managed-bootstrap"],
                           cwd=ROOT, check=True, timeout=180)
            architecture = subprocess.check_output(
                ["docker", "inspect", "--format", "{{.Architecture}}", image], text=True).strip()
            if architecture not in {"amd64", "arm64"}:
                raise ValueError("unsupported fixture architecture")
            linux_env = env.copy()
            linux_env.update(GOOS="linux", GOARCH=architecture, CGO_ENABLED="0")
            for name, package, tags in [
                ("migrate", "github.com/golang-migrate/migrate/v4/cmd/migrate", ["-tags", "postgres"]),
                ("managed-bootstrap", "./cmd/managed-bootstrap", []),
            ]:
                target = str(Path(tool_dir) / (name + "-linux"))
                subprocess.run(["go", "build", *tags, "-o", target, package],
                               cwd=ROOT, env=linux_env, check=True, timeout=180)
                subprocess.run(["docker", "cp", target, f"{container}:/tmp/{name}"], check=True)
            env["SERVICE_POSTGRES_FIXTURE_CONTAINER"] = container
            env["SERVICE_POSTGRES_MIGRATE_EXECUTABLE"] = migrate
            env["SERVICE_POSTGRES_BOOTSTRAP_EXECUTABLE"] = bootstrap
            subprocess.run(["go", "test", "-race", "-count=1", "-v", "-tags", "controlplaneintegration",
                            "./libs/go/bootstrap"], cwd=ROOT, env=env, check=True, timeout=120)
        print(f"Fixture image: {image}", flush=True)
        subprocess.run(
            ["go", "test", "-race", "-count=1", "-v", "./libs/go", "-run", "^TestRestrictedSession"],
            cwd=ROOT,
            env=env,
            check=True,
            timeout=120,
        )
        subprocess.run(
            [
                "go",
                "test",
                "-race",
                "-count=1",
                "-v",
                "-tags",
                "controlplaneintegration",
                "./libs/go/controlplane",
            ],
            cwd=ROOT,
            env=env,
            check=True,
            timeout=300,
        )
    finally:
        subprocess.run(
            ["docker", "rm", "--force", container],
            check=True,
            stdout=subprocess.DEVNULL,
        )


if __name__ == "__main__":
    main()
