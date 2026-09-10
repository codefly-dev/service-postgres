"""Qualify role reconciliation on a disposable, loopback-only Docker fixture."""

import json
import os
import re
import subprocess
import time
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
        print(f"Fixture image: {image}", flush=True)
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
