"""Qualify the standalone Go runtime module without a database or agent fixture."""

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MODULE = "github.com/codefly-dev/service-postgres/libs/go"
PARENT = "github.com/codefly-dev/service-postgres"
CORE = "github.com/codefly-dev/core"


def json_stream(raw):
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(raw):
        if raw[offset].isspace():
            offset += 1
            continue
        value, offset = decoder.raw_decode(raw, offset)
        yield value


def require_independent(module):
    path = module["Path"]
    if path == PARENT or path == CORE or path.startswith(CORE + "/"):
        raise RuntimeError(f"runtime library depends on tooling module: {path}")
    if module.get("Replace"):
        raise RuntimeError(f"runtime library must resolve without replacements: {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    source = args.source_root.resolve()
    child = source / "libs" / "go"
    for name in ("go.mod", "go.sum"):
        if not (child / name).is_file():
            raise RuntimeError(f"runtime library is missing {name}: {child}")
    canonical = source / "contracts" / "workload-attachment" / "example.json"
    packaged = child / "workloadattachment" / "testdata" / "example.json"
    if canonical.read_bytes() != packaged.read_bytes():
        raise RuntimeError("packaged workload attachment example differs from the canonical contract")
    print("Workload attachment example byte parity: PASS", flush=True)

    env = os.environ.copy()
    # The release backfill can repair the parent with a temporary -modfile.
    # Child qualification always uses its own published manifests, never that file
    # or a developer workspace/user Go configuration.
    env.update(GOWORK="off", GOENV="off", GOFLAGS="-mod=readonly -p=2")

    def run(*arguments, capture=False):
        command = ["go", *arguments]
        print(f"{child}: {shlex.join(command)}", flush=True)
        return subprocess.run(command, cwd=child, env=env, check=True,
                              text=True, stdout=subprocess.PIPE if capture else None)

    modules = list(json_stream(run("list", "-m", "-json", "all", capture=True).stdout))
    main_modules = [module for module in modules if module.get("Main")]
    if len(main_modules) != 1 or main_modules[0]["Path"] != MODULE:
        raise RuntimeError("qualification did not select the standalone runtime module")
    for module in modules:
        require_independent(module)
    packages = json_stream(run("list", "-deps", "-test", "-json", "./...", capture=True).stdout)
    for package in packages:
        if package.get("Module"):
            require_independent(package["Module"])
    print("Module and test package graphs exclude Core and the parent module: PASS", flush=True)

    run("test", "-race", "-count=1", "./...")
    run("vet", "./...")
    run("test", "-tags=controlplaneintegration", "-run=^$", "./...")
    run("mod", "verify")
    run("mod", "tidy", "-diff")


if __name__ == "__main__":
    main()
