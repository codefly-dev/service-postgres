#!/usr/bin/env python3
"""Resolve migrate's maintained module version and Go builder digest, without Docker.

Default: update only the migrate portion of bootstrap-image.json atomically.
--resolve: emit that portion for update-bootstrap-lock.sh's full refresh.
MIGRATE_GO_IMAGE selects an exact golang:<patch>-alpine<release> tag deliberately;
otherwise retain the current lock's tag. Module upgrades belong in go.mod.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

if sys.argv[1:] not in ([], ["--resolve"]):
    sys.exit("usage: update-bootstrap-migrate.py [--resolve]")

root = Path(__file__).resolve().parents[2]
lock_path = root / "bootstrap-image.json"
lock = json.loads(lock_path.read_text())
module = json.loads(subprocess.check_output(["go", "mod", "edit", "-json"], cwd=root))
version = next(r["Version"] for r in module["Require"]
               if r["Path"] == "github.com/golang-migrate/migrate/v4")
image = os.environ.get("MIGRATE_GO_IMAGE", lock["migrate"].get("toolchain", "").split("@")[0])
if not re.fullmatch(r"golang:[0-9]+\.[0-9]+\.[0-9]+-alpine[0-9]+\.[0-9]+", image):
    sys.exit("MIGRATE_GO_IMAGE must name an exact golang:<patch>-alpine<release> tag")
with urllib.request.urlopen("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/golang:pull", timeout=30) as response:
    token = json.load(response)["token"]
request = urllib.request.Request(
    "https://registry-1.docker.io/v2/library/golang/manifests/" + image.split(":", 1)[1],
    headers={"Authorization": "Bearer " + token,
             "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json"})
with urllib.request.urlopen(request, timeout=30) as response:
    body = response.read()
    digest = response.headers["Docker-Content-Digest"]
if digest != "sha256:" + hashlib.sha256(body).hexdigest():
    sys.exit("registry toolchain manifest digest mismatch")
platforms = {(m["platform"].get("os"), m["platform"].get("architecture"))
             for m in json.loads(body)["manifests"]}
if not {("linux", "amd64"), ("linux", "arm64")} <= platforms:
    sys.exit("toolchain must support linux/amd64 and linux/arm64")
resolved = {"version": version, "toolchain": image + "@" + digest}
if sys.argv[1:] == ["--resolve"]:
    print(json.dumps(resolved))
elif not sys.argv[1:]:
    lock["migrate"] = resolved
    staged = lock_path.with_suffix(".json.staged")
    staged.write_text(json.dumps(lock, indent=2) + "\n")
    staged.replace(lock_path)
else:
    sys.exit("usage: update-bootstrap-migrate.py [--resolve]")
