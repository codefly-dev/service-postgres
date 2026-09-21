---
name: runtime-image-relock
description: Move the digest in runtime-image.json after changing the Dockerfile or one of its pins (postgres base, pgvector version, apk packages, dockerfile syntax). Use when CI fails with "built digest ... does not match runtime-image.json", when TestDefaultImageMatchesRuntimeImageLock fails, or before opening a PR that edits the Dockerfile. Covers why no script writes this file, how the digest is made predictable, and what the tag string must say.
---

# Relocking the runtime image

`runtime-image.json` pins the image the agent boots by digest:

```json
{ "name": "ghcr.io/codefly-dev/service-postgres",
  "tag": "postgres-17.10-pgvector-0.8.5-alpine3.24",
  "digest": "sha256:…",
  "platforms": ["linux/amd64", "linux/arm64"] }
```

Every Dockerfile change moves that digest. **Nothing writes this file for you** —
CI only verifies it, and the verification is what a stale lock fails on.

## Why there is no writer script

The digest has to be the one a *multi-arch, reproducible* build produces, which
is not what a plain local `docker build` gives you. CI builds it with
`SOURCE_DATE_EPOCH=0`, `rewrite-timestamp=true`, `provenance: false`,
`sbom: false` and `push-by-digest=true` across `linux/amd64,linux/arm64`. Those
flags are what make the digest predictable rather than a function of when and
where the build ran. A script that shelled out to a single-arch build would
write a digest CI then rejects.

## The loop

1. Edit the `Dockerfile`. If the change alters what the image *is* — a new
   postgres patch release, a new pgvector version, a new alpine branch — update
   the `tag` string too. It is descriptive (`postgres-<pg>-pgvector-<ver>-<base>`)
   and a wrong one silently mislabels every release that consumes it.
2. Push the branch. The `image` job builds the candidate and, on a mismatch,
   fails "Verify runtime image candidate" printing both digests.
3. Copy the **built** digest into `runtime-image.json` and push again.

The candidate publish is push-by-digest, so step 2 moves no tag — a failed
verification leaves the shared tag exactly where it was.

## Reproducing the digest locally

Optional, and only worth it to avoid a round trip. It needs buildx with
emulation registered for arm64:

```bash
docker buildx build --build-arg SOURCE_DATE_EPOCH=0 \
  --platform linux/amd64,linux/arm64 --provenance=false --sbom=false \
  --output type=image,name=ghcr.io/codefly-dev/service-postgres,push-by-digest=true,name-canonical=true,push=true,rewrite-timestamp=true .
```

This pushes to the registry, so it needs credentials and it publishes a real
(untagged) manifest. If you cannot or should not push, use the CI loop above
and say in the PR that you did not reproduce the digest locally.

## What else moves with it

- `platforms` must stay equal to the list CI proves the manifest ships.
  `TestRuntimeImageLockPlatformsMatchThePublishedManifest` asserts the literal
  list appears in the ci.yml "Verify published runtime image" step, so changing
  one means changing both.
- The image is embedded in the binary; `TestDefaultImageMatchesRuntimeImageLock`
  fails when the file and the embedded value disagree.
- The tag only moves on a push to `main`, after every gate above it has passed.
  That ordering is deliberate: an image failing a CRITICAL scan must not become
  what a plain `docker pull` of the tag returns.

Run `go test ./...` after editing the lock — the guards above are unit tests and
need no docker.
