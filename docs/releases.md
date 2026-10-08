# Publishing releases and dev builds

`agent.codefly.yaml` declares `.github/workflows/releaser.yml` as the sole
publisher. Its `v*` tag trigger includes `codefly publish dev` tags of the form
`v<major>.<minor>.<patch>-dev.<sha>`. Do not exclude those tags: the workflow is
what turns an iteration tag into a downloadable prerelease.

Both tag paths qualify `libs/go` and retag the digest in `runtime-image.json`
with the Git tag and the lock's runtime tag before publishing binaries. Runs
share a concurrency group and queue without cancellation so they cannot race
on that runtime tag.

## Normal releases

Tags without `-dev.` call core's `go-service-release.yml`, pinned to the commit
for core v0.16.0 (`e54bc852f3d40cd1aeafc0ced2369a8c13a51bb8`). It runs the full Go
test suite, then checks that the tag's commit is reachable from the repository's
default branch before running GoReleaser with `GH_PAT`. The caller registers
arm64 emulation for the bootstrap-image tests. Stable tags produce ordinary
GitHub releases; `.goreleaser.yaml` continues to control their assets and release
metadata.

## Dev prereleases

Iteration commits need not be on the default branch. They therefore use local
jobs instead of core's release job:

1. `dev-build` checks out the tag with full history and no persisted Git
   credential. It validates the dev-tag format and tag/HEAD identity, exports
   `GORELEASER_CURRENT_TAG` (including when multiple tags share a commit), sets up
   arm64 emulation, and runs the full Go test suite. GoReleaser uses the same
   `.goreleaser.yaml` as normal releases, with Syft installed and
   `--skip=publish,announce`. This job has read-only repository permission and
   receives no publishing token or PAT.
2. `dev-publish` downloads that run's build artifact on a fresh runner, with no
   source checkout or build hooks. It checks that all seven expected assets and
   the generated changelog are nonempty, then calls `gh release create` with
   `--verify-tag --prerelease --latest=false`. Only this upload step receives the
   repository-scoped `GITHUB_TOKEN` with `contents: write`; it never uses
   `GH_PAT`.

The seven assets match normal releases: `darwin_amd64`, `darwin_arm64`, and
`linux_amd64` tarballs, one `.tar.gz.sbom.json` alongside each, and a
`service-postgres_<version>_checksums.txt`. The changelog becomes release notes,
not an eighth asset. No GoReleaser snapshot mode is used, so archive names keep
the exact dev version. Dev builds cannot become GitHub's Latest release.

This job split avoids running off-main build hooks with a release credential.
It does not authorize arbitrary tag pushes: repository tag/workflow write
access remains the trust boundary. Releases created with `GITHUB_TOKEN` do not
trigger downstream `release` workflows; this repository has no such consumer.

## Backfills and verification

The manual `workflow_dispatch` path remains the historical `backfill` job. It
checks out the requested source, repairs dependency metadata in a temporary
modfile, and uploads missing archives/checksums without replacing existing
assets. It is not the dev publishing path and does not supply the seven-asset
prerelease contract described above.

When repinning core, retain the mutually exclusive tag routing and run:

```sh
actionlint .github/workflows/releaser.yml
go test . -run 'Test(Release|Dev)' -count=1
```

The tests pin the routing, build/publish separation, and complete seven-asset
upload. They execute the publisher shell with a fake GitHub client, including
missing-asset and non-dev-tag failures. They do not prove a live GitHub publish.
For end-to-end acceptance, observe a normal release tag on the default branch
and a dev tag on an off-main commit containing this workflow: both runs must
succeed, with seven assets each, and only the dev release marked prerelease
(and never Latest). Existing historical tags still contain their old workflow;
rerunning those runs does not exercise this change.
