#!/usr/bin/env bash

# Moves bootstrap-image.json forward: the lock the bootstrap image builds from.
#
#   .github/scripts/update-bootstrap-lock.sh                 # same Alpine branch, same migrate
#   ALPINE_BRANCH=v3.22 .github/scripts/update-bootstrap-lock.sh
#   MIGRATE_VERSION=v4.20.0 .github/scripts/update-bootstrap-lock.sh
#
# Every value is resolved from upstream, never authored here: the base digest comes
# from the registry, package versions from `apk policy` inside the digest-pinned
# base on both architectures, and the migrate archive checksums from the release's
# published sha256sum.txt. Run `go test ./...` afterwards and commit the diff.
#
# Why pinning packages this way, and what it costs:
#
# Alpine publishes no immutable package snapshot — a release branch keeps only the
# newest -rN of each package. Pinning exact versions therefore trades availability
# for integrity: once upstream replaces curl or postgresql17-client, the build fails
# with "unable to select packages" instead of silently installing different bytes.
# That failure is the signal to run this script, which is also how a security fix
# reaches the image: rerun it, the resolved versions move, and the lock records what
# the next build will install.

set -euo pipefail

ALPINE_BRANCH=${ALPINE_BRANCH:-v3.21}
MIGRATE_VERSION=${MIGRATE_VERSION:-v4.19.1}
PACKAGES=(curl postgresql17-client)
ARCHITECTURES=(amd64 arm64)
REPOSITORY="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/main"
LOCK="$(git rev-parse --show-toplevel)/bootstrap-image.json"

resolve_base_digest() {
  local tag="alpine:${ALPINE_BRANCH#v}"
  docker buildx imagetools inspect "$tag" |
    awk '$1 == "Digest:" { print $2; exit }'
}

# The version each architecture resolves to must agree: one lock describes the
# manifest list, so a per-architecture difference has to be resolved upstream
# rather than averaged over here.
resolve_package_versions() {
  local base=$1
  local resolved=""
  local architecture
  for architecture in "${ARCHITECTURES[@]}"; do
    local versions
    versions=$(docker run --rm --platform "linux/${architecture}" "$base" sh -c "
      set -eu
      printf '%s\n' '${REPOSITORY}' >/etc/apk/repositories
      apk update >/dev/null
      for package in ${PACKAGES[*]}; do
        apk policy \"\$package\" | sed -n '2s/^ *\([^:]*\):.*/\1/p'
      done
    ")
    if [[ -z "$resolved" ]]; then
      resolved=$versions
    elif [[ "$resolved" != "$versions" ]]; then
      echo "package versions differ across architectures; resolve upstream first" >&2
      return 1
    fi
  done
  printf '%s\n' "$resolved"
}

resolve_archive_checksums() {
  local checksums
  checksums=$(curl -fsSL \
    "https://github.com/golang-migrate/migrate/releases/download/${MIGRATE_VERSION}/sha256sum.txt")
  local architecture
  for architecture in "${ARCHITECTURES[@]}"; do
    local checksum
    checksum=$(awk -v archive="migrate.linux-${architecture}.tar.gz" \
      '$2 == archive { print $1; exit }' <<<"$checksums")
    if [[ ! "$checksum" =~ ^[0-9a-f]{64}$ ]]; then
      echo "${MIGRATE_VERSION} publishes no checksum for linux-${architecture}" >&2
      return 1
    fi
    printf '%s\n' "$checksum"
  done
}

digest=$(resolve_base_digest)
if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "could not resolve the alpine:${ALPINE_BRANCH#v} digest" >&2
  exit 1
fi
base="alpine@${digest}"

release=$(docker run --rm "$base" cat /etc/alpine-release)
mapfile -t versions < <(resolve_package_versions "$base")
mapfile -t checksums < <(resolve_archive_checksums)

if [[ "${#versions[@]}" -ne "${#PACKAGES[@]}" ]]; then
  echo "could not resolve every package version from ${REPOSITORY}" >&2
  exit 1
fi

pinned=$(jq -n '[]')
for index in "${!PACKAGES[@]}"; do
  pinned=$(jq --arg name "${PACKAGES[$index]}" --arg version "${versions[$index]}" \
    '. + [{name: $name, version: $version}]' <<<"$pinned")
done

archives=$(jq -n '[]')
for index in "${!ARCHITECTURES[@]}"; do
  archives=$(jq --arg architecture "${ARCHITECTURES[$index]}" --arg sha256 "${checksums[$index]}" \
    '. + [{architecture: $architecture, sha256: $sha256}]' <<<"$archives")
done

jq -n \
  --arg version "$release" \
  --arg digest "$digest" \
  --arg repository "$REPOSITORY" \
  --arg migrate "$MIGRATE_VERSION" \
  --argjson pinned "$pinned" \
  --argjson archives "$archives" \
  '{
    base: {image: "alpine", version: $version, digest: $digest},
    packages: {repository: $repository, pinned: $pinned},
    migrate: {version: $migrate, archives: $archives}
  }' >"$LOCK"

echo "updated $LOCK:"
cat "$LOCK"
echo
echo "run: go test ./... && git commit bootstrap-image.json"
