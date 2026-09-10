#!/usr/bin/env bash

# Moves bootstrap-image.json forward: the lock the bootstrap image builds from.
#
#   .github/scripts/update-bootstrap-lock.sh                 # re-resolve what the lock already targets
#   .github/scripts/update-bootstrap-lock.sh --check         # report drift, write nothing, exit 1 if stale
#   ALPINE_BRANCH=v3.22 .github/scripts/update-bootstrap-lock.sh
#   MIGRATE_VERSION=v4.20.0 .github/scripts/update-bootstrap-lock.sh
#
# Every value is resolved from upstream, never authored here: the base digest comes
# from the registry, package versions from inside the digest-pinned base on both
# architectures, and the migrate archive checksums from the release's published
# sha256sum.txt. What the run targets — Alpine branch, migrate version, package set
# — is read out of the current lock, so a plain rerun re-resolves the lock's own
# intent instead of a default that could silently revert someone's bump. Run
# `go test ./...` afterwards and commit the diff.
#
# The checksum file ships in the same GitHub release as the archives it covers, so
# it pins identity — the bytes cannot change under a fixed version, and a mirror or
# CDN cannot substitute them — but it shares a trust root with the artifact and is
# therefore not proof of authorship. Locking the version is what bounds that trust.
#
# Why pinning packages this way, and what it costs:
#
# Alpine publishes no immutable package snapshot — a release branch keeps only the
# newest -rN of each package. Pinning exact versions therefore trades availability
# for integrity: once upstream replaces curl or postgresql17-client, the build fails
# with "unable to select packages" instead of silently installing different bytes.
# That failure is the signal to run this script, which is also how a security fix
# reaches the image: rerun it, the resolved versions move, and the lock records what
# the next build will install. That signal covers pinned packages only, so the
# bootstrap-lock-freshness workflow runs --check on a schedule to catch the inputs
# that never fail a build: a base digest the branch has moved past, and a newer
# migrate release.

set -euo pipefail

CHECK_ONLY=false
if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY=true
elif [[ -n "${1:-}" ]]; then
  echo "usage: ${0##*/} [--check]" >&2
  exit 2
fi

LOCK="$(git rev-parse --show-toplevel)/bootstrap-image.json"

# The lock is the source of truth for what this run targets; the environment only
# overrides it deliberately.
lock_branch=$(jq -er '.packages.repositories[0] | capture("/(?<branch>v[0-9]+\\.[0-9]+)/").branch' "$LOCK")
ALPINE_BRANCH=${ALPINE_BRANCH:-$lock_branch}
MIGRATE_VERSION=${MIGRATE_VERSION:-$(jq -er '.migrate.version' "$LOCK")}
mapfile -t PACKAGES < <(jq -er '.packages.pinned[].name' "$LOCK")
mapfile -t ARCHITECTURES < <(jq -er '.migrate.archives[].architecture' "$LOCK")
if [[ "${#PACKAGES[@]}" -eq 0 || "${#ARCHITECTURES[@]}" -eq 0 ]]; then
  echo "could not read the package or architecture set from $LOCK" >&2
  exit 1
fi

# One repository per apk repository line, all on the targeted branch. Additional
# repositories in the lock are preserved by path, with the branch re-resolved.
mapfile -t REPOSITORIES < <(jq -er --arg branch "$ALPINE_BRANCH" \
  '.packages.repositories[] | sub("/v[0-9]+\\.[0-9]+/"; "/" + $branch + "/")' "$LOCK")
if [[ "${#REPOSITORIES[@]}" -eq 0 ]]; then
  echo "could not read the repository set from $LOCK" >&2
  exit 1
fi

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
      printf '%s\n' ${REPOSITORIES[*]@Q} >/etc/apk/repositories
      apk update >/dev/null
      for package in ${PACKAGES[*]}; do
        # apk policy lists candidates ascending, so the last one is what apk would
        # install. Cross-check against the resolver itself: if a repository set ever
        # makes these disagree, pinning the wrong candidate would silently lock an
        # older, unpatched build.
        candidate=\$(apk policy \"\$package\" | awk '/^  [^ ]/ { sub(/:\$/, \"\", \$1); version=\$1 } END { print version }')
        selected=\$(apk add --simulate \"\$package\" | sed -n \"s/.* Installing \$package (\(.*\))\$/\1/p\" | tail -1)
        if [ \"\$candidate\" != \"\$selected\" ]; then
          echo \"\$package: apk policy offers \$candidate but apk would install \$selected\" >&2
          exit 1
        fi
        printf '%s\n' \"\$candidate\"
      done
    ") || return 1
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
    "https://github.com/golang-migrate/migrate/releases/download/${MIGRATE_VERSION}/sha256sum.txt") || {
    echo "could not fetch published checksums for ${MIGRATE_VERSION}" >&2
    return 1
  }
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

# Reports a newer upstream migrate release. Nothing else signals it: the pinned
# archive keeps verifying and installing forever, so staleness here is invisible
# until someone looks.
report_migrate_staleness() {
  local latest
  if ! latest=$(curl -fsSL https://api.github.com/repos/golang-migrate/migrate/releases/latest |
    jq -er '.tag_name'); then
    echo "warning: could not reach the migrate release API; staleness unchecked" >&2
    return 0
  fi
  if [[ "$latest" != "$MIGRATE_VERSION" ]]; then
    echo "migrate ${MIGRATE_VERSION} is behind upstream ${latest}"
    echo "  to take it: MIGRATE_VERSION=${latest} ${0##*/}"
    return 1
  fi
  echo "migrate ${MIGRATE_VERSION} is the current upstream release"
}

digest=$(resolve_base_digest)
if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "could not resolve the alpine:${ALPINE_BRANCH#v} digest" >&2
  exit 1
fi
base="alpine@${digest}"

release=$(docker run --rm "$base" cat /etc/alpine-release)

# Command substitution, not process substitution: mapfile from <(…) discards the
# producer's exit status, so a failed resolution would flow on as empty output.
if ! versions_output=$(resolve_package_versions "$base"); then
  exit 1
fi
mapfile -t versions <<<"$versions_output"
if ! checksums_output=$(resolve_archive_checksums); then
  exit 1
fi
mapfile -t checksums <<<"$checksums_output"

if [[ "${#versions[@]}" -ne "${#PACKAGES[@]}" ]]; then
  echo "could not resolve every package version from ${REPOSITORIES[*]}" >&2
  exit 1
fi
if [[ "${#checksums[@]}" -ne "${#ARCHITECTURES[@]}" ]]; then
  echo "could not resolve every migrate archive checksum for ${MIGRATE_VERSION}" >&2
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

resolved=$(jq -n \
  --arg version "$release" \
  --arg digest "$digest" \
  --arg migrate "$MIGRATE_VERSION" \
  --argjson repositories "$(jq -n --args '$ARGS.positional' "${REPOSITORIES[@]}")" \
  --argjson pinned "$pinned" \
  --argjson archives "$archives" \
  '{
    base: {image: "alpine", version: $version, digest: $digest},
    packages: {repositories: $repositories, pinned: $pinned},
    migrate: {version: $migrate, archives: $archives}
  }')

stale=false
if ! diff -u "$LOCK" <(printf '%s\n' "$resolved") >/dev/null; then
  stale=true
fi

if [[ "$CHECK_ONLY" == true ]]; then
  if [[ "$stale" == true ]]; then
    echo "$LOCK is behind the inputs upstream now resolves to:"
    diff -u "$LOCK" <(printf '%s\n' "$resolved") || true
  else
    echo "$LOCK matches the inputs upstream currently resolves to"
  fi
  current=true
  report_migrate_staleness || current=false
  if [[ "$stale" == true || "$current" == false ]]; then
    echo "run .github/scripts/update-bootstrap-lock.sh to move the lock forward" >&2
    exit 1
  fi
  exit 0
fi

# Write through a temporary file: redirecting straight into the lock truncates it
# before jq runs, and an empty lock is embedded into the binary and fails at init.
staged="${LOCK}.staged"
trap 'rm -f -- "$staged"' EXIT
printf '%s\n' "$resolved" >"$staged"
mv -- "$staged" "$LOCK"

echo "updated $LOCK:"
cat "$LOCK"
echo
report_migrate_staleness || true
echo
echo "run: go test ./... && git commit bootstrap-image.json"
