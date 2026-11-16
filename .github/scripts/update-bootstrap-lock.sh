#!/usr/bin/env bash

# Moves bootstrap-image.json forward: the lock the bootstrap image builds from.
#
#   .github/scripts/update-bootstrap-lock.sh            # re-resolve what the lock already targets
#   .github/scripts/update-bootstrap-lock.sh --check    # report drift, write nothing, exit 1 if stale
#   MIGRATE_GO_IMAGE=golang:1.27.4-alpine3.23 .github/scripts/update-bootstrap-lock.sh
#
# The lock pins only the source build: migrate's version comes from go.mod and the
# Go builder's manifest digest from the registry (update-bootstrap-migrate.py). The
# image is FROM scratch and installs no package, so there is no package pin here to
# go stale. A pinned migrate source keeps compiling forever, so a newer upstream
# release never fails a build; the bootstrap-lock-freshness workflow runs --check
# on a schedule to report it instead.

set -euo pipefail

CHECK_ONLY=false
if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY=true
elif [[ -n "${1:-}" ]]; then
  echo "usage: ${0##*/} [--check]" >&2
  exit 2
fi

LOCK="$(git rev-parse --show-toplevel)/bootstrap-image.json"
migrate=$(python3 "$(dirname "$0")/update-bootstrap-migrate.py" --resolve)
MIGRATE_VERSION=$(jq -er '.version' <<<"$migrate")
resolved=$(jq --argjson migrate "$migrate" '.migrate = $migrate' "$LOCK")

# Reports a newer upstream migrate release. Nothing else signals it: the pinned
# source version keeps compiling forever, so staleness here is invisible
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
    echo "  to take it: update the migrate dependency in go.mod, then run ${0##*/}"
    return 1
  fi
  echo "migrate ${MIGRATE_VERSION} is the current upstream release"
}

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
