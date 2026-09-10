#!/usr/bin/env bash

set -euo pipefail

# ghcr.io does not promise read-your-writes on tags, and a lagging read shows up
# two ways: the read fails, or it serves the digest the tag held before this
# push. Neither is a verdict until the budget below is spent. Seconds, summing
# to two minutes; a read that lands on the first attempt costs none of it.
readonly PROPAGATION_DELAYS=(2 4 8 16 30 30 30)

# Bounds a hung read, which would otherwise stall the job until GitHub's
# six-hour default, once per attempt.
readonly READ_TIMEOUT=60

# Every tag gets its own budget: one tag having propagated says nothing about
# the next, which was published by the same call but is read afterwards.
verify_tag() {
  local tag=$1
  local tagged_digest=""
  local attempt=0
  while :; do
    # The fallback keeps a failed read from aborting the script under errexit
    # before the diagnosis below can run.
    tagged_digest=$(timeout "$READ_TIMEOUT" docker buildx imagetools inspect "$tag" |
      awk '$1 == "Digest:" { print $2; exit }') || tagged_digest=""
    if [[ "$tagged_digest" == "$EXPECTED_DIGEST" ]]; then
      return 0
    fi
    if ((attempt >= ${#PROPAGATION_DELAYS[@]})); then
      break
    fi
    sleep "${PROPAGATION_DELAYS[attempt]}"
    attempt=$((attempt + 1))
  done

  if [[ -z "$tagged_digest" ]]; then
    echo "$tag was published but did not resolve to a digest" >&2
  else
    echo "$tag resolves to $tagged_digest, want $EXPECTED_DIGEST" >&2
  fi
  return 1
}

: "${EXPECTED_DIGEST:?EXPECTED_DIGEST is required}"
: "${RUNTIME_IMAGE:?RUNTIME_IMAGE is required}"
# Without this a caller that lost its tag arguments would publish nothing and
# still exit 0, because the verification below would have nothing to walk.
: "${1:?at least one tag is required}"

# Checked up front because the read below turns any failure into another
# retry, which would report a missing timeout as an unresolvable tag.
if ! command -v timeout >/dev/null; then
  echo "timeout is required to bound registry reads" >&2
  exit 1
fi

tag_flags=()
for tag in "$@"; do
  tag_flags+=(--tag "$tag")
done
docker buildx imagetools create "${tag_flags[@]}" "$RUNTIME_IMAGE"

for tag in "$@"; do
  verify_tag "$tag"
done
