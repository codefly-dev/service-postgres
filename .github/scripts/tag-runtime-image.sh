#!/usr/bin/env bash

set -euo pipefail

# ghcr.io does not promise read-your-writes on tags: the tag can be published
# and still not resolve for a beat afterwards. Retry the read so propagation
# lag stays distinguishable from the tag holding the wrong digest.
resolve_tag_digest() {
  local attempt
  local digest
  for attempt in 1 2 3 4 5; do
    if ((attempt > 1)); then
      sleep $(((attempt - 1) * 2))
    fi
    if digest=$(docker buildx imagetools inspect "$RUNTIME_TAG" |
      awk '$1 == "Digest:" { print $2; exit }') && [[ -n "$digest" ]]; then
      printf '%s\n' "$digest"
      return 0
    fi
  done
  return 1
}

: "${EXPECTED_DIGEST:?EXPECTED_DIGEST is required}"
: "${RUNTIME_IMAGE:?RUNTIME_IMAGE is required}"
: "${RUNTIME_TAG:?RUNTIME_TAG is required}"

docker buildx imagetools create --tag "$RUNTIME_TAG" "$RUNTIME_IMAGE"

if ! tagged_digest=$(resolve_tag_digest); then
  echo "$RUNTIME_TAG was published but did not resolve to a digest" >&2
  exit 1
fi
if [[ "$tagged_digest" != "$EXPECTED_DIGEST" ]]; then
  echo "tagged digest $tagged_digest does not match $EXPECTED_DIGEST" >&2
  exit 1
fi
