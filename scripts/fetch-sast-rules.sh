#!/usr/bin/env bash
# Fetch a rules repository at a pinned commit into a cache directory and verify it.
#
# Usage: scripts/fetch-sast-rules.sh <git-url> <40-char-sha> <dest-dir>
#
# Re-uses <dest-dir> when it is already a clean checkout of <sha>; otherwise it is
# recreated. Fails if the checked-out HEAD doesn't match the pinned SHA.
set -euo pipefail

url=${1:?git url}
sha=${2:?commit sha}
dest=${3:?destination dir}

[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "error: '$sha' is not a full commit SHA" >&2; exit 2; }

if [[ -d "$dest/.git" ]] \
  && [[ "$(git -C "$dest" rev-parse HEAD 2>/dev/null)" == "$sha" ]] \
  && [[ -z "$(git -C "$dest" status --porcelain)" ]]; then
  exit 0
fi

echo "fetching $url@${sha:0:12}" >&2
rm -rf "$dest"
mkdir -p "$dest"
git -C "$dest" init -q
git -C "$dest" fetch -q --depth 1 "$url" "$sha"
git -C "$dest" -c advice.detachedHead=false checkout -q FETCH_HEAD

if [[ "$(git -C "$dest" rev-parse HEAD)" != "$sha" ]]; then
  echo "error: $dest HEAD does not match pinned $sha" >&2
  exit 1
fi
