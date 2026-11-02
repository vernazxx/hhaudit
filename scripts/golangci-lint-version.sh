#!/usr/bin/env bash
# Print the golangci-lint version pinned in .pre-commit-config.yaml, after
# checking that the pinned `rev:` SHA is the commit its `# frozen: vX.Y.Z` tag
# points to. CI installs this version, so the hook and CI can't drift.
#
# Usage: scripts/golangci-lint-version.sh [path/to/.pre-commit-config.yaml]
set -euo pipefail

config=${1:-.pre-commit-config.yaml}
repo=https://github.com/golangci/golangci-lint

# The `rev:` line directly follows the `- repo:` line for this hook.
line=$(awk -v repo="$repo" '
  found { print; exit }
  $0 == "- repo: " repo { found = 1 }
' "$config")

if [[ ! "$line" =~ ^[[:space:]]+rev:[[:space:]]+\'?([0-9a-f]{40})\'?[[:space:]]+#[[:space:]]frozen:[[:space:]](v[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*$ ]]; then
  echo "error: no '<sha>  # frozen: vX.Y.Z' rev for $repo in $config" >&2
  exit 1
fi
sha=${BASH_REMATCH[1]}
version=${BASH_REMATCH[2]}

# Annotated tags list the tag object first and the commit as `<tag>^{}`.
commit=$(git ls-remote "$repo" "refs/tags/$version" "refs/tags/$version^{}" | awk 'END { print $1 }')
if [[ "$commit" != "$sha" ]]; then
  echo "error: $config pins $repo at $sha, but tag $version is ${commit:-missing}" >&2
  exit 1
fi

echo "$version"
