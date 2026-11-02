#!/usr/bin/env bash
# Cut a release: a signed vX.Y.Z tag on an up-to-date, clean main, pushed alone.
# Pushing the tag triggers .github/workflows/release.yaml (GoReleaser).
#
# Usage (normally via `make release VERSION=vX.Y.Z`):
#   scripts/release.sh check <version>   preflight; fetches origin (one key touch)
#   scripts/release.sh tag <version>     re-checks locally, signs, verifies, asks, pushes
set -euo pipefail

die() { echo "release: $*" >&2; exit 1; }

step=${1:-}
version=${2:-}
remote=${RELEASE_REMOTE:-origin}
branch=main

[[ "$step" == check || "$step" == tag ]] || die "usage: $0 check|tag vX.Y.Z"
[[ "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
  || die "VERSION must look like vX.Y.Z (got '${version}')"

local_checks() {
  [[ "$(git symbolic-ref --quiet --short HEAD || true)" == "$branch" ]] \
    || die "not on $branch"
  [[ -z "$(git status --porcelain --untracked-files=no)" ]] \
    || die "working tree has uncommitted changes"
  [[ "$(git rev-parse HEAD)" == "$(git rev-parse "refs/remotes/$remote/$branch")" ]] \
    || die "$branch is not at $remote/$branch; pull or push first"
  if git rev-parse --quiet --verify "refs/tags/$version" >/dev/null; then
    die "tag $version already exists"
  fi
}

case "$step" in
  check)
    # Refresh $remote/main and all remote tags, so the checks see GitHub's state.
    git fetch --quiet --tags "$remote" "+refs/heads/$branch:refs/remotes/$remote/$branch"
    local_checks
    echo "release: preflight ok for $version at $(git rev-parse --short HEAD)"
    ;;
  tag)
    # The gate ran in between; it must not have changed anything.
    local_checks
    git tag -s -m "Release $version" "$version" HEAD
    git tag -v "$version"
    read -r -p "Push tag $version to $remote and start the release? [y/N] " answer
    if [[ "$answer" != [yY] ]]; then
      git tag -d "$version" >/dev/null
      die "not pushed; local tag $version deleted"
    fi
    git push "$remote" "refs/tags/$version"
    echo "release: pushed $version; follow the run with: gh run watch"
    ;;
esac
