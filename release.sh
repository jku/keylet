#!/bin/bash
set -euo pipefail

# This script does not bump the release version (except to make dev release stable).
# If you want a version bump use "uv version --bump=[minor|major]", then run this script

# This script will
#  * If current version is -dev
#    * Make current release a stable release
#  * If uncommitted (version) changes
#    * Commit changes
#  * Tag the release
#  * Bump patch version, make it a dev version
#  * Commit changes

VER=$(uv version --short)
if [[ $VER == *"dev"* ]]; then
  # Bump to release version (1.2.3-dev1 -> 1.2.3)
  VER=$(uv version --dry-run --short --bump=stable)
  uv version --quiet --bump=stable
fi

if ! git diff --quiet; then
  # Either we bumped or version changes had already been made: commit
  git commit -a -m "Version bump for $VER release"
fi

# Tag release
git tag -m "$VER" "v$VER"

# Bump to next -dev version  (1.2.3 -> 1.2.4-dev1)

VER=$(uv version --dry-run --short --bump=dev --bump=patch)
uv version --quiet --bump=dev --bump=patch
git commit -a -m "dev version bump to $VER"
