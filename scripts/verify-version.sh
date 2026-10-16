#!/usr/bin/env bash
# Checks that tag vX.Y.Z matches the version in all three files; otherwise the installer
# would carry a different version than the tag and auto-update would offer it forever.
#
# Usage: scripts/verify-version.sh v1.1.0
set -euo pipefail

tag="${1:?usage: verify-version.sh <tag>}"
want="${tag#v}"
root="$(dirname "$0")/.."

cargo=$(sed -nE '/^\[workspace\.package\]/,/^\[/{s/^version = "([^"]+)".*/\1/p}' "$root/Cargo.toml" | head -n1)
conf=$(node -p "require(require('path').resolve(process.argv[1])).version" "$root/crates/goldfish-tauri/tauri.conf.json")
ui=$(node -p "require(require('path').resolve(process.argv[1])).version" "$root/src-frontend/package.json")

echo "tag=$want Cargo.toml=$cargo tauri.conf.json=$conf package.json=$ui"
if [ "$want" != "$cargo" ] || [ "$want" != "$conf" ] || [ "$want" != "$ui" ]; then
  echo "::error::Version mismatch - tag=$want, Cargo.toml=$cargo, tauri.conf.json=$conf, package.json=$ui"
  exit 1
fi
