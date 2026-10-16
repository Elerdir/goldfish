#!/usr/bin/env bash
# Prints "what's new" for a version from CHANGELOG.md (without the section heading) -
# it goes to UpdateHub, the in-app updater and www.niderle.cz.
#
# The release commit lives only under the tag (main is protected), so the `## [X.Y.Z]`
# section often does not exist yet. Order: version section -> [Unreleased] -> one line.
#
# Usage: scripts/release-notes.sh 1.1.0 > release-notes.md
set -euo pipefail

version="${1:?usage: release-notes.sh <version>}"
changelog="$(dirname "$0")/../CHANGELOG.md"

section() {
  # Literal comparison (index), not a regex - brackets and dots would need escaping.
  awk -v hdr="## $1" '
    index($0, hdr) == 1 { on = 1; next }
    on && (/^## / || /^---/) { exit }
    on { print }
  ' "$changelog" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}'
}

notes="$(section "[$version]")"
[ -z "$notes" ] && notes="$(section "[Unreleased]")"
[ -z "$notes" ] && notes="Goldfish $version"
printf '%s\n' "$notes"
