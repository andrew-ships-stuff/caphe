#!/usr/bin/env bash
set -euo pipefail

current=${1:-}
messages=${2:-}
[[ -f "$messages" ]] || { echo "commit message file not found: $messages" >&2; exit 2; }

if [[ -n "$current" && ! "$current" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "current version must be empty or vMAJOR.MINOR.PATCH" >&2
  exit 2
fi

bump=patch
if grep -Eiq '(^|[^[:alnum:]])(semver|release)[[:space:]]*[:=][[:space:]]*major([^[:alnum:]]|$)|\[major\]|BREAKING[ -]CHANGE:|^[a-z]+(\([^)]*\))?!:' "$messages"; then
  bump=major
elif grep -Eiq '(^|[^[:alnum:]])(semver|release)[[:space:]]*[:=][[:space:]]*minor([^[:alnum:]]|$)|\[minor\]|^feat(\([^)]*\))?:' "$messages"; then
  bump=minor
fi

if [[ -z "$current" ]]; then
  case "$bump" in
    major) echo v1.0.0 ;;
    minor|patch) echo v0.1.0 ;;
  esac
  exit 0
fi

major=$((10#${BASH_REMATCH[1]}))
minor=$((10#${BASH_REMATCH[2]}))
patch=$((10#${BASH_REMATCH[3]}))
case "$bump" in
  major) major=$((major + 1)); minor=0; patch=0 ;;
  minor) minor=$((minor + 1)); patch=0 ;;
  patch) patch=$((patch + 1)) ;;
esac
printf 'v%d.%d.%d\n' "$major" "$minor" "$patch"
