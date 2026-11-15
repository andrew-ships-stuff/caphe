#!/usr/bin/env bash
set -euo pipefail

version=${1:-}
checksums=${2:-}
repository=${CAPHE_RELEASE_REPOSITORY:-andrew-ships-stuff/caphe}

if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "version must be a v-prefixed semantic version" >&2
  exit 2
fi
[[ -f "$checksums" ]] || { echo "checksums file not found: $checksums" >&2; exit 2; }
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "invalid release repository" >&2; exit 2; }

checksum() {
  local asset=$1 value
  value=$(awk -v asset="$asset" '$2 == asset || $2 == "*" asset { print $1 }' "$checksums")
  [[ "$value" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "missing or invalid checksum for $asset" >&2; exit 2; }
  printf '%s' "$value" | tr '[:upper:]' '[:lower:]'
}

asset_prefix="caphe_${version}"
darwin_amd64=$(checksum "${asset_prefix}_darwin_amd64.tar.gz")
darwin_arm64=$(checksum "${asset_prefix}_darwin_arm64.tar.gz")
linux_amd64=$(checksum "${asset_prefix}_linux_amd64.tar.gz")
linux_arm64=$(checksum "${asset_prefix}_linux_arm64.tar.gz")
base_url="https://github.com/${repository}/releases/download/${version}"

cat <<EOF
# typed: strict
# frozen_string_literal: true

# Caphe is a CPU-native compiled security workflow engine.
class Caphe < Formula
  desc "CPU-native compiled security workflow engine"
  homepage "https://github.com/${repository}"
  version "${version#v}"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "${base_url}/${asset_prefix}_darwin_arm64.tar.gz"
      sha256 "${darwin_arm64}"
    else
      url "${base_url}/${asset_prefix}_darwin_amd64.tar.gz"
      sha256 "${darwin_amd64}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "${base_url}/${asset_prefix}_linux_arm64.tar.gz"
      sha256 "${linux_arm64}"
    else
      url "${base_url}/${asset_prefix}_linux_amd64.tar.gz"
      sha256 "${linux_amd64}"
    end
  end

  def install
    bin.install "caphe"
  end

  test do
    assert_match "compilerVersion", shell_output("#{bin}/caphe version")
  end
end
EOF
