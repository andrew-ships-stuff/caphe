#!/bin/sh
set -eu

version=${CAPHE_VERSION:-}
base_url=${CAPHE_RELEASE_BASE_URL:-https://github.com/andrew-ships-stuff/caphe/releases/download}
install_dir=${CAPHE_INSTALL_DIR:-"$HOME/.local/bin"}

if [ -z "$version" ]; then
  echo "CAPHE_VERSION is required until a signed stable release channel exists" >&2
  exit 2
fi

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) echo "unsupported operating system: $(uname -s)" >&2; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac

archive="caphe_${version}_${os}_${arch}.tar.gz"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT INT TERM
curl -fL "$base_url/$version/$archive" -o "$tmp_dir/$archive"
curl -fL "$base_url/$version/checksums.txt" -o "$tmp_dir/checksums.txt"
(cd "$tmp_dir" && grep "  $archive\$" checksums.txt | shasum -a 256 -c -)
tar -xzf "$tmp_dir/$archive" -C "$tmp_dir" caphe
mkdir -p "$install_dir"
install -m 0755 "$tmp_dir/caphe" "$install_dir/caphe"
"$install_dir/caphe" version
echo "Installed Caphe to $install_dir/caphe"
echo "Run 'caphe tools doctor' to inspect optional scanners. CPU inference is not installed automatically."
