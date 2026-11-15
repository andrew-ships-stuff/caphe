#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="${CAPHE_TOOL_BIN:-${XDG_CACHE_HOME:-${HOME}/.cache}/caphe/bin}"
TOOLS="poutine,actionlint"
POUTINE_VERSION="1.1.4"
ACTIONLINT_VERSION="1.7.8"
LLAMA_VERSION="b12359"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --tools) TOOLS="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$(uname -s)" in Darwin) os=darwin; poutine_os=Darwin ;; Linux) os=linux; poutine_os=Linux ;; *) echo "unsupported OS" >&2; exit 2 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64; poutine_arch=x86_64 ;; arm64|aarch64) arch=arm64; poutine_arch=arm64 ;; *) echo "unsupported architecture" >&2; exit 2 ;; esac

mkdir -p "$BIN_DIR"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

verify_checksum() {
  local file="$1" checksums="$2" asset="$3" expected actual
  expected=$(awk -v name="$asset" '$2 == name {print $1}' "$checksums")
  [[ -n "$expected" ]] || { echo "checksum missing for $asset" >&2; return 1; }
  if command -v shasum >/dev/null 2>&1; then actual=$(shasum -a 256 "$file" | awk '{print $1}'); else actual=$(sha256sum "$file" | awk '{print $1}'); fi
  [[ "$actual" == "$expected" ]] || { echo "checksum mismatch for $asset" >&2; return 1; }
}

install_poutine() {
  local asset="poutine_${poutine_os}_${poutine_arch}.tar.gz" base="https://github.com/boostsecurityio/poutine/releases/download/v${POUTINE_VERSION}"
  curl -fsSL "$base/$asset" -o "$tmp_dir/$asset"
  curl -fsSL "$base/poutine_${POUTINE_VERSION}_checksums.txt" -o "$tmp_dir/poutine-checksums.txt"
  verify_checksum "$tmp_dir/$asset" "$tmp_dir/poutine-checksums.txt" "$asset"
  tar -xzf "$tmp_dir/$asset" -C "$tmp_dir" poutine
  install -m 0755 "$tmp_dir/poutine" "$BIN_DIR/poutine"
  "$BIN_DIR/poutine" version
}

install_actionlint() {
  local asset="actionlint_${ACTIONLINT_VERSION}_${os}_${arch}.tar.gz" base="https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}"
  curl -fsSL "$base/$asset" -o "$tmp_dir/$asset"
  curl -fsSL "$base/actionlint_${ACTIONLINT_VERSION}_checksums.txt" -o "$tmp_dir/actionlint-checksums.txt"
  verify_checksum "$tmp_dir/$asset" "$tmp_dir/actionlint-checksums.txt" "$asset"
  tar -xzf "$tmp_dir/$asset" -C "$tmp_dir" actionlint
  install -m 0755 "$tmp_dir/actionlint" "$BIN_DIR/actionlint"
  "$BIN_DIR/actionlint" -version
}

install_llama_cpp() {
  local asset llama_os expected dest
  case "$os-$arch" in
    linux-amd64) asset="llama-${LLAMA_VERSION}-bin-ubuntu-x64.tar.gz"; expected="0bc1f091e8916102b6d8f2cf944233a620e90a0f856c72d0ce41150c65c2e72e" ;;
    linux-arm64) asset="llama-${LLAMA_VERSION}-bin-ubuntu-arm64.tar.gz"; expected="dc7aa17a67884619b7223870aca9fd6addbc01717713b04a714add1c31137359" ;;
    darwin-amd64) asset="llama-${LLAMA_VERSION}-bin-macos-x64.tar.gz"; expected="25320d529077ef5a3d16e7b5da26438f221d88c8c0930a32b0c79457f5eede56" ;;
    darwin-arm64) asset="llama-${LLAMA_VERSION}-bin-macos-arm64.tar.gz"; expected="82b00abc740160e1b9980e6cc79c117345fa34af058c80e6c0a69aa8ddccde75" ;;
    *) echo "no prebuilt llama.cpp binary for $os/$arch; set CAPHE_LLAMA_SERVER or add llama-server to PATH" >&2; return 2 ;;
  esac
  if [[ -x "$BIN_DIR/llama.cpp-$LLAMA_VERSION/llama-server" ]]; then
    echo "llama.cpp $LLAMA_VERSION already installed at $BIN_DIR/llama.cpp-$LLAMA_VERSION/llama-server"
    return 0
  fi
  curl -fsSL "https://github.com/ggml-org/llama.cpp/releases/download/${LLAMA_VERSION}/${asset}" -o "$tmp_dir/$asset"
  local actual
  if command -v shasum >/dev/null 2>&1; then actual=$(shasum -a 256 "$tmp_dir/$asset" | awk '{print $1}'); else actual=$(sha256sum "$tmp_dir/$asset" | awk '{print $1}'); fi
  [[ "$actual" == "$expected" ]] || { echo "checksum mismatch for $asset" >&2; return 1; }
  tar -xzf "$tmp_dir/$asset" -C "$tmp_dir"
  dest="$BIN_DIR/llama.cpp-$LLAMA_VERSION"
  rm -rf "$dest"
  mv "$tmp_dir/llama-$LLAMA_VERSION" "$dest"
  if [[ ! -x "$dest/llama-server" ]]; then
    [[ -x "$dest/bin/llama-server" ]] || { echo "llama-server missing from ${asset}" >&2; return 1; }
  fi
  "$dest/llama-server" --version >/dev/null 2>&1 || "$dest/bin/llama-server" --version >/dev/null 2>&1 || true
  echo "Installed llama.cpp $LLAMA_VERSION to $dest"
}

IFS=',' read -r -a requested <<< "$TOOLS"
for tool in "${requested[@]}"; do
  case "$tool" in poutine) install_poutine ;; actionlint) install_actionlint ;; llama.cpp) install_llama_cpp ;; *) echo "unsupported managed tool: $tool" >&2; exit 2 ;; esac
done

echo "Installed managed tools to $BIN_DIR"
echo "Add this line to your shell profile:"
echo "  export PATH=\"$BIN_DIR:\$PATH\""
echo "To uninstall these managed tools, delete this dedicated directory: $BIN_DIR"
