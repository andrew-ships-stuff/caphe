#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="${CAPHE_TOOL_BIN:-${XDG_CACHE_HOME:-${HOME}/.cache}/caphe/bin}"
TOOLS="poutine,actionlint"
POUTINE_VERSION="1.1.4"
ACTIONLINT_VERSION="1.7.8"
LLAMA_VERSION="b12359"
SYFT_VERSION="1.57.1"
GRYPE_VERSION="0.121.3"
GITLEAKS_VERSION="8.30.1"

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

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'; else sha256sum "$1" | awk '{print $1}'; fi
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

install_release_binary() {
  local name="$1" repo="$2" version="$3" asset="$4" expected="$5"
  if [[ -x "$BIN_DIR/$name" ]]; then echo "$name already installed at $BIN_DIR/$name"; return 0; fi
  curl -fsSL "https://github.com/$repo/releases/download/v${version}/${asset}" -o "$tmp_dir/$asset"
  local actual; actual=$(sha256_of "$tmp_dir/$asset")
  [[ "$actual" == "$expected" ]] || { echo "checksum mismatch for $asset" >&2; return 1; }
  tar -xzf "$tmp_dir/$asset" -C "$tmp_dir" "$name"
  install -m 0755 "$tmp_dir/$name" "$BIN_DIR/$name"
  "$BIN_DIR/$name" version >/dev/null 2>&1 || "$BIN_DIR/$name" --version >/dev/null 2>&1 || true
  echo "Installed $name $version to $BIN_DIR/$name"
}

install_syft() {
  local asset expected
  case "$os-$arch" in
    linux-amd64) asset="syft_${SYFT_VERSION}_linux_amd64.tar.gz"; expected="bf52519eb57f675d47c07d43213cb6dff6449f3d6d1147ff6701ed91f44eef0c" ;;
    linux-arm64) asset="syft_${SYFT_VERSION}_linux_arm64.tar.gz"; expected="aa3d3e07344f590bcce8d31043b752daa76c8a56c2aa34ceeee63c6168152582" ;;
    darwin-amd64) asset="syft_${SYFT_VERSION}_darwin_amd64.tar.gz"; expected="2355758c1142982a67b309604c5d75effdbe638a57c771979ea8fd1a16656abc" ;;
    darwin-arm64) asset="syft_${SYFT_VERSION}_darwin_arm64.tar.gz"; expected="e0a74a5d2688d1254b4e17b71f068a83215e3625f846265bf6614c7ba06f3a96" ;;
    *) echo "no prebuilt syft for $os/$arch" >&2; return 2 ;;
  esac
  install_release_binary syft anchore/syft "$SYFT_VERSION" "$asset" "$expected"
}

install_grype() {
  local asset expected
  case "$os-$arch" in
    linux-amd64) asset="grype_${GRYPE_VERSION}_linux_amd64.tar.gz"; expected="e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85" ;;
    linux-arm64) asset="grype_${GRYPE_VERSION}_linux_arm64.tar.gz"; expected="b7815598d48da78bfd16f5b98ef28e1bb09c03d34fc8c3e350f99b6ccb3c7cba" ;;
    darwin-amd64) asset="grype_${GRYPE_VERSION}_darwin_amd64.tar.gz"; expected="65bfb1b3b30d32e9dab156a60003c7146e619f649992be227bf09c9ccbf44f7e" ;;
    darwin-arm64) asset="grype_${GRYPE_VERSION}_darwin_arm64.tar.gz"; expected="54336f2cd8cdee8b3d8ea83462561ff7fa9293498054c7c53a193db44bfea4c8" ;;
    *) echo "no prebuilt grype for $os/$arch" >&2; return 2 ;;
  esac
  install_release_binary grype anchore/grype "$GRYPE_VERSION" "$asset" "$expected"
}

install_gitleaks() {
  local garch asset expected
  case "$arch" in amd64) garch=x64 ;; arm64) garch=arm64 ;; *) echo "unsupported architecture" >&2; return 2 ;; esac
  case "$os-$garch" in
    linux-x64) asset="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; expected="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" ;;
    linux-arm64) asset="gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz"; expected="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" ;;
    darwin-x64) asset="gitleaks_${GITLEAKS_VERSION}_darwin_x64.tar.gz"; expected="dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709" ;;
    darwin-arm64) asset="gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz"; expected="b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5" ;;
    *) echo "no prebuilt gitleaks for $os/$arch" >&2; return 2 ;;
  esac
  install_release_binary gitleaks gitleaks/gitleaks "$GITLEAKS_VERSION" "$asset" "$expected"
}

IFS=',' read -r -a requested <<< "$TOOLS"
for tool in "${requested[@]}"; do
  case "$tool" in
    poutine) install_poutine ;;
    actionlint) install_actionlint ;;
    llama.cpp) install_llama_cpp ;;
    syft) install_syft ;;
    grype) install_grype ;;
    gitleaks) install_gitleaks ;;
    *) echo "unsupported managed tool: $tool" >&2; exit 2 ;;
  esac
done

echo "Installed managed tools to $BIN_DIR"
echo "Add this line to your shell profile:"
echo "  export PATH=\"$BIN_DIR:\$PATH\""
echo "To uninstall these managed tools, delete this dedicated directory: $BIN_DIR"
