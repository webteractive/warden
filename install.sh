#!/bin/sh
# warden installer.
#
# Default — download a prebuilt binary. No Go toolchain required:
#   curl -fsSL https://raw.githubusercontent.com/webteractive/warden/main/install.sh | sh
#
# From a local checkout, build from source instead (requires Go):
#   ./install.sh --source
#
# Override the destination with WARDEN_INSTALL_DIR.
set -eu

REPO="webteractive/warden"
BIN="warden"
INSTALL_DIR="${WARDEN_INSTALL_DIR:-$HOME/.local/bin}"
MODE="release"

err() { printf '%s-install: %s\n' "$BIN" "$1" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --source) MODE="source" ;;
    --release) MODE="release" ;;
    -h | --help)
      printf 'Usage: install.sh [--source|--release]\n\n'
      printf '  --release  download a prebuilt binary (default; no Go required)\n'
      printf '  --source   build from the local checkout (requires Go)\n'
      exit 0
      ;;
    *) err "unknown option '$arg' — see --help" ;;
  esac
done

note_path() {
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) printf '\nNote: %s is not on your PATH. Add it to your shell profile:\n  export PATH="%s:$PATH"\n' \
         "$INSTALL_DIR" "$INSTALL_DIR" ;;
  esac
}

# --- source build -----------------------------------------------------------
# Only useful from inside a clone; the release path is what a fresh machine uses.
if [ "$MODE" = "source" ]; then
  command -v go >/dev/null 2>&1 || err "go is required for --source; omit the flag to download a prebuilt binary"
  [ -f go.mod ] || err "--source must be run from the root of a warden checkout"

  version="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
  mkdir -p "$INSTALL_DIR"
  go build -ldflags "-s -w -X github.com/webteractive/warden/internal/buildinfo.version=$version" \
    -o "$INSTALL_DIR/$BIN" ./cmd/warden

  printf 'Built and installed %s %s to %s/%s\n' "$BIN" "$version" "$INSTALL_DIR" "$BIN"
  note_path
  exit 0
fi

# --- prebuilt release -------------------------------------------------------
command -v curl >/dev/null 2>&1 || err "curl is required"
command -v tar  >/dev/null 2>&1 || err "tar is required"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  darwin | linux) ;;
  *) err "unsupported OS '$os' — prebuilt binaries exist for darwin and linux only" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) err "unsupported architecture '$arch'" ;;
esac

# Always install the latest published release.
tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
[ -n "$tag" ] || err "could not determine the latest release tag — has a version been tagged yet?"
ver="${tag#v}"

file="${BIN}_${ver}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

printf 'Downloading %s %s (%s/%s)...\n' "$BIN" "$tag" "$os" "$arch"
curl -fsSL "$base/$file" -o "$tmp/$file" || err "download failed: $base/$file"

# Verify the checksum when a sha256 tool is available.
if curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" 2>/dev/null; then
  if command -v sha256sum >/dev/null 2>&1; then sha='sha256sum'
  elif command -v shasum >/dev/null 2>&1; then sha='shasum -a 256'
  else sha=''; fi
  if [ -n "$sha" ]; then
    want=$(grep " ${file}\$" "$tmp/checksums.txt" | awk '{print $1}')
    got=$($sha "$tmp/$file" | awk '{print $1}')
    [ -n "$want" ] && [ "$want" = "$got" ] || err "checksum mismatch for $file"
    printf 'Checksum OK.\n'
  fi
fi

tar -xzf "$tmp/$file" -C "$tmp" "$BIN" || err "failed to extract $BIN from $file"
mkdir -p "$INSTALL_DIR"
mv "$tmp/$BIN" "$INSTALL_DIR/$BIN"
chmod +x "$INSTALL_DIR/$BIN"

printf 'Installed %s %s to %s/%s\n' "$BIN" "$ver" "$INSTALL_DIR" "$BIN"
note_path
