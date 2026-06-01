#!/bin/sh
# bumper installer — fetches the latest signed release binary for your OS/arch
# and verifies its checksum before installing.
#
#   curl -sSfL https://raw.githubusercontent.com/gnana997/bumper/main/install.sh | sh
#
# Env knobs:
#   BUMPER_VERSION       tag to install (default: latest)
#   BUMPER_INSTALL_DIR   install dir (default: /usr/local/bin if writable, else ~/.local/bin)
set -eu

REPO="gnana997/bumper"
BIN="bumper"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

need curl
need tar

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) die "unsupported architecture: $arch" ;;
esac
case "$os" in
  linux | darwin) ;;
  *) die "unsupported OS: $os — grab a binary from https://github.com/$REPO/releases" ;;
esac

version="${BUMPER_VERSION:-latest}"
if [ "$version" = "latest" ]; then
  version=$(curl -sSfL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name":' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
fi
[ -n "$version" ] || die "could not resolve the latest version"

ver="${version#v}"
asset="${BIN}_${ver}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$version"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say "downloading $asset ($version) …"
curl -sSfL "$base/$asset" -o "$tmp/$asset" || die "download failed: $base/$asset"
curl -sSfL "$base/checksums.txt" -o "$tmp/checksums.txt" || die "could not fetch checksums"

# Verify sha256 (sha256sum on Linux, shasum -a 256 on macOS).
say "verifying checksum …"
expected=$(grep " $asset\$" "$tmp/checksums.txt" | awk '{print $1}')
[ -n "$expected" ] || die "no checksum recorded for $asset"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$asset" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
fi
[ "$expected" = "$actual" ] || die "checksum mismatch — refusing to install"
say "checksum ok"

tar -xzf "$tmp/$asset" -C "$tmp"
[ -f "$tmp/$BIN" ] || die "archive did not contain $BIN"

dir="${BUMPER_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    dir="/usr/local/bin"
  else
    dir="$HOME/.local/bin"
  fi
fi
mkdir -p "$dir"
cp "$tmp/$BIN" "$dir/$BIN"
chmod 0755 "$dir/$BIN"

say "installed $BIN → $dir/$BIN"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "note: $dir is not on your PATH — add:  export PATH=\"$dir:\$PATH\"" ;;
esac
"$dir/$BIN" version 2>/dev/null || true
say "next:  $BIN init   # wire bumper into Claude Code"
