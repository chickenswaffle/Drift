#!/usr/bin/env bash
# Fetch a standalone `tor` binary for bundling into the frozen sidecar.
#
# Uses the Tor Project's *Expert Bundle* — the redistributable tor build meant
# to be shipped inside an app: it ships its own shared libs, which the freeze
# (build_sidecar.py) co-bundles next to the binary. build_sidecar reads the
# printed path from $DRIFT_TOR_BINARY.
#
# Usage:
#   fetch_tor.sh <platform> <arch>
#     platform: linux | macos | windows
#     arch:     x86_64 | aarch64
#
# On success prints the absolute path to the extracted tor binary on the LAST
# line (so a workflow can do `DRIFT_TOR_BINARY=$(fetch_tor.sh linux x86_64)`).
#
# Pin the version with $TOR_EB_VERSION (bump periodically — the archive is
# versioned). Optionally verify integrity by setting $TOR_EB_SHA256 to the
# expected tarball hash; CI should pin it. Runs on all three GitHub runners
# (each ships bash).
set -euo pipefail

PLATFORM="${1:?platform required: linux|macos|windows}"
ARCH="${2:?arch required: x86_64|aarch64}"
VERSION="${TOR_EB_VERSION:-14.5.4}"

BASE="https://archive.torproject.org/tor-package-archive/torbrowser/${VERSION}"
TARBALL="tor-expert-bundle-${PLATFORM}-${ARCH}-${VERSION}.tar.gz"
URL="${BASE}/${TARBALL}"

DEST="$(cd "$(dirname "$0")" && pwd)/tor-${PLATFORM}-${ARCH}"
rm -rf "$DEST"
mkdir -p "$DEST"

# Log to stderr so stdout stays clean for the final path.
echo "fetching $URL" >&2
curl -fsSL "$URL" -o "$DEST/$TARBALL"

if [ -n "${TOR_EB_SHA256:-}" ]; then
  echo "verifying sha256" >&2
  if command -v sha256sum >/dev/null 2>&1; then
    echo "${TOR_EB_SHA256}  $DEST/$TARBALL" | sha256sum -c - >&2
  else
    got="$(shasum -a 256 "$DEST/$TARBALL" | awk '{print $1}')"
    [ "$got" = "$TOR_EB_SHA256" ] || { echo "sha256 mismatch: $got" >&2; exit 1; }
  fi
fi

tar -xzf "$DEST/$TARBALL" -C "$DEST"

# The bundle lays the runtime binary at tor/tor(.exe) with its shared libs
# (libssl/libcrypto/libevent) as siblings; a second, unstripped copy sits under
# debug/ — exclude it and prefer the tor/ subdir so the co-bundled siblings are
# the runtime libs, not the debug ones.
BINNAME="tor"
[ "$PLATFORM" = "windows" ] && BINNAME="tor.exe"
TORBIN="$(find "$DEST" -type f -name "$BINNAME" -path '*/tor/*' 2>/dev/null | grep -v '/debug/' | head -1 || true)"
[ -z "$TORBIN" ] && TORBIN="$(find "$DEST" -type f -name "$BINNAME" | grep -v '/debug/' | head -1 || true)"
[ -z "$TORBIN" ] && { echo "::error::no $BINNAME in expert bundle" >&2; exit 1; }
chmod +x "$TORBIN" || true

# Windows runners: this script runs under Git Bash, whose paths (/d/a/…) the
# native Windows Python in the freeze step cannot resolve. Hand back a native
# path in mixed form (D:/a/…) — valid for Windows Python, safe in bash.
if command -v cygpath >/dev/null 2>&1; then
  TORBIN="$(cygpath -m "$TORBIN")"
fi

echo "tor binary: $TORBIN" >&2
echo "$TORBIN"
