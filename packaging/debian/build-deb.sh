#!/usr/bin/env bash
# Build a .deb package for sda-agent from an already-compiled release
# binary. Requires `dpkg-deb` (ships with `dpkg-dev` on Debian/Ubuntu).
#
# Usage:
#   BIN=target/release/sda-agent packaging/debian/build-deb.sh
#
# Output: dist/sda-agent_<version>_<arch>.deb
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BIN:-$ROOT/target/release/sda-agent}"
ARCH="${ARCH:-amd64}"
VERSION="${VERSION:-$(grep -E '^version' "$ROOT/Cargo.toml" | head -n1 | cut -d'"' -f2)}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"

if [ ! -x "$BIN" ]; then
    echo "error: binary not found at $BIN" >&2
    echo "       build it first with: cargo build --release -p sda-agent" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# File layout
install -d -m 0755 "$STAGE/DEBIAN"
install -d -m 0755 "$STAGE/usr/bin"
install -d -m 0755 "$STAGE/etc/sn360-desktop-agent/sca"
install -d -m 0755 "$STAGE/lib/systemd/system"

install -m 0755 "$BIN" "$STAGE/usr/bin/sda-agent"
install -m 0644 "$ROOT/packaging/config/config.yaml" \
    "$STAGE/etc/sn360-desktop-agent/config.yaml"
install -m 0644 "$ROOT/packaging/systemd/sda-agent.service" \
    "$STAGE/lib/systemd/system/sda-agent.service"

# Control files
sed -E "s/^Version: .*/Version: $VERSION/; s/^Architecture: .*/Architecture: $ARCH/" \
    "$ROOT/packaging/debian/control" > "$STAGE/DEBIAN/control"
install -m 0644 "$ROOT/packaging/debian/conffiles" "$STAGE/DEBIAN/conffiles"
install -m 0755 "$ROOT/packaging/debian/preinst"  "$STAGE/DEBIAN/preinst"
install -m 0755 "$ROOT/packaging/debian/postinst" "$STAGE/DEBIAN/postinst"
install -m 0755 "$ROOT/packaging/debian/prerm"    "$STAGE/DEBIAN/prerm"
install -m 0755 "$ROOT/packaging/debian/postrm"   "$STAGE/DEBIAN/postrm"

OUT="$OUT_DIR/sda-agent_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT" >/dev/null
echo "built $OUT"
