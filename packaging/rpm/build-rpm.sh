#!/usr/bin/env bash
# Build an RPM for sda-agent from an already-compiled release binary.
# Requires `rpmbuild` (from rpm-build) on a Fedora/RHEL-family host.
#
# Usage:
#   BIN=target/release/sda-agent packaging/rpm/build-rpm.sh
#
# Output: dist/sda-agent-<version>-1.<arch>.rpm
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BIN:-$ROOT/target/release/sda-agent}"
VERSION="${VERSION:-$(grep -E '^version' "$ROOT/Cargo.toml" | head -n1 | cut -d'"' -f2)}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
SPEC="$ROOT/packaging/rpm/sda-agent.spec"

if [ ! -x "$BIN" ]; then
    echo "error: binary not found at $BIN" >&2
    exit 1
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "error: rpmbuild not available on this host" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

TARBALL_DIR="$WORK/sda-agent-$VERSION"
mkdir -p "$TARBALL_DIR"
cp "$BIN"                                        "$TARBALL_DIR/sda-agent"
cp "$ROOT/packaging/config/config.yaml"          "$TARBALL_DIR/config.yaml"
cp "$ROOT/packaging/systemd/sda-agent.service"   "$TARBALL_DIR/sda-agent.service"
tar -C "$WORK" -czf "$WORK/sda-agent-$VERSION.tar.gz" "sda-agent-$VERSION"

TOP="$WORK/rpmbuild"
mkdir -p "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cp "$WORK/sda-agent-$VERSION.tar.gz" "$TOP/SOURCES/"
cp "$SPEC" "$TOP/SPECS/"

rpmbuild \
    --define "_topdir $TOP" \
    --define "version $VERSION" \
    -bb "$TOP/SPECS/sda-agent.spec"

find "$TOP/RPMS" -name '*.rpm' -exec cp {} "$OUT_DIR/" \;
echo "built RPMs in $OUT_DIR"
