#!/usr/bin/env bash
# Build a .pkg installer for sda-agent on macOS.
#
# Requires `pkgbuild` and `productbuild` (ship with Xcode Command Line
# Tools). Code-signing is out of scope for this script — sign the
# resulting .pkg with `productsign` in a downstream release job.
#
# Usage:
#   BIN=target/release/sda-agent packaging/macos/build-pkg.sh
#
# Output: dist/sda-agent-<version>.pkg
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BIN:-$ROOT/target/release/sda-agent}"
VERSION="${VERSION:-$(grep -E '^version' "$ROOT/Cargo.toml" | head -n1 | cut -d'"' -f2)}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
IDENT="com.sn360.desktop-agent"

if [ ! -x "$BIN" ]; then
    echo "error: binary not found at $BIN" >&2
    exit 1
fi
if [ "$(uname)" != "Darwin" ]; then
    echo "error: build-pkg.sh must run on macOS" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Payload layout (mirrors final install paths under the destination
# volume root that pkgbuild writes into).
ROOTFS="$WORK/root"
install -d -m 0755 "$ROOTFS/usr/local/bin"
install -d -m 0755 "$ROOTFS/etc/sn360-desktop-agent/sca"
install -d -m 0755 "$ROOTFS/Library/LaunchDaemons"
install -m 0755 "$BIN" "$ROOTFS/usr/local/bin/sda-agent"
install -m 0644 "$ROOT/packaging/config/config.yaml" \
    "$ROOTFS/etc/sn360-desktop-agent/config.yaml"
install -m 0644 "$ROOT/packaging/macos/com.sn360.desktop-agent.plist" \
    "$ROOTFS/Library/LaunchDaemons/com.sn360.desktop-agent.plist"

# Scripts (pre/postinstall)
SCRIPTS_DIR="$WORK/scripts"
install -d -m 0755 "$SCRIPTS_DIR"
install -m 0755 "$ROOT/packaging/macos/scripts/preinstall"  "$SCRIPTS_DIR/preinstall"
install -m 0755 "$ROOT/packaging/macos/scripts/postinstall" "$SCRIPTS_DIR/postinstall"

COMPONENT="$WORK/sda-agent-component.pkg"
FINAL="$OUT_DIR/sda-agent-$VERSION.pkg"

pkgbuild \
    --root "$ROOTFS" \
    --identifier "$IDENT" \
    --version "$VERSION" \
    --scripts "$SCRIPTS_DIR" \
    --install-location "/" \
    "$COMPONENT"

productbuild \
    --package "$COMPONENT" \
    --identifier "$IDENT" \
    --version "$VERSION" \
    "$FINAL"

# ---- Code signing (Apple Developer ID) ------------------------------------
# If DEVELOPER_ID_INSTALLER is set, sign the .pkg with productsign so
# Gatekeeper passes. If DEVELOPER_ID_APPLICATION is set, also codesign
# the binary before packaging. Notarization is handled by the CI
# pipeline (xcrun notarytool) after signing.
#
# Env vars:
#   DEVELOPER_ID_APPLICATION  - "Developer ID Application: <Team> (<ID>)"
#   DEVELOPER_ID_INSTALLER    - "Developer ID Installer: <Team> (<ID>)"
#   APPLE_TEAM_ID             - 10-character Apple team ID (for notarize)
if [ -n "${DEVELOPER_ID_APPLICATION:-}" ]; then
    echo "[sign] codesigning binary with: ${DEVELOPER_ID_APPLICATION}"
    codesign --force --options runtime --timestamp \
        --sign "${DEVELOPER_ID_APPLICATION}" \
        "$ROOTFS/usr/local/bin/sda-agent"
fi

if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
    SIGNED_FINAL="$OUT_DIR/sda-agent-$VERSION-signed.pkg"
    echo "[sign] signing .pkg with: ${DEVELOPER_ID_INSTALLER}"
    productsign --sign "${DEVELOPER_ID_INSTALLER}" "$FINAL" "$SIGNED_FINAL"
    mv -f "$SIGNED_FINAL" "$FINAL"
    echo "[sign] signed $FINAL"

    # Notarize if credentials are available.
    if [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
        echo "[sign] submitting for notarization..."
        xcrun notarytool submit "$FINAL" \
            --apple-id "${APPLE_ID}" \
            --team-id "${APPLE_TEAM_ID}" \
            --password "${APPLE_APP_PASSWORD}" \
            --wait
        xcrun stapler staple "$FINAL"
        echo "[sign] notarization complete"
    else
        echo "[sign] skipping notarization (APPLE_ID / APPLE_TEAM_ID / APPLE_APP_PASSWORD not set)"
    fi
else
    echo "[sign] skipping code signing (DEVELOPER_ID_INSTALLER not set)"
fi

echo "built $FINAL"
