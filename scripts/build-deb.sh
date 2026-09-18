#!/usr/bin/env bash
# Build .deb package from a pre-built binary.
# Usage: TARGET=<rust-triple> ./scripts/build-deb.sh
# Reads the binary from dist/haos-green (or dist/haos-green.exe).
set -euo pipefail

TARGET="${TARGET:-x86_64-unknown-linux-gnu}"
case "$TARGET" in
  x86_64-unknown-linux-gnu) ARCH=amd64 ;;
  aarch64-unknown-linux-gnu) ARCH=arm64 ;;
  *) echo "Unknown Debian arch for target $TARGET"; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/dist/haos-green"
if [ ! -f "$BINARY" ]; then
  echo "Binary not found at $BINARY. Build release first: cargo build --release"
  exit 1
fi

PKG_NAME="haos-green"
PKG_VERSION="${GITHUB_REF_NAME:-1.0.0}"
PKG_VERSION="${PKG_VERSION#v}"  # strip leading v
BUILD_DIR=$(mktemp -d)
PKG_DIR="$BUILD_DIR/haos-green_${PKG_VERSION}_${ARCH}"

# Create package directory structure
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/haos-green"

# Copy binary
cp "$BINARY" "$PKG_DIR/usr/bin/haos-green"
chmod 755 "$PKG_DIR/usr/bin/haos-green"

# Copy config example
cp "$PROJECT_ROOT/config.example.toml" "$PKG_DIR/usr/share/haos-green/"

# Copy service templates
mkdir -p "$PKG_DIR/usr/share/haos-green/services"
cp -r "$PROJECT_ROOT/scripts/services/"* "$PKG_DIR/usr/share/haos-green/services/"

# Create control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: haos-green
Version: $PKG_VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: HaosGreen <haos-green@example.com>
Description: HaosGreen Telegram AI Assistant
 A Telegram AI assistant written in Rust with built-in sandboxed tools
 and MCP server integration.
Build-Depends: debhelper (>= 13)
EOF

# Create postinst — install systemd user service
cat > "$PKG_DIR/DEBIAN/postinst" << 'POSTINST'
#!/bin/sh
set -e
echo "HaosGreen installed to /usr/bin/haos-green"
echo ""
echo "To configure your bot:"
echo "  haos-green --setup"
echo ""
echo "To install as a background service after configuration:"
echo "  haos-green --service install"
POSTINST
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Create prerm
cat > "$PKG_DIR/DEBIAN/prerm" << 'PRERM'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now haos-green.service 2>/dev/null || true
fi
PRERM
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# Build the .deb
mkdir -p "$PROJECT_ROOT/dist"
fakeroot dpkg-deb --build "$PKG_DIR" "$PROJECT_ROOT/dist/haos-green_${PKG_VERSION}_${ARCH}.deb" 2>/dev/null || {
  # Fallback without fakeroot
  dpkg-deb --build "$PKG_DIR" "$PROJECT_ROOT/dist/haos-green_${PKG_VERSION}_${ARCH}.deb"
}

rm -rf "$BUILD_DIR"
echo "✓ Built: dist/haos-green_${PKG_VERSION}_${ARCH}.deb"
