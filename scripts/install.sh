#!/usr/bin/env bash
# HaosGreen universal installer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# When run from the repo, SCRIPT_DIR = <repo>/scripts/, so project root is SCRIPT_DIR/..
# When run from a release archive, install.sh is at archive root (no Cargo.toml there;
# the archive is for binary-only installs — use `tar xzf` and run `haos-green --setup`).
PROJECT_ROOT="$SCRIPT_DIR"
if [ -f "$SCRIPT_DIR/Cargo.toml" ]; then
    PROJECT_ROOT="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../Cargo.toml" ]; then
    PROJECT_ROOT="$SCRIPT_DIR/.."
else
    echo "Error: Cannot find Cargo.toml. Run install.sh from the haos-green repository root."
    exit 1
fi

# Check prerequisites
if ! command -v cargo &>/dev/null; then
    echo "Error: Rust/Cargo not found."
    echo "Install Rust from https://rustup.rs and try again."
    exit 1
fi

# Install from source
echo ""
echo "Installing haos-green from ${PROJECT_ROOT}..."
cargo install --path "$PROJECT_ROOT" --locked

echo ""
echo "✓ haos-green installed to $(which haos-green 2>/dev/null || echo 'PATH')"
echo ""
echo "Run the setup wizard to configure your bot:"
echo "  haos-green --setup"
echo ""
echo "Or use the CLI wizard:"
echo "  haos-green --setup --cli"
echo ""
echo "After setup, install as a background service:"
echo "  haos-green --service install"
