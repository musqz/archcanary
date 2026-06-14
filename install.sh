#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# install.sh — install aur-malware-check to ~/.local/bin or ~/bin
# ---------------------------------------------------------------------------

REPO_DIR="$(dirname "$(realpath "$0")")"

# Determine install dir: prefer ~/.local/bin if in PATH, else ~/bin
DEFAULT_BIN=""
if [[ ":$PATH:" == *":$HOME/.local/bin:"* ]]; then
    DEFAULT_BIN="$HOME/.local/bin"
elif [[ ":$PATH:" == *":$HOME/bin:"* ]]; then
    DEFAULT_BIN="$HOME/bin"
else
    DEFAULT_BIN="$HOME/.local/bin"
fi

BIN_DIR="${1:-$DEFAULT_BIN}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/aur-malware-check"

echo "Installing to: $BIN_DIR"
echo "Config dir:    $CONFIG_DIR"
echo

# Create dirs
mkdir -p "$BIN_DIR" "$CONFIG_DIR"

# Install main script
cp "$REPO_DIR/aur_check-v2.sh" "$BIN_DIR/aur-malware-check.sh"
chmod +x "$BIN_DIR/aur-malware-check.sh"
echo "  installed: $BIN_DIR/aur-malware-check.sh"

# Install menu script
cp "$REPO_DIR/aur_malware_menu.sh" "$BIN_DIR/aur_malware_menu.sh"
chmod +x "$BIN_DIR/aur_malware_menu.sh"
echo "  installed: $BIN_DIR/aur_malware_menu.sh"

# Seed config dir (only if files don't already exist)
for f in package_list.txt malicious_npm_packages.txt; do
    if [[ ! -f "$CONFIG_DIR/$f" ]]; then
        cp "$REPO_DIR/$f" "$CONFIG_DIR/$f"
        echo "  seeded:    $CONFIG_DIR/$f"
    else
        echo "  kept:      $CONFIG_DIR/$f (already exists)"
    fi
done

echo
echo "Done. Run: aur-malware-check.sh --refresh --full --all-time"

# Warn if BIN_DIR is not in PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo
    echo "WARNING: $BIN_DIR is not in your PATH."
    echo "Add this to your shell profile:"
    echo "  export PATH=\"\$PATH:$BIN_DIR\""
fi
