#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# install.sh — install or uninstall aur-malware-check
#   Usage: ./install.sh [--system] [bin-dir]
#          ./install.sh uninstall [--system]
#
#   --system  also install the pkexec root helper + polkit policy (requires sudo)
# ---------------------------------------------------------------------------

REPO_DIR="$(dirname "$(realpath "$0")")"

# Determine install dir: prefer the XDG ~/.local/bin, fall back to ~/bin
DEFAULT_BIN=""
if [[ ":$PATH:" == *":$HOME/.local/bin:"* ]]; then
    DEFAULT_BIN="$HOME/.local/bin"
elif [[ ":$PATH:" == *":$HOME/bin:"* ]]; then
    DEFAULT_BIN="$HOME/bin"
else
    DEFAULT_BIN="$HOME/.local/bin"
fi

# Parse arguments: optional "uninstall" verb, optional bin-dir
UNINSTALL=false
SYSTEM=false
for arg in "$@"; do
    case "$arg" in
        uninstall) UNINSTALL=true ;;
        --system)  SYSTEM=true ;;
    esac
done

BIN_DIR="${DEFAULT_BIN}"
for arg in "$@"; do
    case "$arg" in
        uninstall|--system) ;;
        *) BIN_DIR="$arg" ;;
    esac
done
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/aur-malware-check"

if $UNINSTALL; then
    echo "Uninstalling from: $BIN_DIR"
    echo "Config dir:        $CONFIG_DIR"
    echo

    removed=0
    for f in aur-malware-check.sh aur_malware_menu.sh aur_malware_gui.sh; do
        if [[ -f "$BIN_DIR/$f" ]]; then
            rm "$BIN_DIR/$f"
            echo "  removed: $BIN_DIR/$f"
            removed=$((removed + 1))
        else
            echo "  not found: $BIN_DIR/$f"
        fi
    done

    if [[ -d "$CONFIG_DIR" ]]; then
        rm -rf "$CONFIG_DIR"
        echo "  removed: $CONFIG_DIR"
    else
        echo "  not found: $CONFIG_DIR"
    fi

    if $SYSTEM; then
        echo
        echo "Removing system components (requires root)..."
        sudo rm -rf /usr/lib/aur-malware-check
        echo "  removed: /usr/lib/aur-malware-check"
        sudo rm -f /usr/share/polkit-1/actions/org.aur-malware-check.policy
        echo "  removed: /usr/share/polkit-1/actions/org.aur-malware-check.policy"
    fi

    echo
    if [[ $removed -gt 0 ]]; then
        echo "Done. aur-malware-check uninstalled."
    else
        echo "Nothing was removed (files not found at $BIN_DIR)."
    fi
    exit 0
fi

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

# Install GUI script
cp "$REPO_DIR/aur_malware_gui.sh" "$BIN_DIR/aur_malware_gui.sh"
chmod +x "$BIN_DIR/aur_malware_gui.sh"
echo "  installed: $BIN_DIR/aur_malware_gui.sh"

# Seed config dir (only if files don't already exist)
for f in package_list.txt malicious_npm_packages.txt; do
    if [[ ! -f "$CONFIG_DIR/$f" ]]; then
        cp "$REPO_DIR/$f" "$CONFIG_DIR/$f"
        echo "  seeded:    $CONFIG_DIR/$f"
    else
        echo "  kept:      $CONFIG_DIR/$f (already exists)"
    fi
done

if [[ ! -f "$CONFIG_DIR/dkms_allowlist.conf" ]]; then
    cat > "$CONFIG_DIR/dkms_allowlist.conf" << 'EOF'
# DKMS modules to skip during --check-kmod
# One module name per line; lines starting with # are comments.
# Add modules that are known-good but not tracked by pacman.
#
# Common examples (uncomment as needed):
#   tuxedo-drivers   — TUXEDO Computers hardware driver
#   v4l2loopback     — virtual camera (OBS, video conferencing)
#   vboxdrv          — VirtualBox host kernel module
#   vmmon            — VMware Workstation
EOF
    echo "  seeded:    $CONFIG_DIR/dkms_allowlist.conf"
else
    echo "  kept:      $CONFIG_DIR/dkms_allowlist.conf (already exists)"
fi

if $SYSTEM; then
    echo
    echo "Installing system components (requires root)..."
    SYSTEM_LIB="/usr/lib/aur-malware-check"
    sudo mkdir -p "$SYSTEM_LIB"
    sudo cp "$REPO_DIR/aur_check-v2.sh" "$SYSTEM_LIB/aur-malware-check.sh"
    sudo chmod 755 "$SYSTEM_LIB/aur-malware-check.sh"
    sudo cp "$REPO_DIR/aur-malware-root-helper" "$SYSTEM_LIB/root-helper"
    sudo chown root:root "$SYSTEM_LIB/root-helper"
    sudo chmod 755 "$SYSTEM_LIB/root-helper"
    sudo cp "$REPO_DIR/org.aur-malware-check.policy" /usr/share/polkit-1/actions/
    echo "  installed: $SYSTEM_LIB/aur-malware-check.sh"
    echo "  installed: $SYSTEM_LIB/root-helper"
    echo "  installed: /usr/share/polkit-1/actions/org.aur-malware-check.policy"
    echo
    echo "Root-requiring checks are now available in the GUI via pkexec."
fi

echo
echo "Done. Run: aur-malware-check.sh --refresh --full --all-time"

# Warn if BIN_DIR is not in PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo
    echo "WARNING: $BIN_DIR is not in your PATH."
    echo "Add this to your shell profile:"
    echo "  export PATH=\"\$PATH:$BIN_DIR\""
fi
