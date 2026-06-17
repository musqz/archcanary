#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# install.sh — install or uninstall aur-malware-check
#   Usage: ./install.sh [--system] [bin-dir]
#          ./install.sh uninstall [--system]
#
#   --system  also install the pkexec root helper + polkit policy (requires sudo)
# ---------------------------------------------------------------------------

if [[ $EUID -eq 0 ]]; then
    echo "ERROR: do not run install.sh as root or with sudo." >&2
    echo "Run it as your regular user — it calls sudo internally for system components." >&2
    echo "  ./install.sh [--system]" >&2
    exit 1
fi

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
    for f in aur-malware-check.sh aur_malware_gui.sh; do
        if [[ -f "$BIN_DIR/$f" ]]; then
            rm "$BIN_DIR/$f"
            echo "  removed: $BIN_DIR/$f"
            removed=$((removed + 1))
        else
            echo "  not found: $BIN_DIR/$f"
        fi
    done

    desktop_dst="${XDG_DATA_HOME:-$HOME/.local/share}/applications/aur-malware-check.desktop"
    if [[ -f "$desktop_dst" ]]; then
        rm "$desktop_dst"
        echo "  removed: $desktop_dst"
    fi

    if [[ -d "$CONFIG_DIR" ]]; then
        rm -rf "$CONFIG_DIR"
        echo "  removed: $CONFIG_DIR"
    else
        echo "  not found: $CONFIG_DIR"
    fi

    if $SYSTEM; then
        echo
        echo "Removing system components (requires root)..."

        # User-session notifier
        systemctl --user disable --now aur-malware-check-notify.path 2>/dev/null || true
        rm -f "$HOME/.config/systemd/user/aur-malware-check-notify.path" \
              "$HOME/.config/systemd/user/aur-malware-check-notify.service"
        systemctl --user daemon-reload 2>/dev/null || true

        # System scan units
        sudo systemctl disable --now aur-malware-check.timer aur-malware-check.path 2>/dev/null || true
        sudo rm -f /etc/systemd/system/aur-malware-check.service \
                   /etc/systemd/system/aur-malware-check.timer \
                   /etc/systemd/system/aur-malware-check-onchange.service \
                   /etc/systemd/system/aur-malware-check.path
        sudo systemctl daemon-reload
        sudo rm -rf /var/lib/aur-malware-check
        echo "  removed: systemd units (system scan + user notifier) and /var/lib/aur-malware-check"

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

# Install GUI script
cp "$REPO_DIR/aur_malware_gui.sh" "$BIN_DIR/aur_malware_gui.sh"
chmod +x "$BIN_DIR/aur_malware_gui.sh"
echo "  installed: $BIN_DIR/aur_malware_gui.sh"

# Install desktop entry
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$DESKTOP_DIR"
cp "$REPO_DIR/aur-malware-check.desktop" "$DESKTOP_DIR/aur-malware-check.desktop"
echo "  installed: $DESKTOP_DIR/aur-malware-check.desktop"

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
# One module name per line. Everything after # is a comment.
# Add modules that are known-good but not tracked by pacman.
#
# Common examples (uncomment as needed):
# tuxedo-drivers  # TUXEDO Computers hardware driver
# v4l2loopback    # virtual camera (OBS, video conferencing)
# vboxdrv         # VirtualBox host kernel module
# vmmon           # VMware Workstation
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
    # Seed the bundled package lists next to the system script so a root scan
    # (system service) finds them — root's $HOME is /root, which is not seeded.
    for _list in package_list.txt malicious_npm_packages.txt chaos_rat_packages.txt; do
        [[ -f "$REPO_DIR/$_list" ]] && sudo cp "$REPO_DIR/$_list" "$SYSTEM_LIB/$_list"
    done
    echo "  installed: $SYSTEM_LIB/aur-malware-check.sh"
    echo "  installed: $SYSTEM_LIB/root-helper"
    echo "  installed: $SYSTEM_LIB/{package_list,malicious_npm_packages,chaos_rat_packages}.txt"
    echo "  installed: /usr/share/polkit-1/actions/org.aur-malware-check.policy"

    # --- Automated scan: root system units + user-session notifier ---------
    # Migrate away from the old user-scope scan units (superseded by the root
    # system scan; running --full as the user skips the root checks).
    for _u in aur-malware-check.service aur-malware-check.timer \
              aur-malware-check.path aur-malware-check-onchange.service; do
        if [[ -f "$HOME/.config/systemd/user/$_u" ]]; then
            systemctl --user disable --now "$_u" 2>/dev/null || true
            rm -f "$HOME/.config/systemd/user/$_u"
            echo "  migrated:  removed old user unit $_u"
        fi
    done

    # Pre-create the result dir so the user notifier can watch it right away
    # (the scan's StateDirectory= also creates it, but the .path needs it now).
    sudo install -d -m 755 /var/lib/aur-malware-check

    # System scan units (run as root → complete scan)
    sudo cp "$REPO_DIR"/systemd/system/aur-malware-check.service \
            "$REPO_DIR"/systemd/system/aur-malware-check.timer \
            "$REPO_DIR"/systemd/system/aur-malware-check-onchange.service \
            "$REPO_DIR"/systemd/system/aur-malware-check.path \
            /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now aur-malware-check.timer aur-malware-check.path
    echo "  installed: /etc/systemd/system/aur-malware-check.{service,timer,path} + -onchange.service (enabled)"

    # User-session notifier (raises the desktop alert on a detection)
    USER_UNITS="$HOME/.config/systemd/user"
    mkdir -p "$USER_UNITS"
    cp "$REPO_DIR"/systemd/user/aur-malware-check-notify.path \
       "$REPO_DIR"/systemd/user/aur-malware-check-notify.service \
       "$USER_UNITS/"
    if systemctl --user daemon-reload 2>/dev/null; then
        systemctl --user enable --now aur-malware-check-notify.path 2>/dev/null || true
        echo "  installed: $USER_UNITS/aur-malware-check-notify.{path,service} (enabled)"
    else
        echo "  installed: $USER_UNITS/aur-malware-check-notify.{path,service}"
        echo "             (no user systemd session detected — enable later with:"
        echo "              systemctl --user enable --now aur-malware-check-notify.path)"
    fi

    echo
    echo "Root-requiring checks are also available in the GUI via pkexec."
    echo "Automated scan: weekly + on boot + after each pacman transaction (see docs/systemd.md)."
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
