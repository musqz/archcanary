#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# install.sh — install or uninstall archcanary
#   Usage: ./install.sh [--system] [bin-dir]
#          ./install.sh uninstall [--system]
#
#   (no flag)  user install  → ~/.local/bin  (removes /usr/local/bin copies)
#   --system   system install → /usr/local/bin (sudo; removes ~/.local/bin copies)
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

USER_BIN="${DEFAULT_BIN}"
for arg in "$@"; do
    case "$arg" in
        uninstall|--system) ;;
        *) USER_BIN="$arg" ;;
    esac
done
SYSTEM_BIN="/usr/local/bin"
if $SYSTEM; then BIN_DIR="$SYSTEM_BIN"; else BIN_DIR="$USER_BIN"; fi
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/archcanary"

if $UNINSTALL; then
    echo "Uninstalling from: $BIN_DIR"
    echo "Config dir:        $CONFIG_DIR"
    echo

    removed=0
    for f in archcanary archcanary-gui; do
        if $SYSTEM; then
            if [[ -f "$BIN_DIR/$f" ]]; then
                sudo rm -f "$BIN_DIR/$f"
                echo "  removed: $BIN_DIR/$f"
                removed=$((removed + 1))
            else
                echo "  not found: $BIN_DIR/$f"
            fi
        else
            if [[ -f "$BIN_DIR/$f" ]]; then
                rm "$BIN_DIR/$f"
                echo "  removed: $BIN_DIR/$f"
                removed=$((removed + 1))
            else
                echo "  not found: $BIN_DIR/$f"
            fi
        fi
    done

    desktop_dst="${XDG_DATA_HOME:-$HOME/.local/share}/applications/archcanary.desktop"
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

        # User-scope units (user scan + notifier)
        systemctl --user disable --now archcanary-notify.path 2>/dev/null || true
        systemctl --user disable --now archcanary-user.timer 2>/dev/null || true
        rm -f "$HOME/.config/systemd/user/archcanary-notify.path" \
              "$HOME/.config/systemd/user/archcanary-notify.service" \
              "$HOME/.config/systemd/user/archcanary-user.service" \
              "$HOME/.config/systemd/user/archcanary-user.timer"
        systemctl --user daemon-reload 2>/dev/null || true

        # System scan units
        sudo systemctl disable --now archcanary.timer archcanary.path 2>/dev/null || true
        sudo rm -f /etc/systemd/system/archcanary.service \
                   /etc/systemd/system/archcanary.timer \
                   /etc/systemd/system/archcanary-onchange.service \
                   /etc/systemd/system/archcanary.path
        sudo systemctl daemon-reload
        sudo rm -rf /var/lib/archcanary
        echo "  removed: systemd units (system scan + user notifier) and /var/lib/archcanary"

        sudo rm -rf /usr/lib/archcanary /etc/archcanary
        echo "  removed: /usr/lib/archcanary, /etc/archcanary"
        sudo rm -f /usr/share/polkit-1/actions/org.archcanary.policy
        echo "  removed: /usr/share/polkit-1/actions/org.archcanary.policy"
    fi

    echo
    if [[ $removed -gt 0 ]]; then
        echo "Done. archcanary uninstalled."
    else
        echo "Nothing was removed (files not found at $BIN_DIR)."
    fi
    exit 0
fi

echo "Installing to: $BIN_DIR"
echo "Config dir:    $CONFIG_DIR"
echo

mkdir -p "$CONFIG_DIR"

# Install binaries — system install goes to /usr/local/bin (sudo),
# user install goes to ~/.local/bin. Clean up the other location to avoid
# two competing versions on PATH.
if $SYSTEM; then
    sudo install -m 755 "$REPO_DIR/archcanary.sh"    "$SYSTEM_BIN/archcanary"
    sudo install -m 755 "$REPO_DIR/archcanary-gui.sh" "$SYSTEM_BIN/archcanary-gui"
    echo "  installed: $SYSTEM_BIN/archcanary"
    echo "  installed: $SYSTEM_BIN/archcanary-gui"
    _removed_user=false
    for f in archcanary archcanary-gui; do
        if [[ -f "$USER_BIN/$f" ]]; then
            rm -f "$USER_BIN/$f"
            echo "  removed:   $USER_BIN/$f (superseded by system install)"
            _removed_user=true
        fi
    done
else
    mkdir -p "$USER_BIN"
    install -m 755 "$REPO_DIR/archcanary.sh"    "$USER_BIN/archcanary"
    install -m 755 "$REPO_DIR/archcanary-gui.sh" "$USER_BIN/archcanary-gui"
    echo "  installed: $USER_BIN/archcanary"
    echo "  installed: $USER_BIN/archcanary-gui"
    _removed_system=false
    for f in archcanary archcanary-gui; do
        if [[ -f "$SYSTEM_BIN/$f" ]]; then
            sudo rm -f "$SYSTEM_BIN/$f"
            echo "  removed:   $SYSTEM_BIN/$f (superseded by user install)"
            _removed_system=true
        fi
    done
fi

# Install desktop entry
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$DESKTOP_DIR"
cp "$REPO_DIR/archcanary.desktop" "$DESKTOP_DIR/archcanary.desktop"
echo "  installed: $DESKTOP_DIR/archcanary.desktop"

# Seed config dir (only if files don't already exist)
for f in package_list.txt malicious_npm_packages.txt; do
    if [[ ! -f "$CONFIG_DIR/$f" ]]; then
        cp "$REPO_DIR/$f" "$CONFIG_DIR/$f"
        echo "  seeded:    $CONFIG_DIR/$f"
    else
        echo "  kept:      $CONFIG_DIR/$f (already exists)"
    fi
done

# Seed yay Lua hooks if not already present
YAY_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/yay"
if [[ ! -f "$YAY_CONFIG_DIR/init.lua" ]]; then
    mkdir -p "$YAY_CONFIG_DIR"
    cp "$REPO_DIR/configs/yay-init.lua" "$YAY_CONFIG_DIR/init.lua"
    echo "  seeded:    $YAY_CONFIG_DIR/init.lua"
else
    echo "  kept:      $YAY_CONFIG_DIR/init.lua (already exists)"
fi

# The DKMS allowlist is a single system-wide file at /etc/archcanary/
# (the kmod audit only runs as root). It is seeded by --system below, not here.

if $SYSTEM; then
    echo
    echo "Installing system components (requires root)..."
    SYSTEM_LIB="/usr/lib/archcanary"
    sudo mkdir -p "$SYSTEM_LIB"
    sudo cp "$REPO_DIR/archcanary.sh" "$SYSTEM_LIB/archcanary.sh"
    sudo chmod 755 "$SYSTEM_LIB/archcanary.sh"
    sudo cp "$REPO_DIR/archcanary-root-helper" "$SYSTEM_LIB/root-helper"
    sudo chown root:root "$SYSTEM_LIB/root-helper"
    sudo chmod 755 "$SYSTEM_LIB/root-helper"
    sudo cp "$REPO_DIR/org.archcanary.policy" /usr/share/polkit-1/actions/
    # Seed the bundled package lists next to the system script so a root scan
    # (system service) finds them — root's $HOME is /root, which is not seeded.
    for _list in package_list.txt malicious_npm_packages.txt chaos_rat_packages.txt malicious_russian_spam_packages.txt; do
        [[ -f "$REPO_DIR/$_list" ]] && sudo cp "$REPO_DIR/$_list" "$SYSTEM_LIB/$_list"
    done
    # DKMS allowlist — single system-wide file (the kmod audit only runs as root).
    # Seed it once (mode 644 so non-root runs can read it), preferring an existing
    # legacy ~/.config copy so prior entries are preserved on upgrade; otherwise a
    # commented template. Never clobber an existing /etc copy.
    sudo install -d -m 755 /etc/archcanary
    if [[ ! -f /etc/archcanary/dkms_allowlist.conf ]]; then
        if [[ -f "$CONFIG_DIR/dkms_allowlist.conf" ]]; then
            sudo install -m 644 "$CONFIG_DIR/dkms_allowlist.conf" /etc/archcanary/dkms_allowlist.conf
        else
            sudo tee /etc/archcanary/dkms_allowlist.conf >/dev/null << 'EOF'
# DKMS modules to skip during --check-kmod (system-wide allowlist).
# One module name per line. Everything after # is a comment.
# Add modules that are known-good but not tracked by pacman.
#
# Common examples (uncomment as needed):
# tuxedo-drivers  # TUXEDO Computers hardware driver
# v4l2loopback    # virtual camera (OBS, video conferencing)
# vboxdrv         # VirtualBox host kernel module
# vmmon           # VMware Workstation
EOF
            sudo chmod 644 /etc/archcanary/dkms_allowlist.conf
        fi
    fi
    # The per-user allowlist is no longer read — remove the legacy copy to avoid
    # confusion (its entries were migrated to /etc above on first run).
    if [[ -f "$CONFIG_DIR/dkms_allowlist.conf" ]]; then
        rm -f "$CONFIG_DIR/dkms_allowlist.conf"
        echo "  migrated:  ~/.config dkms_allowlist.conf → /etc (per-user copy removed)"
    fi
    echo "  installed: $SYSTEM_LIB/archcanary.sh"
    echo "  installed: $SYSTEM_LIB/root-helper"
    echo "  installed: $SYSTEM_LIB/{package_list,malicious_npm_packages,chaos_rat_packages,malicious_russian_spam_packages}.txt"
    echo "  installed: /etc/archcanary/dkms_allowlist.conf (system-wide DKMS allowlist for the root scan)"
    echo "  installed: /usr/share/polkit-1/actions/org.archcanary.policy"

    # --- Automated scan: root system units + user-session notifier ---------
    # Migrate away from the old user-scope scan units (superseded by the root
    # system scan; running --full as the user skips the root checks).
    for _u in archcanary.service archcanary.timer \
              archcanary.path archcanary-onchange.service; do
        if [[ -f "$HOME/.config/systemd/user/$_u" ]]; then
            systemctl --user disable --now "$_u" 2>/dev/null || true
            rm -f "$HOME/.config/systemd/user/$_u"
            echo "  migrated:  removed old user unit $_u"
        fi
    done

    # Pre-create the result dir so the user notifier can watch it right away
    # (the scan's StateDirectory= also creates it, but the .path needs it now).
    sudo install -d -m 755 /var/lib/archcanary

    # System scan units (run as root → complete scan)
    sudo cp "$REPO_DIR"/systemd/system/archcanary.service \
            "$REPO_DIR"/systemd/system/archcanary.timer \
            "$REPO_DIR"/systemd/system/archcanary-onchange.service \
            "$REPO_DIR"/systemd/system/archcanary.path \
            /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now archcanary.timer archcanary.path
    echo "  installed: /etc/systemd/system/archcanary.{service,timer,path} + -onchange.service (enabled)"

    # User-scope units: the user-level scan (npm/bun/pkgbuild caches, autostart —
    # run as you so they see your real home) + the notifier that watches the root
    # scan's result. The user scan notifies itself (runs in your session).
    USER_UNITS="$HOME/.config/systemd/user"
    mkdir -p "$USER_UNITS"
    cp "$REPO_DIR"/systemd/user/archcanary-notify.path \
       "$REPO_DIR"/systemd/user/archcanary-notify.service \
       "$REPO_DIR"/systemd/user/archcanary-user.service \
       "$REPO_DIR"/systemd/user/archcanary-user.timer \
       "$USER_UNITS/"
    if systemctl --user daemon-reload 2>/dev/null; then
        systemctl --user enable --now archcanary-notify.path 2>/dev/null || true
        systemctl --user enable --now archcanary-user.timer 2>/dev/null || true
        echo "  installed: $USER_UNITS/archcanary-user.{service,timer} + notify.{path,service} (enabled)"
    else
        echo "  installed: $USER_UNITS/archcanary-user.{service,timer} + notify.{path,service}"
        echo "             (no user systemd session detected — enable later with:"
        echo "              systemctl --user enable --now archcanary-user.timer archcanary-notify.path)"
    fi

    echo
    echo "Root-requiring checks are also available in the GUI via pkexec."
    echo "Automated scan: weekly + on boot + after each pacman transaction (see docs/systemd.md)."
fi

echo
echo "Done. Run: archcanary --refresh --full --all-time"

# Warn if the install dir is not in PATH (only relevant for user install)
if ! $SYSTEM && [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
    echo
    echo "WARNING: $USER_BIN is not in your PATH."
    echo "Add this to your shell profile:"
    echo "  export PATH=\"\$PATH:$USER_BIN\""
fi

# If bins were removed from the other location, bash may have the old path cached.
if ${_removed_system:-false} || ${_removed_user:-false}; then
    echo
    echo "NOTE: binaries were moved. Run 'hash -r' in your current shell"
    echo "(or open a new terminal) so bash picks up the new location."
fi
