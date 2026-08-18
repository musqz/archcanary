#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# install.sh — install or uninstall archcanary
#   Usage: ./install.sh [--system] [bin-dir]
#          ./install.sh uninstall [--system]
#
#   (no flag)  user install  → ~/.local/bin  (removes /usr/local/bin copies)
#   --system   system install → /usr/local/bin (sudo; removes ~/.local/bin copies)
#
#   All root-only steps run through lib/archcanary-root-install.sh (see
#   run_root below) so a sudoers config restricted to a command allowlist
#   only needs to permit that one script, not each command it used to run.
# ---------------------------------------------------------------------------

for arg in "$@"; do
    case "$arg" in
        --help|-h)
            echo "Usage: ./install.sh [--system] [bin-dir]"
            echo "       ./install.sh uninstall [--system]"
            echo "       ./install.sh --help"
            echo
            echo "Install:"
            echo "  ./install.sh               User install → ~/.local/bin (or ~/bin if that's on PATH instead)"
            echo "  ./install.sh /custom/dir   User install to a specific bin dir"
            echo "  ./install.sh --system      System install → /usr/local/bin (sudo)"
            echo "                             Adds: root helper + polkit policy, systemd automated"
            echo "                             scan units, auditd rules (if auditd is installed)"
            echo
            echo "Uninstall:"
            echo "  ./install.sh uninstall            Remove the user install"
            echo "  ./install.sh uninstall --system   Remove the system install (sudo)"
            echo
            echo "Notes:"
            echo "  - A system install removes any user-install copies and vice versa, so"
            echo "    PATH never has two competing versions."
            echo "  - --system needs sudo but funnels every root step through one script"
            echo "    (lib/archcanary-root-install.sh) — see README for the sudoers line to"
            echo "    add if your sudo access is restricted to a command allowlist."
            echo "  - man page: man archcanary"
            exit 0
            ;;
    esac
done

if [[ $EUID -eq 0 ]]; then
    echo "ERROR: do not run install.sh as root or with sudo." >&2
    echo "Run it as your regular user — it calls sudo internally for system components." >&2
    echo "  ./install.sh [--system]" >&2
    exit 1
fi

REPO_DIR="$(dirname "$(realpath "$0")")"
_ver=$(cat "$REPO_DIR/version.txt" 2>/dev/null || echo "unknown")

run_root() {
    sudo bash "$REPO_DIR/lib/archcanary-root-install.sh" "$@"
}

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
USER_BIN="${DEFAULT_BIN}"
for arg in "$@"; do
    case "$arg" in
        uninstall) UNINSTALL=true ;;
        --system)  SYSTEM=true ;;
        -*)
            echo "ERROR: unknown option: $arg" >&2
            echo "Run './install.sh --help' for usage." >&2
            exit 1
            ;;
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
        [[ -f "$BIN_DIR/$f" ]] && removed=$((removed + 1))
    done

    if $SYSTEM; then
        run_root uninstall-bins
    else
        for f in archcanary archcanary-gui; do
            if [[ -f "$BIN_DIR/$f" ]]; then
                rm "$BIN_DIR/$f"
                echo "  removed: $BIN_DIR/$f"
            else
                echo "  not found: $BIN_DIR/$f"
            fi
        done
        rm -f "${XDG_DATA_HOME:-$HOME/.local/share}/man/man1/archcanary.1"
        echo "  removed: ${XDG_DATA_HOME:-$HOME/.local/share}/man/man1/archcanary.1"
        rm -f "${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/archcanary" \
              "${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/canary"
        echo "  removed: ${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/{archcanary,canary}"
    fi

    desktop_dst="${XDG_DATA_HOME:-$HOME/.local/share}/applications/archcanary.desktop"
    if [[ -f "$desktop_dst" ]]; then
        rm "$desktop_dst"
        echo "  removed: $desktop_dst"
    fi

    if [[ -d "$CONFIG_DIR" ]]; then
        echo "  kept:    $CONFIG_DIR (user config — remove manually if desired)"
    fi

    # Remove archcanary's PreBuildCommand hook lines from paru.conf, if
    # present — runs regardless of whether paru is still installed, since
    # the config edit should be cleaned up either way. Only the marker
    # comment line and the PreBuildCommand line right after it are removed;
    # the [bin] header and any other content in the file are left alone —
    # we can't prove the section has no unrelated keys around ours, and
    # removing the header would silently reassign those to whatever section
    # precedes it.
    PARU_CONF="${XDG_CONFIG_HOME:-$HOME/.config}/paru/paru.conf"
    _paru_marker='archcanary PreBuildCommand hook'
    if grep -qF -- "$_paru_marker" "$PARU_CONF" 2>/dev/null; then
        _paru_ln=$(grep -nF -- "$_paru_marker" "$PARU_CONF" | head -1 | cut -d: -f1)
        sed -i "${_paru_ln},$((_paru_ln + 1))d" "$PARU_CONF"
        echo "  removed: archcanary PreBuildCommand hook from $PARU_CONF"
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

        run_root uninstall-components
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
    run_root install-bins "$REPO_DIR" "$_ver"
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
    sed -i "s/@VERSION@/$_ver/" "$USER_BIN/archcanary"
    echo "  installed: $USER_BIN/archcanary"
    echo "  installed: $USER_BIN/archcanary-gui"
    _removed_system=false
    _stray_system_bins=()
    for f in archcanary archcanary-gui; do
        [[ -f "$SYSTEM_BIN/$f" ]] && _stray_system_bins+=("$f")
    done
    if [[ ${#_stray_system_bins[@]} -gt 0 ]]; then
        run_root cleanup-bins
        for f in "${_stray_system_bins[@]}"; do
            echo "  removed:   $SYSTEM_BIN/$f (superseded by user install)"
        done
        _removed_system=true
    fi
    MAN_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/man/man1"
    mkdir -p "$MAN_DIR"
    sed "s/@VERSION@/$_ver/" "$REPO_DIR/man/archcanary.1" > "$MAN_DIR/archcanary.1"
    chmod 644 "$MAN_DIR/archcanary.1"
    echo "  installed: $MAN_DIR/archcanary.1"
    COMPLETION_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
    mkdir -p "$COMPLETION_DIR"
    install -m 644 "$REPO_DIR/configs/archcanary-completion.bash" "$COMPLETION_DIR/archcanary"
    ln -sf archcanary "$COMPLETION_DIR/canary"
    echo "  installed: $COMPLETION_DIR/{archcanary,canary}"
fi

# Install desktop entry
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$DESKTOP_DIR"
cp "$REPO_DIR/configs/archcanary.desktop" "$DESKTOP_DIR/archcanary.desktop"
echo "  installed: $DESKTOP_DIR/archcanary.desktop"

# Seed config dir (only if files don't already exist)
for f in package_list.txt malicious_npm_packages.txt; do
    if [[ ! -f "$CONFIG_DIR/$f" ]]; then
        cp "$REPO_DIR/lists/$f" "$CONFIG_DIR/$f"
        echo "  seeded:    $CONFIG_DIR/$f"
    else
        echo "  kept:      $CONFIG_DIR/$f (already exists)"
    fi
done

# Seed paru's PreBuildCommand hook — only when paru is actually installed.
# Never touches an existing PreBuildCommand line, ours or the user's own,
# at any version — same "never overwrite" rule as yay's init.lua above.
if command -v paru >/dev/null 2>&1; then
    PARU_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/paru"
    PARU_CONF="$PARU_CONFIG_DIR/paru.conf"
    mkdir -p "$PARU_CONFIG_DIR"
    if [[ -f "$PARU_CONF" ]] && grep -qE '^[[:space:]]*PreBuildCommand[[:space:]]*=' "$PARU_CONF" 2>/dev/null; then
        echo "  kept:      $PARU_CONF (PreBuildCommand already set — see docs/my-setup.md, \"paru integration\" to update by hand)"
    else
        [[ -s "$PARU_CONF" ]] && printf '\n' >> "$PARU_CONF"
        cat "$REPO_DIR/configs/paru-hook.conf" >> "$PARU_CONF"
        echo "  seeded:    $PARU_CONF (PreBuildCommand hook appended)"
    fi
fi

# The DKMS allowlist is a single system-wide file at /etc/archcanary/
# (the kmod audit only runs as root). It is seeded by --system below, not here.

if $SYSTEM; then
    echo
    echo "Installing system components (requires root)..."

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

    run_root install-components "$REPO_DIR" "$_ver" "$CONFIG_DIR"

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
    # The source unit uses %h/.local/bin (user install default). For a system
    # install the binary lands in $SYSTEM_BIN, so patch the installed copy.
    if $SYSTEM; then
        sed -i "s|%h/.local/bin/archcanary|$SYSTEM_BIN/archcanary|g" \
            "$USER_UNITS/archcanary-user.service"
    fi
    systemctl --user daemon-reload 2>/dev/null || true
    echo "  installed: $USER_UNITS/archcanary-user.{service,timer} + notify.{path,service} (not enabled — see below)"

    echo
    echo "Root-requiring checks are also available in the GUI via pkexec."
    echo "Automated scan: weekly + on boot + after each pacman transaction (see docs/systemd.md)."
    echo
    echo "Enable the automated system scan (runs as root — weekly + on boot + after pacman):"
    echo "  sudo systemctl enable --now archcanary.timer archcanary.path"
    echo
    echo "Enable the user-scope scan and result notifier (run as your user):"
    echo "  systemctl --user enable --now archcanary-user.timer archcanary-notify.path"
fi

echo
echo "Done. Run: archcanary --refresh --full"

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
