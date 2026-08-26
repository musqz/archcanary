#!/usr/bin/env bash
# lib/archcanary-root-install.sh — root-only steps for install.sh's --system
# mode, run via a single `sudo bash .../archcanary-root-install.sh <mode>`
# call per step group. A sudoers config restricted to a command allowlist
# only needs to permit this one script path, not each individual install
# command (install/rm/cp/sed/chmod/systemctl/tee) it used to run directly.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "archcanary-root-install.sh must be run as root (via sudo)." >&2
    exit 1
fi

SYSTEM_BIN="/usr/local/bin"
SYSTEM_LIB="/usr/lib/archcanary"

mode="${1:?usage: archcanary-root-install.sh <install-bins|install-components|cleanup-bins|uninstall-bins|uninstall-components> [args...]}"
shift

case "$mode" in

install-bins)
    REPO_DIR="$1"; VERSION="$2"
    install -m 755 "$REPO_DIR/archcanary.sh"     "$SYSTEM_BIN/archcanary"
    install -m 755 "$REPO_DIR/archcanary-tui.sh" "$SYSTEM_BIN/archcanary-tui"
    sed -i "s/@VERSION@/$VERSION/" "$SYSTEM_BIN/archcanary"
    echo "  installed: $SYSTEM_BIN/archcanary"
    echo "  installed: $SYSTEM_BIN/archcanary-tui"

    install -d -m 755 /usr/share/man/man1
    sed "s/@VERSION@/$VERSION/" "$REPO_DIR/man/archcanary.1" > /usr/share/man/man1/archcanary.1
    chmod 644 /usr/share/man/man1/archcanary.1
    echo "  installed: /usr/share/man/man1/archcanary.1"

    install -d -m 755 /usr/share/bash-completion/completions
    install -m 644 "$REPO_DIR/configs/archcanary-completion.bash" \
        /usr/share/bash-completion/completions/archcanary
    ln -sf archcanary /usr/share/bash-completion/completions/canary
    echo "  installed: /usr/share/bash-completion/completions/{archcanary,canary}"
    ;;

cleanup-bins)
    for f in archcanary archcanary-tui; do
        rm -f "$SYSTEM_BIN/$f"
    done
    ;;

install-components)
    REPO_DIR="$1"; VERSION="$2"; CONFIG_DIR="$3"

    install -d -m 755 "$SYSTEM_LIB"
    cp "$REPO_DIR/archcanary.sh" "$SYSTEM_LIB/archcanary.sh"
    sed -i "s/@VERSION@/$VERSION/" "$SYSTEM_LIB/archcanary.sh"
    chmod 755 "$SYSTEM_LIB/archcanary.sh"
    cp "$REPO_DIR/lib/archcanary-root-helper" "$SYSTEM_LIB/root-helper"
    chown root:root "$SYSTEM_LIB/root-helper"
    chmod 755 "$SYSTEM_LIB/root-helper"
    install -m 644 "$REPO_DIR/configs/lynis-custom.prf" \
        "$SYSTEM_LIB/lynis-custom.prf"
    # yay Lua hook template — read-only reference copy, never installed to
    # ~/.config/yay/init.lua automatically (per-user path, hooks are opt-in).
    install -m 644 "$REPO_DIR/configs/yay-init.lua" \
        "$SYSTEM_LIB/yay-init.lua"
    cp "$REPO_DIR/configs/org.archcanary.policy" /usr/share/polkit-1/actions/
    # Seed the bundled package lists next to the system script so a root scan
    # (system service) finds them — root's $HOME is /root, which is not seeded.
    # Also the fallback every non-root local user's own first-ever run
    # self-heals from (_bundled_list_path's third candidate). Explicit 644:
    # plain `cp` inherits root's umask, which on a restrictive umask (0027)
    # left these unreadable outside root/root's group — breaking that
    # self-heal for every user but root.
    for _list in package_list.txt malicious_npm_packages.txt chaos_rat_packages.txt malicious_russian_spam_packages.txt community_reports.txt; do
        if [[ -f "$REPO_DIR/lists/$_list" ]]; then
            cp "$REPO_DIR/lists/$_list" "$SYSTEM_LIB/$_list"
            chmod 644 "$SYSTEM_LIB/$_list"
        fi
    done

    # DKMS allowlist — single system-wide file (the kmod audit only runs as root).
    # Seed it once (mode 644 so non-root runs can read it), preferring an existing
    # legacy ~/.config copy so prior entries are preserved on upgrade; otherwise a
    # commented template. Never clobber an existing /etc copy.
    install -d -m 755 /etc/archcanary
    if [[ ! -f /etc/archcanary/dkms_allowlist.conf ]]; then
        if [[ -f "$CONFIG_DIR/dkms_allowlist.conf" ]]; then
            install -m 644 "$CONFIG_DIR/dkms_allowlist.conf" /etc/archcanary/dkms_allowlist.conf
        else
            tee /etc/archcanary/dkms_allowlist.conf >/dev/null << 'EOF'
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
            chmod 644 /etc/archcanary/dkms_allowlist.conf
        fi
    fi
    # The per-user allowlist is no longer read — remove the legacy copy to avoid
    # confusion (its entries were migrated to /etc above on first run).
    if [[ -f "$CONFIG_DIR/dkms_allowlist.conf" ]]; then
        rm -f "$CONFIG_DIR/dkms_allowlist.conf"
        echo "  migrated:  ~/.config dkms_allowlist.conf → /etc (per-user copy removed)"
    fi
    # systemd allowlist — same rationale and seeding rules as the DKMS allowlist
    # above (mode 644, never clobber an existing /etc copy).
    if [[ ! -f /etc/archcanary/systemd_allowlist.conf ]]; then
        tee /etc/archcanary/systemd_allowlist.conf >/dev/null << 'EOF'
# systemd units to skip during the systemd persistence check (--check-systemd),
# system-wide allowlist. One unit name per line. Everything after # is a comment.
# Add units that are known-good but not tracked by pacman and not vetted by the
# standard-prefix check (e.g. a self-hosted app installed from an upstream
# binary release rather than a package). A .timer is matched by its OWN name,
# not its target .service — allowlist both if you want to silence both findings.
#
# Example:
# forgejo.service  # self-hosted git, installed from upstream binary release
# forgejo.timer    # only needed if forgejo also ships a persistent timer
EOF
        chmod 644 /etc/archcanary/systemd_allowlist.conf
    fi
    # bpftool allowlist — same rationale and seeding rules as the DKMS/systemd
    # allowlists above (mode 644, never clobber an existing /etc copy).
    if [[ ! -f /etc/archcanary/bpftool_allowlist.conf ]]; then
        tee /etc/archcanary/bpftool_allowlist.conf >/dev/null << 'EOF'
# eBPF loader binaries to skip during the bpftool LSM-loader check
# (--check-bpftool), system-wide allowlist. One binary basename per line.
# Everything after # is a comment.
# Add loaders that are known-good but not pacman-owned (a self-built or
# manually-installed security/monitoring tool that legitimately loads LSM
# eBPF hooks) — matched against the basename of /proc/<pid>/exe.
#
# Example:
# falco  # runtime security monitoring, installed from upstream binary release
EOF
        chmod 644 /etc/archcanary/bpftool_allowlist.conf
    fi
    # autostart allowlist — same rationale and seeding rules as the DKMS/
    # systemd/bpftool allowlists above (mode 644, never clobber an existing
    # /etc copy).
    if [[ ! -f /etc/archcanary/autostart_allowlist.conf ]]; then
        tee /etc/archcanary/autostart_allowlist.conf >/dev/null << 'EOF'
# Names to skip during the XDG autostart check (--check-autostart),
# system-wide allowlist. One entry per line. Everything after # is a
# comment. Covers two separate findings within the same check, each with
# its own matching rule:
#
# 1. .desktop Exec= names that are known-good but can't be resolved via
#    $PATH or a standard system prefix — e.g. a package-private helper
#    binary the non-PATH fallback (search of /usr/lib, /usr/libexec) still
#    can't find, or an AppImage/Flatpak export. Matched against the bare
#    Exec= value exactly as written in the .desktop file (not a resolved
#    path) — usually just a command name.
#
# 2. User systemd service ExecStart= binaries unowned by pacman. Matched
#    against the ExecStart binary's exact, full path (NOT its basename —
#    a basename match would let an unrelated binary sharing that name
#    anywhere on disk slip through undetected). Useful for a package that
#    ships its user unit via /etc/skel (copied into ~/.config/systemd/user/
#    at account creation, so pacman never tracks that specific copy even
#    though the binary itself is a normal pacman-owned file).
#
# Examples:
# zeitgeist-datahub               # desktop activity logging, ships in a non-PATH libdir
# /usr/bin/eos-update-notifier    # EndeavourOS update notifier, user unit ships via /etc/skel
EOF
        chmod 644 /etc/archcanary/autostart_allowlist.conf
    fi

    echo "  installed: $SYSTEM_LIB/archcanary.sh"
    echo "  installed: $SYSTEM_LIB/root-helper"
    echo "  installed: $SYSTEM_LIB/lynis-custom.prf (template for /etc/lynis/custom.prf)"
    echo "  installed: $SYSTEM_LIB/yay-init.lua (template — cp to ~/.config/yay/init.lua yourself to enable, see --doctor)"
    echo "  installed: $SYSTEM_LIB/{package_list,malicious_npm_packages,chaos_rat_packages,malicious_russian_spam_packages,community_reports}.txt"
    echo "  installed: /etc/archcanary/dkms_allowlist.conf (system-wide DKMS allowlist for the root scan)"
    echo "  installed: /etc/archcanary/systemd_allowlist.conf (system-wide systemd allowlist for the persistence check)"
    echo "  installed: /etc/archcanary/bpftool_allowlist.conf (system-wide bpftool allowlist for the eBPF loader check)"
    echo "  installed: /etc/archcanary/autostart_allowlist.conf (system-wide autostart allowlist for the XDG persistence check)"
    echo "  installed: /usr/share/polkit-1/actions/org.archcanary.policy"

    # Seed Lynis custom profile (only if lynis is installed and file not yet present)
    if command -v lynis &>/dev/null; then
        if [[ ! -f /etc/lynis/custom.prf ]]; then
            install -m 644 "$REPO_DIR/configs/lynis-custom.prf" /etc/lynis/custom.prf
            echo "  installed: /etc/lynis/custom.prf (Lynis false-positive suppressions — edit to enable)"
        else
            echo "  kept:      /etc/lynis/custom.prf (already exists)"
        fi
    fi

    # Seed auditd rules when auditd is installed and file is absent or has no rules
    if command -v auditctl &>/dev/null; then
        _audit_cfg=/etc/audit/rules.d/30-archcanary.rules
        install -d -m 755 /etc/audit/rules.d
        # Remove legacy .conf copy that augenrules ignores
        rm -f /etc/audit/rules.d/30-archcanary.conf /etc/audit/rules.d/archcanary.conf
        if ! grep -qE '^\s*-[waAbfe]' "$_audit_cfg" 2>/dev/null; then
            install -m 644 "$REPO_DIR/configs/audit-rules.conf" "$_audit_cfg"
            augenrules --load >/dev/null 2>&1 || true
            echo "  installed: $_audit_cfg (auditd rules — edit with --audit-rules-get/--audit-rules-set)"
        else
            echo "  kept:      $_audit_cfg (already has rules)"
        fi
        unset _audit_cfg
    fi

    # Pre-create the result dir so the user notifier can watch it right away
    # (the scan's StateDirectory= also creates it, but the .path needs it now).
    install -d -m 755 /var/lib/archcanary

    # System scan units (run as root → complete scan)
    cp "$REPO_DIR"/systemd/system/archcanary.service \
       "$REPO_DIR"/systemd/system/archcanary.timer \
       "$REPO_DIR"/systemd/system/archcanary-onchange.service \
       "$REPO_DIR"/systemd/system/archcanary.path \
       "$REPO_DIR"/systemd/system/archcanary-scan-all-homes.service \
       "$REPO_DIR"/systemd/system/archcanary-scan-all-homes.timer \
       /etc/systemd/system/
    systemctl daemon-reload
    echo "  installed: /etc/systemd/system/archcanary.{service,timer,path} + -onchange.service (not enabled — see below)"
    echo "  installed: /etc/systemd/system/archcanary-scan-all-homes.{service,timer} (opt-in, not enabled — see below)"
    ;;

uninstall-bins)
    for f in archcanary archcanary-tui; do
        if [[ -f "$SYSTEM_BIN/$f" ]]; then
            rm -f "$SYSTEM_BIN/$f"
            echo "  removed: $SYSTEM_BIN/$f"
        else
            echo "  not found: $SYSTEM_BIN/$f"
        fi
    done
    rm -f /usr/share/man/man1/archcanary.1
    echo "  removed: /usr/share/man/man1/archcanary.1"
    rm -f /usr/share/bash-completion/completions/archcanary \
          /usr/share/bash-completion/completions/canary
    echo "  removed: /usr/share/bash-completion/completions/{archcanary,canary}"
    ;;

uninstall-components)
    systemctl disable --now archcanary.timer archcanary.path 2>/dev/null || true
    systemctl disable --now archcanary-scan-all-homes.timer 2>/dev/null || true
    rm -f /etc/systemd/system/archcanary.service \
          /etc/systemd/system/archcanary.timer \
          /etc/systemd/system/archcanary-onchange.service \
          /etc/systemd/system/archcanary.path \
          /etc/systemd/system/archcanary-scan-all-homes.service \
          /etc/systemd/system/archcanary-scan-all-homes.timer
    systemctl daemon-reload
    echo "  kept:    /var/lib/archcanary (scan history — remove manually if desired)"
    echo "  removed: systemd units (system scan + user notifier)"

    rm -rf /usr/lib/archcanary
    echo "  removed: /usr/lib/archcanary"
    echo "  kept:    /etc/archcanary (user config — remove manually if desired)"
    rm -f /usr/share/polkit-1/actions/org.archcanary.policy
    echo "  removed: /usr/share/polkit-1/actions/org.archcanary.policy"
    rm -f /etc/audit/rules.d/30-archcanary.rules \
          /etc/audit/rules.d/30-archcanary.conf \
          /etc/audit/rules.d/archcanary.conf
    augenrules --load >/dev/null 2>&1 || true
    echo "  removed: /etc/audit/rules.d/30-archcanary.rules (auditd rules)"
    rm -f /usr/share/lynis/plugins/plugin_archcanary_phase1 \
          /usr/share/lynis/plugins/plugin_archcanary_phase1.sh
    ;;

*)
    echo "archcanary-root-install.sh: unknown mode '$mode'" >&2
    exit 1
    ;;
esac
