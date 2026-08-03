#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
MAIN_SCRIPT=""

for candidate in \
    "$SCRIPT_DIR/archcanary.sh" \
    "$(command -v archcanary 2>/dev/null || true)" \
    "/usr/lib/archcanary/archcanary.sh"; do
    [[ -n "${candidate:-}" && -x "$candidate" ]] && { MAIN_SCRIPT="$candidate"; break; }
done

if [[ -z "$MAIN_SCRIPT" ]]; then
    yad --image=dialog-error \
        --title="Archcanary" \
        --window-icon=security-high --center \
        --text="<b>archcanary not found.</b>\n\nRun <tt>./install.sh</tt> first." \
        --width=400
    exit 1
fi

# --no-gui: bypass yad, run a full scan in the terminal with structured output.
if [[ "${1:-}" == "--no-gui" ]]; then
    export ARCHCANARY_FROM_GUI=1
    exec "$MAIN_SCRIPT" --full --no-notify "${@:2}"
fi

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: archcanary-gui [--no-gui [OPTIONS]]"
    echo
    echo "Without arguments: open the interactive GUI (yad). Run as your regular user."
    echo "Root-requiring checks are elevated via pkexec (polkit) — do not use sudo."
    echo
    echo "  --no-gui [OPTIONS]  Skip the GUI; run a full terminal scan instead."
    echo "                      Passes --full --no-notify plus any extra OPTIONS to archcanary."
    echo "                      Run with sudo to include root-requiring checks:"
    echo "                        sudo archcanary-gui --no-gui --refresh --full"
    echo
    echo "  --help, -h          Show this help"
    echo
    echo "All other flags (--refresh, --full, etc.) are archcanary flags"
    echo "and are only meaningful after --no-gui. Run 'archcanary --help' for the full list."
    exit 0
fi

if [[ $EUID -eq 0 ]]; then
    echo "ERROR: do not run archcanary-gui as root or with sudo." >&2
    echo "Run it as your regular user — root checks are handled via pkexec (polkit)." >&2
    exit 1
fi

ROOT_HELPER="/usr/lib/archcanary/root-helper"
PKEXEC="$(command -v pkexec 2>/dev/null || true)"
HAS_ROOT=false
[[ -n "$PKEXEC" && -x "$ROOT_HELPER" ]] && HAS_ROOT=true

TRAUR="$(command -v traur 2>/dev/null || true)"
HAS_TRAUR=false
[[ -n "$TRAUR" ]] && HAS_TRAUR=true

LYNIS="$(command -v lynis 2>/dev/null || true)"
HAS_LYNIS=false
[[ -n "$LYNIS" ]] && HAS_LYNIS=true

HAS_AUDITD=false
command -v auditctl &>/dev/null && HAS_AUDITD=true

AUR_HELPER="yay"
command -v yay  &>/dev/null || { command -v paru &>/dev/null && AUR_HELPER="paru"; } || AUR_HELPER="pacman"
_SHOW_OUTPUT_INFECTED_PKGS=""
_SHOW_OUTPUT_ALLOWLIST_HINT=""

# True once the package list has been refreshed this session.
# The first run of the full scan (idx 0) auto-adds --refresh and sets this.
REFRESHED=false

# Read once at startup so build_list_args() doesn't need to re-grep the file
# on every menu redraw; scan_settings() updates this in place after Save.
# Same file/key archcanary.sh itself reads (~/.config/archcanary/env,
# AUR_AUDIT_ENABLE) — this is purely a display cache, not a second source
# of truth.
AUR_AUDIT_ENABLE_GUI=true
grep -qiE '^AUR_AUDIT_ENABLE=false' "${XDG_CONFIG_HOME:-$HOME/.config}/archcanary/env" 2>/dev/null && AUR_AUDIT_ENABLE_GUI=false

# Remembered scan-log save directory (show_output()'s Save button) — same
# file, same "display cache, updated in place after Save" rule as above.
GUI_LOG_SAVE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/archcanary"
_remembered_dir="$(grep -oP '^GUI_LOG_SAVE_DIR=\K.*' "${XDG_CONFIG_HOME:-$HOME/.config}/archcanary/env" 2>/dev/null | tail -1)" || true
if [[ -n "$_remembered_dir" && -d "$_remembered_dir" ]]; then
    GUI_LOG_SAVE_DIR="$_remembered_dir"
fi
unset _remembered_dir

# Rewrites ~/.config/archcanary/env from the two known in-memory settings
# (AUR_AUDIT_ENABLE_GUI, GUI_LOG_SAVE_DIR) — shared by scan_settings() and
# show_output()'s Save button so neither one clobbers the other's line.
# grep-only file, never sourced — see the security note above scan_settings().
_write_gui_env() {
    local cfg_dir="${XDG_CONFIG_HOME:-$HOME/.config}/archcanary"
    mkdir -p "$cfg_dir"
    {
        printf '# archcanary settings — managed by archcanary-gui\n'
        $AUR_AUDIT_ENABLE_GUI || printf 'AUR_AUDIT_ENABLE=false\n'
        printf 'GUI_LOG_SAVE_DIR=%s\n' "$GUI_LOG_SAVE_DIR"
    } > "$cfg_dir/env"
}

# Action data — order here is the canonical index used by run_action
LABELS=(
    "Full scan"                 # 0  root
    "Systemd persistence"       # 1
    "npm cache"                 # 2
    "bun cache"                 # 3
    "yarn cache"                # 4
    "pnpm cache"                # 5
    "PKGBUILD / .install files" # 6
    "ld.so.preload injection"   # 7
    "XDG autostart + shell RCs" # 8
    "eBPF rootkit traces"       # 9  root
    "eBPF programs – bpftool"   # 10 root
    "Kernel modules"            # 11 root
    "Manage allowlists"         # 12
    "Trust scan (traur)"        # 13
    "Edit config"               # 14
    "Lynis hardening report"   # 15
    "Run Lynis audit"          # 16  root
    "Pacman integrity"         # 17
    "About"                    # 18
    "Scan settings"            # 19
)

FLAGS=(
    "--full --no-notify --no-summary"
    "--check-systemd --no-notify --no-summary"
    "--check-npm-cache --no-notify --no-summary"
    "--check-bun-cache --no-notify --no-summary"
    "--check-yarn-cache --no-notify --no-summary"
    "--check-pnpm-cache --no-notify --no-summary"
    "--check-pkgbuild --no-notify --no-summary"
    "--check-ldso --no-notify --no-summary"
    "--check-autostart --no-notify --no-summary"
    "--check-ebpf --no-summary"
    "--check-bpftool --no-summary"
    "--check-kmod --no-summary"
    "__manage_allowlists__"
    "__traur__"
    "__edit_config__"
    "--check-lynis --no-notify --no-summary"
    "--run-lynis"
    "--check-pkginteg --no-notify --no-summary"
    "__about__"
    "__scan_settings__"
)

NEEDS_ROOT=(
    true false false false false false false false false
    true true true
    false false false
    true
    true
    true
    false
    false
)

# Per-session status for each check index.
# Indices without a meaningful pass/fail (dkms, dialogs) stay blank.
declare -A STATUS
for _i in "${!LABELS[@]}"; do STATUS[$_i]="  ?"; done
STATUS[0]="   "   # Full scan — blank until first run
STATUS[12]="   "  # Manage allowlists — config dialog, no scan verdict
STATUS[13]="   "  # traur — opens its own output window, no verdict here
STATUS[14]="   "  # Edit config — config dialog, no scan verdict
STATUS[15]="   "  # Lynis hardening report — informational, no pass/fail verdict
STATUS[18]="   "  # About — no scan verdict
STATUS[19]="   "  # Scan settings — config dialog, no scan verdict
unset _i

# Derive full-scan status (row 0) from whichever individual checks have results.
# Used when the scan window is closed before completion.
_infer_full_status() {
    local worst=0
    for i in 1 2 3 4 5 6 7 8 9 10 11; do
        case "${STATUS[$i]:-}" in
            *"❌"*) worst=2; break ;;
            *"⚠"*)  [[ $worst -lt 1 ]] && worst=1 ;;
        esac
    done
    _update_status 0 "$worst"
}

_update_status() {
    local idx=$1 code=$2
    [[ $idx -eq 15 ]] && return  # Lynis hardening report — informational, stays blank
    case $code in
        0) STATUS[$idx]=" ✅" ;;
        1) STATUS[$idx]=" ⚠ " ;;
        *) STATUS[$idx]=" ❌" ;;
    esac
}

# Map each GUI check row to its section number in the scan output ("--- [N] ---").
declare -A _SCAN_TAG=(
    [1]='3'  [2]='5'  [3]='6'  [4]='6b' [5]='6c'
    [6]='7'  [7]='9'  [8]='10' [9]='4'  [10]='8' [11]='11'
    [15]='12'
)

# After a full scan (idx 0), set each check row from ITS OWN section in the
# output, so a single finding marks only the check that found it — not the
# whole list. $1 = overall exit code (fallback), $2 = scan output file.
_propagate_full_scan() {
    local code=$1 out="${2:-}" i tag block
    for i in 1 2 3 4 5 6 7 8 9 10 11; do
        tag="${_SCAN_TAG[$i]:-}"
        block=""
        [[ -n "$out" && -r "$out" && -n "$tag" ]] && block=$(awk -v t="$tag" '
            $0 ~ ("^--- \\[" t "\\] ") { grab=1; next }
            grab && /^--- \[/ { exit }
            grab { print }
        ' "$out")
        if [[ -n "$block" ]]; then
            if grep -qE 'INFECTED|WARNING' <<<"$block"; then
                STATUS[$i]=" ❌"
            elif grep -qE 'Skipped|needs root|Cannot enumerate' <<<"$block"; then
                STATUS[$i]="  ?"
            else
                STATUS[$i]=" ✅"
            fi
        else
            _update_status "$i" "$code"   # section not found → fall back to overall code
        fi
    done
}

_show_infected_dialog() {
    local pkgs="${1:-}" allowlist_hint="${2:-}"
    local step1
    if [[ -n "$pkgs" ]]; then
        step1="Remove the package(s):\n      <tt>${AUR_HELPER} -R ${pkgs}</tt>"
    elif [[ -n "$allowlist_hint" ]]; then
        step1="Review the flagged ${allowlist_hint} finding(s) in the scan output\n      above. Known-good and not an AUR package? Allowlist it instead of\n      removing it: <i>Manage allowlists</i> (Settings menu)."
    else
        step1="Review and remove/disable the flagged artifact(s) shown in the\n      scan output (systemd unit, eBPF program, autostart entry, etc.)."
    fi
    yad --image=dialog-error \
        --title="Infected — Archcanary" \
        --window-icon=security-high --center \
        --width=520 \
        --text="<b>Infected or compromised indicators detected.</b>\n\n<b>1.</b>  ${step1}\n\n<b>2.</b>  Check persistence — run <i>Systemd persistence</i> and\n      <i>XDG autostart + shell RCs</i> from this menu.\n\n<b>3.</b>  Rotate credentials: SSH keys, GitHub PATs, Discord\n      tokens, npm tokens, browser sessions.\n\nSee README → <i>What to Do If Infected</i>" \
        --button="OK:0" 2>/dev/null || true
}

# Extract infected package names from scan output (lines: "  - pkgname (installed: ...)").
# Scoped to section [1] "Currently installed foreign packages" only — other checks
# (systemd, ebpf, autostart, etc.) also emit "  - " lines via print_list, but those
# aren't AUR package names and must never be fed to `yay -R`.
_extract_infected_pkgs() {
    awk '
        /^--- \[1\] / { grab=1; next }
        grab && /^--- \[/ { exit }
        grab { print }
    ' "$1" 2>/dev/null | grep -oP '^  - \K\S+' | head -20 | tr '\n' ' ' | sed 's/ $//' || true
}

# Names the check (e.g. "systemd") if its section reported a WARNING that the
# allowlist can actually silence — used by _show_infected_dialog to point at
# "Manage allowlists" instead of the generic "review the artifact" wording.
# Each section's match pattern is scoped to ONLY its allowlist-gated warning
# text — systemd's "found" list is entirely allowlist-gated so any WARNING
# there qualifies, but bpftool and DKMS each also emit WARNINGs with no
# allowlist escape hatch at all (bpftool: stealth program types, suspicious
# kprobes, XDP/TC network attachments; DKMS: lsmod modules untraceable to
# pacman/DKMS) — matching generic "WARNING" there would point the user at a
# fix that doesn't apply to their finding. Add a "tag:name:pattern" entry here
# when a new check gets a real allowlist; pattern must be unique to that
# check's allowlist-gated branch, not shared with its unconditional WARNINGs.
_allowlistable_finding_present() {
    local out="$1" pair tag rest desc pattern
    for pair in "3:systemd:WARNING" "8:bpftool:unknown process" "10:Autostart:suspicious autostart entry" "11:DKMS:untracked source"; do
        tag="${pair%%:*}"
        rest="${pair#*:}"
        desc="${rest%%:*}"
        pattern="${rest#*:}"
        if awk -v t="$tag" '
            $0 ~ ("^--- \\[" t "\\] ") { grab=1; next }
            grab && /^--- \[/ { exit }
            grab { print }
        ' "$out" 2>/dev/null | grep -q "$pattern"; then
            printf '%s\n' "$desc"
            return
        fi
    done
}

# Generic root-owned config-file editor: view/edit via yad text-info, write
# back via pkexec. Shared by every allowlist editor (DKMS, systemd, bpftool,
# ...) so adding a new allowlist never means copy-pasting this dialog again.
_edit_conf_file() {
    local title="$1" cfg="$2"
    if [[ ! -f "$cfg" ]]; then
        yad --image=dialog-warning \
            --title="$title — Archcanary" \
            --window-icon=security-high --center \
            --text="<b>$cfg</b> does not exist.\n\nRun <tt>./install.sh --system</tt> first to create it." \
            --width=440 2>/dev/null || true
        return
    fi
    local tmpout
    tmpout="$(mktemp /tmp/archcanary-XXXXXX.txt)"
    if yad --text-info \
        --title="$title (system) — Archcanary" \
        --window-icon=security-high --center \
        --filename="$cfg" \
        --width=640 --height=380 \
        --fontname="Monospace 10" \
        --editable \
        --button="Save (root):0" \
        --button="Cancel:1" \
        > "$tmpout" 2>/dev/null; then
        # Write back to /etc as root — pkexec prompts via the polkit agent.
        if [[ -z "$PKEXEC" ]] || ! "$PKEXEC" tee "$cfg" < "$tmpout" >/dev/null 2>&1; then
            yad --image=dialog-error --title="Archcanary" --window-icon=security-high --center \
                --text="Could not save <tt>$cfg</tt>\n(root authorization failed or cancelled)." \
                --width=420 2>/dev/null || true
        fi
    fi
    rm -f "$tmpout"
}

# Picker in front of _edit_conf_file — keeps the main menu at one row no
# matter how many allowlist-backed checks exist. Add a new allowlist here,
# not as another top-level LABELS/FLAGS row.
manage_allowlists() {
    local choice
    choice=$(yad --list \
        --title="Manage Allowlists — Archcanary" \
        --window-icon=security-high --center \
        --width=460 --height=250 \
        --no-headers \
        --column="Allowlist" \
        "DKMS (kernel modules)" \
        "Systemd (persistence check)" \
        "bpftool (eBPF loaders)" \
        "Autostart (XDG persistence check)" \
        --button="Edit:0" --button="Close:1" \
        --print-column=1 2>/dev/null) || return 0
    choice="${choice%|}"
    case "$choice" in
        "DKMS"*)      _edit_conf_file "DKMS Allowlist"      /etc/archcanary/dkms_allowlist.conf ;;
        "Systemd"*)   _edit_conf_file "Systemd Allowlist"   /etc/archcanary/systemd_allowlist.conf ;;
        "bpftool"*)   _edit_conf_file "bpftool Allowlist"   /etc/archcanary/bpftool_allowlist.conf ;;
        "Autostart"*) _edit_conf_file "Autostart Allowlist" /etc/archcanary/autostart_allowlist.conf ;;
    esac
}

# Picker in front of the individual config editors below (audit rules, Lynis
# config, extra malware lists) — same consolidation pattern as
# manage_allowlists(), but each choice still calls its own distinct function
# (different save targets/side-effects: pkexec+restart auditd, plain copy, a
# user-owned file) rather than being forced through one generic editor.
# Skips entries whose tool isn't installed, matching the old row-hiding
# behavior. Add a new config editor here, not as another top-level row.
edit_config() {
    local -a choices=()
    $HAS_AUDITD && choices+=("Audit rules")
    $HAS_LYNIS  && choices+=("Lynis config")
    choices+=("Extra malware lists")
    choices+=("List overlap check")

    local choice
    choice=$(yad --list \
        --title="Edit Config — Archcanary" \
        --window-icon=security-high --center \
        --width=460 --height=220 \
        --no-headers \
        --column="Config" \
        "${choices[@]}" \
        --button="Edit:0" --button="Close:1" \
        --print-column=1 2>/dev/null) || return 0
    choice="${choice%|}"
    case "$choice" in
        "Audit rules")        edit_audit_rules ;;
        "Lynis config")       edit_lynis_config ;;
        "Extra malware lists") extra_lists_manager ;;
        "List overlap check") list_overlap_check ;;
    esac
}

edit_audit_rules() {
    local cfg="/etc/audit/rules.d/30-archcanary.rules"
    local legacy_cfg="/etc/audit/rules.d/30-archcanary.conf"
    local template="/usr/lib/archcanary/audit-rules.conf"
    local tmpin tmpout
    tmpin="$(mktemp /tmp/archcanary-XXXXXX.conf)"
    tmpout="$(mktemp /tmp/archcanary-XXXXXX.conf)"
    if grep -qE '^\s*-[waAbfe]' "$cfg" 2>/dev/null; then
        cp "$cfg" "$tmpin"
    elif grep -qE '^\s*-[waAbfe]' "$legacy_cfg" 2>/dev/null; then
        cp "$legacy_cfg" "$tmpin"
    elif [[ -f "$template" ]]; then
        cp "$template" "$tmpin"
    else
        printf '# No rules found. Run ./install.sh --system to seed the template.\n' > "$tmpin"
    fi
    if yad --text-info \
        --title="Audit Rules — Archcanary" \
        --window-icon=security-high --center \
        --filename="$tmpin" \
        --width=700 --height=520 \
        --fontname="Monospace 10" \
        --editable \
        --button="Save + restart auditd:0" \
        --button="Cancel:1" \
        > "$tmpout" 2>/dev/null; then
        if [[ ! -s "$tmpout" ]]; then
            yad --image=dialog-error --title="Archcanary" --window-icon=security-high --center \
                --text="Not saved: rules file is empty." \
                --width=420 2>/dev/null || true
        elif [[ -n "$PKEXEC" ]] && "$PKEXEC" tee "$cfg" < "$tmpout" >/dev/null 2>&1; then
            [[ -f "$legacy_cfg" ]] && "$PKEXEC" rm -f "$legacy_cfg" 2>/dev/null || true
            "$PKEXEC" systemctl restart auditd 2>/dev/null || true
        else
            yad --image=dialog-error --title="Archcanary" --window-icon=security-high --center \
                --text="Could not save <tt>$cfg</tt>\n(root authorization failed or cancelled)." \
                --width=420 2>/dev/null || true
        fi
    fi
    rm -f "$tmpin" "$tmpout"
}

edit_lynis_config() {
    local cfg="/etc/lynis/custom.prf"
    local template="/usr/lib/archcanary/lynis-custom.prf"
    local tmpout
    tmpout="$(mktemp /tmp/archcanary-XXXXXX.prf)"
    if [[ -f "$cfg" ]]; then
        cp "$cfg" "$tmpout"
    elif [[ -f "$template" ]]; then
        cp "$template" "$tmpout"
    else
        printf '# Lynis custom profile\n# skip-test=<TEST-ID>\n' > "$tmpout"
    fi
    if yad --text-info \
        --title="Lynis Config — Archcanary" \
        --window-icon=security-high --center \
        --filename="$tmpout" \
        --width=700 --height=520 \
        --fontname="Monospace 10" \
        --editable \
        --button="Save:0" \
        --button="Cancel:1" \
        > "$tmpout.new" 2>/dev/null; then
        if [[ -n "$PKEXEC" ]] && "$PKEXEC" tee "$cfg" < "$tmpout.new" >/dev/null 2>&1; then
            true
        else
            yad --image=dialog-error --title="Archcanary" --window-icon=security-high --center \
                --text="Could not save <tt>$cfg</tt>\n(root authorization failed or cancelled)." \
                --width=420 2>/dev/null || true
        fi
    fi
    rm -f "$tmpout" "$tmpout.new"
}

show_about() {
    local version repo="https://github.com/musqz/archcanary"
    version=$("$MAIN_SCRIPT" --version 2>/dev/null | grep -oP '(?<=Archcanary v).+' || echo "unknown")
    yad --image=dialog-information \
        --title="About Archcanary" \
        --window-icon=security-high --center \
        --width=440 --height=240 \
        --button="Close":0 \
        --text="<b>Archcanary</b>  v${version}

Security scanner for Arch Linux — detects malicious packages,
suspicious systemd units, eBPF backdoors, rogue kernel modules,
and more.

Source: <a href=\"${repo}\">${repo}</a>" \
        2>/dev/null || true
}

# Run a command, stream output live to a text-info window, return its exit code.
show_output() {
    local title="$1" scan_exit=0
    shift
    local tmpout fifo yad_pid
    tmpout="$(mktemp /tmp/archcanary-XXXXXX.txt)"
    fifo="$(mktemp -u /tmp/archcanary-fifo-XXXXXX)"
    mkfifo "$fifo"

    yad --text-info \
        --title="$title — Archcanary" \
        --window-icon=security-high --center \
        --width=1000 --height=660 \
        --fontname="Monospace 10" \
        --wrap --tail --editable \
        --button="Save:0" \
        --button="Close:1" \
        < "$fifo" 2>/dev/null &
    yad_pid=$!
    exec 8>"$fifo"
    rm -f "$fifo"

    "$@" > "$tmpout" 2>&1 &
    local scan_pid=$!
    tail -f -n +1 "$tmpout" >&8 2>/dev/null &
    local tail_pid=$!
    wait "$scan_pid" && scan_exit=0 || scan_exit=$?
    sleep 0.3
    kill "$tail_pid" 2>/dev/null || true
    wait "$tail_pid" 2>/dev/null || true
    printf '\n─── done ───\n' >&8 || true

    local yad_ret=0
    wait "$yad_pid" 2>/dev/null || yad_ret=$?
    exec 8>&-

    # Save:0 — file picker defaults to the remembered directory (or
    # archcanary.sh's own --log-file default the first time), with the same
    # auto-timestamped name a CLI run would use. Picking a different
    # directory updates GUI_LOG_SAVE_DIR for next time.
    if [[ "$yad_ret" -eq 0 ]]; then
        mkdir -p "$GUI_LOG_SAVE_DIR"
        local suggested chosen
        suggested="$GUI_LOG_SAVE_DIR/aur-check-$(date +%Y%m%d-%H%M%S).log"
        chosen=$(yad --file --save --confirm-overwrite \
            --title="Save Scan Log — Archcanary" \
            --window-icon=security-high --center \
            --filename="$suggested" 2>/dev/null) || chosen=""
        if [[ -n "$chosen" ]]; then
            cp "$tmpout" "$chosen"
            GUI_LOG_SAVE_DIR="$(dirname "$chosen")"
            _write_gui_env
            yad --image=dialog-information --title="Archcanary" --window-icon=security-high --center \
                --text="Scan log saved to:\n<tt>${chosen}</tt>" \
                --button="OK:0" 2>/dev/null || true
        fi
    fi

    _SHOW_OUTPUT_INFECTED_PKGS="$(_extract_infected_pkgs "$tmpout")"
    _SHOW_OUTPUT_ALLOWLIST_HINT="$(_allowlistable_finding_present "$tmpout")"
    rm -f "$tmpout"
    return $scan_exit
}

extra_lists_manager() {
    local conf="${XDG_CONFIG_HOME:-$HOME/.config}/archcanary/extra_lists.conf"
    mkdir -p "$(dirname "$conf")"

    # Seed template if missing (matches what archcanary itself creates)
    if [[ ! -f "$conf" ]]; then
        cat > "$conf" <<'CONF'
# archcanary extra package lists
# One entry per line: a file path or an https:// raw URL.
# Lines starting with # are ignored.
# URL entries are re-fetched when you run --refresh.
#
# Examples:
#   /home/user/my_custom_list.txt
#   https://raw.githubusercontent.com/lenucksi/archcanary/main/package_list.txt
CONF
    fi

    local tmpout
    tmpout="$(mktemp /tmp/archcanary-XXXXXX.txt)"
    if yad --text-info \
        --title="Extra Malware Lists — Archcanary" \
        --window-icon=security-high --center \
        --width=600 --height=360 \
        --fontname="Monospace 10" \
        --editable \
        --filename="$conf" \
        --button="Save:0" \
        --button="Cancel:1" \
        > "$tmpout" 2>/dev/null; then
        cp "$tmpout" "$conf"
        local n
        n=$(grep -c '^[^#[:space:]]' "$conf" 2>/dev/null || true)
        yad --image=dialog-information \
            --title="Extra Malware Lists — Archcanary" \
            --window-icon=security-high --center \
            --text="Saved to <tt>$conf</tt>\n$n active entries.\n\nRun <b>Full scan</b> to fetch any new URLs." \
            --width=420 \
            --button="OK:0" 2>/dev/null || true
    fi
    rm -f "$tmpout"
}

# Persisted true/false settings for archcanary.sh itself, written to
# ~/.config/archcanary/env. archcanary.sh reads this file as plain data
# (grep) — it is NEVER sourced as shell, since the pkexec-elevated root
# scan resolves this same path under the invoking user's own $HOME (see
# lib/archcanary-root-helper), and sourcing a user-writable file as root
# would be a local privilege escalation. Top-level menu row (not nested
# under Edit config) so the current state is visible without opening
# anything — see build_list_args()'s "aur-audit sync: ON/OFF" suffix.
scan_settings() {
    local cfg_dir="${XDG_CONFIG_HOME:-$HOME/.config}/archcanary"
    local env_file="$cfg_dir/env"
    mkdir -p "$cfg_dir"

    local cur="TRUE"
    $AUR_AUDIT_ENABLE_GUI || cur="FALSE"

    local result
    result=$(yad --form \
        --title="Scan Settings — Archcanary" \
        --window-icon=security-high --center \
        --width=480 \
        --field="Fetch aur-audit.wtako.net black/red feed on --refresh:CHK" "$cur" \
        --button="Save:0" --button="Cancel:1" \
        2>/dev/null) || return 0

    [[ "$result" == FALSE* ]] && AUR_AUDIT_ENABLE_GUI=false || AUR_AUDIT_ENABLE_GUI=true
    _write_gui_env

    yad --image=dialog-information \
        --title="Archcanary" \
        --window-icon=security-high --center \
        --text="Saved to\n<tt>$env_file</tt>" \
        --width=380 \
        --button="OK:0" 2>/dev/null || true
}

# Runs --check-list-overlap and shows just its own report section (not the
# rest of a default scan) in a read-only window. Fast/local (no network), so
# run synchronously rather than through show_output()'s live-tail machinery.
list_overlap_check() {
    local raw body count
    raw="$("$MAIN_SCRIPT" --check-list-overlap --no-notify --no-summary 2>&1)"
    body="$(awk '/^--- \[14\] /{f=1; next} /^--- \[/{f=0} /^===/{f=0} f' <<< "$raw")"
    # || true: grep exits non-zero when there are no duplicates (no "NOTE:"
    # line to match) — under set -e + pipefail that would otherwise kill the
    # whole GUI instead of just showing "nothing found".
    count="$(grep -oP '(?<=NOTE: )[0-9]+' <<< "$body" | head -1 || true)"
    count="${count:-0}"

    local tmpout
    tmpout="$(mktemp /tmp/archcanary-XXXXXX.txt)"
    printf '%s\n' "$body" > "$tmpout"

    yad --text-info \
        --title="List Overlap Check (${count} found) — Archcanary" \
        --window-icon=security-high --center \
        --width=760 --height=460 \
        --fontname="Monospace 10" \
        --wrap \
        --filename="$tmpout" \
        --button="Close:0" 2>/dev/null || true
    rm -f "$tmpout"
}

run_action() {
    local idx="$1"
    local label="${LABELS[$idx]}"
    local flags="${FLAGS[$idx]}"
    local needs_root="${NEEDS_ROOT[$idx]}"

    if [[ "$idx" -eq 15 || "$idx" -eq 16 ]] && ! $HAS_LYNIS; then
        yad --image=dialog-information \
            --title="Lynis — Archcanary" \
            --window-icon=security-high --center \
            --text="<b>Lynis</b> is not installed.\n\nInstall from official repos:\n  <tt>sudo pacman -S lynis</tt>" \
            --width=420 \
            --button="OK:0" 2>/dev/null || true
        return
    fi

    if [[ "$flags" == "__manage_allowlists__" ]]; then
        manage_allowlists
        return
    fi

    if [[ "$flags" == "__edit_config__" ]]; then
        edit_config
        return
    fi

    if [[ "$flags" == "__about__" ]]; then
        show_about
        return
    fi

    if [[ "$flags" == "__scan_settings__" ]]; then
        scan_settings
        return
    fi

    if [[ "$flags" == "__traur__" ]]; then
        if ! $HAS_TRAUR; then
            yad --image=dialog-warning \
                --title="traur not installed" \
                --window-icon=security-high --center \
                --text="<b>traur</b> is not installed.\n\nInstall it from AUR:\n  <tt>${AUR_HELPER} -S traur</tt>" \
                --width=360 2>/dev/null || true
            return
        fi
        local scan_exit=0
        show_output "Trust scan" "$TRAUR" scan && scan_exit=0 || scan_exit=$?
        _update_status "$idx" "$scan_exit"
        return
    fi

    read -ra flag_arr <<< "$flags"

    # Full scan (idx 0) always refreshes the package list on the first run of
    # the session. Subsequent runs skip the network fetch for speed.
    if [[ "$idx" -eq 0 ]] && ! $REFRESHED; then
        flag_arr=(--refresh "${flag_arr[@]}")
        REFRESHED=true
    fi

    # Full scan (idx 0) is a bundle where most checks don't need root — if root
    # isn't available, fall through to the plain non-root path below instead of
    # refusing to run at all. archcanary.sh's own --full already skips the
    # root-only checks and reports INCOMPLETE in that case (same as the CLI),
    # so this just lets the GUI do what the CLI already does. A single
    # root-only check (eBPF, bpftool, kmod, Lynis, pacman integrity) has no
    # meaningful non-root version, so those still block below.
    if [[ "$needs_root" == "true" ]] && ! $HAS_ROOT && [[ "$idx" -ne 0 ]]; then
        # Two independent causes were previously conflated into one dialog
        # that only ever suggested the install.sh fix — if pkexec itself
        # isn't installed (polkit is optional), re-running install.sh --system
        # does nothing, and the same dialog kept reappearing (reported live).
        if [[ -z "$PKEXEC" ]]; then
            yad --image=dialog-warning \
                --title="polkit not installed" \
                --window-icon=security-high --center \
                --text="This check needs <b>pkexec</b>, which comes from the <b>polkit</b> package (not installed).\n\nRun:\n  <b>sudo pacman -S polkit</b>\n\nthen try again." \
                --width=440 2>/dev/null || true
        else
            yad --image=dialog-warning \
                --title="Root helper not installed" \
                --window-icon=security-high --center \
                --text="The system root helper is not installed.\n\nRun:\n  <b>./install.sh --system</b>\n\nto enable root-requiring checks." \
                --width=440 2>/dev/null || true
        fi
        return
    fi

    if [[ "$needs_root" == "true" ]] && $HAS_ROOT; then
        local tmpout pkexec_exit=0 pkexec_done=false
        tmpout="$(mktemp /tmp/archcanary-XXXXXX.txt)"

        # Open the output window immediately — no blank screen after clicking Run.
        # Deliberately NOT --center: this window's focus behavior around the
        # polkit dialog is fragile (see the xdotool loop + sleep below) and has
        # regressed ~5 times in history; --center is an unvetted variable in
        # that interaction on click-to-focus WMs (Openbox) and stays off here
        # even though every other dialog in this file is centered.
        local fifo
        fifo="$(mktemp -u /tmp/archcanary-fifo-XXXXXX)"
        mkfifo "$fifo"
        yad --text-info \
            --title="$label — Archcanary" \
            --window-icon=security-high \
            --width=1000 --height=660 \
            --fontname="Monospace 10" \
            --wrap --tail --editable \
            --button=Close:0 \
            < "$fifo" 2>/dev/null &
        local yad_pid=$!
        exec 8>"$fifo"
        rm -f "$fifo"

        if [[ "$idx" -eq 0 ]]; then
            printf 'Authenticate in the polkit dialog to continue...\n  After authenticating, please wait — the first scan fetches package lists from the network.\n\n' >&8 || true
        else
            printf 'Authenticate in the polkit dialog to continue...\n\n' >&8 || true
        fi

        # Let yad render and settle so the polkit dialog opens as the newest
        # (and thus focused) window — without this delay, yad may steal focus
        # back from polkit on click-to-focus WMs like Openbox.
        sleep 0.4

        # On Openbox click-to-focus, new windows don't auto-focus: poll for
        # the polkit dialog and activate it as soon as it appears.
        local _xdotool_pid=""
        if command -v xdotool &>/dev/null; then
            { while true; do
                xdotool search --name "Authenticate" windowactivate 2>/dev/null && break
                sleep 0.1
              done; } &
            _xdotool_pid=$!
        fi

        "$PKEXEC" "$ROOT_HELPER" "${flag_arr[@]}" > "$tmpout" 2>&1 &
        local pkexec_pid=$!

        # Wait for auth to succeed (check produces first output) or pkexec to exit
        while [[ ! -s "$tmpout" ]] && kill -0 "$pkexec_pid" 2>/dev/null; do
            sleep 0.1
        done

        printf '\n============================================================\n\n' >&8 2>/dev/null || true
        if [[ "$idx" -eq 16 ]]; then
            printf 'Running lynis audit system, please wait (1-2 minutes)...\n\n' >&8 || true
        fi
        if [[ "$idx" -eq 19 ]]; then
            printf 'Verifying installed file checksums — this may take 20-30 seconds...\n\n' >&8 || true
        fi

        if [[ -n "$_xdotool_pid" ]]; then
            kill "$_xdotool_pid" 2>/dev/null || true
            wait "$_xdotool_pid" 2>/dev/null || true
        fi

        # If pkexec already exited (fast check), reap it now so all writes are
        # guaranteed flushed to tmpout before we inspect the file.
        if ! kill -0 "$pkexec_pid" 2>/dev/null; then
            wait "$pkexec_pid" 2>/dev/null || pkexec_exit=$?
            pkexec_done=true
        fi

        if [[ ! -s "$tmpout" ]]; then
            # Auth cancelled or failed — close the output window before the error dialog.
            exec 8>&-
            kill "$yad_pid" 2>/dev/null || true
            wait "$yad_pid" 2>/dev/null || true
            rm -f "$tmpout"
            [[ $pkexec_exit -ne 0 && $pkexec_exit -ne 126 ]] && \
                yad --image=dialog-error --title="Archcanary" \
                    --window-icon=security-high --center \
                    --text="pkexec failed (exit $pkexec_exit)" \
                    --width=360 2>/dev/null || true
            if [[ "$idx" -eq 0 ]]; then _infer_full_status; fi
            return 0
        fi

        # tail -f (no --pid) avoids the race where tail exits as pkexec exits,
        # dropping content that was written just before pkexec closed its stdout.
        tail -f -n +1 "$tmpout" >&8 2>/dev/null &
        local tail_pid=$!
        local scan_exit=$pkexec_exit
        if ! $pkexec_done; then
            wait "$pkexec_pid" 2>/dev/null || scan_exit=$?
        fi
        # pkexec done — give tail ~300 ms to flush any final bytes to the FIFO,
        # then stop it before writing the sentinel so it doesn't race the marker.
        sleep 0.3
        kill "$tail_pid" 2>/dev/null || true
        wait "$tail_pid" 2>/dev/null || true
        # Guard against SIGPIPE: user may have closed the window while the scan
        # was still running, which closes the FIFO read end before we get here.
        printf '\n─── done ───\n' >&8 || true

        wait "$yad_pid" 2>/dev/null || true
        exec 8>&-
        _update_status "$idx" "$scan_exit"
        if [[ "$idx" -eq 0 ]]; then _propagate_full_scan "$scan_exit" "$tmpout"; fi
        local _inf_pkgs="" _inf_allowlist_hint=""
        if [[ "$scan_exit" -eq 2 ]]; then
            _inf_pkgs="$(_extract_infected_pkgs "$tmpout")"
            _inf_allowlist_hint="$(_allowlistable_finding_present "$tmpout")"
        fi
        rm -f "$tmpout"
        if [[ "$scan_exit" -eq 2 ]]; then _show_infected_dialog "$_inf_pkgs" "$_inf_allowlist_hint"; fi
    else
        local scan_exit=0
        _SHOW_OUTPUT_INFECTED_PKGS=""
        _SHOW_OUTPUT_ALLOWLIST_HINT=""
        show_output "$label" "$MAIN_SCRIPT" "${flag_arr[@]}" && scan_exit=0 || scan_exit=$?
        _update_status "$idx" "$scan_exit"
        if [[ "$idx" -eq 0 ]]; then _propagate_full_scan "$scan_exit"; fi
        if [[ "$scan_exit" -eq 2 ]]; then _show_infected_dialog "$_SHOW_OUTPUT_INFECTED_PKGS" "$_SHOW_OUTPUT_ALLOWLIST_HINT"; fi
    fi
}

# Build two-column display list: [status] [label], with section separators.
# Root items get a 🔐 prefix in column 2; separators have blank status in col 1.
build_list_args() {
    local -n _out=$1
    _sep() {
        local name="$1" dashes='────────────────────────────────'
        _out+=("   " "  ───  ${name}  ${dashes:0:$(( 23 + 15 - ${#name} ))}")
    }
    _row() { local i=$1; local lbl="${2:-${LABELS[$i]}}"; _out+=("${STATUS[$i]}" "$lbl"); }

    _row 0 "🔐  ${LABELS[0]}"

    _sep "Standard checks"
    for i in 1 2 3 4 5 6 7 8; do _row "$i"; done

    _sep "Root checks"
    for i in 9 10 11; do _row "$i" "🔐  ${LABELS[$i]}"; done
    _row 16 "🔐  ${LABELS[16]}"

    _sep "Utilities"
    $HAS_LYNIS   && _row 15 "🔐  ${LABELS[15]}"
    $HAS_TRAUR   && _row 13
    _row 17 "🔐  ${LABELS[17]}"
    _sep "Settings"
    _row 12
    _row 14
    local aa_state="ON"
    $AUR_AUDIT_ENABLE_GUI || aa_state="OFF"
    _row 19 "${LABELS[19]}  (aur-audit sync: ${aa_state})"
    _row 18
}

# Main loop
while true; do
    list_args=()
    build_list_args list_args

    selected=$(yad \
        --list \
        --title="Archcanary" \
        --window-icon=security-high --center \
        --width=440 --height=550 \
        --column="" \
        --column="Action" \
        --no-headers \
        --print-column=2 \
        --button="Run:0" \
        --button="Quit:1" \
        "${list_args[@]}" 2>/dev/null) || break

    selected="${selected%|}"
    [[ -z "$selected" ]] && continue
    [[ "$selected" == *"───"* ]] && continue  # separator row

    selected="${selected#🔐  }"                # strip lock prefix from root items
    selected="${selected%  (aur-audit sync:*}"  # strip Scan settings' state suffix

    for i in "${!LABELS[@]}"; do
        if [[ "${LABELS[$i]}" == "$selected" ]]; then
            run_action "$i"
            break
        fi
    done
done
