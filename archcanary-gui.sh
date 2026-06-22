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
    yad --error \
        --title="Archcanary" \
        --window-icon=security-high \
        --text="<b>archcanary not found.</b>\n\nRun <tt>./install.sh</tt> first." \
        --width=400
    exit 1
fi

# --no-gui: bypass yad, run a full scan in the terminal with structured output.
if [[ "${1:-}" == "--no-gui" ]]; then
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

AURSCAN="$(command -v aurscan 2>/dev/null || true)"
HAS_AURSCAN=false
[[ -n "$AURSCAN" ]] && HAS_AURSCAN=true

LYNIS="$(command -v lynis 2>/dev/null || true)"
HAS_LYNIS=false
[[ -n "$LYNIS" ]] && HAS_LYNIS=true

HAS_AUDITD=false
command -v auditctl &>/dev/null && HAS_AUDITD=true

AUR_HELPER="yay"
command -v yay  &>/dev/null || { command -v paru &>/dev/null && AUR_HELPER="paru"; } || AUR_HELPER="pacman"
_SHOW_OUTPUT_INFECTED_PKGS=""

# True once the package list has been refreshed this session.
# The first run of the full scan (idx 0) auto-adds --refresh and sets this.
REFRESHED=false

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
    "Edit DKMS allowlist"       # 12
    "Trust scan (traur)"        # 13
    "LLM settings (aurscan)"   # 14
    "Extra lists"               # 15
    "Lynis hardening report"   # 16
    "Run Lynis audit"          # 17  root
    "Edit audit rules"         # 18
    "Edit Lynis config"        # 19
    "About"                    # 20
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
    "__dkms_edit__"
    "__traur__"
    "__aurscan_settings__"
    "__extra_lists__"
    "--check-lynis --no-notify --no-summary"
    "--run-lynis"
    "__audit_rules_edit__"
    "__lynis_config_edit__"
    "__about__"
)

NEEDS_ROOT=(
    true false false false false false false false false
    true true true
    false false false false
    true
    true
    false
    false
    false
)

# Per-session status for each check index.
# Indices without a meaningful pass/fail (dkms, dialogs) stay blank.
declare -A STATUS
for _i in "${!LABELS[@]}"; do STATUS[$_i]="  ?"; done
STATUS[0]="   "   # Full scan — blank until first run
STATUS[12]="   "  # Edit DKMS allowlist
STATUS[13]="   "  # traur — opens its own output window, no verdict here
STATUS[14]="   "  # aurscan settings — config dialog, no scan verdict
STATUS[15]="   "  # extra lists — config dialog, no scan verdict
STATUS[16]="   "  # Lynis hardening report — informational, no pass/fail verdict
STATUS[18]="   "  # Edit audit rules — config dialog, no scan verdict
STATUS[19]="   "  # Edit Lynis config — config dialog, no scan verdict
STATUS[20]="   "  # About — no scan verdict
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
    [[ $idx -eq 16 ]] && return  # Lynis hardening report — informational, stays blank
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
    [16]='12'
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
    local pkgs="${1:-}"
    local remove_cmd
    if [[ -n "$pkgs" ]]; then
        remove_cmd="${AUR_HELPER} -R ${pkgs}"
    else
        remove_cmd="${AUR_HELPER} -R &lt;package-name&gt;"
    fi
    yad --error \
        --title="Infected — Archcanary" \
        --window-icon=security-high \
        --width=520 \
        --text="<b>Infected or compromised packages detected.</b>\n\n<b>1.</b>  Remove the package(s):\n      <tt>${remove_cmd}</tt>\n\n<b>2.</b>  Check persistence — run <i>Systemd persistence</i> and\n      <i>XDG autostart + shell RCs</i> from this menu.\n\n<b>3.</b>  Rotate credentials: SSH keys, GitHub PATs, Discord\n      tokens, npm tokens, browser sessions.\n\nSee README → <i>What to Do If Infected</i>" \
        --button="OK:0" 2>/dev/null || true
}

# Extract infected package names from scan output (lines: "  - pkgname (installed: ...)")
_extract_infected_pkgs() {
    grep -oP '^  - \K\S+' "$1" 2>/dev/null | head -20 | tr '\n' ' ' | sed 's/ $//' || true
}

edit_allowlist() {
    # Single system-wide allowlist (the kmod audit only runs as root). The file
    # is world-readable, so yad loads it directly; the save writes back as root.
    local cfg="/etc/archcanary/dkms_allowlist.conf"
    if [[ ! -f "$cfg" ]]; then
        yad --warning \
            --title="DKMS Allowlist — Archcanary" \
            --window-icon=security-high \
            --text="<b>$cfg</b> does not exist.\n\nRun <tt>./install.sh --system</tt> first to create it." \
            --width=440 2>/dev/null || true
        return
    fi
    local tmpout
    tmpout="$(mktemp /tmp/archcanary-XXXXXX.txt)"
    if yad --text-info \
        --title="DKMS Allowlist (system) — Archcanary" \
        --window-icon=security-high \
        --filename="$cfg" \
        --width=640 --height=380 \
        --fontname="Monospace 10" \
        --editable \
        --button="Save (root):0" \
        --button="Cancel:1" \
        > "$tmpout" 2>/dev/null; then
        # Write back to /etc as root — pkexec prompts via the polkit agent.
        if [[ -z "$PKEXEC" ]] || ! "$PKEXEC" tee "$cfg" < "$tmpout" >/dev/null 2>&1; then
            yad --error --title="Archcanary" --window-icon=security-high \
                --text="Could not save <tt>$cfg</tt>\n(root authorization failed or cancelled)." \
                --width=420 2>/dev/null || true
        fi
    fi
    rm -f "$tmpout"
}

edit_audit_rules() {
    local cfg="/etc/audit/rules.d/30-archcanary.conf"
    local template="/usr/lib/archcanary/audit-rules.conf"
    local tmpin tmpout
    tmpin="$(mktemp /tmp/archcanary-XXXXXX.conf)"
    tmpout="$(mktemp /tmp/archcanary-XXXXXX.conf)"
    if grep -qE '^\s*-[waAbfe]' "$cfg" 2>/dev/null; then
        cp "$cfg" "$tmpin"
    elif [[ -f "$template" ]]; then
        cp "$template" "$tmpin"
    else
        printf '# No rules found. Run ./install.sh --system to seed the template.\n' > "$tmpin"
    fi
    if yad --text-info \
        --title="Audit Rules — Archcanary" \
        --window-icon=security-high \
        --filename="$tmpin" \
        --width=700 --height=520 \
        --fontname="Monospace 10" \
        --editable \
        --button="Save + restart auditd:0" \
        --button="Cancel:1" \
        > "$tmpout" 2>/dev/null; then
        if [[ -n "$PKEXEC" ]] && "$PKEXEC" tee "$cfg" < "$tmpout" >/dev/null 2>&1; then
            "$PKEXEC" systemctl restart auditd 2>/dev/null || true
        else
            yad --error --title="Archcanary" --window-icon=security-high \
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
        --window-icon=security-high \
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
            yad --error --title="Archcanary" --window-icon=security-high \
                --text="Could not save <tt>$cfg</tt>\n(root authorization failed or cancelled)." \
                --width=420 2>/dev/null || true
        fi
    fi
    rm -f "$tmpout" "$tmpout.new"
}

show_about() {
    local version repo="https://github.com/musqz/archcanary"
    version=$(grep -oP '(?<=SCRIPT_VERSION=")[^"]+' "$MAIN_SCRIPT" 2>/dev/null || echo "unknown")
    yad --info \
        --title="About Archcanary" \
        --window-icon=security-high \
        --width=440 --height=240 \
        --no-wrap \
        --button="Close":0 \
        --text="<b>Archcanary</b>  v${version}

Security scanner for Arch Linux — detects malicious packages,
suspicious systemd units, eBPF backdoors, rogue kernel modules,
and more.

Source: <a href=\"${repo}\">${repo}</a>"
}

aurscan_settings() {
    local cfg_dir="${XDG_CONFIG_HOME:-$HOME/.config}/aurscan"
    local env_file="$cfg_dir/env"

    # || true: grep exits non-zero on no match / missing file; pipefail would
    # propagate that and set -e would kill the function before yad opens.
    _env_get() { grep -E "^$1=" "$env_file" 2>/dev/null | tail -1 | cut -d= -f2- || true; }
    local cur_backend cur_url cur_fallback cur_model cur_timeout
    cur_backend=$(_env_get AURSCAN_BACKEND)
    cur_url=$(_env_get AURSCAN_OPENAI_URL)
    cur_fallback=$(_env_get AURSCAN_OPENAI_URL_FALLBACK)
    cur_model=$(_env_get AURSCAN_OPENAI_MODEL)
    cur_timeout=$(_env_get AURSCAN_TIMEOUT)
    [[ -z "$cur_timeout" ]] && cur_timeout="180"

    local backends
    case "$cur_backend" in
        claude) backends="claude!auto!openai" ;;
        openai) backends="openai!auto!claude" ;;
        *)      backends="auto!claude!openai" ;;
    esac

    local model_list
    if [[ -n "$cur_model" ]]; then
        model_list="$cur_model!qwen2.5-coder:14b!qwen2.5-coder:7b!llama3.1:8b!llama3.3:70b"
    else
        model_list="!qwen2.5-coder:14b!qwen2.5-coder:7b!llama3.1:8b!llama3.3:70b"
    fi

    local result rc=0
    while true; do
        # && rc=0 || rc=$? captures yad's exit code without triggering set -e
        # (set -e exempts the left side of && from exit-on-error).
        result=$(yad --form \
            --title="LLM Settings — aurscan" \
            --window-icon=security-high \
            --width=540 \
            --separator="|" \
            --field="Backend:CB" "$backends" \
            --field="Endpoint URL  (openai — Ollama / llama.cpp / vLLM):TEXT" "$cur_url" \
            --field="Fallback URL  (optional):TEXT" "$cur_fallback" \
            --field="Model:CBE" "$model_list" \
            --field="Timeout (seconds):NUM" "$cur_timeout" \
            --field="<small><b>Ollama:</b> set num_ctx ≥ 8192 in your Modelfile (see Model guide)</small>:LBL" "" \
            --button="Model guide:2" \
            --button="Save:0" \
            --button="Cancel:1" \
            2>/dev/null) && rc=0 || rc=$?

        if [[ $rc -eq 2 ]]; then
            yad --text-info \
                --title="Local model guide — aurscan" \
                --window-icon=security-high \
                --width=580 --height=440 \
                --fontname="Monospace 10" \
                --button="OK:0" \
                2>/dev/null << 'GUIDE' || true
Local model recommendations (from aurscan README):

 Size      Model                    Verdict quality
 ─────────────────────────────────────────────────────────────
 ≤ 3B      qwen2.5-coder:3b         ✗  Don't. Near-random verdicts,
           llama3.2:3b                  unreliable JSON. Use
           phi-*-mini                   --rules-only instead.

 7–8B      qwen2.5-coder:7b         ⚠  Marginal. ~45% catch rate.
           llama3.1:8b                  Misses subtle supply-chain
           codellama:7b                 tricks. Weak bonus on top of
                                        static rules, not a real auditor.

 14–32B    qwen2.5-coder:14b        ✓  Good. Recommended minimum
           phi-4:14b                    for real protection.
           codellama:13b

 70B+      llama3.3:70b             ✓  Best local. Approaches
           qwen3-coder (MoE)            cloud quality.

IMPORTANT — Ollama context window:
  Ollama defaults to num_ctx=2048. This silently truncates the PKGBUILD
  out of the prompt — the model scans almost nothing. Set num_ctx ≥ 8192
  (16384 recommended). Bake it into a named model:

    cat > Modelfile <<EOF
    FROM qwen2.5-coder:14b
    PARAMETER num_ctx 16384
    EOF
    ollama create aurscan-qwen -f Modelfile

  Then use "aurscan-qwen" as the model name in settings.
GUIDE
            continue  # loop back to settings form
        fi

        break
    done

    [[ $rc -ne 0 ]] && return  # Cancel

    local new_backend new_url new_fallback new_model new_timeout
    IFS='|' read -r new_backend new_url new_fallback new_model new_timeout _ <<< "$result"

    mkdir -p "$cfg_dir"
    {
        printf '# aurscan LLM settings — managed by archcanary-gui\n'
        [[ -n "$new_backend" && "$new_backend" != "auto" ]] && printf 'AURSCAN_BACKEND=%s\n' "$new_backend"
        [[ -n "$new_url" ]] && printf 'AURSCAN_OPENAI_URL=%s\n' "$new_url"
        [[ -n "$new_fallback" ]] && printf 'AURSCAN_OPENAI_URL_FALLBACK=%s\n' "$new_fallback"
        [[ -n "$new_model" ]] && printf 'AURSCAN_OPENAI_MODEL=%s\n' "$new_model"
        [[ -n "$new_timeout" && "$new_timeout" != "180" ]] && printf 'AURSCAN_TIMEOUT=%s\n' "$new_timeout"
    } > "$env_file"

    yad --info \
        --title="aurscan" \
        --window-icon=security-high \
        --text="Settings saved to\n<tt>$env_file</tt>" \
        --width=380 \
        --button="OK:0" 2>/dev/null || true
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
        --window-icon=security-high \
        --width=1000 --height=660 \
        --fontname="Monospace 10" \
        --wrap --tail --editable \
        --button=Close:0 \
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

    wait "$yad_pid" 2>/dev/null || true
    exec 8>&-
    _SHOW_OUTPUT_INFECTED_PKGS="$(_extract_infected_pkgs "$tmpout")"
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
        --title="Extra package lists — Archcanary" \
        --window-icon=security-high \
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
        yad --info \
            --title="Extra lists — Archcanary" \
            --window-icon=security-high \
            --text="Saved to <tt>$conf</tt>\n$n active entries.\n\nRun <b>Full scan</b> to fetch any new URLs." \
            --width=420 \
            --button="OK:0" 2>/dev/null || true
    fi
    rm -f "$tmpout"
}

run_action() {
    local idx="$1"
    local label="${LABELS[$idx]}"
    local flags="${FLAGS[$idx]}"
    local needs_root="${NEEDS_ROOT[$idx]}"

    if [[ "$idx" -eq 16 || "$idx" -eq 17 || "$idx" -eq 19 ]] && ! $HAS_LYNIS; then
        yad --info \
            --title="Lynis — Archcanary" \
            --window-icon=security-high \
            --text="<b>Lynis</b> is not installed.\n\nInstall from official repos:\n  <tt>sudo pacman -S lynis</tt>" \
            --width=420 \
            --button="OK:0" 2>/dev/null || true
        return
    fi

    if [[ "$flags" == "__dkms_edit__" ]]; then
        edit_allowlist
        return
    fi

    if [[ "$flags" == "__audit_rules_edit__" ]]; then
        edit_audit_rules
        return
    fi

    if [[ "$flags" == "__lynis_config_edit__" ]]; then
        edit_lynis_config
        return
    fi

    if [[ "$flags" == "__about__" ]]; then
        show_about
        return
    fi

    if [[ "$flags" == "__aurscan_settings__" ]]; then
        aurscan_settings
        return
    fi

    if [[ "$flags" == "__extra_lists__" ]]; then
        extra_lists_manager
        return
    fi

    if [[ "$flags" == "__traur__" ]]; then
        if ! $HAS_TRAUR; then
            yad --warning \
                --title="traur not installed" \
                --window-icon=security-high \
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

    if [[ "$needs_root" == "true" ]]; then
        if ! $HAS_ROOT; then
            yad --warning \
                --title="Root helper not installed" \
                --window-icon=security-high \
                --text="The system root helper is not installed.\n\nRun:\n  <b>./install.sh --system</b>\n\nto enable root-requiring checks." \
                --width=440 2>/dev/null || true
            return
        fi
        local tmpout pkexec_exit=0 pkexec_done=false
        tmpout="$(mktemp /tmp/archcanary-XXXXXX.txt)"

        # Open the output window immediately — no blank screen after clicking Run.
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
        if [[ "$idx" -eq 17 ]]; then
            printf 'Running lynis audit system, please wait (1-2 minutes)...\n\n' >&8 || true
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
                yad --error --title="Archcanary" \
                    --window-icon=security-high \
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
        local _inf_pkgs=""
        [[ "$scan_exit" -eq 2 ]] && _inf_pkgs="$(_extract_infected_pkgs "$tmpout")"
        rm -f "$tmpout"
        if [[ "$scan_exit" -eq 2 ]]; then _show_infected_dialog "$_inf_pkgs"; fi
    else
        local scan_exit=0
        _SHOW_OUTPUT_INFECTED_PKGS=""
        show_output "$label" "$MAIN_SCRIPT" "${flag_arr[@]}" && scan_exit=0 || scan_exit=$?
        _update_status "$idx" "$scan_exit"
        if [[ "$idx" -eq 0 ]]; then _propagate_full_scan "$scan_exit"; fi
        if [[ "$scan_exit" -eq 2 ]]; then _show_infected_dialog "$_SHOW_OUTPUT_INFECTED_PKGS"; fi
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
    _row 17 "🔐  ${LABELS[17]}"

    _sep "Utilities"
    $HAS_LYNIS   && _row 16 "🔐  ${LABELS[16]}"
    $HAS_TRAUR   && _row 13
    _sep "Settings"
    $HAS_AUDITD  && _row 18
    $HAS_LYNIS   && _row 19
    _row 12
    $HAS_AURSCAN && _row 14
    _row 15
    _row 20
}

# Main loop
while true; do
    list_args=()
    build_list_args list_args

    selected=$(yad \
        --list \
        --title="Archcanary" \
        --window-icon=security-high \
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

    selected="${selected#🔐  }"  # strip lock prefix from root items

    for i in "${!LABELS[@]}"; do
        if [[ "${LABELS[$i]}" == "$selected" ]]; then
            run_action "$i"
            break
        fi
    done
done
