#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
    echo "ERROR: do not run archcanary-gui as root or with sudo." >&2
    echo "Run it as your regular user — root checks are handled via pkexec (polkit)." >&2
    exit 1
fi

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

# Action data — order here is the canonical index used by run_action
LABELS=(
    "Refresh + full scan"       # 0  root
    "Refresh package list"      # 1
    "Systemd persistence"       # 2
    "npm cache"                 # 3
    "bun cache"                 # 4
    "yarn cache"                # 5
    "pnpm cache"                # 6
    "PKGBUILD / .install files" # 7
    "ld.so.preload injection"   # 8
    "XDG autostart + shell RCs" # 9
    "eBPF rootkit traces"       # 10 root
    "eBPF programs – bpftool"   # 11 root
    "Kernel modules"            # 12 root
    "Edit DKMS allowlist"       # 13
    "Trust scan (traur)"        # 14
    "LLM settings (aurscan)"   # 15
    "Extra lists"               # 16
)

FLAGS=(
    "--refresh --full --no-notify"
    "--refresh --no-notify"
    "--check-systemd --no-notify"
    "--check-npm-cache --no-notify"
    "--check-bun-cache --no-notify"
    "--check-yarn-cache --no-notify"
    "--check-pnpm-cache --no-notify"
    "--check-pkgbuild --no-notify"
    "--check-ldso --no-notify"
    "--check-autostart --no-notify"
    "--check-ebpf"
    "--check-bpftool"
    "--check-kmod"
    "__dkms_edit__"
    "__traur__"
    "__aurscan_settings__"
    "__extra_lists__"
)

NEEDS_ROOT=(
    true false false false false false false false false false
    true true true
    false false false false
)

# Per-session status for each check index.
# Indices without a meaningful pass/fail (refresh, dkms) stay blank.
declare -A STATUS
for _i in "${!LABELS[@]}"; do STATUS[$_i]="  ?"; done
STATUS[1]="   "   # Refresh package list — no scan verdict
STATUS[13]="   "  # Edit DKMS allowlist
STATUS[14]="   "  # traur — opens its own output window, no verdict here
STATUS[15]="   "  # aurscan settings — config dialog, no scan verdict
STATUS[16]="   "  # extra lists — config dialog, no scan verdict
unset _i

_update_status() {
    local idx=$1 code=$2
    case $code in
        0) STATUS[$idx]=" ✅" ;;
        1) STATUS[$idx]=" ⚠ " ;;
        *) STATUS[$idx]=" ❌" ;;
    esac
}

# Map each GUI check row to its section number in the scan output ("--- [N] ---").
declare -A _SCAN_TAG=(
    [2]='3'  [3]='5'  [4]='6'  [5]='6b' [6]='6c'
    [7]='7'  [8]='9'  [9]='10' [10]='4' [11]='8' [12]='11'
)

# After a full scan (idx 0), set each check row from ITS OWN section in the
# output, so a single finding marks only the check that found it — not the
# whole list. $1 = overall exit code (fallback), $2 = scan output file.
_propagate_full_scan() {
    local code=$1 out="${2:-}" i tag block
    for i in 2 3 4 5 6 7 8 9 10 11 12; do
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
    yad --error \
        --title="Infected — Archcanary" \
        --window-icon=security-high \
        --width=520 \
        --text="<b>Infected or compromised packages detected.</b>\n\n<b>1.</b>  Remove the package:\n      <tt>paru -R &lt;package-name&gt;</tt>\n\n<b>2.</b>  Check persistence — run <i>Systemd persistence</i> and\n      <i>XDG autostart + shell RCs</i> from this menu.\n\n<b>3.</b>  Rotate credentials: SSH keys, GitHub PATs, Discord\n      tokens, npm tokens, browser sessions.\n\nSee README → <i>What to Do If Infected</i>" \
        --button="OK:0" 2>/dev/null || true
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
    local tmpout
    tmpout=$(mktemp /tmp/archcanary-XXXXXX.txt)
    "$@" > "$tmpout" 2>&1 &
    local scan_pid=$!
    (tail --pid="$scan_pid" -f -n +1 "$tmpout" 2>/dev/null
     printf '\n─── done ───\n') \
        | yad --text-info \
            --title="$title — Archcanary" \
            --window-icon=security-high \
            --width=1000 --height=660 \
            --fontname="Monospace 10" \
            --wrap --tail --editable \
            --button="Close:0" 2>/dev/null || true
    wait "$scan_pid" && scan_exit=0 || scan_exit=$?
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
            --text="Saved to <tt>$conf</tt>\n$n active entries.\n\nRun <b>Refresh package list</b> to fetch any new URLs." \
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

    if [[ "$flags" == "__dkms_edit__" ]]; then
        edit_allowlist
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
                --text="<b>traur</b> is not installed.\n\nInstall it from AUR:\n  <tt>paru -S traur</tt>" \
                --width=360 2>/dev/null || true
            return
        fi
        local scan_exit=0
        show_output "Trust scan" "$TRAUR" scan && scan_exit=0 || scan_exit=$?
        _update_status "$idx" "$scan_exit"
        return
    fi

    read -ra flag_arr <<< "$flags"

    if [[ "$needs_root" == "true" ]]; then
        if ! $HAS_ROOT; then
            yad --warning \
                --title="Root helper not installed" \
                --window-icon=security-high \
                --text="The system root helper is not installed.\n\nRun:\n  <b>./install.sh --system</b>\n\nto enable root-requiring checks." \
                --width=440 2>/dev/null || true
            return
        fi
        local tmpout pkexec_exit=0
        tmpout="$(mktemp /tmp/archcanary-XXXXXX.txt)"

        # Background pkexec: polkit dialog is the only window during auth
        # so it gets focus on its own. Output window opens only after auth.
        "$PKEXEC" "$ROOT_HELPER" "${flag_arr[@]}" > "$tmpout" 2>&1 &
        local pkexec_pid=$!

        # Wait for auth to succeed (check produces first output) or pkexec to exit
        while [[ ! -s "$tmpout" ]] && kill -0 "$pkexec_pid" 2>/dev/null; do
            sleep 0.1
        done

        if [[ ! -s "$tmpout" ]]; then
            wait "$pkexec_pid" 2>/dev/null || pkexec_exit=$?
            rm -f "$tmpout"
            [[ $pkexec_exit -ne 0 && $pkexec_exit -ne 126 ]] && \
                yad --error --title="Archcanary" \
                    --window-icon=security-high \
                    --text="pkexec failed (exit $pkexec_exit)" \
                    --width=360 2>/dev/null || true
            return 0
        fi

        # Sentinel: wait for pkexec to finish, give tee 0.5 s to flush its
        # buffer to tmpout, then append the done marker so tail exits cleanly.
        # (Without this, tail --pid stops at pkexec exit before tee flushes,
        # causing the output window to show only the first few checks.)
        { wait "$pkexec_pid" 2>/dev/null || true
          sleep 0.5
          printf '\n─── done ───\n' >> "$tmpout"; } &
        local sentinel_pid=$!

        # Output window streams live; tail -f stays open until sentinel fires.
        # When user clicks Close, yad exits → pipe breaks → tail exits.
        tail -f -n +1 "$tmpout" 2>/dev/null \
            | yad --text-info \
                --title="$label — Archcanary" \
                --window-icon=security-high \
                --width=1000 --height=660 \
                --fontname="Monospace 10" \
                --wrap --tail --editable \
                --button="Close:0" 2>/dev/null || true

        local scan_exit=0
        wait "$pkexec_pid" 2>/dev/null || scan_exit=$?
        wait "$sentinel_pid" 2>/dev/null || true
        _update_status "$idx" "$scan_exit"
        if [[ "$idx" -eq 0 ]]; then _propagate_full_scan "$scan_exit" "$tmpout"; fi
        rm -f "$tmpout"
        if [[ "$scan_exit" -eq 2 ]]; then _show_infected_dialog; fi
    else
        local scan_exit=0
        show_output "$label" "$MAIN_SCRIPT" "${flag_arr[@]}" && scan_exit=0 || scan_exit=$?
        _update_status "$idx" "$scan_exit"
        if [[ "$idx" -eq 0 ]]; then _propagate_full_scan "$scan_exit"; fi
        if [[ "$scan_exit" -eq 2 ]]; then _show_infected_dialog; fi
    fi
}

# Build two-column display list: [status] [label], with section separators.
# Root items get a 🔐 prefix in column 2; separators have blank status in col 1.
build_list_args() {
    local -n _out=$1
    _sep() { _out+=("   " "  ───  $1  ───────────────────────"); }
    _row() { local i=$1; local lbl="${2:-${LABELS[$i]}}"; _out+=("${STATUS[$i]}" "$lbl"); }

    _row 0 "🔐  ${LABELS[0]}"
    _row 1

    _sep "Standard checks"
    for i in 2 3 4 5 6 7 8 9; do _row "$i"; done

    _sep "Root checks"
    for i in 10 11 12; do _row "$i" "🔐  ${LABELS[$i]}"; done

    _sep "Utilities"
    _row 13
    $HAS_TRAUR && _row 14
    $HAS_AURSCAN && _row 15
    _row 16
}

# Main loop
while true; do
    list_args=()
    build_list_args list_args

    selected=$(yad \
        --list \
        --title="Archcanary" \
        --window-icon=security-high \
        --width=580 --height=560 \
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
