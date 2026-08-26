#!/usr/bin/env bash
set -euo pipefail

if ! command -v archcanary >/dev/null 2>&1; then
    echo "Error: archcanary not found on PATH — install it first (./install.sh)" >&2
    exit 1
fi

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_CYAN=$'\033[36m'
else
    C_RESET=''; C_BOLD=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_CYAN=''
fi

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/archcanary"
mkdir -p "$CONFIG_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

declare -A STATUS=()
LAST_RC=0

declare -A CHECK_FLAGS=(
    [systemd]="--check-systemd"
    [npm]="--check-npm-cache"
    [bun]="--check-bun-cache"
    [yarn]="--check-yarn-cache"
    [pnpm]="--check-pnpm-cache"
    [pkgbuild]="--check-pkgbuild"
    [ldso]="--check-ldso"
    [autostart]="--check-autostart"
)
CHECK_ORDER=(systemd npm bun yarn pnpm pkgbuild ldso autostart)
declare -A CHECK_LABELS=(
    [systemd]="Systemd persistence"
    [npm]="npm cache"
    [bun]="bun cache"
    [yarn]="yarn cache"
    [pnpm]="pnpm cache"
    [pkgbuild]="PKGBUILD / .install files"
    [ldso]="ld.so.preload injection"
    [autostart]="XDG autostart + shell RCs"
)

declare -A ROOT_CHECK_FLAGS=(
    [ebpf]="--check-ebpf"
    [bpftool]="--check-bpftool"
    [kmod]="--check-kmod"
    [pkginteg]="--check-pkginteg"
)
ROOT_CHECK_ORDER=(ebpf bpftool kmod pkginteg)
declare -A ROOT_CHECK_LABELS=(
    [ebpf]="eBPF rootkit traces"
    [bpftool]="eBPF programs (bpftool)"
    [kmod]="Kernel modules"
    [pkginteg]="Pacman integrity"
)

declare -A ALLOWLIST_LABELS=(
    [dkms]="DKMS (kernel modules)"
    [systemd]="systemd (persistence check)"
    [bpftool]="bpftool (eBPF loaders)"
    [autostart]="Autostart (XDG persistence check)"
)

_pause() {
    printf '\nPress Enter to continue...'
    read -r _pause_dummy || exit 0
}

_status_glyph() {
    case "${STATUS[$1]:-}" in
        0) printf '%s✅%s' "$C_GREEN" "$C_RESET" ;;
        1) printf '%s⚠%s' "$C_YELLOW" "$C_RESET" ;;
        2) printf '%s❌%s' "$C_RED" "$C_RESET" ;;
        *) printf '?' ;;
    esac
}

_header() {
    clear
    printf '%s%s🐤 archcanary%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
    printf -- '----------------------------------------------\n'
}

_run() {
    local title="$1" use_sudo="$2"; shift 2
    echo
    echo "\$ archcanary $*"
    [[ "$use_sudo" == true ]] && echo "(sudo may prompt for your password)"
    echo
    LAST_RC=0
    if [[ "$use_sudo" == true ]]; then
        sudo archcanary "$@" || LAST_RC=$?
    else
        archcanary "$@" || LAST_RC=$?
    fi
    local word
    case "$LAST_RC" in
        0) word="${C_GREEN}CLEAN${C_RESET}" ;;
        1) word="${C_YELLOW}WARNINGS${C_RESET}" ;;
        2) word="${C_RED}INFECTED${C_RESET}" ;;
        *) word="${C_RED}ERROR (exit $LAST_RC)${C_RESET}" ;;
    esac
    printf '\n%s: %s\n' "$title" "$word"
    _pause
}

_maybe_show_first_run_notice() {
    local marker="$CONFIG_DIR/.tui_notice_shown"
    if [[ ! -f "$marker" ]]; then
        _header
        echo "archcanary-tui replaces the old graphical interface."
        echo "Same checks under the hood — run archcanary --help for the plain CLI."
        touch "$marker" 2>/dev/null || true
        _pause
    fi
}

_about() {
    _header
    archcanary --version 2>/dev/null || echo "unknown"
    echo
    echo "Layered security scanner for Arch Linux."
    echo "https://github.com/musqz/archcanary"
    _pause
}

_search_packages() {
    local query
    read -rp "Search packages (comma-separated): " query || exit 0
    [[ -n "$query" ]] || return 0
    _run "Search packages" false "--search-packages=$query"
}

_multi_check_menu() {
    local title="$1" use_sudo="$2" order_name="$3" flags_name="$4" labels_name="$5"
    local -n order_ref="$order_name" flags_ref="$flags_name" labels_ref="$labels_name"
    while true; do
        _header
        echo "$title"
        echo
        local i=1 key
        for key in "${order_ref[@]}"; do
            printf '%2d) %-34s %s\n' "$i" "${labels_ref[$key]}" "$(_status_glyph "$key")"
            i=$((i + 1))
        done
        echo " 0) Back"
        echo
        local input
        read -rp "Numbers (space-separated), 'a' for all, 0 to go back: " input || exit 0
        [[ -z "$input" || "$input" == "0" ]] && return 0
        local nums=()
        if [[ "$input" == "a" || "$input" == "A" ]]; then
            local n
            for ((n = 1; n <= ${#order_ref[@]}; n++)); do nums+=("$n"); done
        else
            read -ra nums <<< "$input"
        fi
        local flags=() selected=() n key2
        for n in "${nums[@]}"; do
            if [[ "$n" =~ ^[0-9]+$ ]] && ((10#$n >= 1 && 10#$n <= ${#order_ref[@]})); then
                key2="${order_ref[$((10#$n - 1))]}"
                flags+=("${flags_ref[$key2]}")
                selected+=("$key2")
            fi
        done
        if [[ ${#flags[@]} -eq 0 ]]; then
            echo "No valid checks selected."
            _pause
            continue
        fi
        _run "$title" "$use_sudo" "${flags[@]}" --no-notify
        if [[ ${#selected[@]} -eq 1 ]]; then
            STATUS[${selected[0]}]="$LAST_RC"
        fi
    done
}

_checks_menu() {
    _multi_check_menu "Individual checks" false CHECK_ORDER CHECK_FLAGS CHECK_LABELS
}

_root_checks_menu() {
    _multi_check_menu "Root checks" true ROOT_CHECK_ORDER ROOT_CHECK_FLAGS ROOT_CHECK_LABELS
}

_list_entries() {
    archcanary "$1" 2>&1 || true
}

_pick_editor() {
    if [[ -n "${EDITOR:-}" ]]; then
        read -ra EDITOR_CMD <<< "$EDITOR"
        if [[ ${#EDITOR_CMD[@]} -gt 0 ]] && command -v "${EDITOR_CMD[0]}" >/dev/null 2>&1; then
            return 0
        fi
    fi
    if command -v nano >/dev/null 2>&1; then
        EDITOR_CMD=(nano)
        return 0
    fi
    if command -v vi >/dev/null 2>&1; then
        EDITOR_CMD=(vi)
        return 0
    fi
    return 1
}

_edit_via_get_set() {
    local title="$1" get_flag="$2" set_flag="$3" tmpfile="$TMP_DIR/edit.txt"
    if ! archcanary "$get_flag" > "$tmpfile" 2>"$TMP_DIR/edit.err"; then
        cat "$TMP_DIR/edit.err"
        _pause
        return 0
    fi
    local -a EDITOR_CMD=()
    if ! _pick_editor; then
        echo "No editor found — set \$EDITOR or install nano/vim." >&2
        _pause
        return 0
    fi
    "${EDITOR_CMD[@]}" "$tmpfile" || true
    local ans
    read -rp "Save changes? [y/N]: " ans || exit 0
    [[ "$ans" =~ ^[Yy]$ ]] || return 0
    echo
    if sudo archcanary "$set_flag" < "$tmpfile"; then
        echo "Saved."
    else
        echo "Save failed."
    fi
    _pause
}

_allowlist_view() {
    local name="$1"
    _header
    echo "${ALLOWLIST_LABELS[$name]} — entries"
    echo
    local out
    out="$(_list_entries "--allowlist-list=$name")"
    [[ -n "$out" ]] && printf '%s\n' "$out" || echo "(no entries)"
    _pause
}

_allowlist_add() {
    local name="$1" value
    read -rp "Value to add: " value || exit 0
    [[ -n "$value" ]] || return 0
    _run "Add allowlist entry" true "--allowlist-add=$name:$value"
}

_remove_entry_menu() {
    local title="$1" list_flag="$2" remove_flag_prefix="$3" use_sudo="$4"
    local entries=() line
    while IFS= read -r line; do
        [[ -n "$line" ]] && entries+=("$line")
    done < <(_list_entries "$list_flag")
    if [[ ${#entries[@]} -eq 0 ]]; then
        echo "No entries to remove."
        _pause
        return 0
    fi
    _header
    echo "$title — remove entry"
    echo
    local i=1
    for line in "${entries[@]}"; do
        printf '%2d) %s\n' "$i" "$line"
        i=$((i + 1))
    done
    local n
    read -rp "Number to remove (blank to cancel): " n || exit 0
    [[ "$n" =~ ^[0-9]+$ ]] && ((10#$n >= 1 && 10#$n <= ${#entries[@]})) || return 0
    _run "Remove entry" "$use_sudo" "${remove_flag_prefix}${entries[$((10#$n - 1))]}"
}

_allowlist_remove() {
    local name="$1"
    _remove_entry_menu "${ALLOWLIST_LABELS[$name]}" "--allowlist-list=$name" "--allowlist-remove=$name:" true
}

_allowlist_detail_menu() {
    local name="$1"
    while true; do
        _header
        echo "${ALLOWLIST_LABELS[$name]}"
        echo
        echo "1) View entries"
        echo "2) Add entry"
        echo "3) Remove entry"
        echo "0) Back"
        echo
        local c
        read -rp "Choice: " c || exit 0
        case "$c" in
            1) _allowlist_view "$name" ;;
            2) _allowlist_add "$name" ;;
            3) _allowlist_remove "$name" ;;
            0|"") return 0 ;;
            *) ;;
        esac
    done
}

_allowlists_menu() {
    while true; do
        _header
        echo "Manage allowlists"
        echo
        echo "1) DKMS (kernel modules)"
        echo "2) systemd (persistence check)"
        echo "3) bpftool (eBPF loaders)"
        echo "4) Autostart (XDG persistence check)"
        echo "0) Back"
        echo
        local c
        read -rp "Choice: " c || exit 0
        case "$c" in
            1) _allowlist_detail_menu dkms ;;
            2) _allowlist_detail_menu systemd ;;
            3) _allowlist_detail_menu bpftool ;;
            4) _allowlist_detail_menu autostart ;;
            0|"") return 0 ;;
            *) ;;
        esac
    done
}

_extra_lists_view() {
    _header
    echo "Extra lists — entries"
    echo
    local out
    out="$(_list_entries --extra-lists-list)"
    [[ -n "$out" ]] && printf '%s\n' "$out" || echo "(no entries)"
    _pause
}

_extra_lists_add() {
    local value
    read -rp "Add extra list (path or https:// URL): " value || exit 0
    [[ -n "$value" ]] || return 0
    _run "Add extra list" false "--extra-lists-add=$value"
}

_extra_lists_remove() {
    _remove_entry_menu "Extra lists" "--extra-lists-list" "--extra-lists-remove=" false
}

_extra_lists_menu() {
    while true; do
        _header
        echo "Extra lists"
        echo
        echo "1) View entries"
        echo "2) Add entry"
        echo "3) Remove entry"
        echo "0) Back"
        echo
        local c
        read -rp "Choice: " c || exit 0
        case "$c" in
            1) _extra_lists_view ;;
            2) _extra_lists_add ;;
            3) _extra_lists_remove ;;
            0|"") return 0 ;;
            *) ;;
        esac
    done
}

_config_menu() {
    while true; do
        _header
        echo "Edit config"
        echo
        echo "1) Audit rules"
        echo "2) Lynis profile"
        echo "3) Extra lists"
        echo "4) List overlap check"
        echo "0) Back"
        echo
        local c
        read -rp "Choice: " c || exit 0
        case "$c" in
            1) _edit_via_get_set "Audit rules" --audit-rules-get --audit-rules-set ;;
            2) _edit_via_get_set "Lynis profile" --lynis-config-get --lynis-config-set ;;
            3) _extra_lists_menu ;;
            4) _run "List overlap check" false --check-list-overlap ;;
            0|"") return 0 ;;
            *) ;;
        esac
    done
}

_settings_menu() {
    while true; do
        _header
        local status label
        status=$(archcanary --aur-audit-status 2>/dev/null || echo true)
        label="ON"
        [[ "$status" == "false" ]] && label="OFF"
        echo "Settings"
        echo
        echo "1) Toggle aur-audit feed (currently: $label)"
        echo "0) Back"
        echo
        local c
        read -rp "Choice: " c || exit 0
        case "$c" in
            1)
                if [[ "$status" == "false" ]]; then
                    _run "aur-audit feed" false --aur-audit-enable
                else
                    _run "aur-audit feed" false --aur-audit-disable
                fi
                ;;
            0|"") return 0 ;;
            *) ;;
        esac
    done
}

_main_menu() {
    while true; do
        _header
        printf ' 1) Full scan                        %s\n' "$(_status_glyph full)"
        echo " 2) Refresh + Full scan"
        echo " 3) Individual checks"
        printf ' 4) Root checks                       %s[root]%s\n' "$C_YELLOW" "$C_RESET"
        printf ' 5) Lynis hardening report            %s[root]%s\n' "$C_YELLOW" "$C_RESET"
        printf ' 6) Run Lynis audit                   %s[root]%s\n' "$C_YELLOW" "$C_RESET"
        echo " 7) Setup health check (--doctor)"
        echo " 8) Search packages"
        echo " 9) Manage allowlists"
        echo "10) Edit config"
        echo "11) Settings"
        echo "12) About"
        echo " 0) Quit"
        echo
        local choice
        read -rp "Choice: " choice || exit 0
        case "$choice" in
            1) _run "Full scan" true --full; STATUS[full]="$LAST_RC" ;;
            2) _run "Refresh + Full scan" true --refresh --full; STATUS[full]="$LAST_RC" ;;
            3) _checks_menu ;;
            4) _root_checks_menu ;;
            5) _run "Lynis hardening report" true --check-lynis --no-notify ;;
            6) _run "Run Lynis audit" true --run-lynis ;;
            7) _run "Setup health check" false --doctor ;;
            8) _search_packages ;;
            9) _allowlists_menu ;;
            10) _config_menu ;;
            11) _settings_menu ;;
            12) _about ;;
            0|"") return 0 ;;
            *)
                echo "Invalid choice."
                _pause
                ;;
        esac
    done
}

_maybe_show_first_run_notice
_main_menu
clear
