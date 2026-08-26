#!/usr/bin/env bash
set -euo pipefail

if ! command -v dialog >/dev/null 2>&1; then
    echo "Error: dialog not installed (pacman -S dialog)" >&2
    exit 1
fi
if ! command -v archcanary >/dev/null 2>&1; then
    echo "Error: archcanary not found on PATH — install it first (./install.sh)" >&2
    exit 1
fi

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/archcanary"
mkdir -p "$CONFIG_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

BACKTITLE="🐤 archcanary — terminal UI"

DIALOGRC_FILE="$TMP_DIR/dialogrc"
cat > "$DIALOGRC_FILE" <<'EOF'
use_shadow = ON
use_colors = ON
use_scrollbar = ON
screen_color = (GREEN,BLACK,ON)
shadow_color = (BLACK,BLACK,ON)
dialog_color = (WHITE,BLACK,OFF)
title_color = (GREEN,BLACK,ON)
border_color = (GREEN,BLACK,ON)
button_active_color = (BLACK,GREEN,ON)
button_inactive_color = dialog_color
button_key_active_color = button_active_color
button_key_inactive_color = (GREEN,BLACK,ON)
button_label_active_color = (BLACK,GREEN,ON)
button_label_inactive_color = (WHITE,BLACK,ON)
inputbox_color = dialog_color
inputbox_border_color = border_color
searchbox_color = dialog_color
searchbox_title_color = title_color
searchbox_border_color = border_color
position_indicator_color = title_color
menubox_color = dialog_color
menubox_border_color = border_color
item_color = (WHITE,BLACK,OFF)
item_selected_color = (BLACK,GREEN,ON)
tag_color = (GREEN,BLACK,ON)
tag_selected_color = (BLACK,GREEN,ON)
tag_key_color = (CYAN,BLACK,ON)
tag_key_selected_color = (BLACK,GREEN,ON)
check_color = dialog_color
check_selected_color = (BLACK,GREEN,ON)
uarrow_color = (GREEN,BLACK,ON)
darrow_color = uarrow_color
itemhelp_color = (CYAN,BLACK,OFF)
form_active_text_color = button_active_color
form_text_color = (WHITE,BLACK,ON)
form_item_readonly_color = (CYAN,BLACK,ON)
gauge_color = title_color
border2_color = dialog_color
inputbox_border2_color = dialog_color
searchbox_border2_color = dialog_color
menubox_border2_color = dialog_color
EOF
export DIALOGRC="$DIALOGRC_FILE"

declare -A STATUS=()

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

ALLOWLIST_NAMES=(dkms systemd bpftool autostart)
declare -A ALLOWLIST_LABELS=(
    [dkms]="DKMS (kernel modules)"
    [systemd]="systemd (persistence check)"
    [bpftool]="bpftool (eBPF loaders)"
    [autostart]="Autostart (XDG persistence check)"
)

_dialog_menu() {
    local title="$1" h="$2" w="$3" lh="$4"; shift 4
    local -a extra=()
    [[ -n "${DIALOG_DEFAULT_ITEM:-}" ]] && extra=(--default-item "$DIALOG_DEFAULT_ITEM")
    DIALOG_DEFAULT_ITEM=""
    if DIALOG_RESULT=$(dialog --colors --backtitle "$BACKTITLE" --title "$title" \
            "${extra[@]}" --menu "" "$h" "$w" "$lh" "$@" 3>&1 1>&2 2>&3); then
        return 0
    fi
    return 1
}

_dialog_checklist() {
    local title="$1" h="$2" w="$3" lh="$4"; shift 4
    if DIALOG_RESULT=$(dialog --colors --backtitle "$BACKTITLE" --title "$title" \
            --separate-output --checklist "" "$h" "$w" "$lh" "$@" 3>&1 1>&2 2>&3); then
        return 0
    fi
    return 1
}

_dialog_inputbox() {
    local title="$1" h="$2" w="$3" init="${4:-}"
    if DIALOG_RESULT=$(dialog --backtitle "$BACKTITLE" --title "$title" \
            --inputbox "" "$h" "$w" "$init" 3>&1 1>&2 2>&3); then
        return 0
    fi
    return 1
}

_dialog_editbox() {
    local title="$1" h="$2" w="$3" file="$4"
    if DIALOG_RESULT=$(dialog --backtitle "$BACKTITLE" --title "$title" \
            --editbox "$file" "$h" "$w" 3>&1 1>&2 2>&3); then
        return 0
    fi
    return 1
}

_dialog_msg() {
    dialog --backtitle "$BACKTITLE" --title "$1" --msgbox "$2" 12 70 || true
}

_dialog_textfile() {
    dialog --backtitle "$BACKTITLE" --title "$1" --textbox "$2" 30 100 || true
}

_status_glyph() {
    case "$1" in
        0) printf '\\Z2✅\\Zn' ;;
        1) printf '\\Z3⚠\\Zn' ;;
        2) printf '\\Z1❌\\Zn' ;;
        "") printf '?' ;;
        *) printf '\\Z1?\\Zn' ;;
    esac
}

LAST_RC=0

_run_and_show() {
    local title="$1" use_sudo="$2"; shift 2
    local log="$TMP_DIR/last-run.log"
    clear
    printf 'archcanary %s\n' "$*"
    [[ "$use_sudo" == true ]] && printf '(sudo may prompt for your password)\n'
    printf '\n'
    LAST_RC=0
    if [[ "$use_sudo" == true ]]; then
        sudo archcanary "$@" >"$log" 2>&1 || LAST_RC=$?
    else
        archcanary "$@" >"$log" 2>&1 || LAST_RC=$?
    fi
    local status_word
    case "$LAST_RC" in
        0) status_word="✅ CLEAN" ;;
        1) status_word="⚠ WARNINGS" ;;
        2) status_word="❌ INFECTED" ;;
        *) status_word="❓ ERROR (exit $LAST_RC)" ;;
    esac
    dialog --backtitle "$BACKTITLE" --title "$title — $status_word" --textbox "$log" 30 100 || true
}

_maybe_show_first_run_notice() {
    local marker="$CONFIG_DIR/.tui_notice_shown"
    if [[ ! -f "$marker" ]]; then
        _dialog_msg "Welcome" "archcanary-tui replaces the old graphical interface.

Same checks under the hood — run archcanary --help for the plain CLI."
        touch "$marker" 2>/dev/null || true
    fi
}

_about() {
    local ver
    ver=$(archcanary --version 2>/dev/null || echo "unknown")
    _dialog_msg "About" "$ver

Layered security scanner for Arch Linux.
https://github.com/musqz/archcanary"
}

_search_packages() {
    if _dialog_inputbox "Search packages (comma-separated)" 8 60; then
        [[ -n "$DIALOG_RESULT" ]] || return 0
        _run_and_show "Search packages" false "--search-packages=$DIALOG_RESULT"
    fi
}

_checks_menu() {
    local items=() key
    for key in "${CHECK_ORDER[@]}"; do
        items+=("$key" "${CHECK_LABELS[$key]} $(_status_glyph "${STATUS[$key]:-}")" off)
    done
    if _dialog_checklist "Individual checks" 20 70 8 "${items[@]}"; then
        local selected=() line
        while IFS= read -r line; do
            [[ -n "$line" ]] && selected+=("$line")
        done <<< "$DIALOG_RESULT"
        [[ ${#selected[@]} -eq 0 ]] && return
        local flags=() k
        for k in "${selected[@]}"; do
            flags+=("${CHECK_FLAGS[$k]}")
        done
        _run_and_show "Individual checks" false "${flags[@]}" --no-notify
        if [[ ${#selected[@]} -eq 1 ]]; then
            STATUS[${selected[0]}]="$LAST_RC"
        fi
    fi
}

_root_checks_menu() {
    local items=() key
    for key in "${ROOT_CHECK_ORDER[@]}"; do
        items+=("$key" "${ROOT_CHECK_LABELS[$key]} $(_status_glyph "${STATUS[$key]:-}")" off)
    done
    if _dialog_checklist "🔐 Root checks" 20 70 5 "${items[@]}"; then
        local selected=() line
        while IFS= read -r line; do
            [[ -n "$line" ]] && selected+=("$line")
        done <<< "$DIALOG_RESULT"
        [[ ${#selected[@]} -eq 0 ]] && return
        local flags=() k
        for k in "${selected[@]}"; do
            flags+=("${ROOT_CHECK_FLAGS[$k]}")
        done
        _run_and_show "Root checks" true "${flags[@]}" --no-notify
        if [[ ${#selected[@]} -eq 1 ]]; then
            STATUS[${selected[0]}]="$LAST_RC"
        fi
    fi
}

_allowlist_view() {
    local name="$1" out="$TMP_DIR/al.txt"
    archcanary "--allowlist-list=$name" > "$out" 2>&1 || true
    [[ -s "$out" ]] || printf '(no entries)\n' > "$out"
    _dialog_textfile "${ALLOWLIST_LABELS[$name]} — entries" "$out"
}

_allowlist_add() {
    local name="$1"
    if _dialog_inputbox "Add to ${ALLOWLIST_LABELS[$name]}" 8 60; then
        [[ -n "$DIALOG_RESULT" ]] || return 0
        _run_and_show "Add allowlist entry" true "--allowlist-add=$name:$DIALOG_RESULT"
    fi
}

_allowlist_remove() {
    local name="$1" out="$TMP_DIR/al.txt"
    archcanary "--allowlist-list=$name" > "$out" 2>&1 || true
    if [[ ! -s "$out" ]]; then
        _dialog_msg "${ALLOWLIST_LABELS[$name]}" "No entries to remove."
        return 0
    fi
    local items=() line
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        items+=("$line" "$line")
    done < "$out"
    if _dialog_menu "Remove from ${ALLOWLIST_LABELS[$name]}" 20 70 12 "${items[@]}"; then
        _run_and_show "Remove allowlist entry" true "--allowlist-remove=$name:$DIALOG_RESULT"
    fi
}

_allowlist_detail_menu() {
    local name="$1"
    while true; do
        if _dialog_menu "${ALLOWLIST_LABELS[$name]}" 14 60 4 \
                view "View entries" \
                add "Add entry" \
                remove "Remove entry" \
                back "Back"; then
            case "$DIALOG_RESULT" in
                view) _allowlist_view "$name" ;;
                add) _allowlist_add "$name" ;;
                remove) _allowlist_remove "$name" ;;
                back) return 0 ;;
            esac
        else
            return 0
        fi
    done
}

_allowlists_menu() {
    while true; do
        if _dialog_menu "Manage allowlists" 14 60 5 \
                dkms "${ALLOWLIST_LABELS[dkms]}" \
                systemd "${ALLOWLIST_LABELS[systemd]}" \
                bpftool "${ALLOWLIST_LABELS[bpftool]}" \
                autostart "${ALLOWLIST_LABELS[autostart]}" \
                back "Back"; then
            [[ "$DIALOG_RESULT" == back ]] && return
            _allowlist_detail_menu "$DIALOG_RESULT"
        else
            return 0
        fi
    done
}

_edit_via_get_set() {
    local title="$1" get_flag="$2" set_flag="$3" tmpfile="$TMP_DIR/edit.txt"
    if ! archcanary "$get_flag" > "$tmpfile" 2>"$TMP_DIR/edit.err"; then
        _dialog_textfile "$title — could not read" "$TMP_DIR/edit.err"
        return 0
    fi
    if _dialog_editbox "$title" 24 90 "$tmpfile"; then
        if printf '%s\n' "$DIALOG_RESULT" | sudo archcanary "$set_flag" > "$TMP_DIR/edit_out.log" 2>&1; then
            _dialog_msg "$title" "Saved."
        else
            _dialog_textfile "$title — save failed" "$TMP_DIR/edit_out.log"
        fi
    fi
}

_extra_lists_view() {
    local out="$TMP_DIR/extra.txt"
    archcanary --extra-lists-list > "$out" 2>&1 || true
    [[ -s "$out" ]] || printf '(no entries)\n' > "$out"
    _dialog_textfile "Extra lists" "$out"
}

_extra_lists_add() {
    if _dialog_inputbox "Add extra list (path or https:// URL)" 8 70; then
        [[ -n "$DIALOG_RESULT" ]] || return 0
        _run_and_show "Add extra list" false "--extra-lists-add=$DIALOG_RESULT"
    fi
}

_extra_lists_remove() {
    local out="$TMP_DIR/extra.txt"
    archcanary --extra-lists-list > "$out" 2>&1 || true
    if [[ ! -s "$out" ]]; then
        _dialog_msg "Extra lists" "No entries to remove."
        return 0
    fi
    local items=() line
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        items+=("$line" "$line")
    done < "$out"
    if _dialog_menu "Remove extra list" 20 76 12 "${items[@]}"; then
        _run_and_show "Remove extra list" false "--extra-lists-remove=$DIALOG_RESULT"
    fi
}

_extra_lists_menu() {
    while true; do
        if _dialog_menu "Extra lists" 14 60 4 \
                view "View entries" \
                add "Add entry" \
                remove "Remove entry" \
                back "Back"; then
            case "$DIALOG_RESULT" in
                view) _extra_lists_view ;;
                add) _extra_lists_add ;;
                remove) _extra_lists_remove ;;
                back) return 0 ;;
            esac
        else
            return 0
        fi
    done
}

_config_menu() {
    while true; do
        if _dialog_menu "Edit config" 14 60 5 \
                audit "Audit rules" \
                lynis "Lynis profile" \
                extra "Extra lists" \
                overlap "List overlap check" \
                back "Back"; then
            case "$DIALOG_RESULT" in
                audit) _edit_via_get_set "Audit rules" --audit-rules-get --audit-rules-set ;;
                lynis) _edit_via_get_set "Lynis profile" --lynis-config-get --lynis-config-set ;;
                extra) _extra_lists_menu ;;
                overlap) _run_and_show "List overlap check" false --check-list-overlap ;;
                back) return 0 ;;
            esac
        else
            return 0
        fi
    done
}

_settings_menu() {
    while true; do
        local status label
        status=$(archcanary --aur-audit-status 2>/dev/null || echo true)
        label="ON"
        [[ "$status" == "false" ]] && label="OFF"
        if _dialog_menu "Settings" 12 60 2 \
                toggle "Toggle aur-audit feed (currently: $label)" \
                back "Back"; then
            case "$DIALOG_RESULT" in
                toggle)
                    if [[ "$status" == "false" ]]; then
                        _run_and_show "aur-audit feed" false --aur-audit-enable
                    else
                        _run_and_show "aur-audit feed" false --aur-audit-disable
                    fi
                    ;;
                back) return 0 ;;
            esac
        else
            return 0
        fi
    done
}

_main_menu() {
    local last_choice="doctor"
    while true; do
        DIALOG_DEFAULT_ITEM="$last_choice"
        if _dialog_menu "archcanary" 22 76 14 \
                full "Full scan $(_status_glyph "${STATUS[full]:-}")" \
                refresh_full "Refresh + Full scan" \
                checks "Individual checks" \
                rootchecks "🔐 Root checks" \
                lynis_report "🔐 Lynis hardening report" \
                lynis_run "🔐 Run Lynis audit" \
                doctor "Setup health check (--doctor)" \
                search "Search packages" \
                allowlists "Manage allowlists" \
                config "Edit config" \
                settings "Settings" \
                about "About" \
                quit "Quit"; then
            last_choice="$DIALOG_RESULT"
            case "$DIALOG_RESULT" in
                full) _run_and_show "Full scan" true --full; STATUS[full]="$LAST_RC" ;;
                refresh_full) _run_and_show "Refresh + Full scan" true --refresh --full; STATUS[full]="$LAST_RC" ;;
                checks) _checks_menu ;;
                rootchecks) _root_checks_menu ;;
                lynis_report) _run_and_show "Lynis hardening report" true --check-lynis --no-notify ;;
                lynis_run) _run_and_show "Run Lynis audit" true --run-lynis ;;
                doctor) _run_and_show "Setup health check" false --doctor ;;
                search) _search_packages ;;
                allowlists) _allowlists_menu ;;
                config) _config_menu ;;
                settings) _settings_menu ;;
                about) _about ;;
                quit) return 0 ;;
            esac
        else
            return 0
        fi
    done
}

_maybe_show_first_run_notice
_main_menu
clear
