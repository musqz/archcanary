#!/usr/bin/env bash
#
# archcanary.sh - Consolidated Archcanary Script
# Campaign: June 2026 - atomic-lockfile infostealer + eBPF rootkit
#
# Combines best features from all community forks:
#   - Kidev (original):         package list foundation
#   - BrianCArnold (fork):      pacman -Qm efficiency
#   - commonsourcecs (fork):    batch query + date window check
#   - Kacper-Kondracki (fork):  pacman.log scanning + compressed logs
#   - quantenProjects (fork):   safe comm-based approach
#
# Also checks for:
#   - systemd persistence artifacts
#   - eBPF rootkit traces (/sys/fs/bpf/hidden_*)
#   - atomic-lockfile npm cache presence
#
# Usage:
#   ./archcanary.sh                    # normal check
#   ./archcanary.sh --check-systemd    # also scan systemd for unknown services
#   ./archcanary.sh --check-ebpf       # also check for eBPF rootkit traces
#   ./archcanary.sh --check-npm-cache  # also check npm cache for atomic-lockfile
#   ./archcanary.sh --full             # enable all checks
#
# Environment / date window (env vars or equivalent --start-date/--end-date flags):
#   START_DATE=2026-06-09  END_DATE=2026-06-12  ./archcanary.sh
#   ./archcanary.sh --start-date=2026-06-09 --end-date=2026-06-12
#   PACMAN_LOG_GLOB="/var/log/pacman.log*"       ./archcanary.sh
#
# Exit codes:
#   0 = clean
#   1 = warnings (e.g. log scan issues)
#   2 = infected packages found
#
# Sources:
#   https://gist.github.com/Kidev/59bf9f5fb53ab5eee99f19a6a2fc3992
#   https://gist.github.com/BrianCArnold/beb514ffc95a9a251b0dc2f767471fca
#   https://cscs.pastes.sh/aurvulntest20260611.sh
#   https://gist.github.com/Kacper-Kondracki/88c5b313f79cc1f9c347e7ed61a36d10
#   https://gist.github.com/quantenProjects/3f768dce7331618310f016d975bf8547

set -euo pipefail

SCRIPT_VERSION="@VERSION@"
if [[ "$SCRIPT_VERSION" == *"@"* ]]; then
    # Unstamped — running straight from a git checkout rather than an
    # install.sh-installed copy. Fall back to the sibling version.txt.
    # (Checked via a literal "@" rather than comparing against "@VERSION@"
    # itself — install.sh's sed for the placeholder would otherwise also
    # rewrite that string here and break the check on stamped copies.)
    SCRIPT_VERSION=$(cat "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/version.txt" 2>/dev/null || echo "unknown")
fi

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PACMAN_LOG_GLOB=${PACMAN_LOG_GLOB:-/var/log/pacman.log*}
START_DATE=${START_DATE:-}
END_DATE=${END_DATE:-}
# Pulls the live package list from the official Arch Linux HedgeDoc note.
LIST_URL="https://md.archlinux.org/s/SxbqukK6IA/download"
# Supplementary lists — pulled from the repo on --refresh.
MALICIOUS_NPM_LIST_URL="https://raw.githubusercontent.com/musqz/archcanary/master/lists/malicious_npm_packages.txt"
CHAOS_RAT_LIST_URL="https://raw.githubusercontent.com/musqz/archcanary/master/lists/chaos_rat_packages.txt"
RUSSIAN_SPAM_LIST_URL="https://raw.githubusercontent.com/musqz/archcanary/master/lists/malicious_russian_spam_packages.txt"

CHECK_SYSTEMD=false
CHECK_EBPF=false
CHECK_NPM_CACHE=false
CHECK_BUN_CACHE=false
CHECK_YARN_CACHE=false
CHECK_PNPM_CACHE=false
CHECK_PKGBUILD=false
CHECK_BPFTOOL=false
CHECK_LDSO=false
CHECK_AUTOSTART=false
CHECK_KMOD=false
CHECK_LYNIS=false
CHECK_PKGINTEG=false
CHECK_FULL=false
REFRESH_PACKAGE_LIST=false
VERBOSE=false
NO_NOTIFY=false
NO_SUMMARY=false
DOCTOR=false
DOCTOR_SECTIONS=""
RUN_LYNIS=false
_COLOR_ARG="auto"

# CLI arg overrides for env-var-backed settings
PACKAGE_LIST_FILE_OPT=""
MALICIOUS_NPM_LIST_OPT=""
CHAOS_RAT_LIST_OPT=""
RUSSIAN_SPAM_LIST_OPT=""
START_DATE_OPT=""
END_DATE_OPT=""
EXTRA_LIST_OPTS=()

# Temp file cleanup on exit/interrupt
CLEANUP_FILES=()
trap 'rm -f "${CLEANUP_FILES[@]}"' EXIT
trap 'rm -f "${CLEANUP_FILES[@]}"; exit 1' INT TERM

for arg in "$@"; do
    case "$arg" in
        --check-systemd) CHECK_SYSTEMD=true ;;
        --check-ebpf)    CHECK_EBPF=true ;;
        --check-npm-cache)  CHECK_NPM_CACHE=true ;;
        --check-bun-cache)  CHECK_BUN_CACHE=true ;;
        --check-yarn-cache) CHECK_YARN_CACHE=true ;;
        --check-pnpm-cache) CHECK_PNPM_CACHE=true ;;
        --check-pkgbuild)   CHECK_PKGBUILD=true ;;
        --check-bpftool)    CHECK_BPFTOOL=true ;;
        --check-ldso)       CHECK_LDSO=true ;;
        --check-autostart)  CHECK_AUTOSTART=true ;;
        --check-kmod)       CHECK_KMOD=true ;;
        --check-lynis)      CHECK_LYNIS=true ;;
        --check-pkginteg)   CHECK_PKGINTEG=true ;;
        --full)          CHECK_SYSTEMD=true; CHECK_EBPF=true; CHECK_NPM_CACHE=true; CHECK_BUN_CACHE=true; CHECK_YARN_CACHE=true; CHECK_PNPM_CACHE=true; CHECK_PKGBUILD=true; CHECK_BPFTOOL=true; CHECK_LDSO=true; CHECK_AUTOSTART=true; CHECK_KMOD=true; CHECK_LYNIS=true; CHECK_PKGINTEG=true; CHECK_FULL=true ;;
        --refresh)               REFRESH_PACKAGE_LIST=true ;;
        --verbose|-v)            VERBOSE=true ;;
        --debug)                 VERBOSE=true; set -x ;;
        --log-file=*)            LOG_FILE="${arg#*=}" ;;
        --package-list=*)        PACKAGE_LIST_FILE_OPT="${arg#*=}" ;;
        --malicious-npm-list=*)  MALICIOUS_NPM_LIST_OPT="${arg#*=}" ;;
        --chaos-rat-list=*)      CHAOS_RAT_LIST_OPT="${arg#*=}" ;;
        --russian-spam-list=*)   RUSSIAN_SPAM_LIST_OPT="${arg#*=}" ;;
        --extra-list=*)          EXTRA_LIST_OPTS+=("${arg#*=}") ;;
        --start-date=*)          START_DATE_OPT="${arg#*=}" ;;
        --end-date=*)            END_DATE_OPT="${arg#*=}" ;;
        --no-notify)             NO_NOTIFY=true ;;
        --no-summary)            NO_SUMMARY=true ;;
        --color=*)               _COLOR_ARG="${arg#*=}" ;;
        --doctor)                DOCTOR=true ;;
        --doctor=*)              DOCTOR=true; DOCTOR_SECTIONS="${arg#*=}" ;;
        --run-lynis)             RUN_LYNIS=true ;;
        --version|-V)
            echo "Archcanary v${SCRIPT_VERSION}"
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --check-systemd    Scan for unknown systemd services (Restart=always)"
            echo "  --check-ebpf       Check for eBPF rootkit traces (/sys/fs/bpf/hidden_*)"
            echo "  --check-npm-cache  Check npm cache for packages listed in malicious_npm_packages.txt"
            echo "  --check-bun-cache  Check bun cache for packages listed in malicious_npm_packages.txt"
            echo "  --check-yarn-cache Check yarn cache (v1 + Berry, incl. fnm per-version globals)"
            echo "  --check-pnpm-cache Check pnpm store/cache (global installs + metadata + dlx)"
            echo "  --check-pkgbuild   Scan AUR helper caches for obfuscated malicious commands in PKGBUILD/install files"
            echo "  --check-bpftool    Enumerate loaded eBPF programs/links/perf-hooks/net-attachments (needs root)"
            echo "  --check-ldso       Check /etc/ld.so.preload for shared library injection"
            echo "  --check-autostart  Scan XDG autostart entries and shell RCs for low-privilege persistence"
            echo "  --check-kmod       Audit loaded kernel modules against pacman-tracked files (needs root)"
            echo "  --check-lynis      Parse Lynis hardening report (/var/log/lynis-report.dat)"
            echo "  --check-pkginteg   Verify installed file checksums against pacman database (SHA256 mismatch)"
            echo "  --run-lynis        Run a full Lynis audit (lynis audit system) and exit — not included in --full"
            echo "  --full             Enable all checks"
            echo "  --refresh          Download the latest package list before scanning"
            echo "  --verbose, -v, --debug    Verbose output (--debug also enables set -x)"
            echo "  --log-file=PATH           Write full detail log to PATH (auto: ~/.cache/archcanary/aur-check-<date>.log)"
            echo "  --package-list=PATH       Custom infected AUR package list (default: ./package_list.txt)"
            echo "  --malicious-npm-list=PATH Custom malicious npm package name list (default: ./malicious_npm_packages.txt)"
            echo "  --chaos-rat-list=PATH     Custom CHAOS RAT (2025) package list (default: ./chaos_rat_packages.txt)
  --russian-spam-list=PATH  Custom Russian Spam Campaign (2026) list (default: ./malicious_russian_spam_packages.txt)
  --extra-list=PATH_OR_URL  Load an extra package list (file path or https:// URL); repeatable"
            echo "  --start-date=YYYY-MM-DD   Only flag packages installed on or after this date (env: START_DATE)"
            echo "  --end-date=YYYY-MM-DD     Only flag packages installed on or before this date (env: END_DATE)"
            echo "  --no-notify               Suppress the desktop notification on detection
  --no-summary              Suppress the check summary table at the end of a scan"
            echo "  --color=auto|always|never Control symbol/color output (default: auto; also obeys NO_COLOR env)"
            echo "  --doctor                  Report install/config status of every stack element"
            echo "                            (deps, install, systemd, aurscan, traur, yay/paru hooks) and exit"
            echo "  --doctor=SECTION[,...]    Check only the named section(s), with extra detail."
            echo "                            Sections: platform, deps, user, system, systemd, external"
            echo "                            (tool names like aurscan/traur/yad also map to a section)"
            echo "                            Comma- or space-separated, e.g.:"
            echo "                            --doctor=user,system   --doctor user system   --doctor=deps"
            echo "  --version, -V             Show version and exit"
            echo "  --help, -h                Show this help"
            exit 0
            ;;
        *)
            # Bare words after --doctor are treated as section names. This makes
            # space-separated forms work (--doctor user system) and tolerates a
            # stray space in a comma list (--doctor=user, system), where the
            # shell splits "system" off into its own argument.
            if $DOCTOR && [[ "$arg" != -* ]]; then
                DOCTOR_SECTIONS+="${DOCTOR_SECTIONS:+,}$arg"
            fi
            ;;
    esac
done

# Initialise color/symbol globals — respects NO_COLOR env and --color flag.
_init_color() {
    local use=false
    case "$_COLOR_ARG" in
        always) use=true ;;
        never)  use=false ;;
        auto)   [[ -z "${NO_COLOR:-}" && -t 1 ]] && use=true ;;
    esac
    if $use; then
        _CG=$'\e[32m' _CY=$'\e[33m' _CR=$'\e[31m'
        _CB=$'\e[1m'  _CN=$'\e[0m'  _CC=$'\e[36m'
        _SYM_CLEAN="${_CG}✅  clean${_CN}"
        _SYM_WARNINGS="${_CY}⚠   warnings${_CN}"
        _SYM_INFECTED_TXT="${_CR}${_CB}❌  INFECTED${_CN}"
        _SYM_SKIPPED="⚠   skipped (needs root)"
        _SEP55="$(printf '─%.0s' $(seq 1 55))"
    else
        _CG='' _CY='' _CR='' _CB='' _CN='' _CC=''
        _SYM_CLEAN="[ok]   clean"
        _SYM_WARNINGS="[!!]   warnings"
        _SYM_INFECTED_TXT="[!!]   INFECTED"
        _SYM_SKIPPED="[--]   skipped (needs root)"
        _SEP55="$(printf '%0.s-' $(seq 1 55))"
    fi
}
_init_color

# Focused mode: a specific --check-* flag was given without --full.
# Suppresses the campaign header and the always-on package/log checks so
# each individual check window shows only the output it was asked for.
FOCUSED_MODE=false
if ! $CHECK_FULL && { $CHECK_SYSTEMD || $CHECK_EBPF || $CHECK_NPM_CACHE || \
    $CHECK_BUN_CACHE || $CHECK_YARN_CACHE || $CHECK_PNPM_CACHE || $CHECK_PKGBUILD || \
    $CHECK_BPFTOOL || $CHECK_LDSO || $CHECK_AUTOSTART || $CHECK_KMOD || $CHECK_LYNIS || \
    $CHECK_PKGINTEG; }; then
    FOCUSED_MODE=true
fi

# ---------------------------------------------------------------------------
# Setup doctor
# ---------------------------------------------------------------------------
# Standalone health check: report the install/config status of every element
# of the stack and exit. Runs BEFORE the scan machinery (no log tee, no list
# loading) so it never errors on the very state it is meant to report.
#
# Each missing/misconfigured item prints the exact command to fix it. The GUI
# surfaces these fix commands as copyable text / open-terminal actions — it
# never runs them automatically (this is a security tool: it guides, it does
# not silently execute installs).
# ---------------------------------------------------------------------------
run_doctor() {
    # Warn about scan-only flags that have no effect with --doctor.
    local _ignored=()
    $REFRESH_PACKAGE_LIST             && _ignored+=("--refresh")
    [[ ${#EXTRA_LIST_OPTS[@]} -gt 0 ]] && _ignored+=("--extra-list")
    $CHECK_FULL                       && _ignored+=("--full")
    if [[ ${#_ignored[@]} -gt 0 ]]; then
        printf 'NOTE: the following flags are ignored with --doctor: %s\n\n' "${_ignored[*]}" >&2
    fi

    local repo_dir cfg_dir user_bin user_sd
    repo_dir="$(dirname "$(realpath "$0")")"
    local real_user real_home
    real_user="${SUDO_USER:-$USER}"
    real_home="$(getent passwd "$real_user" | cut -d: -f6)"
    [[ -z "$real_home" ]] && real_home="$HOME"
    # Extend PATH with the real user's bin dirs so command -v finds their tools
    # even when running under sudo (root's PATH omits ~/.local/bin).
    export PATH="$real_home/.local/bin:$real_home/bin:$PATH"
    cfg_dir="${XDG_CONFIG_HOME:-$real_home/.config}/archcanary"
    user_bin="$real_home/.local/bin"
    user_sd="${XDG_CONFIG_HOME:-$real_home/.config}/systemd/user"
    local system_installed=false
    [[ -f /usr/local/bin/archcanary || -f /usr/bin/archcanary ]] && system_installed=true

    # The repo-relative fix sources only exist when run from a clone; degrade
    # gracefully to a hint when run from an installed copy.
    local installer="$repo_dir/install.sh" luasrc="$repo_dir/configs/yay-init.lua"
    local installer_sys="$installer"
    if [[ ! -f $installer ]]; then
        installer="install.sh  # (cd to the archcanary repo first)"
        installer_sys="install.sh --system  # (cd to the archcanary repo first)"
    fi
    [[ -f $luasrc ]] || luasrc="configs/yay-init.lua  # (from the archcanary repo)"

    # --- Section selection -------------------------------------------------
    # Sections are listed in install order (prerequisite chain) so a full run
    # reads start-to-finish. --doctor=SECTION[,...] checks a subset, with extra
    # per-item detail (drill-down). Bare --doctor checks all, compactly.
    local ordered=(platform deps user system systemd external)
    local -A want=()
    local detail=0 s
    if [[ -n $DOCTOR_SECTIONS ]]; then
        detail=1
        local _sel; IFS=',' read -ra _sel <<< "$DOCTOR_SECTIONS"
        for s in "${_sel[@]}"; do
            s="${s//[[:space:]]/}"; [[ -z $s ]] && continue
            case "$s" in
                dep|deps|dependencies|yad|bpftool|bpf|notify-send|libnotify|pkexec|polkit) want[deps]=1 ;;
                user|user_install|user-install)     want[user]=1 ;;
                system|system_install|system-install|root) want[system]=1 ;;
                systemd|automation|timer|timers)    want[systemd]=1 ;;
                external|external_tools|external-tools|tools|preinstall|pre-install) want[external]=1 ;;
                aurscan|traur|yay|paru|hooks|lua|init.lua) want[external]=1 ;;  # tool names → their section
                platform|plat|distro)               want[platform]=1 ;;
                all)                                for s in "${ordered[@]}"; do want[$s]=1; done ;;
                *)
                    printf 'Unknown --doctor section: %s\n' "$s" >&2
                    printf 'Valid: platform, deps, user, system, systemd, external (or all).\n' >&2
                    printf 'Tool names (aurscan, traur, yad, …) also map to a section.\n' >&2
                    return 2 ;;
            esac
        done
    else
        for s in "${ordered[@]}"; do want[$s]=1; done
    fi

    local G=$_CG Y=$_CY R=$_CR B=$_CB N=$_CN C=$_CC

    # Four states: OK (present + working), WARN (present but not functioning),
    # MISS (required, absent), OPT (optional addon — absent is fine). WARN and
    # MISS set fail and feed the next-step pointer; OPT never does.
    local fail=0 first_fix="" first_label=""
    _mark() {  # COLOR TAG LABEL [FIX] [DETAIL]
        printf '  %s%s%s  %s\n' "$1" "$2" "$N" "$3"
        [[ -n ${4:-} ]] && printf '           %s↳ fix:%s %s\n' "$B" "$N" "$4"
        [[ $detail -eq 1 && -n ${5:-} ]] && printf '           %s\n' "$5"
        return 0
    }
    _record() { [[ -z $first_fix && -n ${2:-} ]] && { first_fix="$2"; first_label="$1"; }; return 0; }
    _ok()   { _mark "$G" "[ OK ]" "$1" "" "${2:-}"; }
    _warn() { _mark "$Y" "[WARN]" "$1" "${2:-}" "${3:-}"; fail=1; _record "$1" "${2:-}"; }
    _miss() { _mark "$R" "[MISS]" "$1" "${2:-}" "${3:-}"; fail=1; _record "$1" "${2:-}"; }
    _opt()  { _mark "$C" "[OPT ]" "$1" "${2:-}" "${3:-}"; }  # optional addon — absent is not a failure
    # _item LABEL TEST-EXIT [FIX] [DETAIL]  — binary present/absent helper
    _item() {
        if [[ $2 -eq 0 ]]; then _ok "$1" "${4:-}"; else _miss "$1" "${3:-}" "${4:-}"; fi
        return 0
    }
    # _opt_item / _opt_dep — like _item/_dep but missing → [OPT ] not [MISS]; never sets fail.
    # _opt_item forwards its FIX arg ($3) into the "↳ fix:" line, same as _item.
    _opt_item() {
        if [[ $2 -eq 0 ]]; then _ok "$1" "${4:-}"; else _opt "$1" "${3:-}" "${4:-}"; fi
        return 0
    }
    _opt_dep() {
        local label=$1 cmd=$2 pkg=$3 purpose=$4 d=""
        if [[ $detail -eq 1 ]]; then
            if command -v "$cmd" >/dev/null 2>&1; then
                local p="" v=""
                p="$(command -v "$cmd")"
                v="$(timeout 2 "$cmd" --version </dev/null 2>/dev/null | head -n1 || true)"
                d="path: $p${v:+  |  $v}  |  pkg: $pkg"
            else
                d="pkg: $pkg ($purpose)"
            fi
        fi
        if command -v "$cmd" >/dev/null 2>&1; then _ok "$label" "$d"; else _opt "$label" "" "$d"; fi
        return 0
    }
    _have() { command -v "$1" >/dev/null 2>&1 && echo 0 || echo 1; }
    _file() { [[ -e $1 ]] && echo 0 || echo 1; }
    # _marker PATTERN FILE — does FILE contain PATTERN (fixed string)? echo 0/1.
    _marker() { grep -qF -- "$1" "$2" 2>/dev/null && echo 0 || echo 1; }
    # _dep LABEL CMD PKG PURPOSE FIX [VERSION_ARGS] — like _item but, in detail
    # mode, also reports the resolved path and version of an installed dep.
    # VERSION_ARGS is the EXACT version invocation (default "--version"); never
    # guessed, because a wrong arg can make a GUI tool (yad) pop a dialog. Pass
    # "" to skip running the tool entirely (use for GUI binaries).
    _dep() {
        local label=$1 cmd=$2 pkg=$3 purpose=$4 fix=$5 d=""
        local vargs="--version"; [[ $# -ge 6 ]] && vargs="$6"
        if [[ $detail -eq 1 ]]; then
            if command -v "$cmd" >/dev/null 2>&1; then
                local p="" v=""
                p="$(command -v "$cmd")"
                if [[ -n $vargs ]]; then
                    # </dev/null so it can't block on input; timeout as a backstop.
                    v="$(timeout 2 "$cmd" $vargs </dev/null 2>/dev/null | head -n1 || true)"
                fi
                d="path: $p${v:+  |  $v}  |  pkg: $pkg"
            else
                d="pkg: $pkg ($purpose)"
            fi
        fi
        _item "$label" "$(_have "$cmd")" "$fix" "$d"
    }
    # _unit SCOPE UNIT LABEL — check a systemd unit's real state (enabled), not
    # just that the file exists, and give a state-appropriate fix:
    #   not installed  → re-run the installer
    #   disabled       → enable --now (no reinstall needed)
    # SCOPE is "system" or "user". Status queries need no root; the user bus may
    # be absent over SSH/sudo, which is reported rather than flagged as missing.
    _unit() {
        local scope=$1 unit=$2 label=$3
        local sctl="systemctl" pfx="" uarg=""
        if [[ $scope == user ]]; then
            sctl="systemctl --user"; uarg="--user "
        else
            pfx="sudo "
        fi
        if [[ $scope == user ]]; then
            # Some terminals (Openbox, launch-from-menu) don't inherit
            # DBUS_SESSION_BUS_ADDRESS. Try the well-known socket before giving up.
            if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
                local _xrd="/run/user/$(id -u 2>/dev/null || echo 0)"
                [[ -S "$_xrd/bus" ]] && export DBUS_SESSION_BUS_ADDRESS="unix:path=$_xrd/bus"
            fi
            if ! systemctl --user show-environment >/dev/null 2>&1; then
                _warn "$label" \
                    "in a desktop session run: systemctl --user enable --now $unit" \
                    "scope: user — no session bus (SSH/sudo context); can't verify"
                return 0
            fi
        fi
        local state active
        state="$($sctl is-enabled "$unit" 2>/dev/null || true)"
        case "$state" in
            enabled|enabled-runtime|static|indirect|alias|generated)
                active="$($sctl is-active "$unit" 2>/dev/null || true)"
                if [[ $active == active ]]; then
                    _ok "$label" "state: ${state} / ${active}"
                else
                    # Enabled but not running (failed/inactive) — a .timer/.path
                    # should be active; surface it with a restart + status hint.
                    _warn "$label" \
                        "${pfx}systemctl ${uarg}restart $unit   # then: systemctl ${uarg}status $unit" \
                        "state: enabled but ${active:-inactive} — not running; check status"
                fi ;;
            disabled)
                _warn "$label" "${pfx}systemctl ${uarg}enable --now $unit" \
                    "state: present but disabled — not running automatically" ;;
            *)
                _miss "$label" "bash $installer_sys" \
                    "state: not installed" ;;
        esac
    }

    printf '%s============================================================%s\n' "$B" "$N"
    printf '%s Archcanary — setup doctor%s\n' "$B" "$N"
    if [[ -n $DOCTOR_SECTIONS ]]; then
        # Show the resolved sections (in order), not the raw input — keeps the
        # header clean when tool-name aliases or stray spaces were used.
        local _shown=()
        for s in "${ordered[@]}"; do [[ -n ${want[$s]:-} ]] && _shown+=("$s"); done
        printf ' sections: %s\n' "$(IFS=,; echo "${_shown[*]}")"
    fi
    printf '%s============================================================%s\n\n' "$B" "$N"

    # --- Platform ----------------------------------------------------------
    if [[ -n ${want[platform]:-} ]]; then
        local pretty="unknown"
        if [[ -r /etc/os-release ]]; then
            pretty="$(. /etc/os-release; echo "${PRETTY_NAME:-${ID:-unknown}}")"
        fi
        local helpers=() h
        for h in yay paru pamac pikaur trizen aurutils; do
            command -v "$h" >/dev/null 2>&1 && helpers+=("$h") || true
        done
        printf '%sPlatform%s\n' "$B" "$N"
        printf '  detected:    %s\n' "$pretty"
        printf '  AUR helpers: %s\n' "${helpers[*]:-none found}"
        if command -v mhwd >/dev/null 2>&1; then
            printf '  mhwd:        present (Manjaro driver manager — expect DKMS modules)\n'
        fi
        printf '\n'
    fi

    # --- Dependencies ------------------------------------------------------
    if [[ -n ${want[deps]:-} ]]; then
        printf '%sDependencies (official repos)%s\n' "$B" "$N"
        if true; then
            # yad is a GUI binary — never run it to probe a version (a bad arg opens
            # a dialog); pass "" to skip the probe and just report path + pkg.
            _dep "yad (GUI toolkit)"            yad         yad       "GTK dialog toolkit"          "sudo pacman -S yad"        ""
            _dep "bpftool (eBPF enumeration)"  bpftool      bpf       "loaded-eBPF enumeration"     "sudo pacman -S bpf"        version
            _dep "notify-send (desktop alerts)" notify-send libnotify "desktop notifications"       "sudo pacman -S libnotify"
            _dep "pkexec (GUI root checks)"    pkexec       polkit    "GUI privilege escalation"    "sudo pacman -S polkit"
            printf '\n'
        fi
    fi

    # --- User install ------------------------------------------------------
    if [[ -n ${want[user]:-} ]]; then
        printf '%sUser install%s\n' "$B" "$N"
        if ! $system_installed; then
            _item "main scanner (~/.local/bin)" "$(_file "$user_bin/archcanary")"    "bash $installer" "path: $user_bin/archcanary"
            _item "GUI (~/.local/bin)"          "$(_file "$user_bin/archcanary-gui")" "bash $installer" "path: $user_bin/archcanary-gui"
        fi
        _item "package list (config dir)"   "$(_file "$cfg_dir/package_list.txt")" "archcanary --refresh" "path: $cfg_dir/package_list.txt"
        if [[ -e "$cfg_dir" && ! -w "$cfg_dir" ]]; then
            _warn "config dir writable" \
                "sudo chown -R $real_user: \"$cfg_dir\"" \
                "dir is owned by root — --refresh will fail"
        fi
        printf '\n'
    fi

    # --- System install (root) --------------------------------------------
    if [[ -n ${want[system]:-} ]]; then
        printf '%sSystem install (root)%s\n' "$B" "$N"
        _item "scanner script (/usr/lib/archcanary)"     "$(_file /usr/lib/archcanary/archcanary.sh)"          "bash $installer_sys" "path: /usr/lib/archcanary/archcanary.sh"
        _item "root helper (enables root checks in GUI)" "$(_file /usr/lib/archcanary/root-helper)"           "bash $installer_sys" "path: /usr/lib/archcanary/root-helper"
        _item "polkit policy (authorizes the root helper)" "$(_file /usr/share/polkit-1/actions/org.archcanary.policy)" "bash $installer_sys" "path: /usr/share/polkit-1/actions/org.archcanary.policy"
        _item "DKMS allowlist"                           "$(_file /etc/archcanary/dkms_allowlist.conf)"       "bash $installer_sys" "path: /etc/archcanary/dkms_allowlist.conf"
        _item "systemd allowlist"                        "$(_file /etc/archcanary/systemd_allowlist.conf)"    "bash $installer_sys" "path: /etc/archcanary/systemd_allowlist.conf"
        _item "bpftool allowlist"                        "$(_file /etc/archcanary/bpftool_allowlist.conf)"    "bash $installer_sys" "path: /etc/archcanary/bpftool_allowlist.conf"
        _item "autostart allowlist"                      "$(_file /etc/archcanary/autostart_allowlist.conf)"  "bash $installer_sys" "path: /etc/archcanary/autostart_allowlist.conf"
        printf '\n'
    fi

    # --- Automation (systemd) ---------------------------------------------
    if [[ -n ${want[systemd]:-} ]]; then
        printf '%sAutomation (systemd)%s\n' "$B" "$N"
        # Checks enabled state (not just file presence) for the four units the
        # installer enables: two system, two user.
        _unit system "archcanary.timer"        "system scan timer (weekly + boot)"
        _unit system "archcanary.path"         "post-install trigger (scan after each pacman transaction)"
        if [[ $EUID -eq 0 ]]; then
            _ok "user scan timer (cache/autostart checks)"    "skipped — run --doctor as your regular user to check"
            _ok "desktop notifier (alerts on new scan results)" "skipped — run --doctor as your regular user to check"
        else
            _unit user   "archcanary-user.timer"   "user scan timer (cache/autostart checks)"
            _unit user   "archcanary-notify.path"  "desktop notifier (alerts on new scan results)"
        fi
        printf '\n'
    fi

    # --- Pre-install layer (external) -------------------------------------
    if [[ -n ${want[external]:-} ]]; then
        printf '%sPre-install layer (external tools)%s\n' "$B" "$N"
        local yay_init_lua="${XDG_CONFIG_HOME:-$real_home/.config}/yay/init.lua"
        # Markers below are coupled to two OTHER projects' internal, unexported
        # conventions (not a public API either project has committed to):
        # aurscan's yayHookBegin/hookMarker constants (internal/yay/{yayhook,paru}.go)
        # and archcanary's own configs/yay-init.lua header comment. If either
        # project changes its string, update it here too — these checks fail
        # silently (report a working hook as missing) rather than erroring out.
        local _AURSCAN_YAY_MARKER='-- >>> aurscan begin'
        local _AURSCAN_PARU_MARKER='# added by aurscan'
        local _ARCHCANARY_LUA_MARKER='yay 13.0 Lua hooks for the AUR security stack'
        _opt_item "aurscan (pre-install PKGBUILD scanner)" \
            "$(command -v aurscan >/dev/null 2>&1 && echo 0 || echo 1)" \
            "" \
            "binary: $(command -v aurscan 2>/dev/null || echo 'not found — yay -S aurscan-manticore-git')"
        if command -v aurscan >/dev/null 2>&1; then
            _opt_item "claude CLI (aurscan LLM backend)" \
                "$(command -v claude >/dev/null 2>&1 && echo 0 || echo 1)" \
                "" \
                "$(command -v claude 2>/dev/null || echo 'not found — curl -fsSL https://claude.ai/install.sh | bash')"
            if command -v yay >/dev/null 2>&1; then
                _opt_item "aurscan yay hook (AURPostDownload pre-build scan)" \
                    "$(_marker "$_AURSCAN_YAY_MARKER" "$yay_init_lua")" \
                    "aurscan --install-yay-hook" \
                    "marker: '$_AURSCAN_YAY_MARKER' in $yay_init_lua — without this, aurscan is installed but never runs"
            fi
            if command -v paru >/dev/null 2>&1; then
                local paru_conf="${XDG_CONFIG_HOME:-$real_home/.config}/paru/paru.conf"
                _opt_item "aurscan paru hook (PreBuildCommand pre-build scan)" \
                    "$(_marker "$_AURSCAN_PARU_MARKER" "$paru_conf")" \
                    "aurscan --install-paru-hook" \
                    "marker: '$_AURSCAN_PARU_MARKER' in $paru_conf — without this, aurscan is installed but never runs"
            fi
        fi
        _opt_dep "traur (pre-install behavioral scanner)" traur traur "279-signal pre-install scanner"
        if command -v traur >/dev/null 2>&1; then
            _opt_item "traur pacman hook (auto-runs on every install)" \
                "$(_file /usr/share/libalpm/hooks/traur.hook)" \
                "" \
                "path: /usr/share/libalpm/hooks/traur.hook"
        fi
        _opt_dep "lynis (system hardening auditor)" lynis lynis "post-install hardening audit"
        _opt_item "yay init.lua (archcanary's hooks: upgrade-age warning, pattern block, install log)" "$(_marker "$_ARCHCANARY_LUA_MARKER" "$yay_init_lua")" "" "path: $yay_init_lua"
        printf '\n'
    fi

    # --- Next step (first unmet prerequisite) ------------------------------
    if [[ $fail -ne 0 && -n $first_fix ]]; then
        printf '%sNEXT STEP%s → %s\n' "$B" "$N" "$first_label"
        printf '  run: %s\n' "$first_fix"
        printf '  then re-run --doctor to advance to the next step.\n\n'
    fi

    # --- Summary -----------------------------------------------------------
    local scope="all elements"
    [[ -n $DOCTOR_SECTIONS ]] && scope="selected section(s)"
    printf '%s============================================================%s\n' "$B" "$N"
    if [[ $fail -eq 0 ]]; then
        printf ' %sRESULT: %s present.%s\n' "$G" "$scope" "$N"
    else
        printf ' %sRESULT: %s checked — some need attention, see fixes above.%s\n' "$Y" "$scope" "$N"
    fi
    printf '%s============================================================%s\n' "$B" "$N"
    return $fail
}

if $DOCTOR; then
    _doctor_rc=0; run_doctor || _doctor_rc=$?
    exit $_doctor_rc
fi

if $RUN_LYNIS; then
    if ! command -v lynis &>/dev/null; then
        echo "Error: lynis not installed (pacman -S lynis)" >&2
        exit 1
    fi
    # Can't use exec: pipe through sed to strip non-ASCII block chars (▆ etc.)
    # that yad text-info renders as [?] boxes. pipefail off so set -e doesn't
    # fire on lynis's own exit code before we can capture it.
    set +o pipefail
    lynis audit system --no-colors 2>&1 | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/[^\x09\x0A\x0D\x20-\x7E]//g'
    _lynis_exit="${PIPESTATUS[0]}"
    # Lynis exit 2 = "found suggestions/warnings" — normal for a hardening audit,
    # not a malware signal. Map to 1 (warnings) so the GUI doesn't show INFECTED.
    [[ "$_lynis_exit" -eq 2 ]] && _lynis_exit=1
    exit "$_lynis_exit"
fi

# ---------------------------------------------------------------------------
# Apply CLI overrides for env-var-backed settings
# CLI flag > env var > default
# ---------------------------------------------------------------------------
if [[ -n "$PACKAGE_LIST_FILE_OPT" ]]; then
    PACKAGE_LIST_FILE="$PACKAGE_LIST_FILE_OPT"
fi

if [[ -n "$MALICIOUS_NPM_LIST_OPT" ]]; then
    MALICIOUS_NPM_LIST="$MALICIOUS_NPM_LIST_OPT"
fi

if [[ -n "$CHAOS_RAT_LIST_OPT" ]]; then
    CHAOS_RAT_LIST="$CHAOS_RAT_LIST_OPT"
fi

if [[ -n "$RUSSIAN_SPAM_LIST_OPT" ]]; then
    RUSSIAN_SPAM_LIST="$RUSSIAN_SPAM_LIST_OPT"
fi

if [[ -n "$START_DATE_OPT" ]]; then
    START_DATE="$START_DATE_OPT"
fi

if [[ -n "$END_DATE_OPT" ]]; then
    END_DATE="$END_DATE_OPT"
fi

# ---------------------------------------------------------------------------
# Invoking-user home under sudo/pkexec
# Root-requiring checks (--check-kmod/--check-bpftool/--check-ebpf) are run as
# root, but the package lists, dkms allowlist and log/cache dirs live in the
# *invoking* user's home — not /root. The pkexec path is fixed by the root
# helper (via PKEXEC_UID); this restores the same for a direct `sudo` run
# (via SUDO_USER) so the lists are found and logs land in the user's cache.
# ---------------------------------------------------------------------------
if [[ $EUID -eq 0 ]]; then
    _invoker_home=""
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        _invoker_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    elif [[ -n "${PKEXEC_UID:-}" ]]; then
        _invoker_home="$(getent passwd "$PKEXEC_UID" | cut -d: -f6)"
    fi
    if [[ -n "$_invoker_home" ]]; then
        export HOME="$_invoker_home"
        export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$_invoker_home/.config}"
        export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$_invoker_home/.cache}"
    fi
    unset _invoker_home
fi

# Resolves to the invoking user's login name when this script itself is
# running as root (sudo's SUDO_USER, or pkexec's PKEXEC_UID — resolved via
# getent since chown/sudo both reject a bare numeric "UID:" spec). Shared by
# _chown_to_invoker and _run_as_invoker below.
_invoker_user() {
    [[ $EUID -ne 0 ]] && return 0
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        printf '%s' "$SUDO_USER"
    elif [[ -n "${PKEXEC_UID:-}" ]]; then
        getent passwd "$PKEXEC_UID" | cut -d: -f1
    fi
}

# When running under sudo or pkexec, chown a written file back to the invoking
# user so that user-space config/log files are not left owned by root — the
# pkexec root-helper execs straight into this script with no code path of its
# own left to fix ownership afterward.
_chown_to_invoker() {
    local _invoker
    _invoker="$(_invoker_user)"
    [[ -n "$_invoker" ]] && chown "$_invoker": "$1" 2>/dev/null
    return 0
}

# Runs a read-only command as the invoking user instead of root when this
# script itself is running as root — e.g. `npm config get cache` doesn't need
# root, and running it as root just leaves root-owned debug logs under the
# invoking user's ~/.npm/_logs. No-op passthrough otherwise.
_run_as_invoker() {
    local _invoker
    _invoker="$(_invoker_user)"
    if [[ -n "$_invoker" ]]; then
        sudo -u "$_invoker" "$@"
    else
        "$@"
    fi
}

# systemd *system* services (and some cron contexts) start with no $HOME, which
# would make the ${XDG_*:-$HOME/...} fallbacks below fatal under `set -u`.
# Default it to the running user's home (root → /root for the system scan).
if [[ -z "${HOME:-}" ]]; then
    HOME="$(getent passwd "$(id -u)" | cut -d: -f6)"
    export HOME="${HOME:-/root}"
fi

# ---------------------------------------------------------------------------
# Log file: always write full detail, auto-named unless --log-file=PATH
# Default location: XDG_CACHE_HOME/archcanary/ (~/.cache/archcanary/)
# ---------------------------------------------------------------------------
_AUR_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/archcanary"
mkdir -p "$_AUR_CACHE_DIR"
: "${LOG_FILE:=$_AUR_CACHE_DIR/aur-check-$(date +%Y%m%d-%H%M%S).log}"
unset _AUR_CACHE_DIR
# Verify log file writable before redirecting
: > "$LOG_FILE" 2>/dev/null || { echo >&2 "ERROR: Cannot write log file: $LOG_FILE"; exit 1; }
# Redirect all output through tee: terminal + log file
exec > >(tee "$LOG_FILE") 2>&1

# ---------------------------------------------------------------------------
# Config dir: XDG_CONFIG_HOME/archcanary (default ~/.config/archcanary)
# Can be overridden via PACKAGE_LIST_FILE / MALICIOUS_NPM_LIST env vars
# ---------------------------------------------------------------------------
AUR_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/archcanary"
mkdir -p "$AUR_CONFIG_DIR"

PACKAGE_LIST_FILE="${PACKAGE_LIST_FILE:-$AUR_CONFIG_DIR/package_list.txt}"
INFECTED_PKGS=()

CHAOS_RAT_LIST="${CHAOS_RAT_LIST:-$AUR_CONFIG_DIR/chaos_rat_packages.txt}"
CHAOS_RAT_PKGS=()

RUSSIAN_SPAM_LIST="${RUSSIAN_SPAM_LIST:-$AUR_CONFIG_DIR/malicious_russian_spam_packages.txt}"
RUSSIAN_SPAM_PKGS=()

EXTRA_LISTS_CONF="${EXTRA_LISTS_CONF:-$AUR_CONFIG_DIR/extra_lists.conf}"
EXTRA_PKGS=()

MALICIOUS_NPM_LIST="${MALICIOUS_NPM_LIST:-$AUR_CONFIG_DIR/malicious_npm_packages.txt}"

# Merge the DKMS allowlist into DKMS_ALLOWLIST (colon-separated; the env var, if
# set, takes precedence and is appended to). The allowlist is a single system-wide
# file — DKMS modules are machine-level and the kmod audit only runs as root.
# Override the path with DKMS_ALLOWLIST_FILE (used by the tests).
DKMS_ALLOWLIST="${DKMS_ALLOWLIST:-}"
_dkms_cfg="${DKMS_ALLOWLIST_FILE:-/etc/archcanary/dkms_allowlist.conf}"
if [[ -r "$_dkms_cfg" ]]; then    # skip if missing/unreadable (don't abort under set -e)
    while IFS= read -r _dl || [[ -n "$_dl" ]]; do
        _dl="${_dl%%#*}"       # strip inline comments
        read -r _dl _ <<< "$_dl"  # take first token only (ignores trailing descriptions)
        [[ -z "$_dl" ]] && continue
        DKMS_ALLOWLIST="${DKMS_ALLOWLIST:+${DKMS_ALLOWLIST}:}${_dl}"
    done < "$_dkms_cfg"
fi
unset _dkms_cfg _dl

# Merge the systemd allowlist into SYSTEMD_ALLOWLIST (colon-separated; the env
# var, if set, takes precedence and is appended to). Single system-wide file,
# same rationale as the DKMS allowlist above — for unit names that are
# legitimately unowned by pacman (self-hosted apps installed from upstream
# binary releases, e.g. forgejo) and shouldn't trip the systemd persistence check.
# Override the path with SYSTEMD_ALLOWLIST_FILE (used by the tests).
SYSTEMD_ALLOWLIST="${SYSTEMD_ALLOWLIST:-}"
_svc_cfg="${SYSTEMD_ALLOWLIST_FILE:-/etc/archcanary/systemd_allowlist.conf}"
if [[ -r "$_svc_cfg" ]]; then    # skip if missing/unreadable (don't abort under set -e)
    while IFS= read -r _sl || [[ -n "$_sl" ]]; do
        _sl="${_sl%%#*}"       # strip inline comments
        read -r _sl _ <<< "$_sl"  # take first token only (ignores trailing descriptions)
        [[ -z "$_sl" ]] && continue
        SYSTEMD_ALLOWLIST="${SYSTEMD_ALLOWLIST:+${SYSTEMD_ALLOWLIST}:}${_sl}"
    done < "$_svc_cfg"
fi
unset _svc_cfg _sl

# Merge the bpftool allowlist into BPFTOOL_ALLOWLIST (colon-separated; the env
# var, if set, takes precedence and is appended to). Same rationale as DKMS/
# systemd above — for eBPF loader binaries that are legitimately not
# pacman-owned (e.g. a self-built or manually-installed security/monitoring
# tool that loads LSM hooks) and shouldn't trip the bpftool loader check.
# Override the path with BPFTOOL_ALLOWLIST_FILE (used by the tests).
BPFTOOL_ALLOWLIST="${BPFTOOL_ALLOWLIST:-}"
_bpf_cfg="${BPFTOOL_ALLOWLIST_FILE:-/etc/archcanary/bpftool_allowlist.conf}"
if [[ -r "$_bpf_cfg" ]]; then    # skip if missing/unreadable (don't abort under set -e)
    while IFS= read -r _bl || [[ -n "$_bl" ]]; do
        _bl="${_bl%%#*}"       # strip inline comments
        read -r _bl _ <<< "$_bl"  # take first token only (ignores trailing descriptions)
        [[ -z "$_bl" ]] && continue
        BPFTOOL_ALLOWLIST="${BPFTOOL_ALLOWLIST:+${BPFTOOL_ALLOWLIST}:}${_bl}"
    done < "$_bpf_cfg"
fi
unset _bpf_cfg _bl

# Merge the autostart allowlist into AUTOSTART_ALLOWLIST (colon-separated; the
# env var, if set, takes precedence and is appended to). Same rationale as
# DKMS/systemd/bpftool above — for autostart Exec= binaries that are
# legitimately not resolvable via $PATH or a standard system prefix (e.g. a
# package-private helper the resolution fallback still can't find, or an
# AppImage/Flatpak export) and shouldn't trip the XDG autostart check.
# Override the path with AUTOSTART_ALLOWLIST_FILE (used by the tests).
AUTOSTART_ALLOWLIST="${AUTOSTART_ALLOWLIST:-}"
_auto_cfg="${AUTOSTART_ALLOWLIST_FILE:-/etc/archcanary/autostart_allowlist.conf}"
if [[ -r "$_auto_cfg" ]]; then    # skip if missing/unreadable (don't abort under set -e)
    while IFS= read -r _al || [[ -n "$_al" ]]; do
        _al="${_al%%#*}"       # strip inline comments
        read -r _al _ <<< "$_al"  # take first token only (ignores trailing descriptions)
        [[ -z "$_al" ]] && continue
        AUTOSTART_ALLOWLIST="${AUTOSTART_ALLOWLIST:+${AUTOSTART_ALLOWLIST}:}${_al}"
    done < "$_auto_cfg"
fi
unset _auto_cfg _al

# Resolves a bundled data file next to the running script. Checks the flat
# layout first (/usr/lib/archcanary/<file> — how install.sh --system and the
# AUR package deploy it, since root's $HOME isn't seeded) and falls back to
# the lists/ subdir layout (repo checkout, ./archcanary.sh run in place).
_bundled_list_path() {
    local _dir _f
    _dir="$(dirname "$(realpath "$0")")"
    for _f in "$_dir/$1" "$_dir/lists/$1"; do
        if [[ -f "$_f" ]]; then
            printf '%s' "$_f"
            return 0
        fi
    done
    return 1
}

if [[ ! -f "$MALICIOUS_NPM_LIST" ]]; then
    if _bundled="$(_bundled_list_path malicious_npm_packages.txt)"; then
        cp "$_bundled" "$MALICIOUS_NPM_LIST"
    else
        echo >&2 "ERROR: Malicious npm package list not found: $MALICIOUS_NPM_LIST"
        echo >&2 "Copy malicious_npm_packages.txt from the repo to $AUR_CONFIG_DIR/"
        exit 1
    fi
fi

if [[ ! -f "$CHAOS_RAT_LIST" ]]; then
    _bundled="$(_bundled_list_path chaos_rat_packages.txt)" && cp "$_bundled" "$CHAOS_RAT_LIST"
fi

if [[ ! -f "$RUSSIAN_SPAM_LIST" ]]; then
    _bundled="$(_bundled_list_path malicious_russian_spam_packages.txt)" && cp "$_bundled" "$RUSSIAN_SPAM_LIST"
fi

if [[ ! -f "$EXTRA_LISTS_CONF" ]]; then
    cat > "$EXTRA_LISTS_CONF" <<'CONF'
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

MALICIOUS_NPM_PKGS=()
while IFS= read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    MALICIOUS_NPM_PKGS+=("$line")
done < "$MALICIOUS_NPM_LIST"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
load_packages() {
    if $REFRESH_PACKAGE_LIST && [[ -n "$PACKAGE_LIST_FILE_OPT" ]]; then
        echo >&2 "WARNING: --package-list overrides --refresh; using local file."
        REFRESH_PACKAGE_LIST=false
    fi

    if $REFRESH_PACKAGE_LIST; then
        echo "Fetching infected package list..."

        raw=$(curl -fsSL "$LIST_URL") || {
            echo >&2 "ERROR: failed to fetch $LIST_URL"
            exit 1
        }

        # Extract lines that look like package names only (lowercase, digits, dots, plus, underscore, hyphen)
        # Strips HTML, blank lines, comments, and anything that doesn't match a sane pkgname pattern.
        mapfile -t INFECTED_PKGS < <(
            echo "$raw" |
                grep -E '^[a-z0-9][a-z0-9_.+\-]*[a-z0-9+]$' |
                sort -u
        )

        count=${#INFECTED_PKGS[@]}
        if [[ $count -eq 0 ]]; then
            echo >&2 "ERROR: parsed 0 packages, something went wrong with the fetch/parse."
            exit 1
        fi

        # Update compromised packages list
        echo "Updating $PACKAGE_LIST_FILE..."
        printf "%s\n" "${INFECTED_PKGS[@]}" >"$PACKAGE_LIST_FILE"
        _chown_to_invoker "$PACKAGE_LIST_FILE"

        # Refresh supplementary lists from the repo (non-fatal on failure)
        _refresh_list() {
            local url="$1" dest="$2" label="$3" skip_opt="$4"
            [[ -n "$skip_opt" ]] && return   # user supplied --*-list=PATH; don't overwrite
            echo "Fetching $label..."
            local tmp
            tmp=$(curl -fsSL "$url" 2>/dev/null) || {
                echo >&2 "WARNING: failed to fetch $url — keeping existing $label."
                return
            }
            local n
            n=$(printf '%s\n' "$tmp" | grep -c '^[^#[:space:]]' || true)
            if [[ $n -eq 0 ]]; then
                echo >&2 "WARNING: $label fetch returned 0 entries — keeping existing."
                return
            fi
            printf '%s\n' "$tmp" > "$dest"
            _chown_to_invoker "$dest"
            echo "Updated $dest ($n entries)"
        }
        _refresh_list "$MALICIOUS_NPM_LIST_URL"  "$MALICIOUS_NPM_LIST"  "malicious npm list"   "$MALICIOUS_NPM_LIST_OPT"
        _refresh_list "$CHAOS_RAT_LIST_URL"       "$CHAOS_RAT_LIST"      "CHAOS RAT list"       "$CHAOS_RAT_LIST_OPT"
        _refresh_list "$RUSSIAN_SPAM_LIST_URL"    "$RUSSIAN_SPAM_LIST"   "Russian spam list"    "$RUSSIAN_SPAM_LIST_OPT"
        unset -f _refresh_list
    fi

    if [[ ! -f "$PACKAGE_LIST_FILE" ]]; then
        if _bundled="$(_bundled_list_path package_list.txt)"; then
            cp "$_bundled" "$PACKAGE_LIST_FILE"
        else
            echo >&2 "ERROR: Package list not found: $PACKAGE_LIST_FILE"
            echo >&2 "Copy package_list.txt from the repo to $AUR_CONFIG_DIR/, or run with --refresh."
            exit 1
        fi
    fi

    INFECTED_PKGS=()

    while IFS= read -r line; do
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        INFECTED_PKGS+=("$line")
    done <"$PACKAGE_LIST_FILE"

    # CHAOS RAT list (optional — absence is not fatal)
    CHAOS_RAT_PKGS=()
    if [[ -f "$CHAOS_RAT_LIST" ]]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            CHAOS_RAT_PKGS+=("$line")
        done <"$CHAOS_RAT_LIST"
    fi

    # Russian Spam Campaign list (optional — absence is not fatal)
    RUSSIAN_SPAM_PKGS=()
    if [[ -f "$RUSSIAN_SPAM_LIST" ]]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            RUSSIAN_SPAM_PKGS+=("$line")
        done <"$RUSSIAN_SPAM_LIST"
    fi

    # Extra lists — from extra_lists.conf and --extra-list= flags
    EXTRA_PKGS=()
    _load_extra() {
        local src="$1"
        if [[ "$src" =~ ^https?:// ]]; then
            local cached="$AUR_CONFIG_DIR/extra_$(printf '%s' "$src" | md5sum | cut -c1-8).txt"
            if [[ ! -f "$cached" ]] || $REFRESH_PACKAGE_LIST; then
                echo "Fetching extra list: $src"
                local tmp
                tmp=$(curl -fsSL "$src" 2>/dev/null) || {
                    echo >&2 "WARNING: failed to fetch extra list: $src — keeping existing."
                    return
                }
                local n
                n=$(printf '%s\n' "$tmp" | grep -c '^[^#[:space:]]' || true)
                if [[ $n -eq 0 ]]; then
                    echo >&2 "WARNING: extra list $src returned 0 entries — skipping."
                    return
                fi
                printf '%s\n' "$tmp" > "$cached"
                echo "Cached $src → $cached ($n entries)"
            fi
            src="$cached"
        fi
        if [[ ! -f "$src" ]]; then
            echo >&2 "WARNING: extra list not found: $src"
            return
        fi
        local _n=0
        while IFS= read -r line; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            EXTRA_PKGS+=("$line")
            _n=$(( _n + 1 ))
        done < "$src"
        log_info "Extra list $src: $_n entries"
    }
    if [[ -f "$EXTRA_LISTS_CONF" ]]; then
        while IFS= read -r _entry || [[ -n "$_entry" ]]; do
            _entry="${_entry%%#*}"
            _entry="${_entry//[[:space:]]/}"
            [[ -z "$_entry" ]] && continue
            _load_extra "$_entry"
        done < "$EXTRA_LISTS_CONF"
    fi
    for _opt in "${EXTRA_LIST_OPTS[@]}"; do
        _load_extra "$_opt"
    done
    unset -f _load_extra
}

log_info() {
    if $VERBOSE; then
        echo "[INFO] $*"
    else
        echo "[INFO] $*" >> "$LOG_FILE"
    fi
}
log_warn()  { echo >&2 "[WARN] $*"; }


read_compressed_file() {
    local file=$1
    case "$file" in
        *.gz)   gzip -cd -- "$file" 2>/dev/null ;;
        *.xz)   xz -cd -- "$file" 2>/dev/null ;;
        *.zst)  zstdcat -- "$file" 2>/dev/null ;;
        *.bz2)  bzip2 -cd -- "$file" 2>/dev/null ;;
        *)      cat -- "$file" ;;
    esac
}

print_list() {
    local -n arr=$1
    for item in "${arr[@]}"; do echo "  - $item"; done
}

# ---------------------------------------------------------------------------
# Check 1: Currently installed foreign packages
# (Efficiency from commonsourcecs: pacman -Qmq in batch)
# ---------------------------------------------------------------------------
check_current() {
    local found=()
    while IFS= read -r pkg; do
        [[ -v INFECTED_LOOKUP["$pkg"] ]] || continue
        local install_date install_date_iso
        install_date=$(LC_ALL=C pacman -Qi -- "$pkg" 2>/dev/null | awk -F': ' '/^Install Date/ { print $2; exit }')
        [[ -n "$install_date" ]] || continue
        if [[ -n "$START_DATE" || -n "$END_DATE" ]]; then
            install_date_iso=$(date -d "$install_date" +%F 2>/dev/null) || true
            [[ -n "$install_date_iso" ]] || continue
            [[ -z "$START_DATE" || ! "$install_date_iso" < "$START_DATE" ]] || continue
            [[ -z "$END_DATE"   || ! "$install_date_iso" > "$END_DATE"   ]] || continue
        fi
        if [[ -v CHAOS_LOOKUP["$pkg"] ]]; then
            found+=("$pkg (installed: $install_date) [CHAOS RAT campaign, 2025-07]")
        else
            found+=("$pkg (installed: $install_date)")
        fi
    done < <(pacman -Qmq "${INFECTED_PKGS[@]}" 2>/dev/null)

    if [[ ${#found[@]} -eq 0 ]]; then
        echo "  Clean: no infected packages currently installed."
        return 0
    else
        echo "  WARNING: ${#found[@]} possibly infected package(s):"
        print_list found
        return 2
    fi
}

# ---------------------------------------------------------------------------
# Check 2: Historical pacman logs
# (From Kacper-Kondracki: scan pacman.log* for install events)
# ---------------------------------------------------------------------------
check_logs() {
    local log_files=()

    # shellcheck disable=SC2086
    for file in $PACMAN_LOG_GLOB; do
        [[ -e "$file" ]] && log_files+=("$file")
    done

    if [[ ${#log_files[@]} -eq 0 ]]; then
        log_warn "No pacman log files matched: $PACMAN_LOG_GLOB"
        return 1
    fi

    # O(1) lookup table instead of grep -xF on tempfile per line
    declare -A pkg_map
    for pkg in "${INFECTED_PKGS[@]}"; do pkg_map[$pkg]=1; done

    local re_date='^\[([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:+-]+)\]'
    local re_alpm='\[ALPM\] ([a-z]+) ([^ ]+)'
    local total=${#log_files[@]} idx=0 file line datetime_str date_str action pkg

    for file in "${log_files[@]}"; do
        idx=$((idx + 1))
        if [[ ! -r "$file" ]]; then
            log_warn "Skipped $file: not readable"
            continue
        fi
        log_info "[$idx/$total] Scanning $(basename "$file")..."

        while IFS= read -r line; do
            [[ "$line" =~ $re_date ]] || continue
            datetime_str=${BASH_REMATCH[1]}
            date_str="${datetime_str:0:10}"

            if [[ -n "$START_DATE" || -n "$END_DATE" ]]; then
                [[ -z "$START_DATE" || ! "$date_str" < "$START_DATE" ]] || continue
                [[ -z "$END_DATE"   || ! "$date_str" > "$END_DATE"   ]] || continue
            fi

            [[ "$line" =~ $re_alpm ]] || continue
            action=${BASH_REMATCH[1]}
            pkg=${BASH_REMATCH[2]}

            [[ -v pkg_map[$pkg] ]] || continue
            [[ "$action" == "installed" || "$action" == "upgraded" || "$action" == "reinstalled" ]] || continue

            if [[ -v CHAOS_LOOKUP[$pkg] ]]; then
                echo "LOG_HIT: $pkg ($action on $datetime_str) [CHAOS RAT campaign, 2025-07]"
            else
                echo "LOG_HIT: $pkg ($action on $datetime_str)"
            fi
        done < <(read_compressed_file "$file") || true

        log_info "[$idx/$total] Done with $(basename "$file")"
    done
}

# ---------------------------------------------------------------------------
# Check 3: systemd persistence artifacts
# Widened from the original Restart=always + RestartSec=30 pair to cover:
#   - any broad Restart= policy in .service files and drop-in overrides
#   - .timer units with OnBootSec= + Persistent=true (timer-based persistence)
# Scan dirs are overridable via SYSTEMD_SCAN_DIRS (colon-separated) for testing.
# ---------------------------------------------------------------------------
# Returns 0 if a .service file is legitimate: pacman-owned, or its ExecStart
# binary lives in a standard system prefix and exists on disk. Malware points
# ExecStart at /tmp/, /dev/shm/, $HOME, etc., which is never vetted.
_service_vetted() {
    local svc="$1"
    [[ -f "$svc" ]] || return 1
    pacman -Qo "$svc" &>/dev/null 2>&1 && return 0
    local exec_start
    exec_start=$(grep -oP '^ExecStart=[-+@!:]*\K[^[:space:]]+' "$svc" 2>/dev/null | head -1)
    if [[ -n "$exec_start" && "$exec_start" == /* ]]; then
        if [[ "$exec_start" == /usr/* || "$exec_start" == /opt/* || \
              "$exec_start" == /bin/* || "$exec_start" == /sbin/* || \
              "$exec_start" == /usr/local/* ]] && [[ -f "$exec_start" ]]; then
            return 0
        fi
    fi
    return 1
}

# Locate the .service file a unit name resolves to, across the standard dirs
# plus the directory currently being scanned.
_find_service_file() {
    local name="$1" scan_dir="$2" cand
    for cand in "$scan_dir/$name" /etc/systemd/system/"$name" \
                /run/systemd/system/"$name" /usr/lib/systemd/system/"$name"; do
        [[ -f "$cand" ]] && { printf '%s\n' "$cand"; return 0; }
    done
    return 1
}

# Resolve a scanned .service/.timer/.conf path to the unit name a
# SYSTEMD_ALLOWLIST entry would refer to it by. A drop-in override
# (".../unitname.service.d/override.conf") resolves to "unitname.service" so
# one allowlist entry covers the unit and all its drop-ins.
_systemd_unit_name() {
    local path="$1" base
    base="$(basename "$path")"
    if [[ "$base" == *.service || "$base" == *.timer ]]; then
        printf '%s\n' "$base"
    else
        base="$(basename "$(dirname "$path")")"
        printf '%s\n' "${base%.d}"
    fi
}

# True if $1 (a name — unit, DKMS module, loader binary) is in the allowlist
# array named $2 (passed by name since bash can't return arrays). Shared by
# every allowlist-backed check (systemd, DKMS, bpftool).
_allowlist_contains() {
    local name="$1" allow_arr_name="$2" _a
    local -n _allow="$allow_arr_name"
    for _a in "${_allow[@]}"; do
        [[ "$_a" == "$name" ]] && return 0
    done
    return 1
}

check_systemd() {
    local found=()
    local re_restart='^Restart=(always|on-failure|on-abnormal|on-abort)'
    # SYSTEMD_ALLOWLIST: colon-separated list of unit names that are known-good
    # but not tracked by pacman and not vetted by the standard-prefix check
    # (e.g. a self-hosted app installed from an upstream binary release).
    # Example: SYSTEMD_ALLOWLIST=forgejo.service:forgejo.timer
    local -a _svc_allow
    IFS=: read -ra _svc_allow <<< "${SYSTEMD_ALLOWLIST:-}"

    IFS=: read -ra dirs <<< "${SYSTEMD_SCAN_DIRS:-/etc/systemd/system:$HOME/.config/systemd/user}"

    for dir in "${dirs[@]}"; do
        [[ -d "$dir" ]] || continue

        # User systemd dirs (path ends with systemd/user or systemd/user/...):
        # skip timer check — OnBootSec+Persistent is standard for user timers.
        local is_user_dir=false
        [[ "$dir" == */systemd/user || "$dir" == */systemd/user/* ]] && is_user_dir=true

        # .service files and their drop-in overrides (*.service.d/*.conf)
        # Skip if pacman owns the file (AUR/repo-installed daemon).
        # Skip if the ExecStart binary is in a standard system prefix and exists
        # (proprietary installers — piavpn, forgejo binary releases — register
        # the service file outside pacman but always put their binary in /opt/ or
        # /usr/local/; malware typically points to /tmp/, /dev/shm/, $HOME, etc.)
        while IFS= read -r svc; do
            pacman -Qo "$svc" &>/dev/null 2>&1 && continue
            if grep -qE "$re_restart" "$svc" 2>/dev/null; then
                local exec_start
                exec_start=$(grep -oP '^ExecStart=[-+@!:]*\K[^[:space:]]+' "$svc" 2>/dev/null | head -1)
                if [[ -n "$exec_start" && "$exec_start" == /* ]]; then
                    if [[ "$exec_start" == /usr/* || "$exec_start" == /opt/* || \
                          "$exec_start" == /bin/* || "$exec_start" == /sbin/* || \
                          "$exec_start" == /usr/local/* ]] && [[ -f "$exec_start" ]]; then
                        continue
                    fi
                fi
                local match
                match=$(grep -oE "$re_restart" "$svc" | head -1)
                if _allowlist_contains "$(_systemd_unit_name "$svc")" _svc_allow; then
                    echo "  INFO: systemd unit allowlisted (not vetted): $svc ($match)"
                    continue
                fi
                found+=("$svc ($match)")
            fi
        done < <(find "$dir" \( -name '*.service' -o -name '*.conf' \) -type f 2>/dev/null)

        # .timer units with boot persistence — system dirs only, pacman-owned skipped.
        # A timer itself is harmless; what matters is the service it launches. So a
        # persistent timer is only flagged when its target .service is NOT vetted
        # (e.g. ExecStart in /tmp). A timer triggering a legit service (standard
        # prefix or pacman-owned) is benign — this is why our own units don't trip.
        $is_user_dir && continue
        while IFS= read -r timer; do
            pacman -Qo "$timer" &>/dev/null 2>&1 && continue
            if grep -q 'OnBootSec=' "$timer" 2>/dev/null && grep -q 'Persistent=true' "$timer" 2>/dev/null; then
                local target svc_file
                target=$(grep -oP '^\s*Unit=\K\S+' "$timer" 2>/dev/null | head -1)
                [[ -z "$target" ]] && target="$(basename "${timer%.timer}").service"
                svc_file=$(_find_service_file "$target" "$dir") || svc_file=""
                # Vetted target → benign timer; skip. Otherwise flag it.
                [[ -n "$svc_file" ]] && _service_vetted "$svc_file" && continue
                if _allowlist_contains "$(_systemd_unit_name "$timer")" _svc_allow; then
                    echo "  INFO: systemd timer allowlisted (not vetted): $timer (timer → ${target})"
                    continue
                fi
                found+=("$timer (timer → ${target}${svc_file:+, unvetted})")
            fi
        done < <(find "$dir" -name '*.timer' -type f 2>/dev/null)
    done

    if [[ ${#found[@]} -gt 0 ]]; then
        echo "  WARNING: ${#found[@]} suspicious systemd unit(s) found:"
        print_list found
        return 2
    fi
    echo "  Clean: no suspicious systemd units found."
    return 0
}

# ---------------------------------------------------------------------------
# Check 4: eBPF rootkit traces
# (From ioctl.fail analysis: /sys/fs/bpf/hidden_* maps)
# ---------------------------------------------------------------------------
check_ebpf() {
    if [[ ! -d /sys/fs/bpf ]]; then
        echo "  /sys/fs/bpf not accessible — BPF filesystem not mounted or insufficient privileges."
        echo "  → Requires root to scan for hidden BPF maps (e.g. hidden_pids, hidden_names)."
        echo "  → Try: sudo archcanary --check-ebpf"
        echo "  → Skip this check if eBPF rootkit detection is not needed for your threat model."
        return 77
    fi

    local found=()
    for map in hidden_pids hidden_names hidden_inodes; do
        if [[ -e "/sys/fs/bpf/$map" ]]; then
            found+=("/sys/fs/bpf/$map")
        fi
    done

    if [[ ${#found[@]} -gt 0 ]]; then
        echo "  WARNING: eBPF rootkit traces found:"
        print_list found
        return 2
    fi
    echo "  Clean: no eBPF rootkit traces detected."
    return 0
}

# ---------------------------------------------------------------------------
# Check 8: loaded eBPF programs/links (bpftool)
# Three sub-checks, each covering a different attack surface:
#
# prog show — enumerates ALL programs loaded in the kernel, including unpinned
#   ones an eBPF rootkit keeps alive via an open fd or BPF link (not visible
#   in /sys/fs/bpf). Warns when stealth-associated hook types are present:
#   kprobe/kretprobe/tracepoint/raw_tracepoint/perf_event/tracing/lsm.
#
# perf show — lists every kprobe/kretprobe/tracepoint/uprobe with the owning
#   PID and the exact kernel function being hooked. Flags hooks on functions
#   rootkits use to hide files (getdents64), processes (kill), and network
#   connections (tcp_v4_connect, inet_csk_accept).
#
# net show — lists XDP, TC, TCX, and netfilter programs attached to network
#   interfaces. A rootkit can use XDP/TC to silently drop or intercept packets
#   (e.g. hide C2 traffic). On a typical Arch workstation this should be empty.
# ---------------------------------------------------------------------------
check_bpftool() {
    # BPFTOOL_CMD overrides the real command for testing.
    local bpftool_cmd="${BPFTOOL_CMD:-bpftool}"
    # BPFTOOL_ALLOWLIST: colon-separated list of loader binary basenames that
    # are known-good but not pacman-owned (a self-built or manually-installed
    # security/monitoring tool that legitimately loads LSM eBPF hooks).
    # Example: BPFTOOL_ALLOWLIST=falco:my-lsm-tool
    local -a _bpf_allow
    IFS=: read -ra _bpf_allow <<< "${BPFTOOL_ALLOWLIST:-}"

    if ! command -v "$bpftool_cmd" &>/dev/null; then
        echo "  Skipped: bpftool not installed (pacman -S bpf)."
        return 0
    fi

    # Enumerating BPF objects requires CAP_BPF / CAP_SYS_ADMIN.
    local progs
    if ! progs=$("$bpftool_cmd" prog show 2>/dev/null); then
        echo "  Cannot enumerate BPF programs — needs root."
        echo "  → Try: sudo $0 --check-bpftool"
        return 77
    fi

    local worst_ret=0

    # --- prog show: count programs, flag stealth hook types ---
    if [[ -z "$progs" ]]; then
        echo "  Loaded eBPF programs: 0"
    else
        local total stealth
        total=$(grep -cE '^[0-9]+:' <<<"$progs")
        stealth=$(grep -oiwE 'kprobe|kretprobe|tracepoint|raw_tracepoint|perf_event|tracing|lsm' <<<"$progs" \
                  | tr '[:upper:]' '[:lower:]' | sort -u | paste -sd, -)

        echo "  Loaded eBPF programs: $total"
        if [[ -n "$stealth" ]]; then
            local non_lsm_stealth unknown_loaders
            non_lsm_stealth=$(tr ',' '\n' <<<"$stealth" | grep -v '^lsm$' | paste -sd, -)
            # systemd(1) and its child services (systemd-networkd, systemd-journald, etc.)
            unknown_loaders=$(grep -E '^\s+pids ' <<<"$progs" \
                | grep -Ev 'systemd[a-z-]*\([0-9]+\)|apparmor_parser\([0-9]+\)|selinuxd\([0-9]+\)' || true)

            if [[ -z "$unknown_loaders" ]]; then
                # All programs (with pids) are owned by systemd / AppArmor / SELinux — safe regardless of type.
                if [[ -z "$non_lsm_stealth" ]]; then
                    echo "  INFO: lsm eBPF programs present — expected (systemd sandboxing / AppArmor / SELinux)."
                else
                    echo "  INFO: eBPF hook types present ($non_lsm_stealth) — all loaded by systemd / AppArmor / SELinux."
                fi
            elif [[ -z "$non_lsm_stealth" ]]; then
                # Resolve each loader: if /proc/<pid>/exe is a pacman-owned binary, it's a known package
                # (e.g. VPN daemons, security tools written in Python/Go/etc.) — downgrade to INFO.
                local all_known=true resolved_entries=()
                while IFS= read -r entry; do
                    entry="${entry//[[:space:]]/}"
                    [[ -z "$entry" ]] && continue
                    local pid exe pkg
                    pid=$(grep -oP '\(\K[0-9]+(?=\))' <<<"$entry" || true)
                    if [[ -n "$pid" ]] && exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null); then
                        pkg=$(pacman -Qo "$exe" 2>/dev/null | awk '{print $5}' || true)
                        if [[ -n "$pkg" ]]; then
                            resolved_entries+=("$entry ($pkg)")
                        elif _allowlist_contains "$(basename "$exe")" _bpf_allow; then
                            resolved_entries+=("$entry (allowlisted)")
                        else
                            resolved_entries+=("$entry")
                            all_known=false
                        fi
                    else
                        resolved_entries+=("$entry")
                        all_known=false
                    fi
                done < <(sed 's/^\s*pids\s*//' <<<"$unknown_loaders" | tr ',' '\n')

                local resolved_str
                resolved_str=$(IFS=', '; echo "${resolved_entries[*]}")

                if [[ "$all_known" == true ]]; then
                    echo "  INFO: lsm eBPF programs loaded by non-systemd process (pacman-owned or allowlisted)."
                    echo "  Loaders: $resolved_str"
                else
                    echo "  WARNING: lsm eBPF programs loaded by unknown process (expected systemd / AppArmor / SELinux)."
                    echo "  Unknown loaders: $resolved_str"
                    echo "  If this looks like a false positive, report it at https://github.com/musqz/archcanary/issues"
                    worst_ret=1
                fi
            else
                local warn_types="${non_lsm_stealth:-$stealth}"
                echo "  WARNING: stealth-associated program types present: $warn_types"
                echo "  These hook types are used by eBPF rootkits to hide PIDs/files/processes."
                echo "  Review: sudo bpftool prog show ; sudo bpftool link show"
                echo "  (Legitimate if you run bpftrace/bcc/sysprof/Falco — confirm the source.)"
                worst_ret=1
            fi
        else
            echo "  Clean: only non-stealth program types (cgroup/net) loaded."
        fi
    fi

    # --- perf show: kprobe/tracepoint attachments with owning PID and target ---
    local perf_out
    perf_out=$("$bpftool_cmd" perf show 2>/dev/null) || true
    if [[ -z "$perf_out" ]]; then
        echo "  Perf attachments (kprobe/tracepoint): none."
    else
        local perf_count
        perf_count=$(grep -c 'prog_id' <<<"$perf_out" || true)
        echo "  Perf attachments (kprobe/tracepoint/uprobe): $perf_count"
        # Flag hooks on the functions rootkits use to hide files, PIDs, and network connections.
        local suspicious_perf
        suspicious_perf=$(grep -iE '\b(getdents|sys_kill|__x64_sys_kill|tcp_v4_connect|inet_csk_accept|security_inode_getattr|security_file_open)\b' \
                          <<<"$perf_out" || true)
        if [[ -n "$suspicious_perf" ]]; then
            echo "  WARNING: kprobes on rootkit-associated functions (file-hide/process-hide/network):"
            echo "$suspicious_perf" | sed 's/^/    /'
            echo "  Confirm: sudo bpftool perf show"
            worst_ret=1
        else
            echo "  No hooks on rootkit-associated functions."
        fi
        echo "$perf_out" | sed 's/^/    /'
    fi

    # --- net show: XDP / TC programs attached to network interfaces ---
    local net_out
    net_out=$("$bpftool_cmd" net show 2>/dev/null) || true
    local net_entries
    net_entries=$(grep -vE '^(xdp:|tc:|flow_dissector:|netfilter:|tcx:|netkit:)\s*$' <<<"$net_out" \
                  | grep -v '^\s*$' || true)
    if [[ -z "$net_entries" ]]; then
        echo "  Net attachments (XDP/TC): none."
    else
        echo "  WARNING: eBPF programs attached to network interfaces:"
        echo "$net_out" | sed 's/^/    /'
        echo "  On a workstation, unexpected XDP/TC programs may intercept or filter traffic."
        echo "  Confirm: sudo bpftool net show"
        [[ $worst_ret -lt 1 ]] && worst_ret=1
    fi

    return $worst_ret
}

# ---------------------------------------------------------------------------
# Check 5: npm cache for malicious packages
# ---------------------------------------------------------------------------
check_npm_cache() {
    local pkgs=("${MALICIOUS_NPM_PKGS[@]}")
    local found_count=0

    # Hoisted out of the loop: each is invariant per run (same output
    # regardless of which package name is being checked), so calling them
    # once per package was firing 2-3x redundant npm subprocesses per entry
    # in the list — and, under sudo/pkexec, each one left a root-owned debug
    # log in the invoking user's ~/.npm/_logs (npm 7+ logs every invocation).
    local npm_cache global_root npm_cache_dir
    npm_cache=$(_run_as_invoker npm cache ls 2>/dev/null)
    global_root=$(_run_as_invoker npm root -g 2>/dev/null)
    npm_cache_dir=$(_run_as_invoker npm config get cache 2>/dev/null)

    for pkg in "${pkgs[@]}"; do
        local hit
        hit=$(grep "$pkg" <<< "$npm_cache" || true)
        if [[ -n "$hit" ]]; then
            echo "  WARNING: $pkg found in npm cache:"
            # shellcheck disable=SC2001
            sed 's/^/    /' <<< "$hit"
            found_count=2
        fi

        local global_mod="$global_root/$pkg"
        if [[ -d "$global_mod" ]]; then
            echo "  WARNING: $pkg found in global node_modules"
            found_count=2
        fi

        if [[ -d "$npm_cache_dir" ]]; then
            local cached
            cached=$(find "$npm_cache_dir" -name "*${pkg}*" -type d 2>/dev/null | head -5 || true)
            if [[ -n "$cached" ]]; then
                echo "  WARNING: $pkg in npm cache directory:"
                # shellcheck disable=SC2001
                sed 's/^/    /' <<< "$cached"
                found_count=2
            fi
        fi
    done

    if [[ $found_count -eq 0 ]]; then
        echo "  Clean: no malicious packages in npm cache."
    fi
    return $found_count
}

# ---------------------------------------------------------------------------
# Check 6: bun cache for malicious packages
# ---------------------------------------------------------------------------
check_bun_cache() {
    local pkgs=("${MALICIOUS_NPM_PKGS[@]}")
    local found_count=0

    for pkg in "${pkgs[@]}"; do
        local bun_cache
        bun_cache=$(bun pm cache ls 2>/dev/null | grep "$pkg" || true)
        if [[ -n "$bun_cache" ]]; then
            echo "  WARNING: $pkg found in bun cache:"
            # shellcheck disable=SC2001
            sed 's/^/    /' <<< "$bun_cache"
            found_count=2
        fi
    done

    local bun_cache_dir
    bun_cache_dir=$(bun pm cache 2>/dev/null || echo ~/.bun/install/cache)
    if [[ -d "$bun_cache_dir" ]]; then
        for pkg in "${pkgs[@]}"; do
            local cached
            cached=$(find "$bun_cache_dir" -name "*${pkg}*" -type d 2>/dev/null | head -5 || true)
            if [[ -n "$cached" ]]; then
                echo "  WARNING: $pkg in bun cache directory:"
                # shellcheck disable=SC2001
                sed 's/^/    /' <<< "$cached"
                found_count=2
            fi
        done
    fi

    if [[ $found_count -eq 0 ]]; then
        echo "  Clean: no malicious packages in bun cache."
    fi
    return $found_count
}

# ---------------------------------------------------------------------------
# Check 7: PKGBUILD / install file scan for obfuscated malicious commands
# Strips single and double quotes from each line before matching, catching
# obfuscation like 'b''u''n' 'a'"d""d" 'j''s'"-""d""i""g""e""s""t"
# ---------------------------------------------------------------------------
check_pkgbuild_caches() {
    # PKGBUILD_CACHE_DIRS overrides the default AUR helper cache locations (colon-separated)
    local cache_dirs_default="$HOME/.cache/yay:$HOME/.cache/paru:$HOME/.cache/aurutils:$HOME/.cache/pikaur:$HOME/.cache/trizen"
    IFS=: read -ra cache_dirs <<< "${PKGBUILD_CACHE_DIRS:-$cache_dirs_default}"

    local found_count=0
    local scanned=0
    # matches $'\x.. or $'\0.. (ANSI-C hex/octal quoting)
    local re_ansi_c
    re_ansi_c='\$'"'"'\\x|\$'"'"'\\0'

    while IFS= read -r file; do
        (( scanned++ )) || true
        local lineno=0
        while IFS= read -r line; do
            (( lineno++ )) || true

            # --- Pattern 1: quote-split bun/npm command (original) ---
            local stripped="${line//\'/}"
            stripped="${stripped//\"/}"
            if [[ "$stripped" =~ (bun[[:space:]]+add|npm[[:space:]]+install) ]]; then
                for pkg in "${MALICIOUS_NPM_PKGS[@]}"; do
                    if [[ "$stripped" == *"$pkg"* ]]; then
                        echo "  WARNING: malicious package install in $file:$lineno"
                        echo "    $line"
                        found_count=2
                        break
                    fi
                done
            fi

            # --- Pattern 2: base64 decode piped to shell ---
            if [[ "$line" =~ base64[[:space:]]+(--decode|-d)[[:space:]]*\|[[:space:]]*(bash|sh|eval) ]]; then
                echo "  WARNING: base64-decode-to-shell in $file:$lineno"
                echo "    $line"
                found_count=2
            fi

            # --- Pattern 3: eval + command substitution ---
            if [[ "$line" =~ eval[[:space:]]+\$\( || "$line" =~ eval[[:space:]]+\` ]]; then
                echo "  WARNING: eval+subshell in $file:$lineno"
                echo "    $line"
                found_count=2
            fi

            # --- Pattern 4: printf hex/octal obfuscation ---
            if [[ "$line" == *'printf'* ]] && [[ "$line" == *'\x'* || "$line" == *'\0'* ]]; then
                echo "  WARNING: printf hex/octal obfuscation in $file:$lineno"
                echo "    $line"
                found_count=2
            fi

            # --- Pattern 5: variable-split command reassembly (a=bu; b=n; $a$b) ---
            if [[ "$line" =~ [a-z_]+=[a-zA-Z]+\;[[:space:]]*[a-z_]+=[a-zA-Z]+\;[[:space:]]*\$ ]]; then
                echo "  WARNING: variable-split command reassembly in $file:$lineno"
                echo "    $line"
                found_count=2
            fi

            # --- Pattern 6: ANSI-C quoting with hex/octal ($'\x.. or $'\0..) ---
            if [[ "$line" =~ $re_ansi_c ]]; then
                echo "  WARNING: ANSI-C hex/octal quoting in $file:$lineno"
                echo "    $line"
                found_count=2
            fi

            # --- Pattern 7: rev/tr pipe-to-shell obfuscation ---
            if [[ "$line" =~ \|[[:space:]]*(rev|tr)[[:space:]] ]] && \
               [[ "$line" =~ \|[[:space:]]*(bash|sh|eval) ]]; then
                echo "  WARNING: rev/tr pipe-to-shell obfuscation in $file:$lineno"
                echo "    $line"
                found_count=2
            fi

        done < "$file"
    done < <(
        for dir in "${cache_dirs[@]}"; do
            [[ -d "$dir" ]] || continue
            find "$dir" \( -name "PKGBUILD" -o -name "*.install" \) -type f 2>/dev/null
        done
    )

    if [[ $scanned -eq 0 ]]; then
        echo "  Skipped: no AUR helper cache directories found."
    elif [[ $found_count -eq 0 ]]; then
        echo "  Clean: no malicious commands found in $scanned PKGBUILD/install file(s)."
    fi
    return $found_count
}

# ---------------------------------------------------------------------------
# Helper: scan every fnm-managed Node version's global node_modules.
# fnm installs a separate Node per version; `npm root -g` only sees the active
# one. Honors $FNM_DIR, falling back to ~/.local/share/fnm then ~/.fnm.
# ---------------------------------------------------------------------------
scan_fnm_globals() {
    local pkgs=("${MALICIOUS_NPM_PKGS[@]}")
    local found=0
    local fnm_dir="${FNM_DIR:-$HOME/.local/share/fnm}"
    [[ -d "$HOME/.fnm/node-versions" ]] && fnm_dir="$HOME/.fnm"
    [[ -d "$fnm_dir/node-versions" ]] || return 0
    for ver_dir in "$fnm_dir"/node-versions/*; do
        local ver_modules="$ver_dir/installation/lib/node_modules"
        [[ -d "$ver_modules" ]] || continue
        for pkg in "${pkgs[@]}"; do
            if [[ -d "$ver_modules/$pkg" ]]; then
                echo "  WARNING: $pkg found in fnm Node global node_modules ($ver_modules)"
                found=2
            fi
        done
    done
    return $found
}

# ---------------------------------------------------------------------------
# Check: yarn cache for malicious packages (Classic v1 + Berry v2+, incl. fnm)
# ---------------------------------------------------------------------------
check_yarn_cache() {
    local pkgs=("${MALICIOUS_NPM_PKGS[@]}")
    local found_count=0 fnm_ret

    local -a cache_dirs=()
    if command -v yarn >/dev/null 2>&1; then
        local yarn_cache_dir
        yarn_cache_dir=$(yarn cache dir 2>/dev/null || true)
        [[ -n "$yarn_cache_dir" && -d "$yarn_cache_dir" ]] && cache_dirs+=("$yarn_cache_dir")
    fi
    [[ -d "${XDG_CACHE_HOME:-$HOME/.cache}/yarn" ]] && cache_dirs+=("${XDG_CACHE_HOME:-$HOME/.cache}/yarn")
    [[ -d "$HOME/.yarn/berry/cache" ]] && cache_dirs+=("$HOME/.yarn/berry/cache")

    for dir in "${cache_dirs[@]}"; do
        for pkg in "${pkgs[@]}"; do
            local cached
            cached=$(find "$dir" -name "*${pkg}*" 2>/dev/null | head -5 || true)
            if [[ -n "$cached" ]]; then
                echo "  WARNING: $pkg in yarn cache ($dir):"
                sed 's/^/    /' <<< "$cached"
                found_count=2
            fi
        done
    done

    if command -v yarn >/dev/null 2>&1; then
        local yarn_global_dir
        yarn_global_dir=$(yarn global dir 2>/dev/null || true)
        if [[ -n "$yarn_global_dir" && -d "$yarn_global_dir/node_modules" ]]; then
            for pkg in "${pkgs[@]}"; do
                if [[ -d "$yarn_global_dir/node_modules/$pkg" ]]; then
                    echo "  WARNING: $pkg found in yarn global ($yarn_global_dir/node_modules)"
                    found_count=2
                fi
            done
        fi
    fi

    scan_fnm_globals && fnm_ret=$? || fnm_ret=$?
    [[ $fnm_ret -gt $found_count ]] && found_count=$fnm_ret

    [[ $found_count -eq 0 ]] && echo "  Clean: no malicious packages in yarn cache."
    return $found_count
}

# ---------------------------------------------------------------------------
# Check: pnpm store/cache for malicious packages
# Content-addressable store is hash-named — cannot match by name, skipped.
# Scans: global installs, metadata cache, dlx cache.
# ---------------------------------------------------------------------------
check_pnpm_cache() {
    local pkgs=("${MALICIOUS_NPM_PKGS[@]}")
    local found_count=0

    local pnpm_home
    if [[ -n "${PNPM_HOME:-}" ]]; then
        pnpm_home="$PNPM_HOME"
    elif [[ -n "${XDG_DATA_HOME:-}" ]]; then
        pnpm_home="$XDG_DATA_HOME/pnpm"
    else
        pnpm_home="$HOME/.local/share/pnpm"
    fi
    local pnpm_cache="${XDG_CACHE_HOME:-$HOME/.cache}/pnpm"

    if command -v pnpm >/dev/null 2>&1; then
        local pnpm_global_root
        pnpm_global_root=$(pnpm root -g 2>/dev/null || true)
        if [[ -n "$pnpm_global_root" && -d "$pnpm_global_root" ]]; then
            for pkg in "${pkgs[@]}"; do
                if [[ -d "$pnpm_global_root/$pkg" ]]; then
                    echo "  WARNING: $pkg found in pnpm global ($pnpm_global_root)"
                    found_count=2
                fi
            done
        fi
    fi

    if [[ -d "$pnpm_home/global" ]]; then
        for pkg in "${pkgs[@]}"; do
            local gmod
            gmod=$(find "$pnpm_home/global" -maxdepth 5 -type d -name "$pkg" -path "*/node_modules/*" 2>/dev/null | head -5 || true)
            if [[ -n "$gmod" ]]; then
                echo "  WARNING: $pkg in pnpm global installs:"
                sed 's/^/    /' <<< "$gmod"
                found_count=2
            fi
        done
    fi

    for meta_root in "$pnpm_cache"/metadata*/; do
        [[ -d "$meta_root" ]] || continue
        for reg_dir in "$meta_root"*/; do
            [[ -d "$reg_dir" ]] || continue
            for pkg in "${pkgs[@]}"; do
                if [[ -f "$reg_dir$pkg.json" ]]; then
                    echo "  WARNING: $pkg resolved in pnpm metadata cache: $reg_dir$pkg.json"
                    found_count=2
                fi
            done
        done
    done

    if [[ -d "$pnpm_cache/dlx" ]]; then
        for pkg in "${pkgs[@]}"; do
            local dlx
            dlx=$(find "$pnpm_cache/dlx" -type d -name "$pkg" -path "*/node_modules/*" 2>/dev/null | head -5 || true)
            if [[ -n "$dlx" ]]; then
                echo "  WARNING: $pkg in pnpm dlx cache:"
                sed 's/^/    /' <<< "$dlx"
                found_count=2
            fi
        done
    fi

    [[ $found_count -eq 0 ]] && echo "  Clean: no malicious packages in pnpm store/cache."
    return $found_count
}

# ---------------------------------------------------------------------------
# Check 9: ld.so.preload shared library injection
# A non-empty /etc/ld.so.preload causes the dynamic linker to load the listed
# .so into every process at startup — the classic root-level rootkit hook.
# Any content here is a hard indicator; legitimate packages do not use it.
# Also reports /etc/ld.so.conf.d/*.conf entries for review.
# Paths are overridable via env vars for testing without root.
# ---------------------------------------------------------------------------
check_ldso() {
    local preload_file="${LDSO_PRELOAD_FILE:-/etc/ld.so.preload}"
    local conf_dir="${LDSO_CONF_DIR:-/etc/ld.so.conf.d}"
    local found=0

    if [[ -s "$preload_file" ]]; then
        echo "  WARNING: $preload_file exists and is non-empty — shared library injection:"
        sed 's/^/    /' "$preload_file"
        echo "  Every process on this system loads the above library at startup."
        echo "  Remove the file (or its contents) if you did not add it intentionally."
        found=2
    else
        echo "  Clean: $preload_file not present or empty."
    fi

    while IFS= read -r conf; do
        local mtime mdate
        mtime=$(stat -c %Y "$conf" 2>/dev/null) || continue
        mdate=$(date -d "@$mtime" +%F 2>/dev/null) || continue
        echo "  INFO: ld.so.conf.d entry present: $conf (mtime $mdate)"
    done < <(find "$conf_dir" -name '*.conf' -type f 2>/dev/null)

    [[ $found -eq 0 ]] || return $found
    return 0
}

# ---------------------------------------------------------------------------
# Check 10: XDG autostart + shell RC persistence
# Detects low-privilege persistence requiring no root:
#   1. ~/.config/autostart/*.desktop — Exec= outside /usr/ or /opt/
#   2. ~/.config/systemd/user/*.service — ExecStart= binary not owned by pacman
#   3. Shell RCs — lines matching download-and-execute or eval+subshell patterns
# Home dir injectable via AUTOSTART_HOME for testing.
# ---------------------------------------------------------------------------
check_autostart() {
    # When running as root without an explicit override, use the invoking user's
    # home — root's ~/.config/autostart/ is for live-session relics and bare
    # command names there can't be resolved by root's PATH.
    local home_dir
    if [[ -n "${AUTOSTART_HOME:-}" ]]; then
        home_dir="$AUTOSTART_HOME"
    elif [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
        home_dir=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    else
        home_dir="$HOME"
    fi
    local found=0

    # XDG autostart .desktop files
    # Flag absolute paths outside standard system prefixes; for bare names, resolve
    # via command -v and apply the same prefix check.
    # AUTOSTART_ALLOWLIST: colon-separated list of Exec= names/basenames that
    # are known-good but can't be resolved via $PATH or a standard prefix
    # (e.g. an AppImage/Flatpak export, or a package-private helper the
    # non-PATH fallback below still can't find).
    # Example: AUTOSTART_ALLOWLIST=zeitgeist-datahub
    local -a _autostart_allow
    IFS=: read -ra _autostart_allow <<< "${AUTOSTART_ALLOWLIST:-}"
    # Non-PATH dirs to search for a bare Exec= name before giving up.
    # Many desktop packages (zeitgeist, various indicator/tray helpers) ship
    # their autostart binary in a package-private dir like /usr/lib/<pkg>/ or
    # /usr/libexec/ rather than on $PATH — command -v alone can't see those,
    # producing a false "suspicious" verdict for a perfectly legitimate,
    # pacman-owned binary. Override with AUTOSTART_LIBDIRS for testing.
    local -a _autostart_libdirs
    IFS=: read -ra _autostart_libdirs <<< "${AUTOSTART_LIBDIRS:-/usr/lib:/usr/libexec}"

    local desktop_dir="$home_dir/.config/autostart"
    if [[ -d "$desktop_dir" ]]; then
        while IFS= read -r desktop; do
            # Hidden=true / X-GNOME-Autostart-enabled=false is how DE autostart
            # managers (incl. Mabox's) disable an entry without deleting the
            # file — per the XDG spec, it must be treated as if the file does
            # not exist. Such an entry can never actually execute, so there is
            # nothing to warn about regardless of whether Exec= resolves.
            if grep -qE '^[[:space:]]*Hidden[[:space:]]*=[[:space:]]*true[[:space:]]*$' "$desktop" 2>/dev/null || \
               grep -qE '^[[:space:]]*X-GNOME-Autostart-enabled[[:space:]]*=[[:space:]]*false[[:space:]]*$' "$desktop" 2>/dev/null; then
                continue
            fi
            while IFS= read -r line; do
                [[ "$line" =~ ^Exec= ]] || continue
                local exec_val="${line#Exec=}"
                exec_val=$(printf '%s' "$exec_val" | sed 's/[[:space:]]*%[a-zA-Z]//g' | awk '{print $1}')
                [[ -z "$exec_val" ]] && continue

                local suspicious=false
                if [[ "$exec_val" == /* ]]; then
                    if [[ "$exec_val" != /usr/* && "$exec_val" != /opt/* && \
                          "$exec_val" != /bin/* && "$exec_val" != /sbin/* && \
                          "$exec_val" != /usr/local/* ]]; then
                        suspicious=true
                    fi
                else
                    local resolved
                    resolved=$(command -v "$exec_val" 2>/dev/null) || true
                    if [[ -n "$resolved" ]]; then
                        if [[ "$resolved" != /usr/* && "$resolved" != /opt/* && \
                              "$resolved" != /bin/* && "$resolved" != /sbin/* && \
                              "$resolved" != /usr/local/* ]]; then
                            suspicious=true
                        fi
                    else
                        # Not on $PATH — search the curated non-PATH system
                        # libdirs. A hit there is trusted outright (that's
                        # what the dir list represents); no prefix recheck.
                        # find(1) -name treats its argument as a glob, not a
                        # literal string — escape */?/[/] and backslash so an
                        # attacker-controlled Exec=* (or similar) can't match
                        # an arbitrary executable and bypass this check.
                        local exec_glob_safe="$exec_val"
                        exec_glob_safe="${exec_glob_safe//\\/\\\\}"
                        exec_glob_safe="${exec_glob_safe//\*/\\*}"
                        exec_glob_safe="${exec_glob_safe//\?/\\?}"
                        exec_glob_safe="${exec_glob_safe//\[/\\[}"
                        exec_glob_safe="${exec_glob_safe//\]/\\]}"
                        local libhit
                        libhit=$(find "${_autostart_libdirs[@]}" -mindepth 1 -maxdepth 3 \
                            -type f -name "$exec_glob_safe" -perm -u+x 2>/dev/null | head -1)
                        [[ -z "$libhit" ]] && suspicious=true
                    fi
                fi

                if $suspicious; then
                    if _allowlist_contains "$exec_val" _autostart_allow; then
                        echo "  INFO: autostart entry allowlisted (unresolved binary): $desktop"
                        echo "    Exec=$exec_val"
                    else
                        echo "  WARNING: suspicious autostart entry: $desktop"
                        echo "    Exec=$exec_val (outside standard system path)"
                        found=2
                    fi
                fi
            done < "$desktop"
        done < <(find "$desktop_dir" -name '*.desktop' -type f 2>/dev/null)
    fi

    # User systemd services whose ExecStart= binary is unowned by pacman.
    # Expand %h (systemd home-dir specifier) before querying pacman.
    # Skip XDG user bin dirs — these are never tracked by pacman.
    local user_svc_dir="$home_dir/.config/systemd/user"
    if [[ -d "$user_svc_dir" ]]; then
        while IFS= read -r svc; do
            local exec_bin
            exec_bin=$(grep -oP '^ExecStart=\K\S+' "$svc" 2>/dev/null | head -1) || continue
            [[ -z "$exec_bin" ]] && continue
            exec_bin="${exec_bin//%h/$home_dir}"
            [[ "$exec_bin" == "$home_dir/.local/bin/"* ]] && continue
            [[ "$exec_bin" == "$home_dir/bin/"* ]] && continue
            # /usr/local/ is the FHS-conventional prefix for manually-installed
            # software; Arch's pacman never writes there, so unowned binaries in
            # /usr/local/bin/ are expected and not a persistence signal.
            [[ "$exec_bin" == "/usr/local/bin/"* ]] && continue
            if ! pacman -Qo "$exec_bin" &>/dev/null 2>&1; then
                echo "  WARNING: user service with unowned ExecStart binary: $svc"
                echo "    ExecStart=$exec_bin (not tracked by pacman)"
                found=2
            fi
        done < <(find "$user_svc_dir" -name '*.service' -type f 2>/dev/null)
    fi

    # Shell RC files — download-and-execute or eval+subshell with dangerous tools.
    # eval alone (e.g. eval $(dircolors)) is not flagged — the subshell must begin
    # with a known network/execution tool.
    local re_pipe_exec='(curl|wget)[[:space:]].*\|[[:space:]]*(bash|sh[[:space:]]|sh$|python)'
    local re_base64='base64[[:space:]]+(--decode|-d)'
    local re_eval_net='eval[[:space:]]+[\$`]\(?(curl|wget|python[0-9.]?|bash|sh)[[:space:]]'
    local rc_files=("$home_dir/.bashrc" "$home_dir/.zshrc" "$home_dir/.bash_profile" "$home_dir/.profile")
    for rc in "${rc_files[@]}"; do
        [[ -f "$rc" ]] || continue
        local lineno=0
        while IFS= read -r line; do
            (( lineno++ )) || true
            if [[ "$line" =~ $re_pipe_exec ]] || [[ "$line" =~ $re_base64 ]] || \
               [[ "$line" =~ $re_eval_net ]]; then
                echo "  WARNING: suspicious pattern in $rc:$lineno"
                echo "    $line"
                found=2
            fi
        done < "$rc"
    done

    [[ $found -eq 0 ]] && echo "  Clean: no suspicious autostart or shell RC entries found."
    return $found
}

# ---------------------------------------------------------------------------
# Check 11: kernel module / DKMS audit
# Flags loaded modules not traceable to any pacman-installed package, and
# DKMS modules whose source package is not tracked by pacman.
# Requires root for reliable module attribution; skips gracefully otherwise.
# LSMOD_CMD / DKMS_CMD env vars override the real commands for testing.
# ---------------------------------------------------------------------------
check_kmod() {
    local lsmod_cmd="${LSMOD_CMD:-lsmod}"
    local dkms_cmd="${DKMS_CMD:-dkms}"
    local found=0

    # Root check — module file attribution via pacman -Ql needs root-readable paths
    if [[ $EUID -ne 0 && -z "${LSMOD_CMD:-}" ]]; then
        echo "  Skipped: --check-kmod requires root for reliable module attribution."
        echo "  → Try: sudo $0 --check-kmod"
        return 77
    fi

    # Build set of all .ko paths owned by pacman.
    # Normalize to underscores: lsmod uses underscores, .ko filenames use hyphens.
    # || true: grep exits 1 on no matches; don't let set -o pipefail abort here.
    local pacman_mods
    pacman_mods=$(pacman -Ql 2>/dev/null | awk '{print $2}' | grep '\.ko' | \
        sed 's/\.ko.*//' | xargs -I{} basename {} 2>/dev/null | \
        tr '-' '_' | sort -u) || true

    # Build set of module names that DKMS has compiled onto this kernel.
    # These live under updates/dkms/ and are NOT in pacman -Ql output —
    # the DKMS section below audits them separately, so exclude them here
    # to avoid false-positive "unknown module" warnings.
    local dkms_fs_mods
    dkms_fs_mods=$(find /usr/lib/modules -maxdepth 5 \
        -path '*/updates/dkms/*.ko*' 2>/dev/null | \
        xargs -I{} basename {} 2>/dev/null | \
        sed 's/\.ko.*//' | tr '-' '_' | sort -u) || true

    local lsmod_out
    if ! lsmod_out=$($lsmod_cmd 2>/dev/null); then
        echo "  Skipped: could not run lsmod."
        return 0
    fi

    local unknown=()
    while IFS= read -r line; do
        # lsmod format: Module Size UsedBy
        local mod
        mod=$(awk '{print $1}' <<< "$line")
        [[ "$mod" == "Module" || -z "$mod" ]] && continue
        # Normalize to underscores before lookup (matches normalization above)
        local mod_norm="${mod//-/_}"
        if grep -qxF "$mod_norm" <<< "$pacman_mods" 2>/dev/null; then
            continue  # owned by a pacman package
        fi
        if grep -qxF "$mod_norm" <<< "$dkms_fs_mods" 2>/dev/null; then
            continue  # compiled by DKMS — audited in the DKMS section below
        fi
        unknown+=("$mod")
    done <<< "$lsmod_out"

    if [[ ${#unknown[@]} -gt 0 ]]; then
        echo "  WARNING: ${#unknown[@]} loaded module(s) not traceable to pacman or DKMS:"
        print_list unknown
        echo "  Verify with: modinfo <module> ; pacman -Qo \$(modinfo -n <module>)"
        found=2
    else
        echo "  Clean: all loaded modules traceable to pacman packages or DKMS."
    fi

    # DKMS check (optional — skip if dkms not installed)
    # DKMS_ALLOWLIST: colon-separated list of DKMS module names that are known-good
    # but not installed via pacman (e.g. proprietary hardware drivers).
    # Example: DKMS_ALLOWLIST=tuxedo-drivers:v4l2loopback
    IFS=: read -ra _dkms_allow <<< "${DKMS_ALLOWLIST:-}"
    if command -v "$dkms_cmd" &>/dev/null || [[ -n "${DKMS_CMD:-}" ]]; then
        local dkms_out
        dkms_out=$($dkms_cmd status 2>/dev/null) || dkms_out=""
        if [[ -n "$dkms_out" ]]; then
            while IFS= read -r entry; do
                [[ -z "$entry" ]] && continue
                local pkg_name
                # dkms status format: "name/version, kernel, arch: status"
                pkg_name=$(awk -F'[/,]' '{print $1}' <<< "$entry" | xargs)
                # Skip if pacman-tracked
                pacman -Qi "$pkg_name" &>/dev/null 2>&1 && continue
                if _allowlist_contains "$pkg_name" _dkms_allow; then
                    echo "  INFO: DKMS module allowlisted (not pacman-tracked): $entry"
                else
                    echo "  WARNING: DKMS module from untracked source: $entry"
                    found=2
                fi
            done <<< "$dkms_out"
        fi
    fi
    unset _dkms_allow

    return $found
}

# ---------------------------------------------------------------------------
# Check 13: package file integrity via pacman -Qkk
# ---------------------------------------------------------------------------
# Verifies that files installed by pacman still match the stored checksums.
# Filters: backup= files (expected to change), /factory/ paths, and
# permission errors (unreadable files). Only SHA256 mismatches on regular
# installed files are reported — those indicate post-install modification.
check_pkginteg() {
    echo "  Verifying installed file checksums against pacman database..."
    echo "  (May take 30-60 seconds on large installs)"

    local raw findings count
    raw=$(/usr/bin/pacman -Qkk 2>/dev/null)

    findings=$(
        printf '%s\n' "$raw" \
        | grep "SHA256 checksum mismatch" \
        | grep -v "^backup file:" \
        | grep -v "/factory/"
    )

    if [[ -z "$findings" ]]; then
        echo "  All accessible installed files match pacman database checksums."
        return 0
    fi

    count=$(wc -l <<< "$findings")
    printf '  %d file(s) with unexpected checksum mismatch:\n\n' "$count"
    while IFS= read -r line; do
        printf '  * %s\n' "$line"
    done <<< "$findings"
    echo
    echo "  Note: some mismatches are benign (app-managed config files, browser policies)."
    echo "  Prioritise binaries in /usr/bin/, /usr/lib/, /usr/sbin/."
    return 1
}

# ---------------------------------------------------------------------------
# Check 12: Lynis hardening report
# Parses /var/log/lynis-report.dat (written by: sudo lynis audit system).
# Reports the hardening index and warnings from the last Lynis run.
# The report file is root-owned (600) — returns 77 if unreadable without root.
# Override the report path with LYNIS_REPORT_FILE for testing.
# ---------------------------------------------------------------------------
check_lynis() {
    local report_file="${LYNIS_REPORT_FILE:-/var/log/lynis-report.dat}"

    if ! command -v lynis &>/dev/null; then
        echo "  Skipped: lynis not installed (pacman -S lynis)."
        return 0
    fi

    if [[ ! -f "$report_file" ]]; then
        echo "  No Lynis report found at $report_file."
        echo "  Generate one with: sudo lynis audit system"
        return 1
    fi

    if [[ ! -r "$report_file" ]]; then
        echo "  Cannot read $report_file — needs root."
        echo "  → Try: sudo archcanary --check-lynis"
        return 77
    fi

    local hardening_index scan_date
    hardening_index=$(grep '^hardening_index=' "$report_file" | cut -d= -f2 | tr -d '[:space:]' || true)
    scan_date=$(grep '^report_datetime_start=' "$report_file" | cut -d= -f2 | head -1 | cut -c1-10 || true)

    local stale_warning=""
    if [[ -n "$scan_date" ]]; then
        local scan_epoch today_epoch days_ago
        scan_epoch=$(date -d "$scan_date" +%s 2>/dev/null || true)
        today_epoch=$(date +%s)
        if [[ -n "$scan_epoch" && "$scan_epoch" -gt 0 ]]; then
            days_ago=$(( (today_epoch - scan_epoch) / 86400 ))
            if [[ $days_ago -gt 30 ]]; then
                stale_warning=" (${days_ago} days old — consider re-running: sudo lynis audit system)"
            fi
        fi
    fi

    echo "  Last scan: ${scan_date:-unknown}${stale_warning}"
    [[ -n "$hardening_index" ]] && echo "  Hardening index: $hardening_index / 100"

    local warnings=()
    while IFS= read -r line; do
        local id desc
        id=$(cut -d'|' -f1 <<< "$line")
        desc=$(cut -d'|' -f2 <<< "$line")
        warnings+=("$id  $desc")
    done < <(grep '^warning\[\]=' "$report_file" | sed 's/^warning\[\]=//' || true)

    if [[ ${#warnings[@]} -gt 0 ]]; then
        echo "  Warnings (${#warnings[@]}):"
        for w in "${warnings[@]}"; do
            echo "    * $w"
        done
    else
        echo "  No warnings in last Lynis report."
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
EXIT_CODE=0
# Root-requiring checks return 77 when they cannot run without root. We track
# them so the final result is reported as INCOMPLETE (and exit 1) instead of a
# misleading CLEAN — a scan that skipped checks is not a clean bill of health.
SKIPPED_ROOT=()

# Fold a check's return code into EXIT_CODE; 77 means "skipped, needs root".
_apply_ret() { # $1=return code  $2=check label
    if [[ "$1" -eq 77 ]]; then
        SKIPPED_ROOT+=("$2")
    elif [[ "$1" -gt $EXIT_CODE ]]; then
        EXIT_CODE="$1"
    fi
}

# Summary table — parallel arrays appended as each check runs.
_SUMMARY_NAMES=()
_SUMMARY_CODES=()
_rec() { _SUMMARY_NAMES+=("$1"); _SUMMARY_CODES+=("$2"); }

_print_summary() {
    local _w=36
    printf '\n Check summary\n'
    printf ' %s\n' "$_SEP55"
    local i
    for i in "${!_SUMMARY_NAMES[@]}"; do
        local name="${_SUMMARY_NAMES[$i]}" code="${_SUMMARY_CODES[$i]}"
        case "$code" in
            0)  printf ' %-*s %s\n'  "$_w" "$name" "$_SYM_CLEAN" ;;
            1)  printf ' %-*s %s\n'  "$_w" "$name" "$_SYM_WARNINGS" ;;
            2)  printf ' %-*s %s\n'  "$_w" "$name" "$_SYM_INFECTED_TXT" ;;
            77) printf ' %-*s %s\n'  "$_w" "$name" "$_SYM_SKIPPED" ;;
        esac
    done
    printf ' %s\n' "$_SEP55"
}

load_packages

# Build CHAOS_LOOKUP before merging into INFECTED_PKGS so checks can apply
# the CHAOS RAT date window separately from the main campaign window.
declare -A CHAOS_LOOKUP
for p in "${CHAOS_RAT_PKGS[@]}"; do
    CHAOS_LOOKUP["$p"]=1
    INFECTED_PKGS+=("$p")
done

# Russian Spam Campaign — packages injecting spam into shell configs
for p in "${RUSSIAN_SPAM_PKGS[@]}"; do
    INFECTED_PKGS+=("$p")
done

# Extra lists — merged last so they appear in INFECTED_LOOKUP
for p in "${EXTRA_PKGS[@]}"; do
    INFECTED_PKGS+=("$p")
done

# Build exact-match lookup table from INFECTED_PKGS
# (pacman -Qmq does prefix matching; this prevents false positives)
declare -A INFECTED_LOOKUP
for p in "${INFECTED_PKGS[@]}"; do
    INFECTED_LOOKUP["$p"]=1
done

if ! $FOCUSED_MODE; then
    echo "============================================================"
    echo " Archcanary v${SCRIPT_VERSION}"
    echo " Scanned: $(date '+%Y-%m-%d %H:%M')"
    echo
    echo " Lists loaded"
    echo "   $(basename "$PACKAGE_LIST_FILE")  infostealer + eBPF rootkit"
    if [[ ${#CHAOS_RAT_PKGS[@]} -gt 0 ]]; then
        printf "   + CHAOS RAT%10s pkgs\n" "${#CHAOS_RAT_PKGS[@]}"
    fi
    if [[ ${#RUSSIAN_SPAM_PKGS[@]} -gt 0 ]]; then
        printf "   + Russian Spam%7s pkgs\n" "${#RUSSIAN_SPAM_PKGS[@]}"
    fi
    if [[ ${#EXTRA_PKGS[@]} -gt 0 ]]; then
        printf "   + extra lists%8s pkgs  (extra_lists.conf / --extra-list)\n" "${#EXTRA_PKGS[@]}"
    fi
    echo
    echo " Packages checked: ${#INFECTED_PKGS[@]}"
    if [[ -n "$START_DATE" || -n "$END_DATE" ]]; then
        echo " Date window: ${START_DATE:-beginning} → ${END_DATE:-now}"
    fi
    echo "============================================================"
    echo

    log_info "Loaded ${#INFECTED_PKGS[@]} packages from $PACKAGE_LIST_FILE"

    echo "--- [1] Currently installed foreign packages ---"
    log_info "Querying ${#INFECTED_PKGS[@]} packages via pacman -Qmq..."
    check_current && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "Package list (${#INFECTED_PKGS[@]} pkgs)" "$ret"
    echo

    echo "--- [2] Historical pacman logs ---"
    _log_ret=0
    if [[ -f /var/log/pacman.log ]]; then
        LOGS_TMP=$(mktemp)
        CLEANUP_FILES+=("$LOGS_TMP")
        check_logs 2>&1 | tee "$LOGS_TMP" || true
        if grep -q 'LOG_HIT' "$LOGS_TMP" 2>/dev/null; then
            echo "  WARNING: historical log matches (name-match against official compromised list):"
            grep 'LOG_HIT' "$LOGS_TMP" | sed 's/LOG_HIT: /  - /'
            echo "  NOTE: if the PKGBUILD looks clean now, the malicious commit may have been"
            echo "  reverted — check AUR git history around the install date/time above."
            echo "  Either way, treat the install-time window as a potential exposure."
            [[ 2 -gt $EXIT_CODE ]] && EXIT_CODE=2
            _log_ret=2
        else
            echo "  Clean: no historical log matches found."
        fi
        rm -f "$LOGS_TMP"
    else
        echo "  Skipped: /var/log/pacman.log not found."
    fi
    _rec "pacman.log history" "$_log_ret"
    echo
fi

if $CHECK_SYSTEMD; then
    echo "--- [3] Systemd persistence check ---"
    check_systemd && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "Systemd persistence" "$ret"
    echo
fi

if $CHECK_EBPF; then
    echo "--- [4] eBPF rootkit check ---"
    check_ebpf && ret=$? || ret=$?
    _apply_ret "$ret" ebpf
    _rec "eBPF rootkit traces" "$ret"
    echo
fi

if $CHECK_NPM_CACHE; then
    echo "--- [5] npm cache check ---"
    check_npm_cache && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "npm cache" "$ret"
    echo
fi

if $CHECK_BUN_CACHE; then
    echo "--- [6] bun cache check ---"
    check_bun_cache && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "bun cache" "$ret"
    echo
fi

if $CHECK_YARN_CACHE; then
    echo "--- [6b] yarn cache check ---"
    check_yarn_cache && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "yarn cache" "$ret"
    echo
fi

if $CHECK_PNPM_CACHE; then
    echo "--- [6c] pnpm cache check ---"
    check_pnpm_cache && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "pnpm cache" "$ret"
    echo
fi

if $CHECK_PKGBUILD; then
    echo "--- [7] PKGBUILD/install file scan (obfuscation-aware) ---"
    check_pkgbuild_caches && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "PKGBUILD obfuscation scan" "$ret"
    echo
fi

if $CHECK_BPFTOOL; then
    echo "--- [8] Loaded eBPF programs/links (bpftool) ---"
    check_bpftool && ret=$? || ret=$?
    _apply_ret "$ret" bpftool
    _rec "eBPF programs (bpftool)" "$ret"
    echo
fi

if $CHECK_LDSO; then
    echo "--- [9] ld.so.preload injection check ---"
    check_ldso && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "ld.so.preload injection" "$ret"
    echo
fi

if $CHECK_AUTOSTART; then
    echo "--- [10] XDG autostart + shell RC persistence check ---"
    check_autostart && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "XDG autostart + shell RCs" "$ret"
    echo
fi

if $CHECK_KMOD; then
    echo "--- [11] Kernel module / DKMS audit ---"
    check_kmod && ret=$? || ret=$?
    _apply_ret "$ret" kmod
    _rec "Kernel modules (DKMS)" "$ret"
    echo
fi

if $CHECK_LYNIS; then
    echo "--- [12] Lynis hardening report ---"
    check_lynis && ret=$? || ret=$?
    _apply_ret "$ret" lynis
    _rec "Lynis hardening" "$ret"
    echo
fi

if $CHECK_PKGINTEG; then
    echo "--- [13] Package file integrity ---"
    check_pkginteg && ret=$? || ret=$?
    _apply_ret "$ret" pkginteg
    _rec "Package integrity" "$ret"
    echo
fi

# A scan that skipped root checks is incomplete, not clean — surface it and
# escalate a would-be CLEAN (0) to WARNINGS (1) so it isn't read as all-clear.
if [[ ${#SKIPPED_ROOT[@]} -gt 0 && $EXIT_CODE -lt 1 ]]; then
    EXIT_CODE=1
fi

$NO_SUMMARY || _print_summary

printf '%s============================================================%s\n' "$_CB" "$_CN"
case $EXIT_CODE in
    0) printf ' %sRESULT: CLEAN - No indicators found.%s\n'                           "$_CG"       "$_CN" ;;
    1) printf ' %sRESULT: WARNINGS - Review output above.%s\n'                        "$_CY"       "$_CN" ;;
    2) printf ' %sRESULT: INFECTED - Indicators found! Follow incident response.%s\n' "$_CR$_CB"   "$_CN" ;;
esac
if [[ ${#SKIPPED_ROOT[@]} -gt 0 ]]; then
    printf ' INCOMPLETE: %d root check(s) skipped (no root): %s\n' "${#SKIPPED_ROOT[@]}" "${SKIPPED_ROOT[*]}"
    if [[ -n "${ARCHCANARY_FROM_GUI:-}" ]]; then
        printf ' Re-run with sudo for the full picture: sudo archcanary-gui --no-gui\n'
    else
        printf ' Re-run with sudo for the full picture: sudo %s --full\n' "$0"
    fi
fi
printf '%s============================================================%s\n' "$_CB" "$_CN"

if [[ $EXIT_CODE -eq 2 ]] && ! $NO_NOTIFY; then
    if command -v notify-send &>/dev/null; then
        # Some terminals (Openbox, launch-from-menu) don't inherit
        # DBUS_SESSION_BUS_ADDRESS, and a root scan (sudo archcanary --full)
        # has no session bus of its own at all — same SUDO_USER pattern used
        # elsewhere (check_autostart's home-dir resolution, log ownership
        # around line 612). Without this, notify-send falls back to spawning
        # dbus-launch --autolaunch, which fails outright in both contexts and
        # prints "Failed to show notification" instead of popping up.
        _notify_runner=()
        if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
            _notify_uid=$(id -u "$SUDO_USER" 2>/dev/null) || _notify_uid=""
            if [[ -n "$_notify_uid" && -S "/run/user/$_notify_uid/bus" ]]; then
                _notify_runner=(sudo -u "$SUDO_USER" env "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$_notify_uid/bus")
            fi
            unset _notify_uid
        fi
        # No SUDO_USER-targeted runner (not root, or the invoking user has no
        # active session/runtime dir, or a systemd-timer root scan where
        # SUDO_USER is unset) — fall back to our own uid's socket rather than
        # leaving DBUS_SESSION_BUS_ADDRESS unset outright.
        if [[ ${#_notify_runner[@]} -eq 0 && -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
            _notify_xrd="/run/user/$EUID"
            [[ -S "$_notify_xrd/bus" ]] && export DBUS_SESSION_BUS_ADDRESS="unix:path=$_notify_xrd/bus"
            unset _notify_xrd
        fi
        # Only checks [1]/[2] (currently-installed / historically-installed foreign
        # packages) confirm an actual malicious package. Other checks at this exit
        # code (systemd, ebpf, autostart, etc.) flag suspicious artifacts, not
        # packages, so the notification wording must not claim "package" for those.
        _notify_title="archcanary: security indicator detected"
        for _i in "${!_SUMMARY_NAMES[@]}"; do
            case "${_SUMMARY_NAMES[$_i]}" in
                "Package list "*|"pacman.log history")
                    [[ "${_SUMMARY_CODES[$_i]}" -eq 2 ]] && _notify_title="archcanary: malicious package detected" ;;
            esac
        done
        "${_notify_runner[@]}" notify-send -u critical -i dialog-warning \
            "$_notify_title" \
            "Indicators found. Open Archcanary to review."
        unset _notify_runner
    fi
fi

# Log was created while running as root (sudo/pkexec) but lives under the
# invoking user's ~/.cache — hand it back so it isn't left root-owned there.
_chown_to_invoker "$LOG_FILE"

exit "$EXIT_CODE"
