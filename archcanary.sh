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
COMMUNITY_REPORTS_LIST_URL="https://raw.githubusercontent.com/musqz/archcanary/master/lists/community_reports.txt"

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
CHECK_LIST_OVERLAP=false
CHECK_FULL=false
SCAN_ALL_HOMES=false
# True only if --check-lynis was passed directly, not just via --full.
EXPLICIT_LYNIS=false
REFRESH_PACKAGE_LIST=false
VERBOSE=false
NO_NOTIFY=false
NO_SUMMARY=false
DOCTOR=false
DOCTOR_SECTIONS=""
SEARCH_PACKAGES_ARG=""
RUN_LYNIS=false
_COLOR_ARG="auto"
_FORMAT_ARG="text"

# CLI arg overrides for env-var-backed settings
PACKAGE_LIST_FILE_OPT=""
MALICIOUS_NPM_LIST_OPT=""
CHAOS_RAT_LIST_OPT=""
RUSSIAN_SPAM_LIST_OPT=""
COMMUNITY_LIST_OPT=""
START_DATE_OPT=""
END_DATE_OPT=""
EXTRA_LIST_OPTS=()
SCAN_USER_OPTS=()

# Temp file cleanup on exit/interrupt
CLEANUP_FILES=()
trap 'rm -f "${CLEANUP_FILES[@]}"' EXIT
trap 'rm -f "${CLEANUP_FILES[@]}"; exit 1' INT TERM

# ---------------------------------------------------------------------------
# --allowlist-{list,add,remove} — manage the four system-wide allowlists at
# /etc/archcanary/*_allowlist.conf (seeded by install.sh --system). --list
# needs no root (the files are mode 644); --add/--remove do, and are meant to
# be invoked as `pkexec /usr/lib/archcanary/root-helper --allowlist-add=NAME:
# VALUE` — root-helper independently re-validates NAME/VALUE before exec'ing
# back into this script, since it (not this script) is the actual polkit
# privilege boundary. Env var overrides match the ones the scan-time parsing
# below already uses, so both point at the same file.
# ---------------------------------------------------------------------------
_allowlist_path() {
    case "$1" in
        dkms)      echo "${DKMS_ALLOWLIST_FILE:-/etc/archcanary/dkms_allowlist.conf}" ;;
        systemd)   echo "${SYSTEMD_ALLOWLIST_FILE:-/etc/archcanary/systemd_allowlist.conf}" ;;
        bpftool)   echo "${BPFTOOL_ALLOWLIST_FILE:-/etc/archcanary/bpftool_allowlist.conf}" ;;
        autostart) echo "${AUTOSTART_ALLOWLIST_FILE:-/etc/archcanary/autostart_allowlist.conf}" ;;
        *)         return 1 ;;
    esac
}

# Prints one semantic value per line — same "strip inline comment, take first
# token" rule the scan-time DKMS/SYSTEMD/BPFTOOL/AUTOSTART_ALLOWLIST parsing
# below applies — so list output always matches what a scan actually treats
# as allowlisted, not raw file lines (which may carry a trailing description).
_allowlist_values() {
    awk '{
        line = $0
        sub(/#.*/, "", line)
        n = split(line, tok, /[ \t]+/)
        for (i = 1; i <= n; i++) { if (tok[i] != "") { print tok[i]; break } }
    }' "$1"
}

_allowlist_cli() {
    local action="$1" arg2="$2" name value path
    if [[ "$action" == list ]]; then
        name="$arg2"
    else
        if [[ "$arg2" != *:* ]]; then
            echo "Error: expected NAME:VALUE, got '$arg2'" >&2
            exit 1
        fi
        name="${arg2%%:*}"
        value="${arg2#*:}"
    fi
    path="$(_allowlist_path "$name")" || {
        echo "Error: unknown allowlist '$name' (expected: dkms, systemd, bpftool, autostart)" >&2
        exit 1
    }
    if [[ ! -f "$path" ]]; then
        echo "Error: $path does not exist — run install.sh --system first" >&2
        exit 3
    fi
    if [[ "$action" == list ]]; then
        _allowlist_values "$path"
        exit 0
    fi
    # Allows an absolute path (needed for autostart's unowned-ExecStart-binary
    # finding, which allowlists by exact full path — see check_autostart) as
    # well as a bare name (module/unit/binary basename, the other 3 lists and
    # autostart's .desktop-Exec= finding). Still excludes whitespace, '#'
    # (would silently become a comment), and ':' (the loaded env var joins
    # multiple file entries with IFS=:, so a literal ':' in a value would
    # get mis-split into two allowlist entries).
    if [[ ! "$value" =~ ^[A-Za-z0-9/][A-Za-z0-9._@+/-]{0,127}$ ]]; then
        echo "Error: invalid allowlist value '$value'" >&2
        exit 1
    fi
    if [[ $EUID -ne 0 ]]; then
        echo "Error: modifying $path requires root — run via pkexec (root-helper)" >&2
        exit 1
    fi
    if [[ "$action" == add ]]; then
        if _allowlist_values "$path" | grep -qxF "$value"; then
            echo "already allowlisted: $value"
            exit 0
        fi
        printf '%s\n' "$value" >> "$path"
        echo "added: $value"
        exit 0
    else
        if ! _allowlist_values "$path" | grep -qxF "$value"; then
            echo "not found: $value" >&2
            exit 1
        fi
        local tmp
        tmp="$(mktemp "${path}.XXXXXX")"
        CLEANUP_FILES+=("$tmp")
        awk -v val="$value" '{
            line = $0
            stripped = line
            sub(/#.*/, "", stripped)
            n = split(stripped, tok, /[ \t]+/)
            first = ""
            for (i = 1; i <= n; i++) { if (tok[i] != "") { first = tok[i]; break } }
            if (first == val) next
            print line
        }' "$path" > "$tmp"
        mv "$tmp" "$path"
        chmod 644 "$path"
        echo "removed: $value"
        exit 0
    fi
}

# ---------------------------------------------------------------------------
# --extra-lists-{list,add,remove} — manage ~/.config/archcanary/extra_lists.conf
# (one file path or https:// URL per line, auto-loaded on every scan — see
# _load_extra below). User-owned, no root/pkexec involved, unlike the
# allowlists above. EXTRA_LISTS_CONF is the same env var the scan-time loader
# further down honors, so both agree on the same file.
# ---------------------------------------------------------------------------
_extra_lists_path() {
    echo "${EXTRA_LISTS_CONF:-${XDG_CONFIG_HOME:-$HOME/.config}/archcanary/extra_lists.conf}"
}

# Mirrors the scan-time parsing in _load_extra: strip inline comments, then
# strip ALL whitespace (not just leading/trailing — matches archcanary's own
# ${_entry//[[:space:]]/} behavior) so list output matches what a scan
# actually loads, not raw file lines.
_extra_lists_values() {
    awk '{
        line = $0
        sub(/#.*/, "", line)
        gsub(/[ \t]+/, "", line)
        if (line != "") print line
    }' "$1"
}

_extra_lists_cli() {
    local action="$1" value="${2:-}" path
    path="$(_extra_lists_path)"

    if [[ "$action" == list ]]; then
        [[ -f "$path" ]] && _extra_lists_values "$path"
        exit 0
    fi

    if [[ -z "$value" || "$value" == *$'\n'* ]]; then
        echo "Error: invalid extra-list value" >&2
        exit 1
    fi

    mkdir -p "$(dirname "$path")"
    if [[ ! -f "$path" ]]; then
        cat > "$path" <<'CONF'
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

    if [[ "$action" == add ]]; then
        if _extra_lists_values "$path" | grep -qxF "$value"; then
            echo "already present: $value"
            exit 0
        fi
        printf '%s\n' "$value" >> "$path"
        echo "added: $value"
        exit 0
    else
        if ! _extra_lists_values "$path" | grep -qxF "$value"; then
            echo "not found: $value" >&2
            exit 1
        fi
        local tmp
        tmp="$(mktemp "${path}.XXXXXX")"
        CLEANUP_FILES+=("$tmp")
        awk -v val="$value" '{
            line = $0
            stripped = line
            sub(/#.*/, "", stripped)
            gsub(/[ \t]+/, "", stripped)
            if (stripped == val) next
            print line
        }' "$path" > "$tmp"
        mv "$tmp" "$path"
        echo "removed: $value"
        exit 0
    fi
}

# ---------------------------------------------------------------------------
# --aur-audit-{status,enable,disable} — the one persisted setting the yad
# GUI's "Scan Settings" dialog writes to ~/.config/archcanary/env (see
# scan_settings() in archcanary-gui.sh): whether to fetch the
# aur-audit.wtako.net feed on --refresh. User-owned, no root needed. Absence
# of the AUR_AUDIT_ENABLE line means enabled — mirrors the yad GUI's own
# format exactly, so either can edit the file and the other still reads it.
# ---------------------------------------------------------------------------
_aur_audit_env_path() {
    echo "${ARCHCANARY_ENV_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/archcanary/env}"
}

_aur_audit_status_cli() {
    local f val="true"
    f="$(_aur_audit_env_path)"
    if [[ -f "$f" ]]; then
        val="$(grep -E '^AUR_AUDIT_ENABLE=' "$f" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
        [[ -z "$val" ]] && val="true"
    fi
    echo "$val"
    exit 0
}

_aur_audit_set_cli() {
    local enable="$1" f
    f="$(_aur_audit_env_path)"
    mkdir -p "$(dirname "$f")"
    # Preserve GUI_LOG_SAVE_DIR (archcanary-gui.sh's remembered scan-log save
    # directory) — this file has two writers, and rebuilding it from only
    # this function's own known key would silently wipe the other one out.
    local gui_log_dir
    gui_log_dir="$(grep -oP '^GUI_LOG_SAVE_DIR=\K.*' "$f" 2>/dev/null | tail -1)" || true
    {
        printf '# archcanary settings — managed by archcanary-gui\n'
        [[ "$enable" == false ]] && printf 'AUR_AUDIT_ENABLE=false\n'
        [[ -n "$gui_log_dir" ]] && printf 'GUI_LOG_SAVE_DIR=%s\n' "$gui_log_dir"
    } > "$f"
    if [[ "$enable" == false ]]; then
        echo "aur-audit: disabled"
    else
        echo "aur-audit: enabled"
    fi
    exit 0
}

# ---------------------------------------------------------------------------
# --audit-rules-{get,set} — the root-owned auditd rules file the yad GUI
# edits via a raw pkexec-tee text editor (edit_audit_rules() in
# archcanary-gui.sh). --get mirrors that function's exact same read-fallback
# order (real rules in the live file, then the pre-migration legacy path,
# then the seed template) so both frontends see identical content. --set
# needs root; content comes from stdin, matching the existing GUI's
# free-form text editor (no line-level validation here either — auditctl
# syntax isn't something this script can meaningfully validate).
# ---------------------------------------------------------------------------
_audit_rules_get_cli() {
    local cfg="/etc/audit/rules.d/30-archcanary.rules"
    local legacy_cfg="/etc/audit/rules.d/30-archcanary.conf"
    local template="/usr/lib/archcanary/audit-rules.conf"
    if grep -qE '^\s*-[waAbfe]' "$cfg" 2>/dev/null; then
        cat "$cfg"
    elif grep -qE '^\s*-[waAbfe]' "$legacy_cfg" 2>/dev/null; then
        cat "$legacy_cfg"
    elif [[ -f "$template" ]]; then
        cat "$template"
    else
        echo "Error: no audit rules found — run install.sh --system first" >&2
        exit 3
    fi
    exit 0
}

_audit_rules_set_cli() {
    local cfg="/etc/audit/rules.d/30-archcanary.rules"
    local legacy_cfg="/etc/audit/rules.d/30-archcanary.conf"
    if [[ $EUID -ne 0 ]]; then
        echo "Error: modifying $cfg requires root — run via pkexec (root-helper)" >&2
        exit 1
    fi
    local content
    content="$(cat)"
    if [[ -z "$content" ]]; then
        echo "Error: refusing to write an empty audit-rules file" >&2
        exit 1
    fi
    printf '%s\n' "$content" > "$cfg"
    chmod 644 "$cfg"
    rm -f "$legacy_cfg"
    systemctl restart auditd 2>/dev/null || true
    echo "saved: $cfg"
    exit 0
}

# ---------------------------------------------------------------------------
# --lynis-config-{get,set} — the root-owned Lynis custom profile, same
# rationale as audit rules above (see edit_lynis_config() in
# archcanary-gui.sh). No daemon to restart — Lynis reads this at scan time.
# ---------------------------------------------------------------------------
_lynis_config_get_cli() {
    local cfg="/etc/lynis/custom.prf"
    local template="/usr/lib/archcanary/lynis-custom.prf"
    if [[ -f "$cfg" ]]; then
        cat "$cfg"
    elif [[ -f "$template" ]]; then
        cat "$template"
    else
        printf '# Lynis custom profile\n# skip-test=<TEST-ID>\n'
    fi
    exit 0
}

_lynis_config_set_cli() {
    local cfg="/etc/lynis/custom.prf"
    if [[ $EUID -ne 0 ]]; then
        echo "Error: modifying $cfg requires root — run via pkexec (root-helper)" >&2
        exit 1
    fi
    local content
    content="$(cat)"
    mkdir -p "$(dirname "$cfg")"
    printf '%s\n' "$content" > "$cfg"
    chmod 644 "$cfg"
    echo "saved: $cfg"
    exit 0
}

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
        --check-lynis)      CHECK_LYNIS=true; EXPLICIT_LYNIS=true ;;
        --check-pkginteg)   CHECK_PKGINTEG=true ;;
        --check-list-overlap) CHECK_LIST_OVERLAP=true ;;
        --scan-all-homes) SCAN_ALL_HOMES=true ;;
        --scan-user=*)    SCAN_USER_OPTS+=("${arg#*=}") ;;
        --full)          CHECK_SYSTEMD=true; CHECK_EBPF=true; CHECK_NPM_CACHE=true; CHECK_BUN_CACHE=true; CHECK_YARN_CACHE=true; CHECK_PNPM_CACHE=true; CHECK_PKGBUILD=true; CHECK_BPFTOOL=true; CHECK_LDSO=true; CHECK_AUTOSTART=true; CHECK_KMOD=true; CHECK_LYNIS=true; CHECK_PKGINTEG=true; CHECK_FULL=true ;;
        --refresh)               REFRESH_PACKAGE_LIST=true ;;
        --verbose|-v)            VERBOSE=true ;;
        --debug)                 VERBOSE=true; set -x ;;
        --log-file=*)            LOG_FILE="${arg#*=}" ;;
        --package-list=*)        PACKAGE_LIST_FILE_OPT="${arg#*=}" ;;
        --malicious-npm-list=*)  MALICIOUS_NPM_LIST_OPT="${arg#*=}" ;;
        --chaos-rat-list=*)      CHAOS_RAT_LIST_OPT="${arg#*=}" ;;
        --russian-spam-list=*)   RUSSIAN_SPAM_LIST_OPT="${arg#*=}" ;;
        --community-list=*)      COMMUNITY_LIST_OPT="${arg#*=}" ;;
        --extra-list=*)          EXTRA_LIST_OPTS+=("${arg#*=}") ;;
        --search-packages=*)     SEARCH_PACKAGES_ARG="${arg#*=}" ;;
        --start-date=*)          START_DATE_OPT="${arg#*=}" ;;
        --end-date=*)            END_DATE_OPT="${arg#*=}" ;;
        --no-aur-audit)          AUR_AUDIT_ENABLE=false ;;
        --no-notify)             NO_NOTIFY=true ;;
        --no-summary)            NO_SUMMARY=true ;;
        --color=*)               _COLOR_ARG="${arg#*=}" ;;
        --format=*)              _FORMAT_ARG="${arg#*=}" ;;
        --doctor)                DOCTOR=true ;;
        --doctor=*)              DOCTOR=true; DOCTOR_SECTIONS="${arg#*=}" ;;
        --run-lynis)             RUN_LYNIS=true ;;
        --allowlist-list=*)      _allowlist_cli list "${arg#*=}" ;;
        --allowlist-add=*)       _allowlist_cli add "${arg#*=}" ;;
        --allowlist-remove=*)    _allowlist_cli remove "${arg#*=}" ;;
        --extra-lists-list)      _extra_lists_cli list ;;
        --extra-lists-add=*)     _extra_lists_cli add "${arg#*=}" ;;
        --extra-lists-remove=*)  _extra_lists_cli remove "${arg#*=}" ;;
        --aur-audit-status)      _aur_audit_status_cli ;;
        --aur-audit-enable)      _aur_audit_set_cli true ;;
        --aur-audit-disable)     _aur_audit_set_cli false ;;
        --audit-rules-get)       _audit_rules_get_cli ;;
        --audit-rules-set)       _audit_rules_set_cli ;;
        --lynis-config-get)      _lynis_config_get_cli ;;
        --lynis-config-set)      _lynis_config_set_cli ;;
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
            echo "  --check-list-overlap  Note custom-list entries already covered by an official list, safe to"
            echo "                        remove — advisory only, not included in --full"
            echo "  --scan-all-homes   Enumerate real local users and run the npm/bun/yarn/pnpm/pkgbuild/autostart"
            echo "                     checks against each of their homes, not just yours (needs root, not included in --full)"
            echo "  --scan-user=NAME   Run those same checks against one specific user's home instead of yours"
            echo "                     (repeatable: --scan-user=a --scan-user=b; needs root; mutually exclusive"
            echo "                     with --scan-all-homes)"
            echo "  --search-packages=PKG[,PKG...]  Check package name(s) against every loaded threat list"
            echo "                                   (no scan; prints a ready-to-copy 'pacman -Rns' command"
            echo "                                   for any match) and exit"
            echo "  --run-lynis        Run a full Lynis audit (lynis audit system) and exit — not included in --full"
            echo "  --full             Enable all checks"
            echo "  --refresh          Download the latest package list before scanning (incl. aur-audit black/red feed)"
            echo "  --no-aur-audit     Skip the aur-audit.wtako.net feed on --refresh (env: AUR_AUDIT_ENABLE=false)"
            echo "  --verbose, -v, --debug    Verbose output (--debug also enables set -x)"
            echo "  --log-file=PATH           Write full detail log to PATH (auto: ~/.cache/archcanary/aur-check-<date>.log)"
            echo "  --package-list=PATH       Custom infected AUR package list (default: ./package_list.txt)"
            echo "  --malicious-npm-list=PATH Custom malicious npm package name list (default: ./malicious_npm_packages.txt)"
            echo "  --chaos-rat-list=PATH     Custom CHAOS RAT (2025) package list (default: ./chaos_rat_packages.txt)
  --russian-spam-list=PATH  Custom Russian Spam Campaign (2026) list (default: ./malicious_russian_spam_packages.txt)
  --community-list=PATH     Custom community-reported package list (default: ./community_reports.txt)
  --extra-list=PATH_OR_URL  Load an extra package list (file path or https:// URL); repeatable"
            echo "  --start-date=YYYY-MM-DD   Only flag packages installed on or after this date (env: START_DATE)"
            echo "  --end-date=YYYY-MM-DD     Only flag packages installed on or before this date (env: END_DATE)"
            echo "  --no-notify               Suppress the desktop notification on detection
  --no-summary              Suppress the check summary table at the end of a scan"
            echo "  --color=auto|always|never Control symbol/color output (default: auto; also obeys NO_COLOR env)"
            echo "  --format=text|json        Output a JSON summary instead of the human-readable report"
            echo "                            (default: text; JSON goes to stdout, full narrative still logged)"
            echo "  --doctor                  Report install/config status of every stack element"
            echo "                            (deps, install, systemd, yay/paru hooks) and exit"
            echo "  --doctor=SECTION[,...]    Check only the named section(s), with extra detail."
            echo "                            Sections: platform, deps, user, system, systemd, external"
            echo "                            (tool names like paru/yad also map to a section)"
            echo "                            Comma- or space-separated, e.g.:"
            echo "                            --doctor=user,system   --doctor user system   --doctor=deps"
            echo "  --allowlist-list=NAME             List entries in an allowlist and exit"
            echo "                                     NAME: dkms, systemd, bpftool, autostart"
            echo "  --allowlist-add=NAME:VALUE        Add VALUE to an allowlist and exit (needs root)"
            echo "  --allowlist-remove=NAME:VALUE     Remove VALUE from an allowlist and exit (needs root)"
            echo "  --extra-lists-list                List ~/.config/archcanary/extra_lists.conf entries and exit"
            echo "  --extra-lists-add=VALUE           Add a path/URL to extra_lists.conf and exit"
            echo "  --extra-lists-remove=VALUE        Remove a path/URL from extra_lists.conf and exit"
            echo "  --aur-audit-status                Print aur-audit.wtako.net feed setting (true/false)"
            echo "  --aur-audit-enable                Enable the aur-audit.wtako.net feed on --refresh"
            echo "  --aur-audit-disable               Disable the aur-audit.wtako.net feed on --refresh"
            echo "  --audit-rules-get                 Print the auditd rules file and exit"
            echo "  --audit-rules-set                 Read new auditd rules from stdin and save (needs root)"
            echo "  --lynis-config-get                Print the Lynis custom profile and exit"
            echo "  --lynis-config-set                Read a new Lynis custom profile from stdin and save (needs root)"
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
            else
                echo "Error: unknown option: $arg" >&2
                echo "Run '$0 --help' for usage." >&2
                exit 1
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
        *)
            echo "Error: --color must be 'auto', 'always', or 'never' (got '$_COLOR_ARG')" >&2
            exit 1
            ;;
    esac
    if $use; then
        _CG=$'\e[32m' _CY=$'\e[33m' _CR=$'\e[31m'
        _CB=$'\e[1m'  _CN=$'\e[0m'  _CC=$'\e[36m'
        _SYM_CLEAN="${_CG}✅  clean${_CN}"
        _SYM_WARNINGS="${_CY}⚠   warnings${_CN}"
        _SYM_INFECTED_TXT="${_CR}${_CB}❌  INFECTED${_CN}"
        _SYM_REVIEW_TXT="${_CY}⚠   REVIEW${_CN}"
        _SYM_SKIPPED="⚠   skipped (needs root)"
        _SYM_SKIPPED_MISSING="⚠   skipped (not installed)"
        _SEP55="$(printf '─%.0s' $(seq 1 55))"
    else
        _CG='' _CY='' _CR='' _CB='' _CN='' _CC=''
        _SYM_CLEAN="[ok]   clean"
        _SYM_WARNINGS="[!!]   warnings"
        _SYM_INFECTED_TXT="[!!]   INFECTED"
        _SYM_REVIEW_TXT="[??]   REVIEW"
        _SYM_SKIPPED="[--]   skipped (needs root)"
        _SYM_SKIPPED_MISSING="[--]   skipped (not installed)"
        _SEP55="$(printf '%0.s-' $(seq 1 55))"
    fi
}
_init_color

# --scan-all-homes/--scan-user interact silently with several other flags:
# some are pure no-ops when combined (the six per-user checks, since those
# are already covered per scanned user), others quietly scope to only the
# invoking user (list overrides, --refresh, --verbose, --log-file) or lose
# per-user granularity (--format=json). None of these are errors, but each
# is a real "I expected X, got Y" trap — reported live combining --scan-user
# with --check-ldso and separately expecting a custom --malicious-npm-list=
# to apply to a scanned user. Surfaced as one-line NOTEs (stderr, same
# convention as --doctor's ignored-flags notice) so they're visible before
# the scan runs, not discovered after the fact. Call site (after the root
# guard, main script body) skips this entirely under --doctor, which never
# runs a real scan.
_warn_scan_homes_flag_interactions() {
    local -a dup=() overrides=()

    $CHECK_NPM_CACHE  && dup+=("--check-npm-cache")
    $CHECK_BUN_CACHE  && dup+=("--check-bun-cache")
    $CHECK_YARN_CACHE && dup+=("--check-yarn-cache")
    $CHECK_PNPM_CACHE && dup+=("--check-pnpm-cache")
    $CHECK_PKGBUILD   && dup+=("--check-pkgbuild")
    $CHECK_AUTOSTART  && dup+=("--check-autostart")
    if [[ ${#dup[@]} -gt 0 ]]; then
        printf 'NOTE: %s add nothing extra here -- those checks are already covered per scanned user.\n' "${dup[*]}" >&2
    fi

    [[ -n "$PACKAGE_LIST_FILE_OPT" ]]  && overrides+=("--package-list=")
    [[ -n "$MALICIOUS_NPM_LIST_OPT" ]] && overrides+=("--malicious-npm-list=")
    [[ -n "$CHAOS_RAT_LIST_OPT" ]]     && overrides+=("--chaos-rat-list=")
    [[ -n "$RUSSIAN_SPAM_LIST_OPT" ]]  && overrides+=("--russian-spam-list=")
    [[ -n "$COMMUNITY_LIST_OPT" ]]     && overrides+=("--community-list=")
    if [[ ${#overrides[@]} -gt 0 ]]; then
        printf 'NOTE: %s only applies to your own checks -- each scanned user always uses their own default lists.\n' "${overrides[*]}" >&2
    fi

    if $REFRESH_PACKAGE_LIST; then
        printf 'NOTE: --refresh only refreshes your own lists -- scanned users keep whatever lists they already have until they refresh themselves.\n' >&2
    fi

    if $VERBOSE; then
        printf 'NOTE: --verbose/--debug only affects your own output -- per-user child scans always run at default verbosity.\n' >&2
    fi

    if [[ -n "${LOG_FILE:-}" ]]; then
        printf "NOTE: --log-file only applies to this summary -- each scanned user's own detail always logs to ~/.cache/archcanary/last-user-scan.log in their home.\n" >&2
    fi

    if $FORMAT_JSON; then
        printf "NOTE: --format=json has no per-user breakdown -- each scanned user's detail is only in their own ~/.cache/archcanary/last-user-scan.log.\n" >&2
    fi
}

# --format=json: a stable, structured contract for callers other than a human
# terminal (archcanary-gtk in particular) instead of scraping the text output
# above, which is formatted for a human and not meant to be a stable contract.
case "$_FORMAT_ARG" in
    text) FORMAT_JSON=false ;;
    json) FORMAT_JSON=true ;;
    *)
        echo "Error: --format must be 'text' or 'json' (got '$_FORMAT_ARG')" >&2
        exit 1
        ;;
esac

if $SCAN_ALL_HOMES && [[ ${#SCAN_USER_OPTS[@]} -gt 0 ]]; then
    echo "Error: --scan-all-homes and --scan-user are mutually exclusive" >&2
    exit 1
fi

# Derived: true for either "scan everyone" or "scan these specific named
# users" -- the two share the exact same privilege-dropped-subprocess
# machinery in _run_scan_all_homes, just differing in which users get
# enumerated (see _resolve_scan_user_opts vs _enumerate_local_users). Every
# other place that used to branch on $SCAN_ALL_HOMES alone to mean "the
# per-user-subprocess path owns these checks instead of the normal
# single-shot ones" now branches on this instead.
SCAN_HOMES_MODE=false
{ $SCAN_ALL_HOMES || [[ ${#SCAN_USER_OPTS[@]} -gt 0 ]]; } && SCAN_HOMES_MODE=true

if $SCAN_HOMES_MODE && ! $DOCTOR && [[ $EUID -ne 0 ]]; then
    echo "Error: --scan-all-homes/--scan-user requires root (enumerating other users' homes needs root) — run via sudo" >&2
    exit 1
fi

$SCAN_HOMES_MODE && ! $DOCTOR && _warn_scan_homes_flag_interactions

# Focused mode: a specific --check-* flag was given without --full.
# Suppresses the campaign header and the always-on package/log checks so
# each individual check window shows only the output it was asked for.
FOCUSED_MODE=false
if ! $CHECK_FULL && { $CHECK_SYSTEMD || $CHECK_EBPF || $CHECK_NPM_CACHE || \
    $CHECK_BUN_CACHE || $CHECK_YARN_CACHE || $CHECK_PNPM_CACHE || $CHECK_PKGBUILD || \
    $CHECK_BPFTOOL || $CHECK_LDSO || $CHECK_AUTOSTART || $CHECK_KMOD || $CHECK_LYNIS || \
    $CHECK_PKGINTEG || $SCAN_HOMES_MODE; }; then
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
    $SCAN_ALL_HOMES                   && _ignored+=("--scan-all-homes")
    [[ ${#SCAN_USER_OPTS[@]} -gt 0 ]]  && _ignored+=("--scan-user")
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
    # Not run from a clone (AUR install): fall back to the read-only template
    # the package ships at /usr/lib/archcanary/yay-init.lua so there's still
    # something to `cp` from without needing a git clone. (Not reusing
    # _bundled_list_path for this — it's defined much later in this script,
    # past the --doctor dispatch's own `exit`, so it isn't callable yet.)
    # luasrc_found tracks whether $luasrc is an actual file — when it's
    # neither, no path is safe to embed in a literal `cp` command below.
    local luasrc_found=1
    if [[ ! -f $luasrc ]]; then
        if [[ -f /usr/lib/archcanary/yay-init.lua ]]; then
            luasrc="/usr/lib/archcanary/yay-init.lua"
        else
            luasrc_found=0
        fi
    fi

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
                yay|paru|hooks|lua|init.lua)        want[external]=1 ;;  # tool names → their section
                platform|plat|distro)               want[platform]=1 ;;
                all)                                for s in "${ordered[@]}"; do want[$s]=1; done ;;
                *)
                    printf 'Unknown --doctor section: %s\n' "$s" >&2
                    printf 'Valid: platform, deps, user, system, systemd, external (or all).\n' >&2
                    printf 'Tool names (paru, yad, …) also map to a section.\n' >&2
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
        # A stale user-level completion file silently shadows a correct
        # system-level one forever: bash's dynamic loader checks the user
        # completions dir first, so it wins even when it's the wrong one.
        # This happens to anyone who did a plain install once, then switched
        # to --system/package installs/updates without ever repeating the
        # plain one — nothing else in either install path touches the other
        # location, so the two silently drift apart with no obvious symptom
        # beyond "my new flag doesn't tab-complete." Reported live.
        local user_completion="${XDG_DATA_HOME:-$real_home/.local/share}/bash-completion/completions/archcanary"
        local sys_completion="${ARCHCANARY_SYS_COMPLETION:-/usr/share/bash-completion/completions/archcanary}"
        if [[ -f "$user_completion" && -f "$sys_completion" ]] && ! cmp -s "$user_completion" "$sys_completion"; then
            _warn "bash completion (user copy differs from system copy)" \
                "bash $installer   # refreshes the user copy, which is the one that actually wins" \
                "$user_completion is out of sync with $sys_completion — bash prefers the user copy regardless of which is newer"
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
        # Markers are coupled to archcanary's own configs/yay-init.lua header
        # comment (not a public API, just this project's own convention) — if
        # that header ever changes, bump these too. STABLE prefix-matches any
        # archcanary-authored version; CURRENT matches only the exact latest
        # one, so a present-but-outdated copy is distinguishable from "never
        # installed". Nothing ever writes $yay_init_lua automatically — it's
        # a per-user path no install path can reach, and the hook is opt-in
        # either way (see docs/my-setup.md, "yay 13.0 integration") — so
        # "never installed" is the common, unremarkable case, not a failure.
        # This check fails silently (reports a working hook as missing)
        # rather than erroring out.
        local _ARCHCANARY_LUA_MARKER_STABLE='yay 13.0 Lua hooks for the AUR security stack'
        local _ARCHCANARY_LUA_MARKER_CURRENT="$_ARCHCANARY_LUA_MARKER_STABLE (v9)"
        local _lua_label="yay init.lua (archcanary hooks: upgrade-age warning, pattern block, aur-audit black/red check, install log)"
        # No local copy at all (neither a git clone nor an AUR/--system
        # install) — nothing safe to embed in a literal `cp` command.
        local _lua_fix
        if [[ $luasrc_found -eq 1 ]]; then
            _lua_fix="cp $luasrc $yay_init_lua"
        else
            _lua_fix="grab configs/yay-init.lua from https://github.com/musqz/archcanary, then cp it to $yay_init_lua"
        fi
        _opt_dep "lynis (system hardening auditor)" lynis lynis "post-install hardening audit"
        if [[ "$(_marker "$_ARCHCANARY_LUA_MARKER_CURRENT" "$yay_init_lua")" -eq 0 ]]; then
            _ok "$_lua_label" "path: $yay_init_lua"
        elif [[ "$(_marker "$_ARCHCANARY_LUA_MARKER_STABLE" "$yay_init_lua")" -eq 0 ]]; then
            _warn "$_lua_label (outdated)" \
                "$_lua_fix   # merge in any of your own customizations first" \
                "$yay_init_lua's archcanary-managed hooks are from an older version"
        else
            _opt "$_lua_label" \
                "$_lua_fix" \
                "not installed — hooks are opt-in, never installed automatically; path once enabled: $yay_init_lua"
        fi
        if command -v paru >/dev/null 2>&1; then
            local paru_conf="${XDG_CONFIG_HOME:-$real_home/.config}/paru/paru.conf"
            local _ARCHCANARY_PARU_MARKER_STABLE='archcanary PreBuildCommand hook'
            local _ARCHCANARY_PARU_MARKER_CURRENT="$_ARCHCANARY_PARU_MARKER_STABLE (v1)"
            local _paru_label="paru PreBuildCommand hook (archcanary pre-build PKGBUILD scan)"
            if [[ "$(_marker "$_ARCHCANARY_PARU_MARKER_CURRENT" "$paru_conf")" -eq 0 ]]; then
                _ok "$_paru_label" "path: $paru_conf"
            elif [[ "$(_marker "$_ARCHCANARY_PARU_MARKER_STABLE" "$paru_conf")" -eq 0 ]]; then
                _warn "$_paru_label (outdated)" \
                    "edit $paru_conf by hand — see docs/my-setup.md, \"paru integration\" for the current PreBuildCommand line" \
                    "$paru_conf's archcanary-managed hook is from an older version"
            else
                _opt "$_paru_label" "" "path: $paru_conf"
            fi
        fi
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

if [[ -n "$COMMUNITY_LIST_OPT" ]]; then
    COMMUNITY_REPORTS_LIST="$COMMUNITY_LIST_OPT"
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

# Populates OUT_ARRAY_NAME with "username:home" entries for real local users
# — UID in [UID_MIN, UID_MAX] from /etc/login.defs (falls back to Arch's own
# defaults, 1000-60000, if login.defs is missing/unreadable), shell not
# ending in nologin or false, home directory exists. SCAN_ALL_HOMES_EXCLUDE
# (colon-separated usernames) skips additional accounts. Test seam:
# _SCAN_ALL_HOMES_TEST_PASSWD points at a passwd-format file instead of
# querying getent, same convention as AUTOSTART_HOME/PKGBUILD_CACHE_DIRS.
_enumerate_local_users() {
    local -n _seu_out="$1"
    _seu_out=()

    local uid_min=1000 uid_max=60000 _v
    if [[ -r /etc/login.defs ]]; then
        _v="$(awk '$1=="UID_MIN"{print $2}' /etc/login.defs)"
        [[ "$_v" =~ ^[0-9]+$ ]] && uid_min="$_v"
        _v="$(awk '$1=="UID_MAX"{print $2}' /etc/login.defs)"
        [[ "$_v" =~ ^[0-9]+$ ]] && uid_max="$_v"
    fi

    local -a _exclude=()
    IFS=':' read -ra _exclude <<< "${SCAN_ALL_HOMES_EXCLUDE:-}"

    local name uid home shell skip ex
    while IFS=: read -r name _ uid _ _ home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        (( uid >= uid_min && uid <= uid_max )) || continue
        [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        [[ -d "$home" ]] || continue
        skip=false
        for ex in "${_exclude[@]}"; do
            [[ -n "$ex" && "$name" == "$ex" ]] && { skip=true; break; }
        done
        $skip && continue
        _seu_out+=("$name:$home")
    done < <(if [[ -n "${_SCAN_ALL_HOMES_TEST_PASSWD:-}" ]]; then
                 cat -- "$_SCAN_ALL_HOMES_TEST_PASSWD"
             else
                 getent passwd
             fi)
}

# Resolves SCAN_USER_OPTS (repeatable --scan-user=NAME, order preserved,
# de-duped) to "name:home" pairs — the same convention _enumerate_local_users
# produces, so _run_scan_all_homes's loop works unchanged regardless of
# source. Unlike full enumeration, a named user skips the UID-range/shell
# filters entirely: naming a specific account is exactly the case those
# filters exist to make unnecessary. An unknown name or a missing home
# directory is a hard error (a typo here should be obvious, not silently
# dropped the way enumeration silently excludes non-matching accounts). Same
# _SCAN_ALL_HOMES_TEST_PASSWD test seam as _enumerate_local_users.
_resolve_scan_user_opts() {
    local -n _rsuo_out="$1"
    _rsuo_out=()
    local _name _home _seen=":"
    for _name in "${SCAN_USER_OPTS[@]}"; do
        [[ "$_seen" == *":$_name:"* ]] && continue
        _seen+="$_name:"
        # Targeted lookup (getent passwd NAME), not bulk enumeration
        # (getent passwd) -- matches the pattern used elsewhere in this file
        # (e.g. real_home/_invoker_home above) and avoids two problems bulk
        # enumeration has here: (1) some NSS backends (sssd's `enumerate =
        # false`, common on LDAP/AD-joined systems) refuse bulk listing
        # while still answering targeted lookups, so a valid --scan-user=X
        # could never resolve; (2) a targeted lookup's own "not found" exit
        # status, piped through pipefail into this bare `var=$(...)`
        # assignment, would otherwise kill the whole script under set -e on
        # every ordinary typo (not just the NSS-refusal case) -- `|| true`
        # neutralizes that, leaving the existing empty-$_home check below to
        # report it properly instead.
        if [[ -n "${_SCAN_ALL_HOMES_TEST_PASSWD:-}" ]]; then
            _home=$(awk -F: -v u="$_name" '$1==u{print $6; exit}' "$_SCAN_ALL_HOMES_TEST_PASSWD")
        else
            _home=$(getent passwd "$_name" | cut -d: -f6) || true
        fi
        if [[ -z "$_home" ]]; then
            echo "Error: --scan-user='$_name' is not a known local user" >&2
            exit 1
        fi
        if [[ ! -d "$_home" ]]; then
            echo "Error: --scan-user='$_name' has no home directory ($_home)" >&2
            exit 1
        fi
        _rsuo_out+=("$_name:$_home")
    done
}

# --scan-all-homes/--scan-user: enumerates real local users (or resolves the
# explicitly named ones) and runs the six home-dependent checks against each
# of their homes as a privilege-dropped subprocess (the same flag bundle
# archcanary-user.service already runs in production, just centrally
# triggered) — not an in-process loop, since check_autostart's `command -v`
# resolution needs the target user's real PATH, and only check_npm_cache
# privilege-drops today. Folds each user's worst-of-N result into the
# existing summary labels/indices (never a per-user-suffixed label —
# _is_behavior_check_name matches names verbatim).
# The six checks --scan-all-homes/--scan-user cover per-user (their own
# ~/.npm, ~/.cache/yarn, AUR helper caches, ~/.config/autostart, etc. --
# everything else archcanary checks is machine-wide, checked once regardless
# of who's named). Single source of truth for _run_scan_all_homes (fold into
# the shared worst-of-N / _rec), _is_sah_per_user_check (exclude from the
# general table), and _print_sah_per_user_checks (render one row per user)
# -- previously duplicated independently in all three, with nothing
# enforcing agreement between them.
_SAH_PER_USER_CHECK_NAMES=(
    "npm cache" "bun cache" "yarn cache" "pnpm cache"
    "PKGBUILD obfuscation scan" "XDG autostart + shell RCs"
)
declare -A _SAH_PER_USER_CHECK_IDX=(
    ["npm cache"]="5" ["bun cache"]="6" ["yarn cache"]="6b" ["pnpm cache"]="6c"
    ["PKGBUILD obfuscation scan"]="7" ["XDG autostart + shell RCs"]="10"
)

_run_scan_all_homes() {
    local _sah_bin _sah_users=() _sah_any_failed=false
    _sah_bin="${_SCAN_ALL_HOMES_TEST_BIN:-$(realpath "$0")}"
    # Per-user, per-check detail, alongside the existing shared worst-of-N
    # fold below — only ever rendered for --scan-user (see
    # _print_sah_per_user_checks's call site), but populated unconditionally
    # since it's cheap and keeps this loop uniform. Global (no `local`),
    # same convention as _SUMMARY_NAMES/_SUMMARY_CODES. _SAH_USER_NAMES is
    # the ordered, de-duped list of users actually scanned this run (added
    # once each, whether or not their child scan produced usable data);
    # _SAH_USER_CHECKS is keyed "user|checkname" -> code — a user with no
    # entries at all means their child scan never returned parseable output.
    _SAH_USER_NAMES=()
    declare -gA _SAH_USER_CHECKS=()
    if [[ ${#SCAN_USER_OPTS[@]} -gt 0 ]]; then
        # Already resolved/validated once, before the log-file/JSON redirect
        # (see _SAH_RESOLVED_USERS below _run_scan_all_homes's own
        # definition) — reused here rather than re-resolving.
        _sah_users=("${_SAH_RESOLVED_USERS[@]}")
    else
        _enumerate_local_users _sah_users
    fi
    if [[ ${#_sah_users[@]} -eq 0 ]]; then
        echo "  No real local users found (UID range, shell, or home-dir filters excluded everyone)."
    fi

    local -A _sah_worst=()
    local _sah_init_name
    for _sah_init_name in "${_SAH_PER_USER_CHECK_NAMES[@]}"; do
        _sah_worst[$_sah_init_name]=-1
    done

    local _sah_entry _sah_user _sah_home _sah_log _sah_json
    local _sah_name _sah_status _sah_code
    for _sah_entry in "${_sah_users[@]}"; do
        _sah_user="${_sah_entry%%:*}"
        _sah_home="${_sah_entry#*:}"
        echo "  === user: $_sah_user ($_sah_home) ==="
        _sah_log="$_sah_home/.cache/archcanary/last-user-scan.log"
        # PATH is set via `env` *after* the user switch, not prefixed before
        # `sudo`, since sudo's own env_reset/secure_path policy (sudoers is
        # per-machine config, not something to assume about) can silently
        # discard a PATH set only on the invoking side.
        # Deliberately no --malicious-npm-list/--package-list/--chaos-rat-list/
        # --russian-spam-list/--community-list here: those default to
        # $MALICIOUS_NPM_LIST etc. in *this* (root) process, which — thanks to
        # the SUDO_USER HOME-rebind above — resolve to the invoking user's own
        # $HOME/.config/archcanary/. Passing them through would point every
        # other user's child scan at a directory only the invoking user can
        # read (typically 700), making the list look "missing" and sending the
        # self-heal `cp` in the bundled-default fallback at a destination it
        # can't write either — a guaranteed permission-denied, unparseable-JSON
        # failure for every user but the invoking one. Let each child resolve
        # its own list paths from its own $HOME instead, same as a standalone
        # run or archcanary-user.service.
        _sah_json=$(sudo -H -u "$_sah_user" -- env \
                PATH="$_sah_home/.local/bin:$_sah_home/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin" \
                "$_sah_bin" \
                --check-npm-cache --check-bun-cache --check-yarn-cache \
                --check-pnpm-cache --check-pkgbuild --check-autostart \
                --no-notify --color=never --format=json \
                --log-file="$_sah_log" 2>/dev/null) || true
        if [[ -f "$_sah_log" ]]; then
            cat -- "$_sah_log"
        else
            echo "  WARNING: no log produced for $_sah_user"
        fi
        _SAH_USER_NAMES+=("$_sah_user")
        if [[ -z "$_sah_json" ]]; then
            echo "  WARNING: could not evaluate result for $_sah_user (no parseable output)"
            _sah_any_failed=true
            continue
        fi
        while IFS='|' read -r _sah_name _sah_status; do
            [[ -n "${_sah_worst[$_sah_name]+x}" ]] || continue
            _sah_code=$(_sah_status_to_code "$_sah_status")
            (( _sah_code > _sah_worst[$_sah_name] )) && _sah_worst[$_sah_name]=$_sah_code
            _SAH_USER_CHECKS["$_sah_user|$_sah_name"]=$_sah_code
        done < <(_sah_parse_checks "$_sah_json")
    done

    for _sah_name in "${_SAH_PER_USER_CHECK_NAMES[@]}"; do
        _sah_code="${_sah_worst[$_sah_name]}"
        if [[ $_sah_code -eq -1 ]]; then
            $_sah_any_failed && _sah_code=1 || _sah_code=0
        fi
        [[ $_sah_code -gt $EXIT_CODE ]] && EXIT_CODE=$_sah_code
        _rec "$_sah_name" "$_sah_code" "${_SAH_PER_USER_CHECK_IDX[$_sah_name]}"
    done
}

# Resolve/validate --scan-user names now, before the log-file/--format=json
# redirect below -- a typo previously wasn't caught until deep inside
# _run_scan_all_homes (check-sequence position "10b"), by which point
# earlier requested checks had already run, and in JSON mode the error
# message went only to the (already-redirected) log file, leaving a JSON
# caller's actual stdout completely empty. The mutual-exclusion and root
# checks above already validate early for the same reason; this closes the
# same gap for name resolution. _run_scan_all_homes reuses this array
# instead of re-resolving (also fixes the "--- [10b] ... ---" header below,
# which used to print the raw, non-deduped SCAN_USER_OPTS). Named function
# (not inlined) so tests can populate _SAH_RESOLVED_USERS directly without
# needing to fake $SCAN_HOMES_MODE/$DOCTOR.
_resolve_and_store_scan_users() {
    _SAH_RESOLVED_USERS=()
    [[ ${#SCAN_USER_OPTS[@]} -gt 0 ]] && _resolve_scan_user_opts _SAH_RESOLVED_USERS
    return 0
}
if $SCAN_HOMES_MODE && ! $DOCTOR; then
    _resolve_and_store_scan_users
fi

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
# Preserve the real stdout on fd 3 before any redirection below — --format=json
# needs a clean fd for its JSON payload even when the narrative output is
# redirected to the log file only (see _print_summary_json).
exec 3>&1
if $FORMAT_JSON; then
    # JSON mode: narrative goes to the log only, not to the captured stdout —
    # a caller consuming this via a subprocess pipe (archcanary-gtk) needs
    # nothing but the JSON payload on stdout.
    exec > "$LOG_FILE" 2>&1
else
    # Redirect all output through tee: terminal + log file
    exec > >(tee "$LOG_FILE") 2>&1
fi

# ---------------------------------------------------------------------------
# Config dir: XDG_CONFIG_HOME/archcanary (default ~/.config/archcanary)
# Can be overridden via PACKAGE_LIST_FILE / MALICIOUS_NPM_LIST env vars
# ---------------------------------------------------------------------------
AUR_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/archcanary"
mkdir -p "$AUR_CONFIG_DIR"

# Persisted settings written by archcanary-gui's "Edit config" > "Network
# feeds" dialog. Read as plain data (grep), never `source`d as shell — this
# file resolves into the invoking user's $HOME even during the pkexec-elevated
# root scan (see lib/archcanary-root-helper), so sourcing it would let any
# local user run arbitrary code as root.
ARCHCANARY_ENV_FILE="${ARCHCANARY_ENV_FILE:-$AUR_CONFIG_DIR/env}"
# || true twice: grep exits non-zero on no match / missing file, and under
# `pipefail` that would propagate through tail/cut; under `set -e` a bare
# `return` would then inherit that non-zero status and kill the whole script
# (same failure class as the picker bug documented for archcanary-gui.sh).
_archcanary_env_get() {
    [[ -f "$ARCHCANARY_ENV_FILE" ]] || return 0
    grep -E "^$1=" "$ARCHCANARY_ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true
}

PACKAGE_LIST_FILE="${PACKAGE_LIST_FILE:-$AUR_CONFIG_DIR/package_list.txt}"
INFECTED_PKGS=()

CHAOS_RAT_LIST="${CHAOS_RAT_LIST:-$AUR_CONFIG_DIR/chaos_rat_packages.txt}"
CHAOS_RAT_PKGS=()

RUSSIAN_SPAM_LIST="${RUSSIAN_SPAM_LIST:-$AUR_CONFIG_DIR/malicious_russian_spam_packages.txt}"
RUSSIAN_SPAM_PKGS=()

COMMUNITY_REPORTS_LIST="${COMMUNITY_REPORTS_LIST:-$AUR_CONFIG_DIR/community_reports.txt}"
COMMUNITY_REPORTS_PKGS=()

AUR_AUDIT_BLACK_LIST="${AUR_AUDIT_BLACK_LIST:-$AUR_CONFIG_DIR/aur_audit_black.txt}"
AUR_AUDIT_BLACK_PKGS=()
# Companion file: "pkgname YYYY-MM-DD" per line, the flagged version's own AUR
# publish date (pubDateTs from the API) — lets check_logs tell "this pacman.log
# entry predates the version that got flagged" from "it's the same or a later
# one". Package-name-only aur_audit_black.txt/red.txt above are untouched by
# this — configs/yay-init.lua's Lua hook reads those directly and must keep
# seeing one bare name per line.
AUR_AUDIT_BLACK_DATES_LIST="${AUR_AUDIT_BLACK_DATES_LIST:-$AUR_CONFIG_DIR/aur_audit_black_dates.txt}"
AUR_AUDIT_BLACK_DATE_LINES=()

AUR_AUDIT_RED_LIST="${AUR_AUDIT_RED_LIST:-$AUR_CONFIG_DIR/aur_audit_red.txt}"
AUR_AUDIT_RED_PKGS=()
AUR_AUDIT_RED_DATES_LIST="${AUR_AUDIT_RED_DATES_LIST:-$AUR_CONFIG_DIR/aur_audit_red_dates.txt}"
AUR_AUDIT_RED_DATE_LINES=()
# Companion file: "pkgname pkgver-pkgrel" per line, the flagged version's own
# Arch version string (wtako's "version" field). Read directly by
# configs/yay-init.lua's Lua hook, which compares it against the PKGBUILD
# currently being installed so a name-only match doesn't warn forever once a
# newer version has been rescanned clean. RED only -- BLACK's yay.abort()
# stays unconditional regardless of version. No bash-side consumer, so unlike
# the dates file above this gets no *_LINES array or associative lookup.
AUR_AUDIT_RED_VERSIONS_LIST="${AUR_AUDIT_RED_VERSIONS_LIST:-$AUR_CONFIG_DIR/aur_audit_red_versions.txt}"

# Fetch the aur-audit.wtako.net black/red feed on --refresh. Disable via
# AUR_AUDIT_ENABLE=false (env), --no-aur-audit (one-off), or the GUI checkbox.
# Lowercased so a hand-edited env file (TRUE/False/etc.) still matches the
# exact-string gate below, and so it agrees with the GUI's own case-insensitive
# grep for the checkbox's current state.
AUR_AUDIT_ENABLE="${AUR_AUDIT_ENABLE:-$(_archcanary_env_get AUR_AUDIT_ENABLE)}"
AUR_AUDIT_ENABLE="${AUR_AUDIT_ENABLE:-true}"
AUR_AUDIT_ENABLE="${AUR_AUDIT_ENABLE,,}"
unset -f _archcanary_env_get

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

# Resolves a bundled data file. Checks two locations relative to the running
# script first (flat layout — $0 is /usr/lib/archcanary/archcanary.sh, the
# root-scan copy; then the lists/ subdir layout — repo checkout,
# ./archcanary.sh run in place), then falls back to the fixed system path
# /usr/lib/archcanary/<file>. That last fallback is required when $0 is
# /usr/bin/archcanary (the plain user-facing binary both install.sh and the
# AUR PKGBUILD install) — it has no data files next to it; only
# /usr/lib/archcanary/ does, since root's $HOME isn't seeded and needs its own
# copy regardless of which entry point the user actually runs.
# ARCHCANARY_SYSTEM_LIB overrides the fixed path for testing.
_bundled_list_path() {
    local _dir _f
    _dir="$(dirname "$(realpath "$0")")"
    for _f in "$_dir/$1" "$_dir/lists/$1" "${ARCHCANARY_SYSTEM_LIB:-/usr/lib/archcanary}/$1"; do
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

if [[ ! -f "$COMMUNITY_REPORTS_LIST" ]]; then
    _bundled="$(_bundled_list_path community_reports.txt)" && cp "$_bundled" "$COMMUNITY_REPORTS_LIST"
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
while IFS= read -r line || [[ -n "$line" ]]; do
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
        _refresh_list "$COMMUNITY_REPORTS_LIST_URL" "$COMMUNITY_REPORTS_LIST" "community reports list" "$COMMUNITY_LIST_OPT"
        unset -f _refresh_list

        # aur-audit.wtako.net — community/third-party continuous AUR scan feed.
        # Paginated JSON API (no auth, no jq dependency: grep -oP field pull).
        # Fails soft per filter, like the supplementary lists above. Also
        # captures each entry's pubDateTs (the flagged version's own AUR
        # publish timestamp — epoch ms, RSS-style "pubDate" field, not
        # wtako's own analysisOn scan time) into a companion "pkgname
        # YYYY-MM-DD" dates file, so check_logs can tell a pacman.log entry
        # that predates the flagged version from one that doesn't. Per-page
        # name/date counts are verified equal before pairing — if a future
        # API response ever drops the field for some entries, dates are
        # skipped for that page (names still update) rather than risk
        # silently misaligning name[i] with date[j]. RED's call also passes a
        # versions_dest, capturing the flagged version's own "pkgver-pkgrel"
        # string into a companion versions file — configs/yay-init.lua's Lua
        # hook compares it against the PKGBUILD being installed so a
        # name-only match doesn't warn forever once a newer version is
        # rescanned clean. BLACK gets no versions_dest: a confirmed-malicious
        # verdict stays an unconditional block regardless of version.
        _refresh_aur_audit() {
            local filter="$1" dest="$2" label="$3" dates_dest="$4" versions_dest="${5:-}"
            local base="https://aur-audit.wtako.net/packages"
            local cursor="" page pages=0
            local -a page_names page_dates_ms all=() all_dates=() all_versions=()
            echo "Fetching aur-audit $label list..."
            while :; do
                page=$(curl -fsSL "${base}?filter=${filter}&limit=500${cursor:+&before=$cursor}" 2>/dev/null) || {
                    echo >&2 "WARNING: failed to fetch aur-audit $label list — keeping existing."
                    return
                }
                mapfile -t page_names < <(grep -oP '"packageName":"\K[^"]*' <<<"$page")
                mapfile -t page_dates_ms < <(grep -oP '"pubDateTs":\K[0-9]+' <<<"$page")
                all+=("${page_names[@]}")
                if [[ ${#page_names[@]} -eq ${#page_dates_ms[@]} ]]; then
                    local i ds
                    for i in "${!page_names[@]}"; do
                        ds=$(date -d "@$(( page_dates_ms[i] / 1000 ))" +%F 2>/dev/null) || continue
                        all_dates+=("${page_names[i]} $ds")
                    done
                fi
                if [[ -n "$versions_dest" ]]; then
                    # Not every entry carries a "version" field (live feed:
                    # ~3% don't) -- the flat index-pairing used for dates
                    # above would silently drop the whole page on any count
                    # mismatch, and a lazy cross-field regex risks pairing a
                    # name with the WRONG object's version. Split into one
                    # record per package object first (each starts with the
                    # fixed "guid" field) so packageName/version are pulled
                    # from the same object and never misattributed.
                    local -a page_objs
                    mapfile -t page_objs < <(awk -v RS='{"guid":"' 'NR>1{print RS $0}' <<<"$page")
                    local obj oname over
                    for obj in "${page_objs[@]}"; do
                        oname=$(grep -oP '"packageName":"\K[^"]*' <<<"$obj" | head -1) || true
                        over=$(grep -oP '"version":"\K[^"]*' <<<"$obj" | head -1) || true
                        [[ -n "$oname" && -n "$over" ]] && all_versions+=("$oname $over")
                    done
                fi
                cursor=$(grep -oP '"nextCursor":\K[0-9]+' <<<"$page" || true)
                pages=$((pages + 1))
                [[ -n "$cursor" && $pages -lt 200 ]] || break
            done
            if [[ ${#all[@]} -eq 0 ]]; then
                echo >&2 "WARNING: aur-audit $label fetch returned 0 entries — keeping existing."
                return
            fi
            printf '%s\n' "${all[@]}" | sort -u > "$dest"
            _chown_to_invoker "$dest"
            echo "Updated $dest ($(grep -c '^[^#[:space:]]' "$dest") entries)"
            if [[ ${#all_dates[@]} -gt 0 ]]; then
                printf '%s\n' "${all_dates[@]}" | sort -u > "$dates_dest"
                _chown_to_invoker "$dates_dest"
            fi
            if [[ -n "$versions_dest" ]]; then
                if [[ ${#all_versions[@]} -gt 0 ]]; then
                    printf '%s\n' "${all_versions[@]}" | sort -u > "$versions_dest"
                    _chown_to_invoker "$versions_dest"
                else
                    # Unlike dest/dates_dest above, an empty capture here is
                    # NOT left stale -- a stale flagged-version line drives an
                    # active severity *downgrade* in the Lua hook (full
                    # warning vs. "different version, might be stale"), not
                    # just outdated-but-still-flagged threat data. If a
                    # future page format ever breaks this extraction, fail
                    # toward the conservative default (no data -> full
                    # warning for every RED match) rather than risk a wrong
                    # version silently softening a warning that shouldn't be.
                    : > "$versions_dest"
                    _chown_to_invoker "$versions_dest"
                fi
            fi
        }
        if [[ "$AUR_AUDIT_ENABLE" == true ]]; then
            _refresh_aur_audit black "$AUR_AUDIT_BLACK_LIST" "black" "$AUR_AUDIT_BLACK_DATES_LIST"
            _refresh_aur_audit red   "$AUR_AUDIT_RED_LIST"   "red"   "$AUR_AUDIT_RED_DATES_LIST" "$AUR_AUDIT_RED_VERSIONS_LIST"
        else
            echo "Skipping aur-audit.wtako.net fetch (disabled)."
        fi
        unset -f _refresh_aur_audit
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

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        INFECTED_PKGS+=("$line")
    done <"$PACKAGE_LIST_FILE"

    # CHAOS RAT list (optional — absence is not fatal)
    CHAOS_RAT_PKGS=()
    if [[ -f "$CHAOS_RAT_LIST" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            CHAOS_RAT_PKGS+=("$line")
        done <"$CHAOS_RAT_LIST"
    fi

    # Russian Spam Campaign list (optional — absence is not fatal)
    RUSSIAN_SPAM_PKGS=()
    if [[ -f "$RUSSIAN_SPAM_LIST" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            RUSSIAN_SPAM_PKGS+=("$line")
        done <"$RUSSIAN_SPAM_LIST"
    fi

    # Community-reported package list (optional — absence is not fatal)
    COMMUNITY_REPORTS_PKGS=()
    if [[ -f "$COMMUNITY_REPORTS_LIST" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            COMMUNITY_REPORTS_PKGS+=("$line")
        done <"$COMMUNITY_REPORTS_LIST"
    fi

    # aur-audit.wtako.net black/red lists (optional — only exist after --refresh)
    AUR_AUDIT_BLACK_PKGS=()
    if [[ -f "$AUR_AUDIT_BLACK_LIST" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            AUR_AUDIT_BLACK_PKGS+=("$line")
        done <"$AUR_AUDIT_BLACK_LIST"
    fi

    AUR_AUDIT_RED_PKGS=()
    if [[ -f "$AUR_AUDIT_RED_LIST" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            AUR_AUDIT_RED_PKGS+=("$line")
        done <"$AUR_AUDIT_RED_LIST"
    fi

    # Companion "pkgname YYYY-MM-DD" dates files — optional, only exist after
    # a --refresh run that includes this feature. Absence (not yet refreshed,
    # or a fetch that failed soft) just means check_logs falls back to its
    # old no-cutoff behavior for that source, not an error.
    AUR_AUDIT_BLACK_DATE_LINES=()
    if [[ -f "$AUR_AUDIT_BLACK_DATES_LIST" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -n "$line" ]] && AUR_AUDIT_BLACK_DATE_LINES+=("$line")
        done <"$AUR_AUDIT_BLACK_DATES_LIST"
    fi

    AUR_AUDIT_RED_DATE_LINES=()
    if [[ -f "$AUR_AUDIT_RED_DATES_LIST" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -n "$line" ]] && AUR_AUDIT_RED_DATE_LINES+=("$line")
        done <"$AUR_AUDIT_RED_DATES_LIST"
    fi

    # Extra lists — from extra_lists.conf and --extra-list= flags
    EXTRA_PKGS=()
    EXTRA_LIST_NAMES=()
    EXTRA_LIST_KEYS=()
    EXTRA_LIST_COUNTS=()
    _load_extra() {
        local orig="$1" src="$1"
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
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            EXTRA_PKGS+=("$line")
            _n=$(( _n + 1 ))
        done < "$src"
        EXTRA_LIST_NAMES+=("$(basename "$orig")")
        EXTRA_LIST_KEYS+=("$orig")
        EXTRA_LIST_COUNTS+=("$_n")
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
    local found=() found_pkgs=()
    declare -gA CURRENTLY_INSTALLED_MAP=()
    while IFS= read -r pkg; do
        CURRENTLY_INSTALLED_MAP[$pkg]=1
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
        elif [[ -v AUR_AUDIT_BLACK_LOOKUP["$pkg"] ]]; then
            found+=("$pkg (installed: $install_date) [aur-audit: black]")
        elif [[ -v AUR_AUDIT_RED_LOOKUP["$pkg"] ]]; then
            found+=("$pkg (installed: $install_date) [aur-audit: red]")
        elif [[ -v COMMUNITY_REPORTS_LOOKUP["$pkg"] ]]; then
            found+=("$pkg (installed: $install_date) [community report]")
        else
            found+=("$pkg (installed: $install_date)")
        fi
        found_pkgs+=("$pkg")
    done < <(pacman -Qmq "${INFECTED_PKGS[@]}" 2>/dev/null)

    if [[ ${#found[@]} -eq 0 ]]; then
        echo "  Clean: no infected packages currently installed."
        return 0
    else
        echo "  WARNING: ${#found[@]} possibly infected package(s):"
        print_list found
        echo "  Remove them:"
        printf '    sudo pacman -Rns -- %s\n' "${found_pkgs[*]}"
        return 2
    fi
}

# ---------------------------------------------------------------------------
# Check 2: Historical pacman logs
# (From Kacper-Kondracki: scan pacman.log* for install events)
# ---------------------------------------------------------------------------
check_logs() {
    local log_files=()
    # Per-source cutoff dates (YYYY-MM-DD) below which a name match predates
    # any known compromise for that list — see the tag-selection logic
    # further down for how these are used. Only set where SOURCES.md
    # documents an actual campaign start date, or (aur-audit black/red) a
    # per-package cutoff is available from AUR_AUDIT_{BLACK,RED}_DATE
    # (populated from the flagged version's own AUR publish date, captured
    # on --refresh — see _refresh_aur_audit). Community Reports has no fixed
    # scope/end date and no per-entry date data at all, so it intentionally
    # has no cutoff.
    local campaign_cutoff="2026-06-09"  # earliest documented malicious commit
    local chaos_cutoff="2025-07-22"     # CHAOS RAT campaign discovery date

    local seen_file="${XDG_CACHE_HOME:-$HOME/.cache}/archcanary/log_hist_seen.txt"
    declare -A seen_map
    if [[ -r "$seen_file" ]]; then
        while IFS=$'\t' read -r _sp _sd; do
            seen_map["$_sp"$'\t'"$_sd"]=1
        done < "$seen_file"
    fi
    local -a new_seen=()

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

    # CURRENTLY_INSTALLED_MAP is populated by check_current(), which always
    # runs immediately before this function — reused here instead of
    # repeating its `pacman -Qmq` query, so a log hit for a package removed
    # long ago can be reported as historical-only rather than an active
    # infection.

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

            # Select this match's source annotation and, where a date exists
            # to compare against, its cutoff -- cutoff empty means "never
            # downgrade". Russian Spam has no lookup array of its own (merged
            # into INFECTED_PKGS untagged) and shares the base list's
            # (earlier, safer) cutoff via the else branch below. aur-audit's
            # cutoff is per-package (the flagged version's own AUR publish
            # date) rather than one fixed constant -- falls back to "" (never
            # downgrade, the old behavior) for a package with no date on file.
            local tag cutoff="" annotation=""
            if [[ -v CHAOS_LOOKUP[$pkg] ]]; then
                cutoff="$chaos_cutoff"
                annotation=" [CHAOS RAT campaign, 2025-07]"
            elif [[ -v AUR_AUDIT_BLACK_LOOKUP[$pkg] ]]; then
                cutoff="${AUR_AUDIT_BLACK_DATE[$pkg]:-}"
                annotation=" [aur-audit: black]"
            elif [[ -v AUR_AUDIT_RED_LOOKUP[$pkg] ]]; then
                cutoff="${AUR_AUDIT_RED_DATE[$pkg]:-}"
                annotation=" [aur-audit: red]"
            elif [[ -v COMMUNITY_REPORTS_LOOKUP[$pkg] ]]; then
                annotation=" [community report]"
            else
                cutoff="$campaign_cutoff"
            fi

            # A match predating its source's cutoff is treated as
            # essentially unrelated regardless of current install state --
            # takes priority over the installed/historical split below. If
            # a still-installed package's only logged actions predate the
            # cutoff, a rebuild/upgrade always produces a new pacman.log
            # line, so nothing on this system ever pulled a compromised
            # version; that's just as safe to downgrade as a removed one.
            if [[ -n "$cutoff" && "$date_str" < "$cutoff" ]]; then
                tag="LOG_OLD"
            elif [[ -v CURRENTLY_INSTALLED_MAP[$pkg] ]]; then
                tag="LOG_HIT"
            elif [[ -v seen_map["$pkg"$'\t'"$datetime_str"] ]]; then
                tag="LOG_HIST_SEEN"
            else
                tag="LOG_HIST"
                new_seen+=("$pkg"$'\t'"$datetime_str")
            fi

            echo "$tag: $pkg ($action on $datetime_str)$annotation"
        done < <(read_compressed_file "$file") || true

        log_info "[$idx/$total] Done with $(basename "$file")"
    done

    if [[ ${#new_seen[@]} -gt 0 ]]; then
        mkdir -p "$(dirname "$seen_file")"
        printf '%s\n' "${new_seen[@]}" >> "$seen_file"
        _chown_to_invoker "$seen_file"
    fi
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
        echo "  If you recognize any of these, mark it known-good:"
        echo "    pkexec /usr/lib/archcanary/root-helper --allowlist-add=systemd:<unit-name>"
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
        echo "  No legitimate software creates files with these names — pinned BPF maps"
        echo "  named after a hiding technique are a strong compromise indicator, not a"
        echo "  configuration artifact. Recommend offline analysis before continuing to"
        echo "  use this system normally."
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
                    echo "  Recognize this loader? Mark it known-good:"
                    echo "    pkexec /usr/lib/archcanary/root-helper --allowlist-add=bpftool:<loader-basename>"
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
    # Matches an ANSI-C-quoted string built from 3+ chained \xHH (hex) or
    # \NNN (octal) escapes back to back — the actual obfuscation signature
    # (spelling out a command a byte at a time, e.g. $'\x63\x75\x72\x6c' for
    # "curl"). A single escape, e.g. read -d $'\0' (the standard, extremely
    # common idiom for NUL-delimited `find -print0` iteration), is not
    # obfuscation and must not match — the previous regex matched on just
    # one occurrence of $'\x or $'\0, flagging that exact legitimate idiom
    # (reported live, real nvidia-utils-beta PKGBUILD).
    local re_ansi_c
    re_ansi_c='\$'"'"'(\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}){3,}'

    # Tor/SOCKS-proxied fetch (curl -x socks5h://..., torsocks, proxychains,
    # or a bare .onion URL) — a real 2026-08-23 AUR incident (xsnow/xsnow-bin,
    # reported on aur-general) used exactly this to pull a payload binary
    # through Tor from a .install scriptlet, evading plain URL-blocklist
    # scanning. No legitimate PKGBUILD/.install fetches a build source or
    # dependency through Tor.
    # -[A-Za-z]*x / -[A-Za-z]*[oO] (not bare -x / -[oO]) so a bundled short
    # option cluster (e.g. curl's extremely common `-fsSLo file`/`-fsSLx
    # proxy` idiom, boolean flags bundled ahead of the value-taking one)
    # isn't missed just because it isn't written as a standalone flag —
    # caught in code review, verified live with a real bundled-flag PoC.
    local re_tor_proxy='(curl|wget)[[:space:]].*(-[A-Za-z]*x[[:space:]]*socks[0-9]?h?://|--socks[0-9]?h?[[:space:]]|--proxy[[:space:]]+socks)'
    local re_torsocks='(^|[;&|[:space:]])(torsocks|proxychains4?)[[:space:]]'
    # Trailing delimiter is optional (end-of-line included) — a bare .onion
    # URL as the last token on a line has nothing after it to delimit on.
    local re_onion='\.onion([/"'"'"'[:space:]]|$)'

    # Fetching straight into a system path (/usr, /etc, /opt, /boot) instead
    # of the makepkg build sandbox ($srcdir/$pkgdir) — same incident: the
    # scriptlet curl'd a binary directly to /usr/local/bin/systemmanager,
    # bypassing pacman's own file tracking entirely.
    local re_dl_syspath='(curl|wget)[[:space:]].*-[A-Za-z]*[oO][[:space:]]*/(usr|etc|opt|boot)/'

    # A reference to the AUR's own git SSH remote (aur@aur.archlinux.org) —
    # the same incident's self-propagation mechanism: harvest each local
    # user's SSH keys, clone every repo the key can push to, and commit a
    # trojaned install= field back into it. No legitimate PKGBUILD/.install
    # has any reason to reference this remote at all.
    local re_aur_ssh='aur@aur\.archlinux\.org'

    # pacman invoked non-interactively from inside a scriptlet — pacman
    # cannot safely re-enter itself mid-transaction, so any real .install
    # usage of pacman is a read-only query (e.g. `pacman -Qi`, as
    # archcanary's own PKGBUILD does). --noconfirm only makes sense paired
    # with a mutating operation (-S/-R), which the incident used to silently
    # install an unrelated dependency (tor) to stage its backdoor.
    local re_pacman_noninteractive='pacman[[:space:]].*--noconfirm'

    while IFS= read -r file; do
        (( scanned++ )) || true
        local lineno=0
        local -A _source_seen=()
        local _dup_source_key=""
        local _is_pkgbuild=false
        [[ "$(basename "$file")" == "PKGBUILD" ]] && _is_pkgbuild=true
        while IFS= read -r line || [[ -n "$line" ]]; do
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

            # --- Pattern 10: Tor/SOCKS-proxied network fetch ---
            if [[ "$line" =~ $re_tor_proxy ]] || [[ "$line" =~ $re_torsocks ]] || \
               [[ "$line" =~ $re_onion ]]; then
                echo "  WARNING: Tor/SOCKS-proxied fetch in $file:$lineno"
                echo "    $line"
                found_count=2
            fi

            # --- Pattern 11: download straight into a system path ---
            if [[ "$line" =~ $re_dl_syspath ]]; then
                echo "  WARNING: download targets a system path (bypasses pacman) in $file:$lineno"
                echo "    $line"
                found_count=2
            fi

            # --- Pattern 12: reference to the AUR's own git SSH remote ---
            if [[ "$line" =~ $re_aur_ssh ]]; then
                echo "  WARNING: reference to the AUR git SSH remote in $file:$lineno"
                echo "    $line"
                echo "    A PKGBUILD/.install has no legitimate reason to touch its own AUR"
                echo "    remote -- this is the self-propagation mechanism seen in the"
                echo "    2026-08 xsnow/xsnow-bin incident (harvest local SSH keys, push a"
                echo "    trojaned install= into every other repo reachable with them)."
                found_count=2
            fi

            # --- Pattern 13: pacman invoked non-interactively from a scriptlet ---
            if [[ "$line" =~ $re_pacman_noninteractive ]]; then
                echo "  WARNING: non-interactive pacman call in $file:$lineno"
                echo "    $line"
                echo "    pacman can't safely re-enter itself mid-transaction -- a real"
                echo "    .install usage is a read-only query, never a mutating -S/-R with"
                echo "    --noconfirm."
                found_count=2
            fi

            # --- Pattern 9: duplicate source=()/source_$CARCH=() declaration ---
            # makepkg only ever honors the last assignment to a given array
            # name -- an earlier source=() is silently dead code. A legitimate
            # PKGBUILD has no reason to declare the *same* source key twice;
            # per-arch keys (source_x86_64=, source_i686=, ...) are a separate,
            # normal mechanism and don't collide with the bare source= key or
            # each other, since each is tracked under its own key below. Known
            # false-positive shape: a small number of PKGBUILDs pick between
            # two source=() arrays via if/else instead of source_$CARCH= --
            # rarer than the arch-specific idiom, and worth a look either way,
            # since a real duplicate is either dead build-variant logic or a
            # staged-but-not-yet-armed payload. Reported live: storageexplorer-
            # bin prepended a fake source=('optimizer') above the real
            # source=() to stage a git-tracked binary makepkg never actually
            # references -- a later push correcting the array would arm it.
            # Only a bare `=` is destructive -- it unconditionally replaces
            # the whole array, silently discarding anything assigned to the
            # same key before it (via `=` or `+=`). `source+=(...)` never
            # discards anything, so it must never itself trip this check
            # (e.g. vscodium-bin's legitimate source=(...) then
            # source+=("...code.svg")) -- but a prior `+=` still counts as
            # "already assigned" for the purpose of catching a *later* bare
            # `=` that wipes it out, since `source+=('optimizer')` staged
            # before the real `source=(...)` is the storageexplorer-bin
            # attack with the two operators swapped, not a different case.
            # Known limitation: `unset source` between two assignments resets
            # the array outside what this line-by-line tracker models, so
            # `source=(A); unset source; source+=(B)` still isn't caught --
            # not worth chasing further; Pattern 9 is a best-effort heuristic
            # like the others in this scan, not an adversarial-proof parser.
            if $_is_pkgbuild && [[ "$line" =~ ^[[:space:]]*(source(_[A-Za-z0-9_]+)?)(\+?)=\( ]]; then
                local _key="${BASH_REMATCH[1]}"
                local _is_append="${BASH_REMATCH[3]}"
                if [[ -z "$_is_append" && -n "${_source_seen[$_key]:-}" ]]; then
                    _dup_source_key="$_key"
                fi
                _source_seen["$_key"]=1
            fi

        done < "$file"

        if [[ -n "$_dup_source_key" ]]; then
            echo "  WARNING: duplicate ${_dup_source_key}=() declaration in $file"
            echo "    makepkg only honors the last one -- the earlier declaration is dead"
            echo "    code, a known trick for staging a file that isn't fetched/used yet."
            found_count=2
        fi
    done < <(
        for dir in "${cache_dirs[@]}"; do
            [[ -d "$dir" ]] || continue
            find "$dir" \( -name "PKGBUILD" -o -name "*.install" \) -type f 2>/dev/null
        done
    )

    # --- Pattern 8: undocumented ELF binary committed directly to a
    # package's cache/git tree (not build output under src/ or pkg/) ---
    # A source-based PKGBUILD has no legitimate reason to ship a compiled
    # binary in its own git-tracked directory — even -bin packages that
    # install a vendor binary fetch it into src/ via source=() at build
    # time, they don't commit it to the AUR git repo itself. -maxdepth 1
    # relative to each PKGBUILD's own directory naturally excludes src/ and
    # pkg/, which only exist as subdirectories after a build. -L follows
    # symlinks before the -type test — a symlink to an ELF binary committed
    # alongside PKGBUILD is the same undocumented-binary-execution pattern
    # one level of indirection away, and plain -type f (no -L) misses it
    # entirely since a symlink itself is type l, not f.
    while IFS= read -r pkgbuild; do
        local pdir
        pdir="$(dirname "$pkgbuild")"
        while IFS= read -r bin; do
            local magic
            IFS= read -r -n4 magic < "$bin" 2>/dev/null
            if [[ "$magic" == $'\x7fELF' ]]; then
                # A -bin package's source=()/source_$CARCH=() often points at
                # a raw binary URL — makepkg downloads it straight into this
                # same top-level dir (src/ only gets a symlink back to it) as
                # a normal, expected part of building, indistinguishable by
                # plain file presence from something the maintainer actually
                # committed. Only flag it if it's tracked in the package's own
                # AUR git repo — genuinely part of the git tree, not a local
                # build artifact (reported live: false positive on pistol-bin
                # and coolercontrol-bin, both legitimate long-standing -bin
                # packages). No git repo at all (non-git cache layout) is
                # treated the same as untracked — nothing to compare against,
                # so err toward not flagging rather than a guaranteed false
                # positive on every raw-binary -bin package.
                if git -C "$pdir" ls-files --error-unmatch -- "$(basename "$bin")" &>/dev/null; then
                    echo "  WARNING: undocumented ELF binary in $bin"
                    echo "    Source-based PKGBUILDs don't ship compiled binaries in their own git"
                    echo "    tree — inspect before building: file \"$bin\"; strings \"$bin\" | less"
                    found_count=2
                fi
            fi
        done < <(find -L "$pdir" -maxdepth 1 -type f 2>/dev/null)
    done < <(
        for dir in "${cache_dirs[@]}"; do
            [[ -d "$dir" ]] || continue
            find "$dir" -name "PKGBUILD" -type f 2>/dev/null
        done
    )

    if [[ $scanned -eq 0 ]]; then
        echo "  Skipped: no AUR helper cache directories found."
    elif [[ $found_count -eq 0 ]]; then
        echo "  Clean: no malicious commands found in $scanned PKGBUILD/install file(s)."
    else
        echo
        echo "  Before rebuilding: diff what's flagged above against a fresh clone of"
        echo "  the same AUR package — don't delete this cache first, you need it to"
        echo "  compare against. Still there upstream? Don't build it. Already gone"
        echo "  upstream? Your local cache was just stale — safe to delete and re-fetch."
        echo
        echo "  If this holds up, report it so others are protected too:"
        echo "    archcanary: https://github.com/musqz/archcanary/issues/new?template=report-package.yml"
        echo "    Arch AUR:   https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/"
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
    # pacman-owned binary. Flatpak's own export dirs are included for the
    # same reason (a Flatpak app not on $PATH in this scan's environment) —
    # they're standardized, distro-integrated locations (/etc/profile.d/
    # flatpak-bindir.sh adds them to PATH on any Flatpak-enabled system),
    # not a per-app quirk, so trusting them outright is the same call already
    # made for /usr/lib and /usr/libexec above. Override with AUTOSTART_LIBDIRS
    # for testing.
    local -a _autostart_libdirs
    IFS=: read -ra _autostart_libdirs <<< "${AUTOSTART_LIBDIRS:-/usr/lib:/usr/libexec:/var/lib/flatpak/exports/bin:$home_dir/.local/share/flatpak/exports/bin}"

    # Override with AUTOSTART_SKEL_DIR for testing — real /etc/skel is a
    # system path, not something a test should write to.
    local skel_dir="${AUTOSTART_SKEL_DIR:-/etc/skel}"

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
            while IFS= read -r line || [[ -n "$line" ]]; do
                [[ "$line" =~ ^Exec= ]] || continue
                local exec_val="${line#Exec=}"
                exec_val=$(printf '%s' "$exec_val" | sed 's/[[:space:]]*%[a-zA-Z]//g' | awk '{print $1}')
                [[ -z "$exec_val" ]] && continue
                # Desktop Entry Spec allows (and some installers, e.g. pCloud's,
                # use) a quoted Exec= value even with no spaces to quote — awk
                # has no concept of quoting, so a wrapped "/path/to/bin" comes
                # out with the literal quote characters still attached. Left
                # alone, that (a) misclassifies an absolute path as an
                # unresolvable bare name (starts with '"', not '/') and (b)
                # makes the value un-allowlistable: a normal shell strips the
                # quotes when the user types the suggested --allowlist-add
                # command, so the stored value could never match this raw one.
                if [[ "$exec_val" == \"*\" && ${#exec_val} -gt 1 ]]; then
                    exec_val="${exec_val#\"}"
                    exec_val="${exec_val%\"}"
                fi

                # $home_dir/bin and $home_dir/.local/bin are standard, common
                # places for a user's own scripts (e.g. a DE-generated
                # autostart entry pointing at a personal launcher script like
                # Conky's) — the user-systemd-service branch below already
                # carries this same exception; this branch never had it,
                # producing a false "suspicious" verdict for any legitimate
                # personal script. Flatpak's export dirs get the same
                # treatment — /etc/profile.d/flatpak-bindir.sh puts them on
                # $PATH on any Flatpak-enabled system, so a resolved Flatpak
                # app (command -v succeeds directly) needs to be recognized
                # here too, not just via the non-PATH libdir search below.
                # $skel_dir/* is trusted the same as /usr/local/* — both require
                # root to write and neither is pacman-tracked by definition, but
                # this check's own threat model is "could an unprivileged
                # attacker have planted this," not "is this in a package db".
                # /etc/skel ships distro/admin first-boot workaround scripts
                # (e.g. an xfce4-panel crash-loop workaround referenced
                # directly from a copied ~/.config/autostart/*.desktop rather
                # than duplicated into each home dir) that only root could
                # have placed there (reported live: xfce-pbw.sh).
                local suspicious=false
                if [[ "$exec_val" == /* ]]; then
                    if [[ "$exec_val" != /usr/* && "$exec_val" != /opt/* && \
                          "$exec_val" != /bin/* && "$exec_val" != /sbin/* && \
                          "$exec_val" != /usr/local/* && \
                          "$exec_val" != "$skel_dir/"* && \
                          "$exec_val" != "$home_dir/bin/"* && \
                          "$exec_val" != "$home_dir/.local/bin/"* && \
                          "$exec_val" != /var/lib/flatpak/exports/bin/* && \
                          "$exec_val" != "$home_dir/.local/share/flatpak/exports/bin/"* ]]; then
                        suspicious=true
                    fi
                else
                    local resolved
                    resolved=$(command -v "$exec_val" 2>/dev/null) || true
                    if [[ -n "$resolved" ]]; then
                        if [[ "$resolved" != /usr/* && "$resolved" != /opt/* && \
                              "$resolved" != /bin/* && "$resolved" != /sbin/* && \
                              "$resolved" != /usr/local/* && \
                              "$resolved" != "$skel_dir/"* && \
                              "$resolved" != /var/lib/flatpak/exports/bin/* && \
                              "$resolved" != "$home_dir/.local/share/flatpak/exports/bin/"* && \
                              "$resolved" != "$home_dir/bin/"* && \
                              "$resolved" != "$home_dir/.local/bin/"* ]]; then
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
                        # -L: Flatpak's exports/bin entries are symlinks (to
                        # .../export/bin/<app-id> inside the app's own
                        # sandboxed install dir) — plain -type f never matches
                        # a symlink, so without -L this search would always
                        # miss a Flatpak export regardless of AUTOSTART_LIBDIRS.
                        local libhit
                        libhit=$(find -L "${_autostart_libdirs[@]}" -mindepth 1 -maxdepth 3 \
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
                        echo "    If you recognize this app (e.g. an AppImage/Flatpak launcher or a"
                        echo "    personal script), mark it known-good: pkexec /usr/lib/archcanary/root-helper --allowlist-add=autostart:$exec_val"
                        found=2
                    fi
                fi
            done < "$desktop"
        done < <(find "$desktop_dir" -name '*.desktop' -type f 2>/dev/null)
    fi

    # User systemd services whose ExecStart= binary is unowned by pacman.
    # Expand %h (systemd home-dir specifier) before querying pacman.
    # Skip XDG user bin dirs — these are never tracked by pacman.
    # Reuses AUTOSTART_ALLOWLIST/_autostart_allow (parsed above) matched
    # against the ExecStart binary's exact, expanded path (not its basename —
    # a basename-only match would let an attacker-placed binary anywhere on
    # disk slip through just by sharing a name with something legitimately
    # allowlisted). e.g. a package (EndeavourOS's eos-update-notifier) that
    # ships its user unit via /etc/skel, so the copy materialized into
    # ~/.config/systemd/user/ at account creation is never itself
    # pacman-tracked even though /usr/bin/<binary> still is.
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
                if _allowlist_contains "$exec_bin" _autostart_allow; then
                    echo "  INFO: user service allowlisted (unowned ExecStart binary): $svc"
                    echo "    ExecStart=$exec_bin"
                else
                    echo "  WARNING: user service with unowned ExecStart binary: $svc"
                    echo "    ExecStart=$exec_bin (not tracked by pacman)"
                    echo "    If you recognize this (e.g. a package that ships its unit via /etc/skel),"
                    echo "    mark it known-good: pkexec /usr/lib/archcanary/root-helper --allowlist-add=autostart:$exec_bin"
                    found=2
                fi
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
        while IFS= read -r line || [[ -n "$line" ]]; do
            (( lineno++ )) || true
            # A fully commented-out line (# possibly after leading
            # whitespace) can never execute — shell RCs commonly keep old
            # commands/aliases around as commented-out notes/history, and
            # that text can legitimately still contain the flagged patterns
            # (e.g. a comment reminding the user what a past threat looked
            # like) without posing any actual risk. Mirrors the .desktop
            # Hidden=true/X-GNOME-Autostart-enabled=false skip above: a line
            # that can't run isn't a finding regardless of what it contains.
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            if [[ "$line" =~ $re_pipe_exec ]] || [[ "$line" =~ $re_base64 ]] || \
               [[ "$line" =~ $re_eval_net ]]; then
                echo "  WARNING: suspicious pattern in $rc:$lineno"
                echo "    $line"
                echo "    If you don't recognize this, remove the line from $rc."
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
            local -A _dkms_hint_shown=()
            while IFS= read -r entry; do
                [[ -z "$entry" ]] && continue
                local pkg_name pkg_ver
                # dkms status format: "name/version, kernel, arch: status"
                pkg_name=$(awk -F'[/,]' '{print $1}' <<< "$entry" | xargs)
                pkg_ver=$(awk -F'[/,]' '{print $2}' <<< "$entry" | xargs)
                # Skip if pacman-tracked. dkms's own self-reported name is
                # often the upstream driver name without Arch's "-dkms"
                # package suffix (e.g. module "broadcom-wl" vs package
                # "broadcom-wl-dkms"), so also resolve ownership via the
                # module's own dkms.conf before concluding it's untracked.
                { pacman -Qi "$pkg_name" ||
                  pacman -Qo "/usr/src/$pkg_name-$pkg_ver/dkms.conf"; } &>/dev/null 2>&1 && continue
                if _allowlist_contains "$pkg_name" _dkms_allow; then
                    echo "  INFO: DKMS module allowlisted (not pacman-tracked): $entry"
                else
                    echo "  WARNING: DKMS module from untracked source: $entry"
                    # dkms status lists one entry per kernel a module is built
                    # for, all sharing the same name/version — only show the
                    # hint once per module instead of once per kernel.
                    if [[ -z "${_dkms_hint_shown[$pkg_name/$pkg_ver]:-}" ]]; then
                        echo "    Still using it (e.g. a proprietary driver never meant to be"
                        echo "    pacman-tracked)? Mark it known-good:"
                        echo "      pkexec /usr/lib/archcanary/root-helper --allowlist-add=dkms:$pkg_name"
                        echo "    Leftover from a package you already removed? Clean up the"
                        echo "    stale registration instead:"
                        echo "      sudo dkms remove $pkg_name/$pkg_ver --all"
                        _dkms_hint_shown["$pkg_name/$pkg_ver"]=1
                    fi
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

    local raw findings count stderr_tmp
    # PACMAN_CMD overrides the real binary for testing (fake pacman script).
    local pacman_cmd="${PACMAN_CMD:-/usr/bin/pacman}"
    # The "warning: <pkg>: <path> (SHA256 checksum mismatch)" lines this check
    # actually cares about go to stderr — only the "backup file: ..." (expected
    # divergence) and per-package summary lines are on stdout. 2>/dev/null used
    # to discard exactly the findings the grep -v "^backup file:" below is meant
    # to keep, so this check could never surface a real mismatch.
    #
    # Fix is NOT `2>&1` — stdout and stderr are buffered differently (stdout is
    # block-buffered since it's not a TTY, stderr is unbuffered), so merging
    # them into one command substitution interleaves writes unpredictably and
    # can glue the tail of one stream's line onto the front of the other's
    # mid-word (reported live: "backup file: libvirtwarning: libvirt: ..." and
    # "rubwarning: shadow: ..." — real text from two different lines fused
    # together with no newline between them). Capture stderr into a real file
    # instead — same single pacman invocation, but the two streams never share
    # a buffer, so each capture is clean before they're concatenated as text.
    stderr_tmp=$(mktemp)
    CLEANUP_FILES+=("$stderr_tmp")
    raw=$("$pacman_cmd" -Qkk 2>"$stderr_tmp")
    raw+=$'\n'"$(cat "$stderr_tmp")"
    rm -f "$stderr_tmp"

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
    # Bucketed by whether reinstalling would help — a lot of what pacman -Qkk
    # flags is a file a pacman hook or the package's own tooling regenerates
    # on every install/upgrade by design (depmod, vlc-cache-gen, Manjaro's
    # firefox/networkmanager hooks, GHC/pacman-mirrors caches), so reinstalling
    # doesn't fix it and it's not a real finding. Only the ELF bucket (magic-
    # byte check, same as check_pkgbuild_caches) counts as WARNING, below and
    # in the return code; classify before printing so the label matches.
    local -A _mismatch_pkgs_elf=() _mismatch_pkgs_other=()
    while IFS= read -r line; do
        # pacman -Qkk line format: "warning: <pkgname>: <path> (SHA256 checksum mismatch)"
        local mpkg mfile magic
        mpkg=$(sed -n 's/^warning: \([^:]*\):.*/\1/p' <<< "$line")
        if [[ -z "$mpkg" ]]; then
            printf '  * %s\n' "$line"
            continue
        fi
        mfile=$(sed -n 's/^warning: [^:]*: \(.*\) (SHA256 checksum mismatch)$/\1/p' <<< "$line")
        magic=""
        [[ -n "$mfile" && -r "$mfile" ]] && IFS= read -r -n4 magic < "$mfile" 2>/dev/null
        if [[ "$magic" == $'\x7fELF' ]]; then
            printf '  * %s\n' "$line"
            _mismatch_pkgs_elf["$mpkg"]=1
        else
            printf '  * %s\n' "${line/#warning:/info:}"
            _mismatch_pkgs_other["$mpkg"]=1
        fi
    done <<< "$findings"
    # A package with at least one ELF mismatch only needs the reinstall
    # suggestion once — drop it from the "won't help" bucket if present there.
    local p
    for p in "${!_mismatch_pkgs_elf[@]}"; do
        unset '_mismatch_pkgs_other[$p]'
    done
    echo
    if [[ ${#_mismatch_pkgs_elf[@]} -gt 0 ]]; then
        echo "  WARNING: binary file(s) changed — reinstall to restore the originals:"
        printf '    sudo pacman -S -- %s\n' "${!_mismatch_pkgs_elf[*]}"
    fi
    if [[ ${#_mismatch_pkgs_other[@]} -gt 0 ]]; then
        echo "  INFO: non-binary mismatches (config/cache/state) — likely a pacman hook or"
        echo "  the package's own tooling regenerating them by design. Reinstalling won't"
        echo "  fix this; only worth investigating if the change itself looks unexpected."
        local other_list=""
        for p in "${!_mismatch_pkgs_other[@]}"; do
            other_list="${other_list:+$other_list, }$p"
        done
        echo "  Packages: $other_list"
    fi
    [[ ${#_mismatch_pkgs_elf[@]} -gt 0 ]] && return 1
    return 0
}

# ---------------------------------------------------------------------------
# Check 14: Custom-list entries already covered by an official list
# A note, not a warning — never affects EXIT_CODE, doesn't warn in the check
# summary either. Just a quick way to keep track of what's redundant between
# your own list(s) and the official ones, so extra_lists.conf doesn't quietly
# grow entries the official feeds (package_list.txt, CHAOS RAT, Russian Spam,
# Community Reports, aur-audit black/red) already track — the official list
# is authoritative, so the custom entry is the one that's safe to remove.
# ---------------------------------------------------------------------------
check_list_overlap() {
    local -A owner=()   # pkgname -> 1 if covered by any official list
    local pkg

    # INFECTED_PKGS is package_list.txt merged with every other list further
    # down (for the unified detection lookup) — BASE_PKG_COUNT was captured
    # right before that merge, so slice back to just the package_list.txt
    # portion rather than re-reading the file.
    local -a _base_pkgs=("${INFECTED_PKGS[@]:0:$BASE_PKG_COUNT}")
    for pkg in "${_base_pkgs[@]}";          do owner["$pkg"]=1; done
    for pkg in "${CHAOS_RAT_PKGS[@]}";      do owner["$pkg"]=1; done
    for pkg in "${RUSSIAN_SPAM_PKGS[@]}";   do owner["$pkg"]=1; done
    for pkg in "${COMMUNITY_REPORTS_PKGS[@]}"; do owner["$pkg"]=1; done
    for pkg in "${AUR_AUDIT_BLACK_PKGS[@]}"; do owner["$pkg"]=1; done
    for pkg in "${AUR_AUDIT_RED_PKGS[@]}";   do owner["$pkg"]=1; done

    # Custom lists aren't kept as per-source arrays after loading (only the
    # combined EXTRA_PKGS), so re-resolve each source's own file here — same
    # cache-path logic _load_extra uses for a URL source.
    #
    # LIST_OVERLAP_CUSTOM_TOTAL / LIST_OVERLAP_FILE_PKGS / LIST_OVERLAP_FILE_CMD
    # are globals (no `local`/declared with -g) — read by the caller after
    # this function returns, to print the same note again at the very end of
    # the scan instead of leaving it buried in this section's own output.
    local i orig path line
    LIST_OVERLAP_CUSTOM_TOTAL=0
    declare -gA LIST_OVERLAP_FILE_PKGS=()
    for i in "${!EXTRA_LIST_KEYS[@]}"; do
        orig="${EXTRA_LIST_KEYS[$i]}"
        if [[ "$orig" =~ ^https?:// ]]; then
            path="$AUR_CONFIG_DIR/extra_$(printf '%s' "$orig" | md5sum | cut -c1-8).txt"
        else
            path="$orig"
        fi
        [[ -f "$path" ]] || continue
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            if [[ -n "${owner[$line]:-}" ]]; then
                LIST_OVERLAP_CUSTOM_TOTAL=$(( LIST_OVERLAP_CUSTOM_TOTAL + 1 ))
                LIST_OVERLAP_FILE_PKGS["$path"]="${LIST_OVERLAP_FILE_PKGS[$path]:+${LIST_OVERLAP_FILE_PKGS[$path]}, }$line"
            fi
        done < "$path"
    done

    if [[ "$LIST_OVERLAP_CUSTOM_TOTAL" -eq 0 ]]; then
        echo "  No custom-list entries duplicate an official list."
        return 0
    fi

    # Build a ready-to-run removal command per file — an ERE alternation of
    # the exact duplicate names, anchored per line. Package names can only
    # contain [a-z0-9@._+-] (pacman naming rules); of those, only . and +
    # are ERE metacharacters, so those are the only two that need escaping.
    local pattern
    declare -gA LIST_OVERLAP_FILE_CMD=()
    for path in "${!LIST_OVERLAP_FILE_PKGS[@]}"; do
        pattern="${LIST_OVERLAP_FILE_PKGS[$path]//, /|}"
        pattern="${pattern//./\\.}"
        pattern="${pattern//+/\\+}"
        LIST_OVERLAP_FILE_CMD["$path"]="sed -i -E '/^(${pattern})\$/d' '$path'"
    done

    printf '  NOTE: %d package(s) below are already covered by an official list — safe to remove.\n' \
        "$LIST_OVERLAP_CUSTOM_TOTAL"
    printf '  Run the command shown for each file to remove them:\n\n'
    for path in "${!LIST_OVERLAP_FILE_PKGS[@]}"; do
        printf '    %s\n' "$path"
        printf '      %s\n\n' "${LIST_OVERLAP_FILE_CMD[$path]}"
    done
    return 0
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
        return 78
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
# Same idea, but for optional tools that aren't installed (e.g. lynis).
SKIPPED_MISSING=()

# Fold a check's return code into EXIT_CODE; 77 means "skipped, needs root",
# 78 means "skipped, optional tool not installed". A 78 only feeds into
# SKIPPED_MISSING (and the INCOMPLETE verdict) when the check was requested
# via its own --check-* flag, not just pulled in by --full.
_apply_ret() { # $1=return code  $2=check label  $3=explicitly requested (true/false)
    if [[ "$1" -eq 77 ]]; then
        SKIPPED_ROOT+=("$2")
    elif [[ "$1" -eq 78 ]]; then
        [[ "${3:-false}" == true ]] && SKIPPED_MISSING+=("$2")
        true
    elif [[ "$1" -gt $EXIT_CODE ]]; then
        EXIT_CODE="$1"
    fi
}

# Summary table — parallel arrays appended as each check runs. _SUMMARY_IDX
# mirrors the "--- [N] ... ---" section number printed above each check's
# own output, so a summary row can be traced back to its detail section.
_SUMMARY_NAMES=()
_SUMMARY_CODES=()
_SUMMARY_IDX=()
_rec() { _SUMMARY_NAMES+=("$1"); _SUMMARY_CODES+=("$2"); _SUMMARY_IDX+=("${3:-}"); }

# Checks tagged here are heuristic/behavior-based (prone to real false
# positives — legitimate personal scripts, AppImage/Flatpak launchers in
# unusual paths, custom systemd units, non-pacman kernel modules, etc.),
# as opposed to name/hash matches against a known-malicious list (package
# list, pacman.log history, npm/bun/yarn/pnpm cache, package integrity),
# which stay "INFECTED" since those really are confirmed hits. A code-2
# result from one of these instead shows the softer "REVIEW" — reported
# live by two separate users whose legitimate autostart entries (a
# personal Conky script; AppImage-style apps like pCloud/Gearlever/
# MEGAsync) produced an "INFECTED" verdict, which is needlessly alarming
# for something that's often just "an app archcanary can't recognize yet."
_is_behavior_check_name() {
    case "$1" in
        "Systemd persistence"|"eBPF programs (bpftool)"|"ld.so.preload injection"|\
        "XDG autostart + shell RCs"|"Kernel modules (DKMS)"|"PKGBUILD obfuscation scan")
            return 0 ;;
        *) return 1 ;;
    esac
}

# True if any RECORDED code-2 finding came from a high-confidence
# (non-behavior-based) check — used to decide the final overall RESULT
# banner's wording, same rationale as _is_behavior_check_name above.
_any_confirmed_infected() {
    local i
    for i in "${!_SUMMARY_NAMES[@]}"; do
        [[ "${_SUMMARY_CODES[$i]}" -eq 2 ]] || continue
        _is_behavior_check_name "${_SUMMARY_NAMES[$i]}" || return 0
    done
    return 1
}

# Renders one summary row -- shared by _print_summary, _print_summary_general_only,
# and _print_sah_per_user_checks, all three of which otherwise repeat the
# identical icon/idx/width formatting.
_print_summary_row() {
    local _iw=5 _w=36 idx="$1" name="$2" code="$3"
    case "$code" in
        0)  printf ' %-*s%-*s %s\n'  "$_iw" "$idx" "$_w" "$name" "$_SYM_CLEAN" ;;
        1)  printf ' %-*s%-*s %s\n'  "$_iw" "$idx" "$_w" "$name" "$_SYM_WARNINGS" ;;
        2)  if _is_behavior_check_name "$name"; then
                printf ' %-*s%-*s %s\n'  "$_iw" "$idx" "$_w" "$name" "$_SYM_REVIEW_TXT"
            else
                printf ' %-*s%-*s %s\n'  "$_iw" "$idx" "$_w" "$name" "$_SYM_INFECTED_TXT"
            fi
            ;;
        77) printf ' %-*s%-*s %s\n'  "$_iw" "$idx" "$_w" "$name" "$_SYM_SKIPPED" ;;
        78) printf ' %-*s%-*s %s\n'  "$_iw" "$idx" "$_w" "$name" "$_SYM_SKIPPED_MISSING" ;;
    esac
}

_print_summary() {
    printf '\n Check summary\n'
    printf ' %s\n' "$_SEP55"
    local i idx
    for i in "${!_SUMMARY_NAMES[@]}"; do
        idx="${_SUMMARY_IDX[$i]:+[${_SUMMARY_IDX[$i]}]}"
        _print_summary_row "$idx" "${_SUMMARY_NAMES[$i]}" "${_SUMMARY_CODES[$i]}"
    done
    printf ' %s\n' "$_SEP55"
}

# Used by _print_summary_general_only to skip the six per-user checks (they
# get their own table per user instead) -- see _SAH_PER_USER_CHECK_IDX
# (defined above _run_scan_all_homes) for the single source of truth.
_is_sah_per_user_check() {
    [[ -n "${_SAH_PER_USER_CHECK_IDX[$1]+x}" ]]
}

# --scan-user only (see call site below) — the *other* checks (--check-ldso,
# --check-systemd, --check-kmod, etc., all machine-wide, not per-user) still
# need a summary somewhere; _print_sah_per_user_checks below only ever
# covers the six per-user ones. Same table as _print_summary, just filtered
# to skip those six. Prints nothing at all if every recorded check was one
# of the six (the common case: bare --scan-user with no other --check-*
# flags) -- an empty "Check summary" table would be pointless.
_print_summary_general_only() {
    local i has_any=false
    for i in "${!_SUMMARY_NAMES[@]}"; do
        _is_sah_per_user_check "${_SUMMARY_NAMES[$i]}" || { has_any=true; break; }
    done
    $has_any || return 0

    # Labeled distinctly from _print_summary's plain "Check summary" (and
    # from the "Check summary: USER x" tables below) -- reported live as
    # genuinely ambiguous: these rows aren't about any of the named users,
    # they're the machine as a whole, checked once regardless of who you
    # named.
    printf '\n Check summary (system-wide, not per-user)\n'
    printf ' %s\n' "$_SEP55"
    local idx
    for i in "${!_SUMMARY_NAMES[@]}"; do
        _is_sah_per_user_check "${_SUMMARY_NAMES[$i]}" && continue
        idx="${_SUMMARY_IDX[$i]:+[${_SUMMARY_IDX[$i]}]}"
        _print_summary_row "$idx" "${_SUMMARY_NAMES[$i]}" "${_SUMMARY_CODES[$i]}"
    done
    printf ' %s\n' "$_SEP55"
}

# --scan-user only (see call site below) — replaces _print_summary's shared,
# folded-across-everyone table with one full per-check table per named user,
# reusing _SAH_USER_NAMES/_SAH_USER_CHECKS (populated in _run_scan_all_homes)
# and _print_summary_row's exact same rendering (including the real
# _is_behavior_check_name REVIEW-vs-INFECTED distinction, since this reads
# each user's actual per-check codes, not just a coarse overall verdict) —
# so naming specific accounts shows exactly whose result is whose, per
# check, without cross-referencing two separate tables. A user with no
# entries in _SAH_USER_CHECKS at all means their child scan never returned
# parseable output (the "could not evaluate" narrative warning above already
# explains why); shown as a one-line note instead of a table of blanks.
_print_sah_per_user_checks() {
    local user name code has_any
    for user in "${_SAH_USER_NAMES[@]}"; do
        printf '\nCheck summary: USER %s\n' "$user"
        printf ' %s\n' "$_SEP55"
        has_any=false
        for name in "${_SAH_PER_USER_CHECK_NAMES[@]}"; do
            code="${_SAH_USER_CHECKS["$user|$name"]:-}"
            [[ -z "$code" ]] && continue
            has_any=true
            _print_summary_row "[${_SAH_PER_USER_CHECK_IDX[$name]}]" "$name" "$code"
        done
        $has_any || printf ' (could not evaluate — no parseable output)\n'
        printf ' %s\n' "$_SEP55"
    done
}

# The "--- [10b] ... ---" section header, printed once before
# _run_scan_all_homes. --scan-user's variant lists names from
# _SAH_RESOLVED_USERS ("name:home" pairs, already resolved/deduped by
# _resolve_and_store_scan_users above) rather than the raw SCAN_USER_OPTS,
# which can repeat a name (--scan-user=a --scan-user=a) even though only
# one child scan and one "Check summary: USER a" table actually happen.
# Named (not inlined at the call site) so this is directly unit-testable.
_print_sah_section_header() {
    if $SCAN_ALL_HOMES; then
        echo "--- [10b] Scan all local user homes (npm/bun/yarn/pnpm/pkgbuild/autostart) ---"
    else
        local -a _shm_names=()
        local _shm_entry
        for _shm_entry in "${_SAH_RESOLVED_USERS[@]}"; do
            _shm_names+=("${_shm_entry%%:*}")
        done
        echo "--- [10b] Scan user home(s): ${_shm_names[*]} (npm/bun/yarn/pnpm/pkgbuild/autostart) ---"
    fi
}

# Dispatches between --scan-user's per-user tables (plus a general-checks
# table for anything else that ran alongside it) and the normal/
# --scan-all-homes shared per-check table -- named (not inlined at the call
# site) so this choice is directly unit-testable via the same
# extract-and-source technique the other scan-all-homes/scan-user tests use.
_print_scan_summary_section() {
    if [[ ${#SCAN_USER_OPTS[@]} -gt 0 ]]; then
        _print_summary_general_only
        _print_sah_per_user_checks
    else
        _print_summary
    fi
}

# Escapes backslash/double-quote for the JSON string values below. The
# inputs here are always script-controlled labels (check names) plus a
# package count, never raw user/network input, but escaping is cheap and
# correct regardless.
_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

_json_status() {
    case "$1" in
        0)  printf 'clean' ;;
        1)  printf 'warning' ;;
        2)  printf 'infected' ;;
        77) printf 'skipped_root' ;;
        78) printf 'skipped_missing' ;;
        *)  printf 'unknown' ;;
    esac
}

# --scan-all-homes: pulls "name|status" lines out of a per-user child's
# --format=json output (see _print_summary_json's "checks" array below), and
# the inverse of _json_status to fold each child's result back into a code.
_sah_parse_checks() {
    grep -oP '"checks":\[\K[^]]*' <<< "$1" | grep -oP '\{[^}]*\}' | while read -r _sah_obj; do
        printf '%s|%s\n' \
            "$(grep -oP '"name":"\K[^"]*' <<< "$_sah_obj")" \
            "$(grep -oP '"status":"\K[^"]*' <<< "$_sah_obj")"
    done
}
_sah_status_to_code() {
    case "$1" in
        clean)           echo 0 ;;
        warning)         echo 1 ;;
        infected)        echo 2 ;;
        skipped_root)    echo 77 ;;
        skipped_missing) echo 78 ;;
        *)               echo 1 ;;
    esac
}

# --format=json's whole output: a stable {name,status} array built from the
# same _SUMMARY_NAMES/_SUMMARY_CODES that _print_summary renders as a table,
# plus scan-level metadata. Written to fd 3 (the real stdout, saved before
# the log-only redirect above) so it's the only thing a caller piping our
# stdout ever sees, regardless of --no-summary.
_print_summary_json() {
    local result
    case "$EXIT_CODE" in
        0) result="clean" ;;
        1) result="warnings" ;;
        2) result="infected" ;;
        *) result="unknown" ;;
    esac

    local json='{'
    json+="\"version\":\"$(_json_escape "$SCRIPT_VERSION")\","
    json+="\"scanned_at\":\"$(date -Iseconds)\","
    json+="\"result\":\"$result\","
    json+="\"packages_checked\":${#INFECTED_PKGS[@]},"

    json+='"checks":['
    local i sep=""
    for i in "${!_SUMMARY_NAMES[@]}"; do
        json+="${sep}{\"name\":\"$(_json_escape "${_SUMMARY_NAMES[$i]}")\",\"status\":\"$(_json_status "${_SUMMARY_CODES[$i]}")\"}"
        sep=","
    done
    json+='],'

    json+='"skipped_root":['
    sep=""
    for i in "${!SKIPPED_ROOT[@]}"; do
        json+="${sep}\"$(_json_escape "${SKIPPED_ROOT[$i]}")\""
        sep=","
    done
    json+='],'

    json+='"skipped_missing":['
    sep=""
    for i in "${!SKIPPED_MISSING[@]}"; do
        json+="${sep}\"$(_json_escape "${SKIPPED_MISSING[$i]}")\""
        sep=","
    done
    json+=']}'

    printf '%s\n' "$json" >&3
}

load_packages

# Captured before the merge loops below append the supplementary lists, so
# it reflects package_list.txt alone (used by the "Lists loaded" banner).
BASE_PKG_COUNT=${#INFECTED_PKGS[@]}

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

# Community-reported packages — built before merging, same reason as
# CHAOS_LOOKUP above (source-specific annotation in check_current/check_logs).
declare -A COMMUNITY_REPORTS_LOOKUP
for p in "${COMMUNITY_REPORTS_PKGS[@]}"; do
    COMMUNITY_REPORTS_LOOKUP["$p"]=1
    INFECTED_PKGS+=("$p")
done

# aur-audit.wtako.net black/red — built before merging, same reason as
# CHAOS_LOOKUP above (source-specific annotation in check_current/check_logs).
declare -A AUR_AUDIT_BLACK_LOOKUP
for p in "${AUR_AUDIT_BLACK_PKGS[@]}"; do
    AUR_AUDIT_BLACK_LOOKUP["$p"]=1
    INFECTED_PKGS+=("$p")
done

declare -A AUR_AUDIT_RED_LOOKUP
for p in "${AUR_AUDIT_RED_PKGS[@]}"; do
    AUR_AUDIT_RED_LOOKUP["$p"]=1
    INFECTED_PKGS+=("$p")
done

# pkgname -> the flagged version's AUR publish date (YYYY-MM-DD), from the
# companion dates files above — check_logs' per-package cutoff. A package
# absent here (not yet re-refreshed since this feature shipped, or a fetch
# that skipped dates) simply gets no cutoff, same as before this feature.
declare -A AUR_AUDIT_BLACK_DATE
for p in "${AUR_AUDIT_BLACK_DATE_LINES[@]}"; do
    AUR_AUDIT_BLACK_DATE["${p%% *}"]="${p#* }"
done

declare -A AUR_AUDIT_RED_DATE
for p in "${AUR_AUDIT_RED_DATE_LINES[@]}"; do
    AUR_AUDIT_RED_DATE["${p%% *}"]="${p#* }"
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

# ---------------------------------------------------------------------------
# --search-packages=PKG[,PKG...] — standalone list lookup, independent of
# what's installed locally. Same source-tagging elif chain as check_current/
# check_logs (kept separate rather than a shared helper, matching how those
# two already duplicate it). Never runs pacman itself — only echoes the
# suggested removal command.
# ---------------------------------------------------------------------------
_search_packages_cli() {
    local input="$1" pkg tag
    local -a names=() hits=()
    local -A seen=()
    IFS=',' read -ra names <<< "$input"

    for pkg in "${names[@]}"; do
        pkg="${pkg//[[:space:]]/}"
        [[ -n "$pkg" ]] || continue
        [[ -v seen["$pkg"] ]] && continue
        seen["$pkg"]=1
        if [[ -v INFECTED_LOOKUP["$pkg"] ]]; then
            if [[ -v CHAOS_LOOKUP["$pkg"] ]]; then
                tag="CHAOS RAT campaign, 2025-07"
            elif [[ -v AUR_AUDIT_BLACK_LOOKUP["$pkg"] ]]; then
                tag="aur-audit: black"
            elif [[ -v AUR_AUDIT_RED_LOOKUP["$pkg"] ]]; then
                tag="aur-audit: red"
            elif [[ -v COMMUNITY_REPORTS_LOOKUP["$pkg"] ]]; then
                tag="community report"
            else
                tag="package list"
            fi
            echo "  FLAGGED: $pkg [$tag]"
            hits+=("$pkg")
        else
            echo "  clean: $pkg (not on any list)"
        fi
    done

    if [[ ${#hits[@]} -gt 0 ]]; then
        echo
        echo "  Suggested removal (review before running):"
        printf '    sudo pacman -Rns -- %s\n' "${hits[*]}"
        return 2
    fi
    return 0
}

if [[ -n "$SEARCH_PACKAGES_ARG" ]]; then
    _search_packages_cli "$SEARCH_PACKAGES_ARG"
    exit $?
fi

if ! $FOCUSED_MODE; then
    # Per-list pkg counts from the previous run, so the banner below can show
    # a "(+N)"/"(-N)" delta and flag when a threat-intel feed grew or shrank.
    # Keyed by each list's own file path (not a fixed label) so a one-off run
    # against a different --package-list / test fixture can't clobber the
    # baseline used by normal scans of the real list.
    LIST_COUNTS_FILE="$AUR_CONFIG_DIR/.list_counts"
    declare -A _PREV_LIST_COUNTS
    if [[ -f "$LIST_COUNTS_FILE" ]]; then
        while IFS=$'\t' read -r _k _v || [[ -n "$_k" ]]; do
            [[ -z "$_k" ]] && continue
            _PREV_LIST_COUNTS["$_k"]="$_v"
        done < "$LIST_COUNTS_FILE"
    fi

    # Prints " (+N)" / " (-N)" against last run's count for key $1, or nothing
    # if unchanged / not tracked yet (first run, or a newly-populated list).
    _count_diff() {
        local prev="${_PREV_LIST_COUNTS[$1]:-}" delta
        [[ -z "$prev" ]] && return
        delta=$(( $2 - prev ))
        [[ $delta -ne 0 ]] && printf ' (%+d)' "$delta"
    }

    echo "============================================================"
    echo " Archcanary v${SCRIPT_VERSION}"
    echo " Scanned: $(date '+%Y-%m-%d %H:%M')"
    echo
    echo " Lists loaded"
    printf "   %s  infostealer + eBPF rootkit  %s pkgs%s\n" \
        "$(basename "$PACKAGE_LIST_FILE")" "$BASE_PKG_COUNT" "$(_count_diff "$PACKAGE_LIST_FILE" "$BASE_PKG_COUNT")"
    if [[ ${#CHAOS_RAT_PKGS[@]} -gt 0 ]]; then
        printf "   + CHAOS RAT%10s pkgs%s\n" "${#CHAOS_RAT_PKGS[@]}" "$(_count_diff "$CHAOS_RAT_LIST" "${#CHAOS_RAT_PKGS[@]}")"
    fi
    if [[ ${#RUSSIAN_SPAM_PKGS[@]} -gt 0 ]]; then
        printf "   + Russian Spam%7s pkgs%s\n" "${#RUSSIAN_SPAM_PKGS[@]}" "$(_count_diff "$RUSSIAN_SPAM_LIST" "${#RUSSIAN_SPAM_PKGS[@]}")"
    fi
    if [[ ${#COMMUNITY_REPORTS_PKGS[@]} -gt 0 ]]; then
        printf "   + Community Reports %s pkgs%s\n" "${#COMMUNITY_REPORTS_PKGS[@]}" "$(_count_diff "$COMMUNITY_REPORTS_LIST" "${#COMMUNITY_REPORTS_PKGS[@]}")"
    fi
    if [[ ${#AUR_AUDIT_BLACK_PKGS[@]} -gt 0 ]]; then
        printf "   + aur-audit black%4s pkgs%s\n" "${#AUR_AUDIT_BLACK_PKGS[@]}" "$(_count_diff "$AUR_AUDIT_BLACK_LIST" "${#AUR_AUDIT_BLACK_PKGS[@]}")"
    fi
    if [[ ${#AUR_AUDIT_RED_PKGS[@]} -gt 0 ]]; then
        printf "   + aur-audit red%6s pkgs%s\n" "${#AUR_AUDIT_RED_PKGS[@]}" "$(_count_diff "$AUR_AUDIT_RED_LIST" "${#AUR_AUDIT_RED_PKGS[@]}")"
    fi
    for _i in "${!EXTRA_LIST_NAMES[@]}"; do
        printf "   + extra: %-20s %3s pkgs%s\n" "${EXTRA_LIST_NAMES[$_i]}" "${EXTRA_LIST_COUNTS[$_i]}" \
            "$(_count_diff "${EXTRA_LIST_KEYS[$_i]}" "${EXTRA_LIST_COUNTS[$_i]}")"
    done
    echo
    echo " Packages checked: ${#INFECTED_PKGS[@]}"
    if [[ -n "$START_DATE" || -n "$END_DATE" ]]; then
        echo " Date window: ${START_DATE:-beginning} → ${END_DATE:-now}"
    fi
    echo "============================================================"
    echo

    # Merge this run's counts into the previously loaded map (rather than
    # overwriting the file outright) so a one-off run against a different set
    # of list paths doesn't erase the baseline recorded for the usual ones.
    _PREV_LIST_COUNTS["$PACKAGE_LIST_FILE"]="$BASE_PKG_COUNT"
    _PREV_LIST_COUNTS["$CHAOS_RAT_LIST"]="${#CHAOS_RAT_PKGS[@]}"
    _PREV_LIST_COUNTS["$RUSSIAN_SPAM_LIST"]="${#RUSSIAN_SPAM_PKGS[@]}"
    _PREV_LIST_COUNTS["$COMMUNITY_REPORTS_LIST"]="${#COMMUNITY_REPORTS_PKGS[@]}"
    _PREV_LIST_COUNTS["$AUR_AUDIT_BLACK_LIST"]="${#AUR_AUDIT_BLACK_PKGS[@]}"
    _PREV_LIST_COUNTS["$AUR_AUDIT_RED_LIST"]="${#AUR_AUDIT_RED_PKGS[@]}"
    for _i in "${!EXTRA_LIST_NAMES[@]}"; do
        _PREV_LIST_COUNTS["${EXTRA_LIST_KEYS[$_i]}"]="${EXTRA_LIST_COUNTS[$_i]}"
    done
    {
        for _k in "${!_PREV_LIST_COUNTS[@]}"; do
            printf '%s\t%s\n' "$_k" "${_PREV_LIST_COUNTS[$_k]}"
        done
    } > "$LIST_COUNTS_FILE"
    _chown_to_invoker "$LIST_COUNTS_FILE"
    unset -f _count_diff

    log_info "Loaded ${#INFECTED_PKGS[@]} packages from $PACKAGE_LIST_FILE"

    echo "--- [1] Currently installed foreign packages ---"
    log_info "Querying ${#INFECTED_PKGS[@]} packages via pacman -Qmq..."
    check_current && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "Package list (${#INFECTED_PKGS[@]} pkgs)" "$ret" "1"
    echo

    echo "--- [2] Historical pacman logs ---"
    _log_ret=0
    _pacman_log_found=false
    # shellcheck disable=SC2086
    for _plf in $PACMAN_LOG_GLOB; do [[ -e "$_plf" ]] && _pacman_log_found=true && break; done
    unset _plf
    if $_pacman_log_found; then
        LOGS_TMP=$(mktemp)
        CLEANUP_FILES+=("$LOGS_TMP")
        check_logs 2>&1 | tee "$LOGS_TMP" || true
        _has_current_hit=false
        _has_hist_hit=false
        _has_old_hit=false
        _has_seen_hit=false
        grep -q '^LOG_HIT:' "$LOGS_TMP" 2>/dev/null && _has_current_hit=true
        grep -q '^LOG_HIST:' "$LOGS_TMP" 2>/dev/null && _has_hist_hit=true
        grep -q '^LOG_OLD:' "$LOGS_TMP" 2>/dev/null && _has_old_hit=true
        grep -q '^LOG_HIST_SEEN:' "$LOGS_TMP" 2>/dev/null && _has_seen_hit=true

        if $_has_current_hit; then
            echo "  WARNING: currently-installed package(s) with a matching log entry"
            echo "  (name-match against official compromised list):"
            grep '^LOG_HIT:' "$LOGS_TMP" | sed 's/^LOG_HIT: /  - /'
            echo "  NOTE: if the PKGBUILD looks clean now, the malicious commit may have been"
            echo "  reverted — check AUR git history around the install date/time above."
            echo "  Either way, treat the install-time window as a potential exposure."
            [[ 2 -gt $EXIT_CODE ]] && EXIT_CODE=2
            _log_ret=2
        fi
        if $_has_hist_hit; then
            echo "  NOTE: historical-only log matches (package no longer installed):"
            grep '^LOG_HIST:' "$LOGS_TMP" | sed 's/^LOG_HIST: /  - /'
            echo "  These were removed at some point after the log entry above, so they are"
            echo "  not an active infection — but if they were compromised while installed,"
            echo "  treat that install-time window as a potential past exposure."
            [[ 1 -gt $EXIT_CODE ]] && EXIT_CODE=1
            [[ $_log_ret -lt 1 ]] && _log_ret=1
        fi
        if $_has_old_hit; then
            echo "  NOTE: log match(es) predating the known compromise window for that"
            echo "  list (the name later became malicious, but this specific"
            echo "  install/upgrade happened before that) — almost certainly unrelated:"
            grep '^LOG_OLD:' "$LOGS_TMP" | sed 's/^LOG_OLD: /  - /'
        fi
        if $_has_seen_hit; then
            echo "  NOTE: log match(es) already flagged in a previous scan (package no"
            echo "  longer installed) — shown for the record, not re-counted as a warning:"
            grep '^LOG_HIST_SEEN:' "$LOGS_TMP" | sed 's/^LOG_HIST_SEEN: /  - /'
        fi
        if ! $_has_current_hit && ! $_has_hist_hit && ! $_has_old_hit && ! $_has_seen_hit; then
            echo "  Clean: no historical log matches found."
        fi
        unset _has_current_hit _has_hist_hit _has_old_hit _has_seen_hit
        rm -f "$LOGS_TMP"
    else
        echo "  Skipped: /var/log/pacman.log not found."
    fi
    _rec "pacman.log history" "$_log_ret" "2"
    echo
fi

if $CHECK_SYSTEMD; then
    echo "--- [3] Systemd persistence check ---"
    check_systemd && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "Systemd persistence" "$ret" "3"
    echo
fi

if $CHECK_EBPF; then
    echo "--- [4] eBPF rootkit check ---"
    check_ebpf && ret=$? || ret=$?
    _apply_ret "$ret" ebpf
    _rec "eBPF rootkit traces" "$ret" "4"
    echo
fi

if $CHECK_NPM_CACHE && ! $SCAN_HOMES_MODE; then
    echo "--- [5] npm cache check ---"
    check_npm_cache && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "npm cache" "$ret" "5"
    echo
fi

if $CHECK_BUN_CACHE && ! $SCAN_HOMES_MODE; then
    echo "--- [6] bun cache check ---"
    check_bun_cache && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "bun cache" "$ret" "6"
    echo
fi

if $CHECK_YARN_CACHE && ! $SCAN_HOMES_MODE; then
    echo "--- [6b] yarn cache check ---"
    check_yarn_cache && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "yarn cache" "$ret" "6b"
    echo
fi

if $CHECK_PNPM_CACHE && ! $SCAN_HOMES_MODE; then
    echo "--- [6c] pnpm cache check ---"
    check_pnpm_cache && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "pnpm cache" "$ret" "6c"
    echo
fi

if $CHECK_PKGBUILD && ! $SCAN_HOMES_MODE; then
    echo "--- [7] PKGBUILD/install file scan (obfuscation-aware) ---"
    check_pkgbuild_caches && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "PKGBUILD obfuscation scan" "$ret" "7"
    echo
fi

if $CHECK_BPFTOOL; then
    echo "--- [8] Loaded eBPF programs/links (bpftool) ---"
    check_bpftool && ret=$? || ret=$?
    _apply_ret "$ret" bpftool
    _rec "eBPF programs (bpftool)" "$ret" "8"
    echo
fi

if $CHECK_LDSO; then
    echo "--- [9] ld.so.preload injection check ---"
    check_ldso && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "ld.so.preload injection" "$ret" "9"
    echo
fi

if $CHECK_AUTOSTART && ! $SCAN_HOMES_MODE; then
    echo "--- [10] XDG autostart + shell RC persistence check ---"
    check_autostart && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    _rec "XDG autostart + shell RCs" "$ret" "10"
    echo
fi

if $SCAN_HOMES_MODE; then
    _print_sah_section_header
    _run_scan_all_homes
    echo
fi

if $CHECK_KMOD; then
    echo "--- [11] Kernel module / DKMS audit ---"
    check_kmod && ret=$? || ret=$?
    _apply_ret "$ret" kmod
    _rec "Kernel modules (DKMS)" "$ret" "11"
    echo
fi

if $CHECK_LYNIS; then
    echo "--- [12] Lynis hardening report ---"
    check_lynis && ret=$? || ret=$?
    _apply_ret "$ret" lynis "$EXPLICIT_LYNIS"
    _rec "Lynis hardening" "$ret" "12"
    echo
fi

if $CHECK_PKGINTEG; then
    echo "--- [13] Package file integrity ---"
    check_pkginteg && ret=$? || ret=$?
    _apply_ret "$ret" pkginteg
    _rec "Package integrity" "$ret" "13"
    echo
fi

if $CHECK_LIST_OVERLAP; then
    echo "--- [14] Custom-list entries already covered elsewhere ---"
    check_list_overlap
    # Always "clean" in the summary — this is a note, not a warning, so it
    # never signals a problem in the summary table itself.
    _rec "List overlap check" 0 "14"
    echo
fi

# A scan that skipped root or missing-tool checks is incomplete, not clean —
# surface it and escalate a would-be CLEAN (0) to WARNINGS (1) so it isn't
# read as all-clear. Remember whether this escalation is the ONLY reason
# for a non-zero code (as opposed to a real check reporting 1 on its own,
# e.g. Lynis findings or bpftool's non-lsm-stealth warning) so the RESULT
# banner can say something less alarming than "WARNINGS" — reported live:
# a scan where every check that ran was clean, and the only "warning" was
# an optional tool being absent, still printed "RESULT: WARNINGS".
_ONLY_SKIP_CAUSED_WARNINGS=false
if [[ ( ${#SKIPPED_ROOT[@]} -gt 0 || ${#SKIPPED_MISSING[@]} -gt 0 ) && $EXIT_CODE -lt 1 ]]; then
    EXIT_CODE=1
    _ONLY_SKIP_CAUSED_WARNINGS=true
fi

if $FORMAT_JSON; then
    _print_summary_json
else
    if ! $NO_SUMMARY; then
        _print_scan_summary_section
    fi
fi

printf '%s============================================================%s\n' "$_CB" "$_CN"
case $EXIT_CODE in
    0) printf ' %sRESULT: CLEAN - No indicators found.%s\n'                           "$_CG"       "$_CN" ;;
    1) if $_ONLY_SKIP_CAUSED_WARNINGS; then
           printf ' %sRESULT: CLEAN (INCOMPLETE) - No indicators found in the checks that ran; see below.%s\n' "$_CY" "$_CN"
       else
           printf ' %sRESULT: WARNINGS - Review output above.%s\n'                        "$_CY"       "$_CN"
       fi
       ;;
    2) if _any_confirmed_infected; then
           printf ' %sRESULT: INFECTED - Indicators found! Follow incident response.%s\n' "$_CR$_CB" "$_CN"
       else
           printf ' %sRESULT: REVIEW NEEDED - Suspicious behavior found, see checks above.%s\n' "$_CY$_CB" "$_CN"
       fi
       ;;
esac
if [[ ${#SKIPPED_ROOT[@]} -gt 0 ]]; then
    printf ' INCOMPLETE: %d root check(s) skipped (no root): %s\n' "${#SKIPPED_ROOT[@]}" "${SKIPPED_ROOT[*]}"
    if [[ -n "${ARCHCANARY_FROM_GUI:-}" ]]; then
        printf ' Re-run with sudo for the full picture: sudo archcanary-gui --no-gui\n'
    else
        printf ' Re-run with sudo for the full picture: sudo %s --full\n' "$0"
    fi
fi
if [[ ${#SKIPPED_MISSING[@]} -gt 0 ]]; then
    printf ' INCOMPLETE: %d optional check(s) skipped (tool not installed): %s\n' "${#SKIPPED_MISSING[@]}" "${SKIPPED_MISSING[*]}"
fi
if [[ "${LIST_OVERLAP_CUSTOM_TOTAL:-0}" -gt 0 ]]; then
    printf ' %sNOTE: %d package(s) in your custom list(s) are already covered by an official list — safe to remove.%s\n' \
        "$_CC" "$LIST_OVERLAP_CUSTOM_TOTAL" "$_CN"
    for _f in "${!LIST_OVERLAP_FILE_PKGS[@]}"; do
        printf '   %s\n' "$_f"
        printf '     %s\n' "${LIST_OVERLAP_FILE_CMD[$_f]}"
    done
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
