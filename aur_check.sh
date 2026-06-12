#!/usr/bin/env bash
#
# aur_check.sh - Consolidated AUR Malware Check Script
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
#   ./aur_check.sh                    # normal check
#   ./aur_check.sh --check-systemd    # also scan systemd for unknown services
#   ./aur_check.sh --check-ebpf       # also check for eBPF rootkit traces
#   ./aur_check.sh --check-npm-cache  # also check npm cache for atomic-lockfile
#   ./aur_check.sh --full             # enable all checks
#
# Environment:
#   START_DATE=2026-06-09  END_DATE=2026-06-12  ./aur_check.sh
#   PACMAN_LOG_GLOB="/var/log/pacman.log*"       ./aur_check.sh
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

SCRIPT_VERSION="2.2.0"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
START_DATE=${START_DATE:-2026-06-09}
END_DATE=${END_DATE:-2026-06-12}
PACMAN_LOG_GLOB=${PACMAN_LOG_GLOB:-/var/log/pacman.log*}

CHECK_SYSTEMD=false
CHECK_EBPF=false
CHECK_NPM_CACHE=false
CHECK_BUN_CACHE=false
VERBOSE=false

# Temp file cleanup on exit/interrupt
CLEANUP_FILES=()
trap 'rm -f "${CLEANUP_FILES[@]}"' EXIT
trap 'rm -f "${CLEANUP_FILES[@]}"; exit 1' INT TERM

for arg in "$@"; do
    case "$arg" in
        --check-systemd) CHECK_SYSTEMD=true ;;
        --check-ebpf)    CHECK_EBPF=true ;;
        --check-npm-cache) CHECK_NPM_CACHE=true ;;
        --check-bun-cache) CHECK_BUN_CACHE=true ;;
        --full)          CHECK_SYSTEMD=true; CHECK_EBPF=true; CHECK_NPM_CACHE=true; CHECK_BUN_CACHE=true ;;
        --verbose|-v)            VERBOSE=true ;;
        --log-file=*)            LOG_FILE="${arg#*=}" ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --check-systemd    Scan for unknown systemd services (Restart=always)"
            echo "  --check-ebpf       Check for eBPF rootkit traces (/sys/fs/bpf/hidden_*)"
            echo "  --check-npm-cache  Check npm cache for atomic-lockfile / js-digest"
            echo "  --check-bun-cache  Check bun cache for js-digest / atomic-lockfile"
            echo "  --full             Enable all checks"
            echo "  --verbose, -v      Verbose output"
            echo "  --log-file=PATH    Write full detail log to PATH (auto: aur-check-<date>.log)"
            echo "  --help, -h         Show this help"
            exit 0
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Log file: always write full detail, auto-named unless --log-file=PATH
# ---------------------------------------------------------------------------
: "${LOG_FILE:=aur-check-$(date +%Y%m%d-%H%M%S).log}"
# Verify log file writable before redirecting
: > "$LOG_FILE" 2>/dev/null || { echo >&2 "ERROR: Cannot write log file: $LOG_FILE"; exit 1; }
# Redirect all output through tee: terminal + log file
exec > >(tee "$LOG_FILE") 2>&1

# ---------------------------------------------------------------------------
# Load package list from external file (single source of truth)
# Can be overridden via PACKAGE_LIST_FILE env var
# ---------------------------------------------------------------------------
PACKAGE_LIST_FILE="${PACKAGE_LIST_FILE:-$(dirname "$0")/package_list.txt}"

if [[ ! -f "$PACKAGE_LIST_FILE" ]]; then
    echo >&2 "ERROR: Package list not found: $PACKAGE_LIST_FILE"
    echo >&2 "Set PACKAGE_LIST_FILE or run from the repo root."
    exit 1
fi

INFECTED_PKGS=()
while IFS= read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    INFECTED_PKGS+=("$line")
done < "$PACKAGE_LIST_FILE"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
log_info() {
    if $VERBOSE; then
        echo "[INFO] $*"
    else
        echo "[INFO] $*" >> "$LOG_FILE"
    fi
}
log_warn()  { echo >&2 "[WARN] $*"; }

date_in_window() {
    local date_val=$1
    [[ "$date_val" < "$START_DATE" ]] && return 1
    [[ "$date_val" > "$END_DATE" ]] && return 1
    return 0
}

install_date_in_window() {
    local raw_date=$1 normalized
    normalized=$(LC_ALL=C date -d "$raw_date" +%F 2>/dev/null) || return 1
    date_in_window "$normalized"
}

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
        local install_date
        install_date=$(LC_ALL=C pacman -Qi -- "$pkg" 2>/dev/null | awk -F': ' '/^Install Date/ { print $2; exit }')
        if [[ -n "$install_date" ]] && install_date_in_window "$install_date"; then
            found+=("$pkg (installed: $install_date)")
        fi
    done < <(pacman -Qmq "${INFECTED_PKGS[@]}" 2>/dev/null)

    if [[ ${#found[@]} -eq 0 ]]; then
        echo "  Clean: no infected packages installed within campaign window."
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

    local tmpfile total idx file
    tmpfile=$(mktemp)
    CLEANUP_FILES+=("$tmpfile")
    printf '%s\n' "${INFECTED_PKGS[@]}" > "$tmpfile"

    total=${#log_files[@]}
    idx=0
    log_info "Found $total log file(s)"

    for file in "${log_files[@]}"; do
        idx=$((idx + 1))
        if [[ ! -r "$file" ]]; then
            log_warn "Skipped $file: not readable"
            continue
        fi
        log_info "[$idx/$total] Scanning $(basename "$file")..."

        while IFS= read -r line; do
            local date_str action pkg
            date_str=$(echo "$line" | sed -n 's/^\[\([0-9-]*\).*/\1/p')
            [[ -z "$date_str" ]] && continue
            date_in_window "$date_str" || continue

            action=$(echo "$line" | sed -n 's/.*\[ALPM\] \([a-z]*\) .*/\1/p')
            pkg=$(echo "$line" | sed -n 's/.*\[ALPM\] [a-z]* \([^ ]*\).*/\1/p')
            [[ -z "$action" || -z "$pkg" ]] && continue

            if grep -qxF "$pkg" "$tmpfile" 2>/dev/null; then
                if [[ "$action" == "installed" || "$action" == "upgraded" || "$action" == "reinstalled" ]]; then
                    echo "LOG_HIT: $pkg ($action on $date_str)"
                fi
            fi
        done < <(read_compressed_file "$file") || true

        log_info "[$idx/$total] Done with $(basename "$file")"
    done

    rm -f "$tmpfile"
}

# ---------------------------------------------------------------------------
# Check 3: systemd persistence artifacts
# (Original addition: look for services with Restart=always + RestartSec=30)
# ---------------------------------------------------------------------------
check_systemd() {
    local found=()
    local dirs=("/etc/systemd/system" "$HOME/.config/systemd/user")

    for dir in "${dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r svc; do
            if grep -q 'Restart=always' "$svc" 2>/dev/null && grep -q 'RestartSec=30' "$svc" 2>/dev/null; then
                found+=("$svc")
            fi
        done < <(find "$dir" -name '*.service' -type f 2>/dev/null)
    done

    if [[ ${#found[@]} -gt 0 ]]; then
        echo "  WARNING: ${#found[@]} service(s) with Restart=always + RestartSec=30:"
        print_list found
        return 2
    fi
    echo "  Clean: no suspicious systemd services found."
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
        echo "  → Try: sudo ./aur_check.sh --check-ebpf"
        echo "  → Skip this check if eBPF rootkit detection is not needed for your threat model."
        return 0
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
# Check 5: npm cache for malicious packages
# ---------------------------------------------------------------------------
check_npm_cache() {
    local pkgs=('atomic-lockfile' 'js-digest')
    local found_count=0

    for pkg in "${pkgs[@]}"; do
        local npm_cache
        npm_cache=$(npm cache ls 2>/dev/null | grep "$pkg" || true)
        if [[ -n "$npm_cache" ]]; then
            echo "  WARNING: $pkg found in npm cache:"
            # shellcheck disable=SC2001
            sed 's/^/    /' <<< "$npm_cache"
            found_count=2
        fi

        local global_mod
        global_mod=$(npm root -g 2>/dev/null)/"$pkg"
        if [[ -d "$global_mod" ]]; then
            echo "  WARNING: $pkg found in global node_modules"
            found_count=2
        fi

        local npm_cache_dir
        npm_cache_dir=$(npm config get cache 2>/dev/null)
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
    local pkgs=('js-digest' 'atomic-lockfile')
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
# Main
# ---------------------------------------------------------------------------
EXIT_CODE=0

echo "============================================================"
echo " AUR Malware Check v${SCRIPT_VERSION}"
echo " Campaign: atomic-lockfile / js-digest infostealer + eBPF rootkit"
echo " Date window: ${START_DATE} to ${END_DATE}"
echo " Packages checked: ${#INFECTED_PKGS[@]}"
echo "============================================================"
echo

log_info "Loaded ${#INFECTED_PKGS[@]} packages from $PACKAGE_LIST_FILE"

echo "--- [1] Currently installed foreign packages ---"
log_info "Querying ${#INFECTED_PKGS[@]} packages via pacman -Qmq..."
check_current && ret=$? || ret=$?
[[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
echo

echo "--- [2] Historical pacman logs ---"
if [[ -f /var/log/pacman.log ]]; then
    LOGS_TMP=$(mktemp)
    CLEANUP_FILES+=("$LOGS_TMP")
    check_logs 2>&1 | tee "$LOGS_TMP" || true
    if grep -q 'LOG_HIT' "$LOGS_TMP" 2>/dev/null; then
        echo "  WARNING: historical log matches:"
        grep 'LOG_HIT' "$LOGS_TMP" | sed 's/LOG_HIT: /  - /'
        [[ 2 -gt $EXIT_CODE ]] && EXIT_CODE=2
    else
        echo "  Clean: no historical log matches found."
    fi
    rm -f "$LOGS_TMP"
else
    echo "  Skipped: /var/log/pacman.log not found."
fi
echo

if $CHECK_SYSTEMD; then
    echo "--- [3] Systemd persistence check ---"
    check_systemd && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    echo
fi

if $CHECK_EBPF; then
    echo "--- [4] eBPF rootkit check ---"
    check_ebpf && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    echo
fi

if $CHECK_NPM_CACHE; then
    echo "--- [5] npm cache check ---"
    check_npm_cache && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    echo
fi

if $CHECK_BUN_CACHE; then
    echo "--- [6] bun cache check ---"
    check_bun_cache && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    echo
fi

echo "============================================================"
case $EXIT_CODE in
    0) echo " RESULT: CLEAN - No indicators found." ;;
    1) echo " RESULT: WARNINGS - Review output above." ;;
    2) echo " RESULT: INFECTED - Indicators found! Follow incident response." ;;
esac
echo "============================================================"

exit "$EXIT_CODE"
