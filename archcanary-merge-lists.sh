#!/usr/bin/env bash
#
# custom_list_merge_aur_scan.sh — Fetch, merge, dedup, and scan
#
# Fetches the official HedgeDoc list (optional), merges with custom package
# lists from URLs or files, deduplicates, and runs aur_check-v2.sh.
# By default the campaign date window applies.  Pass -- --all-time after
# the options separator to scan regardless of install date.
#
# Usage:
#   ./custom_list_merge_aur_scan.sh -l ./historical_packages.txt
#   ./custom_list_merge_aur_scan.sh -l https://paste.example.org/list.txt -l ./more.txt
#   ./custom_list_merge_aur_scan.sh --skip-hedgedoc -l legacy.txt -- --all-time
#   ./custom_list_merge_aur_scan.sh --skip-hedgedoc -l legacy.txt -- --all-time --verbose
#
# Options:
#   -l, --list=URL|FILE          Additional AUR package list (repeatable)
#   -m, --malicious-npm=URL|FILE Additional malicious npm list (repeatable)
#   -o, --output=FILE            Save merged AUR list to FILE (default: temp)
#   --skip-hedgedoc              Skip the official HedgeDoc list
#   -v, --verbose                Verbose wrapper output
#   --debug                      Verbose + set -x trace
#   --help                       Show this help
#
#   --    Separator — all following arguments are passed through to
#         aur_check-v2.sh unchanged.
#         Useful flags: --all-time (disable date window), --verbose,
#         --check-systemd, --check-npm-cache, --check-bun-cache, --full.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUR_CHECK="$SCRIPT_DIR/aur_check-v2.sh"
HEDGEDOC_URL="https://md.archlinux.org/s/SxbqukK6IA/download"

LISTS=()
NPM_LISTS=()
OUTPUT_FILE=""
SKIP_HEDGEDOC=false
VERBOSE=false
AUR_ARGS=()

usage() {
    sed -n '3,/^$/{ /^#/s/^# //p }' "$0"
    exit 0
}

error() {
    echo >&2 "ERROR: $*"
    exit 1
}

warn() {
    echo >&2 "WARN: $*"
}

info() {
    if $VERBOSE; then
        echo >&2 "[INFO] $*"
    fi
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
PASSTHROUGH=false
ARGS=("$@")
i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
    arg="${ARGS[$i]}"
    [[ "$PASSTHROUGH" == true ]] && { AUR_ARGS+=("$arg"); ((++i)); continue; }

    case "$arg" in
        --help|-h) usage ;;
        --)        PASSTHROUGH=true; ((++i)); continue ;;
        -v|--verbose) VERBOSE=true ;;
        --debug)      VERBOSE=true; set -x ;;
        --skip-hedgedoc) SKIP_HEDGEDOC=true ;;
        -l|--list)
            ((++i))
            [[ $i -ge ${#ARGS[@]} ]] && error "$arg requires a value"
            LISTS+=("${ARGS[$i]}")
            ;;
        --list=*)  LISTS+=("${arg#*=}") ;;
        -m|--malicious-npm)
            ((++i))
            [[ $i -ge ${#ARGS[@]} ]] && error "$arg requires a value"
            NPM_LISTS+=("${ARGS[$i]}")
            ;;
        --malicious-npm=*) NPM_LISTS+=("${arg#*=}") ;;
        -o|--output)
            ((++i))
            [[ $i -ge ${#ARGS[@]} ]] && error "$arg requires a value"
            OUTPUT_FILE="${ARGS[$i]}"
            ;;
        --output=*) OUTPUT_FILE="${arg#*=}" ;;
        *) error "unknown option: $arg (use --help)" ;;
    esac
    ((++i))
done

# ---------------------------------------------------------------------------
# Validate: --skip-hedgedoc without any -l is pointless
# ---------------------------------------------------------------------------
if $SKIP_HEDGEDOC && [[ ${#LISTS[@]} -eq 0 ]]; then
    error "You used --skip-hedgedoc but provided no --list=... sources.
  Either remove --skip-hedgedoc (to include the official HedgeDoc list),
  or add at least one -l/--list= with a URL or file path."
fi

# ---------------------------------------------------------------------------
# Check aur_check-v2.sh exists
# ---------------------------------------------------------------------------
[[ -x "$AUR_CHECK" ]] || error "aur_check-v2.sh not found or not executable at: $AUR_CHECK"

# ---------------------------------------------------------------------------
# Source helpers (reuse load_list logic)
# ---------------------------------------------------------------------------
# We just use sort -u for dedup, no need to source the full script

# ---------------------------------------------------------------------------
# Merge AUR package lists
# ---------------------------------------------------------------------------
AUR_TEMP=$(mktemp /tmp/aur_merge_aur_XXXXXX.txt)
NPM_TEMP=$(mktemp /tmp/aur_merge_npm_XXXXXX.txt)
AUR_SOURCES=0
NPM_SOURCES=0

cleanup() {
    rm -f "$AUR_TEMP" "$NPM_TEMP"
}
trap cleanup EXIT

fetch_into() {
    local url="$1"
    local dest="$2"
    local label="$3"
    if curl -sL --max-time 15 "$url" >> "$dest" 2>/dev/null; then
        info "fetched $label: $url"
        return 0
    else
        warn "failed to fetch $label: $url (skipping, non-fatal)"
        return 1
    fi
}

append_file() {
    local path="$1"
    local dest="$2"
    if [[ -f "$path" ]]; then
        cat "$path" >> "$dest"
        info "added local file: $path"
    else
        error "file not found: $path"
    fi
}

append_source() {
    local src="$1"
    local dest="$2"
    local label="$3"
    if [[ "$src" =~ ^https?:// ]]; then
        fetch_into "$src" "$dest" "$label"
    else
        append_file "$src" "$dest"
    fi
}

# 1. HedgeDoc (unless --skip-hedgedoc)
if ! $SKIP_HEDGEDOC; then
    if fetch_into "$HEDGEDOC_URL" "$AUR_TEMP" "HedgeDoc"; then
        AUR_SOURCES=$((AUR_SOURCES + 1))
    fi
fi

# 2. Custom AUR lists
for src in "${LISTS[@]}"; do
    append_source "$src" "$AUR_TEMP" "custom AUR list" && AUR_SOURCES=$((AUR_SOURCES + 1))
done

# 3. Custom npm lists
for src in "${NPM_LISTS[@]}"; do
    append_source "$src" "$NPM_TEMP" "custom npm list" && NPM_SOURCES=$((NPM_SOURCES + 1))
done

# 4. If no custom npm lists given, use the default from the repo
if [[ ${#NPM_LISTS[@]} -eq 0 ]]; then
    DEFAULT_NPM="$SCRIPT_DIR/malicious_npm_packages.txt"
    if [[ -f "$DEFAULT_NPM" ]]; then
        cat "$DEFAULT_NPM" >> "$NPM_TEMP"
        info "using default npm list: $DEFAULT_NPM"
    fi
fi

# ---------------------------------------------------------------------------
# Validate: at least one AUR source succeeded
# ---------------------------------------------------------------------------
if [[ $AUR_SOURCES -eq 0 ]]; then
    error "No AUR package sources available.
  The HedgeDoc fetch failed and no --list=... sources were provided."
fi

# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------
sort -u "$AUR_TEMP" -o "$AUR_TEMP"
if [[ -s "$NPM_TEMP" ]]; then
    sort -u "$NPM_TEMP" -o "$NPM_TEMP"
fi

AUR_COUNT=$(wc -l < "$AUR_TEMP")
NPM_COUNT=$(wc -l < "$NPM_TEMP")
info "Merged AUR list: $AUR_COUNT unique packages from $AUR_SOURCES source(s)"
[[ $NPM_SOURCES -gt 0 ]] && info "Merged npm list: $NPM_COUNT unique packages from $NPM_SOURCES source(s)"

# ---------------------------------------------------------------------------
# Optionally save merged AUR list
# ---------------------------------------------------------------------------
if [[ -n "$OUTPUT_FILE" ]]; then
    cp "$AUR_TEMP" "$OUTPUT_FILE" || error "cannot write output: $OUTPUT_FILE"
    info "merged AUR list saved to: $OUTPUT_FILE"
fi

# ---------------------------------------------------------------------------
# Warn when custom lists are loaded
# ---------------------------------------------------------------------------
if [[ ${#LISTS[@]} -gt 0 || ${#NPM_LISTS[@]} -gt 0 ]]; then
    echo >&2 "============================================================"
    echo >&2 " WARNING: Custom package list(s) loaded via -l or -m."
    echo >&2 " Detection is name-based only — matches mean the package name"
    echo >&2 " appears in the list, NOT that campaign IOCs were found."
    echo >&2 " Optional checks (systemd, eBPF, npm/bun cache) target the"
    echo >&2 " June 2026 campaign and may not correspond to the actual"
    echo >&2 " threat vector of custom-list packages. Verify results manually."
    echo >&2 "============================================================"
    echo >&2
fi

# ---------------------------------------------------------------------------
# Run aur_check-v2.sh
# Temp files remain in /tmp — v2 reads them via --package-list= and
# --malicious-npm-list=.  The cleanup trap above handles early exits;
# after exec the trap is irrelevant (process image replaced).
# ---------------------------------------------------------------------------
info "running: aur_check-v2.sh --package-list=$AUR_TEMP ${AUR_ARGS[*]}"
exec "$AUR_CHECK" \
    --package-list="$AUR_TEMP" \
    --malicious-npm-list="$NPM_TEMP" \
    "${AUR_ARGS[@]}"
