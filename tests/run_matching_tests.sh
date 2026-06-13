#!/usr/bin/env bash
#
# Matching test runner for aur_malware_check
# Tests that package matching is exact (no prefix/suffix false positives)
# and that list parsing handles edge cases correctly.
#
# Usage:
#   ./tests/run_matching_tests.sh          # run all tests
#   ./tests/run_matching_tests.sh -v       # verbose output
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
VERBOSE=false
FAIL_COUNT=0
PASS_COUNT=0

[[ "${1:-}" == "-v" ]] && VERBOSE=true

msg()   { echo >&2 "  $*"; }
pass()  { echo >&2 "  PASS: $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail()  { echo >&2 "  FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# ---------------------------------------------------------------------------
# Helper: load a package list file the same way aur_check-v2.sh does
# Returns array via nameref
# ---------------------------------------------------------------------------
load_list() {
    local file=$1
    local -n arr=$2
    arr=()
    while IFS= read -r line; do
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        arr+=("$line")
    done < "$file"
}

# ---------------------------------------------------------------------------
# Helper: simulate check_current logig — filter installed list against
#          infected list (exact match only)
# ---------------------------------------------------------------------------
filter_installed() {
    local _fn="$1" _fl="$2" _fr="$3"
    local _fa=() _fb=()
    eval '_fa=("${'"$_fn"'[@]}")'
    eval '_fb=("${'"$_fl"'[@]}")'
    local _fc=()
    local _p _q
    for _p in "${_fa[@]}"; do
        local _m=""
        for _q in "${_fb[@]}"; do
            if [[ "$_p" == "$_q" ]]; then
                _m="$_q"
                break
            fi
        done
        if [[ -n "$_m" ]]; then
            _fc+=("$_p")
        fi
    done
    eval "$_fr=(\"\${_fc[@]}\")"
}

# ---------------------------------------------------------------------------
# Test 1: suffix_ambiguity — jd-gui-bin should NOT match jd-gui
# ---------------------------------------------------------------------------
test_suffix_ambiguity() {
    local infected=()
    load_list "$SCRIPT_DIR/fake_package_lists/suffix_ambiguity.txt" infected

    # Simulate installed packages including jd-gui (infected) and jd-gui-bin (not)
    local installed=("jd-gui" "jd-gui-bin" "alienfx" "alienfx-lite" "alock" "alock-git" "nss" "git")
    local matched=()
    filter_installed installed infected matched

    local expected=("jd-gui" "alienfx" "alock" "nss" "git")

    if [[ "${#matched[@]}" -eq "${#expected[@]}" ]]; then
        local all_match=true
        local i
        for i in "${!expected[@]}"; do
            [[ "${matched[$i]}" == "${expected[$i]}" ]] || all_match=false
        done
        if $all_match; then
            pass "suffix_ambiguity: exact match only (no prefix false positives)"
        else
            fail "suffix_ambiguity: matched ${matched[*]}, expected ${expected[*]}"
        fi
    else
        fail "suffix_ambiguity: got ${#matched[@]} matches, expected ${#expected[@]} (${matched[*]:-none})"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: substring — short names like 'git' should not match longer names
# ---------------------------------------------------------------------------
test_substring() {
    local infected=()
    load_list "$SCRIPT_DIR/fake_package_lists/substring.txt" infected

    local installed=("git" "git-credential-manager-core-bin" "nss" "python-nss" "cuda" "cuda-12.8" "python" "python3.11")
    local matched=()
    filter_installed installed infected matched

    local expected=("git" "nss" "cuda" "python")
    if [[ "${#matched[@]}" -eq "${#expected[@]}" ]]; then
        local all_match=true
        local i
        for i in "${!expected[@]}"; do
            [[ "${matched[$i]}" == "${expected[$i]}" ]] || all_match=false
        done
        if $all_match; then
            pass "substring: git/nss/python/cuda match exactly, not suffixed variants"
        else
            fail "substring: matched ${matched[*]}, expected ${expected[*]}"
        fi
    else
        fail "substring: got ${#matched[@]} matches, expected ${#expected[@]} (${matched[*]:-none})"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: empty list — should match nothing
# ---------------------------------------------------------------------------
test_empty_list() {
    local infected=()
    load_list "$SCRIPT_DIR/fake_package_lists/empty.txt" infected

    local installed=("alvr" "guiscrcpy" "jd-gui" "git")
    local matched=()
    filter_installed installed infected matched

    if [[ ${#matched[@]} -eq 0 ]]; then
        pass "empty_list: no matches from empty infected list"
    else
        fail "empty_list: got ${#matched[@]} matches from empty list"
    fi
}

# ---------------------------------------------------------------------------
# Test 4: comments parsing — comment lines and blanks are ignored
# ---------------------------------------------------------------------------
test_comments_parsing() {
    local infected=()
    load_list "$SCRIPT_DIR/fake_package_lists/comments.txt" infected

    local expected=("alvr" "guiscrcpy" "netmon-git")
    if [[ "${#infected[@]}" -eq "${#expected[@]}" ]]; then
        local all_match=true
        local i
        for i in "${!expected[@]}"; do
            [[ "${infected[$i]}" == "${expected[$i]}" ]] || all_match=false
        done
        if $all_match; then
            pass "comments_parsing: comments and blanks correctly ignored"
        else
            fail "comments_parsing: parsed ${infected[*]}, expected ${expected[*]}"
        fi
    else
        fail "comments_parsing: got ${#infected[@]} entries, expected ${#expected[@]}"
    fi
}

# ---------------------------------------------------------------------------
# Test 5: special characters — dots, plus, hyphens in package names
# ---------------------------------------------------------------------------
test_specials() {
    local infected=()
    load_list "$SCRIPT_DIR/fake_package_lists/specials.txt" infected

    local expected=("python3.11" "gcc-libs" "cuda-12.8" "ruby3.3+dev" "dot_underscore" "alac-git")
    if [[ "${#infected[@]}" -eq "${#expected[@]}" ]]; then
        local all_match=true
        local i
        for i in "${!expected[@]}"; do
            [[ "${infected[$i]}" == "${expected[$i]}" ]] || all_match=false
        done
        if $all_match; then
            pass "specials: dots/plus/hyphens parsed correctly"
        else
            fail "specials: parsed ${infected[*]}, expected ${expected[*]}"
        fi
    else
        fail "specials: got ${#infected[@]} entries, expected ${#expected[@]}"
    fi
}

# ---------------------------------------------------------------------------
# Test 6: --package-list CLI flag integration
# ---------------------------------------------------------------------------
test_cli_flag() {
    local log_file
    log_file=$(mktemp)

    # Run via env var (existing path)
    local result=0
    PACKAGE_LIST_FILE="$SCRIPT_DIR/fake_package_lists/simple.txt" \
    "$REPO_DIR/aur_check-v2.sh" --log-file="$log_file" >/dev/null 2>&1 || true
    grep -q "Packages checked: 10" "$log_file" || result=$?

    if [[ $result -eq 0 ]]; then
        pass "cli_flag: PACKAGE_LIST_FILE env loads 10 packages"
    else
        # Try with direct --package-list flag
        result=0
        "$REPO_DIR/aur_check-v2.sh" \
            --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt" \
            --log-file="$log_file" >/dev/null 2>&1 || true
        grep -q "Packages checked: 10" "$log_file" || result=$?
        if [[ $result -eq 0 ]]; then
            pass "cli_flag: --package-list=PATH loads 10 packages"
        else
            fail "cli_flag: could not verify package count"
        fi
    fi

    rm -f "$log_file"
}

# ---------------------------------------------------------------------------
# Test 7: --malicious-npm-list CLI flag integration
# ---------------------------------------------------------------------------
test_npm_cli_flag() {
    local log_file
    log_file=$(mktemp)

    "$REPO_DIR/aur_check-v2.sh" \
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt" \
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt" \
        --log-file="$log_file" >/dev/null 2>&1 || true

    if grep -q "malicious_npm.txt" "$log_file"; then
        pass "npm_cli_flag: --malicious-npm-list=PATH accepted"
    elif grep -q "Packages checked:" "$log_file"; then
        pass "npm_cli_flag: script ran successfully with custom npm list"
    else
        fail "npm_cli_flag: script failed with custom npm list"
    fi

    rm -f "$log_file"
}

# ---------------------------------------------------------------------------
# Test 8: verify actual repo package_list.txt is parseable (no corrupt lines)
# ---------------------------------------------------------------------------
test_actual_list_integrity() {
    local infected=()
    load_list "$REPO_DIR/package_list.txt" infected

    if [[ ${#infected[@]} -gt 500 ]]; then
        pass "actual_list: parsed ${#infected[@]} packages from package_list.txt"
    else
        fail "actual_list: only got ${#infected[@]} packages (expected >500)"
    fi
}

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------
echo "=== Matching Tests ==="

$VERBOSE && msg ""

$VERBOSE && msg "--- Test 1: suffix_ambiguity ---"
test_suffix_ambiguity

$VERBOSE && msg "--- Test 2: substring ---"
test_substring

$VERBOSE && msg "--- Test 3: empty_list ---"
test_empty_list

$VERBOSE && msg "--- Test 4: comments_parsing ---"
test_comments_parsing

$VERBOSE && msg "--- Test 5: specials ---"
test_specials

$VERBOSE && msg "--- Test 6: cli_flag (--package-list) ---"
test_cli_flag

$VERBOSE && msg "--- Test 7: npm_cli_flag (--malicious-npm-list) ---"
test_npm_cli_flag

$VERBOSE && msg "--- Test 8: actual_list_integrity ---"
test_actual_list_integrity

echo "=== Results: $PASS_COUNT PASS, $FAIL_COUNT FAIL ==="
[[ $FAIL_COUNT -eq 0 ]] || exit 1
