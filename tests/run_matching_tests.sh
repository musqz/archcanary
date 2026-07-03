#!/usr/bin/env bash
#
# Matching test runner for archcanary
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
# Helper: load a package list file the same way archcanary.sh does
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
    "$REPO_DIR/archcanary.sh" --log-file="$log_file" >/dev/null 2>&1 || true
    grep -q "Packages checked: 10" "$log_file" || result=$?

    if [[ $result -eq 0 ]]; then
        pass "cli_flag: PACKAGE_LIST_FILE env loads 10 packages"
    else
        # Try with direct --package-list flag
        result=0
        "$REPO_DIR/archcanary.sh" \
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

    "$REPO_DIR/archcanary.sh" \
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
    load_list "$REPO_DIR/lists/package_list.txt" infected

    if [[ ${#infected[@]} -gt 500 ]]; then
        pass "actual_list: parsed ${#infected[@]} packages from package_list.txt"
    else
        fail "actual_list: only got ${#infected[@]} packages (expected >500)"
    fi
}

# ---------------------------------------------------------------------------
# Test 9: check_ldso — detects non-empty /etc/ld.so.preload
# ---------------------------------------------------------------------------
test_check_ldso() {
    local tmpdir preload_file conf_dir
    tmpdir=$(mktemp -d)
    preload_file="$tmpdir/ld.so.preload"
    conf_dir="$tmpdir/ld.so.conf.d"
    mkdir -p "$conf_dir"

    local out rc=0

    # Sub-test A: absent/empty preload, empty conf.d → clean
    rc=0
    out=$(LDSO_PRELOAD_FILE="$preload_file" LDSO_CONF_DIR="$conf_dir" \
        "$REPO_DIR/archcanary.sh" \
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt" \
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt" \
        --check-ldso --no-notify 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_ldso: absent preload → clean"
    else
        fail "check_ldso: absent preload → expected clean, got: $out"
    fi

    # Sub-test B: non-empty preload → WARNING (exit 2)
    echo "/tmp/evil.so" > "$preload_file"
    rc=0
    out=$(LDSO_PRELOAD_FILE="$preload_file" LDSO_CONF_DIR="$conf_dir" \
        "$REPO_DIR/archcanary.sh" \
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt" \
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt" \
        --check-ldso --no-notify 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING"* && "$out" == *"evil.so"* ]]; then
        pass "check_ldso: non-empty preload → WARNING (exit 2) with library listed"
    else
        fail "check_ldso: non-empty preload → expected WARNING+exit2, got rc=$rc"
    fi

    rm -rf "$tmpdir"
}

# ---------------------------------------------------------------------------
# Test 10: check_systemd hardened — drop-ins, timers, wider Restart= match
# ---------------------------------------------------------------------------
test_check_systemd_hardened() {
    local fixture_dir="$SCRIPT_DIR/systemd"
    local base_args=(
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt"
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt"
        --check-systemd --no-notify
    )

    local out rc=0

    # Sub-test A: drop-in override with Restart=on-failure → WARNING
    out=$(SYSTEMD_SCAN_DIRS="$fixture_dir" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING"* && "$out" == *"on-failure"* ]]; then
        pass "check_systemd: drop-in Restart=on-failure → WARNING (exit 2)"
    else
        fail "check_systemd: drop-in Restart=on-failure → expected WARNING+exit2, got rc=$rc"
    fi

    # Sub-test B: timer with OnBootSec + Persistent=true → WARNING
    if [[ "$out" == *"timer"* || "$out" == *"Persistent"* ]]; then
        pass "check_systemd: OnBootSec+Persistent timer → WARNING"
    else
        fail "check_systemd: timer not detected — got: $out"
    fi

    # Sub-test C: empty dir → clean
    local tmpdir
    tmpdir=$(mktemp -d)
    rc=0
    out=$(SYSTEMD_SCAN_DIRS="$tmpdir" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_systemd: empty scan dir → clean"
    else
        fail "check_systemd: empty dir → expected clean, got: $out"
    fi
    rm -rf "$tmpdir"
}

# ---------------------------------------------------------------------------
# Test 11: check_autostart — suspicious .desktop and shell RC detection
# ---------------------------------------------------------------------------
test_check_autostart() {
    local fake_home="$SCRIPT_DIR/fake_home"
    local base_args=(
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt"
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt"
        --check-autostart --no-notify
    )
    local out rc=0

    # Sub-test A: fixture home with evil.desktop + malicious .bashrc → WARNING
    rc=0
    out=$(AUTOSTART_HOME="$fake_home" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING"* ]]; then
        pass "check_autostart: evil.desktop + malicious .bashrc → WARNING (exit 2)"
    else
        fail "check_autostart: expected WARNING+exit2, got rc=$rc"
    fi

    # Sub-test B: evil.desktop is flagged, clean.desktop is not
    if [[ "$out" == *"evil.desktop"* && "$out" != *"clean.desktop"* ]]; then
        pass "check_autostart: evil.desktop flagged, clean.desktop not flagged"
    else
        fail "check_autostart: desktop filtering wrong — out: $out"
    fi

    # Sub-test C: .bashrc curl|bash pattern detected
    if [[ "$out" == *".bashrc"* ]]; then
        pass "check_autostart: curl|bash in .bashrc detected"
    else
        fail "check_autostart: .bashrc pattern not detected — out: $out"
    fi

    # Sub-test D: clean home dir → clean
    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/.config/autostart"
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: empty home → clean"
    else
        fail "check_autostart: empty home → expected clean, got: $out"
    fi
    rm -rf "$tmpdir"
}

# ---------------------------------------------------------------------------
# Test 12: check_pkgbuild_caches hardened obfuscation patterns
# ---------------------------------------------------------------------------
test_pkgbuild_obfuscation() {
    local fixtures="$SCRIPT_DIR/fake_pkgbuilds"
    local base_args=(
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt"
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt"
        --check-pkgbuild --no-notify
    )
    local out rc=0

    # Sub-test A: base64 -d | bash → WARNING
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-base64" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"base64"* ]]; then
        pass "pkgbuild_obfuscation: base64-decode-to-shell detected"
    else
        fail "pkgbuild_obfuscation: base64 pattern missed, rc=$rc"
    fi

    # Sub-test B: eval $(...) → WARNING
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-eval" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"eval"* ]]; then
        pass "pkgbuild_obfuscation: eval+subshell detected"
    else
        fail "pkgbuild_obfuscation: eval pattern missed, rc=$rc"
    fi

    # Sub-test C: printf hex → WARNING
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-printf" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"printf"* ]]; then
        pass "pkgbuild_obfuscation: printf hex/octal detected"
    else
        fail "pkgbuild_obfuscation: printf pattern missed, rc=$rc"
    fi

    # Sub-test D: variable-split reassembly → WARNING
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-varsplit" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"variable-split"* ]]; then
        pass "pkgbuild_obfuscation: variable-split reassembly detected"
    else
        fail "pkgbuild_obfuscation: varsplit pattern missed, rc=$rc"
    fi

    # Sub-test E: clean PKGBUILD → no WARNING
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-clean" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "pkgbuild_obfuscation: clean PKGBUILD → no false positive"
    else
        fail "pkgbuild_obfuscation: clean PKGBUILD triggered WARNING — false positive"
    fi
}

# ---------------------------------------------------------------------------
# Test 13: check_kmod — unknown module detection via mocked lsmod
# ---------------------------------------------------------------------------
test_check_kmod() {
    local base_args=(
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt"
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt"
        --check-kmod --no-notify
    )
    local out rc=0

    # Helper: create a script that outputs fixed content
    make_cmd_script() {
        local script content
        script=$(mktemp); content="$1"
        printf '#!/bin/sh\nprintf "%%s" "%s"\n' "$content" > "$script"
        chmod +x "$script"; echo "$script"
    }

    local null_dkms
    null_dkms=$(make_cmd_script "")

    # Sub-test A: lsmod with an unknown module → WARNING (exit 2)
    local lsmod_evil
    lsmod_evil=$(make_cmd_script "$(printf 'Module                  Size  Used by\nevil_rootkit_kmod      65536  0\n')")

    rc=0
    out=$(LSMOD_CMD="$lsmod_evil" DKMS_CMD="$null_dkms" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING"* && "$out" == *"evil_rootkit_kmod"* ]]; then
        pass "check_kmod: unknown module → WARNING (exit 2) with name listed"
    else
        fail "check_kmod: unknown module not detected, rc=$rc"
    fi

    # Sub-test B: empty lsmod + empty dkms → clean
    local lsmod_empty
    lsmod_empty=$(make_cmd_script "$(printf 'Module                  Size  Used by\n')")

    rc=0
    out=$(LSMOD_CMD="$lsmod_empty" DKMS_CMD="$null_dkms" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_kmod: empty lsmod/dkms → clean"
    else
        fail "check_kmod: empty lsmod/dkms → expected clean, got: $out"
    fi

    rm -f "$null_dkms" "$lsmod_evil" "$lsmod_empty"
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

$VERBOSE && msg "--- Test 9: check_ldso ---"
test_check_ldso

$VERBOSE && msg "--- Test 10: check_systemd hardened ---"
test_check_systemd_hardened

$VERBOSE && msg "--- Test 11: check_autostart ---"
test_check_autostart

$VERBOSE && msg "--- Test 12: pkgbuild_obfuscation ---"
test_pkgbuild_obfuscation

$VERBOSE && msg "--- Test 13: check_kmod ---"
test_check_kmod

echo "=== Results: $PASS_COUNT PASS, $FAIL_COUNT FAIL ==="
[[ $FAIL_COUNT -eq 0 ]] || exit 1
