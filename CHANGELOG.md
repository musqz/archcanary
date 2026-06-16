# Changelog

## 2.6.1 (2026-06-16) — personal fork
- Fix: `check_systemd` no longer requires the exact `Restart=always` + `RestartSec=30` pair from the 2024 campaign — now flags any of `always|on-failure|on-abnormal|on-abort` in `.service` files
- New: also scans drop-in override dirs (`*.service.d/*.conf`) — attackers use these to re-enable restart on existing units without modifying the unit file itself
- New: detects `.timer` units with `OnBootSec=` + `Persistent=true` — a common alternative to `.service` persistence that the original check missed entirely
- Scan dirs injectable via `SYSTEMD_SCAN_DIRS` (colon-separated) for testing

## 2.6.0 (2026-06-16) — personal fork
- New: `--check-ldso` (included in `--full`) — detects shared library injection via `/etc/ld.so.preload`; any non-empty content causes the dynamic linker to load the listed `.so` into every process at startup. Hard indicator of root-level compromise; lists each injected library verbatim (exit 2).

## 2.5.1 (2026-06-16) — personal fork
- Fix: Check [2] historical log now shows full ISO timestamp (`2026-06-10T14:23:45+0100`) instead of date-only, so the exact install time is visible alongside the package name
- Improved: Check [2] WARNING output now explains these are name-matches and that a clean-looking PKGBUILD may mean the malicious commit was reverted — clarifies context without dismissing the risk

## 2.5.0 (2026-06-16) — personal fork
- New: `--check-bpftool` (included in `--full`) — enumerates **all** loaded eBPF programs via `bpftool prog show`, complementing `--check-ebpf` (which only globs pinned `/sys/fs/bpf/hidden_*` maps). Catches unpinned or differently-named programs an eBPF rootkit may keep alive via an open fd or a BPF link. Informational by default; **warns** (exit 1) when stealth-associated hook types are present (`kprobe`/`kretprobe`/`tracepoint`/`raw_tracepoint`/`perf_event`/`tracing`/`lsm`). Requires root to enumerate; skips gracefully otherwise. Needs the `bpf` package (provides `bpftool`).
- Change: `install.sh` now prefers `~/.local/bin` (XDG) over `~/bin`

## 2.4.0 (2026-06-14) — personal fork
- New: XDG config dir — package lists live in `~/.config/aur-malware-check/` (respects `$XDG_CONFIG_HOME`); created automatically on first run
- New: auto-seed config dir from bundled txt files when running from a new install location
- New: `--check-pkgbuild` (included in `--full`) — obfuscation-aware scan of AUR helper caches (`~/.cache/yay`, `~/.cache/paru`, etc.) for `bun add` / `npm install` of malicious packages; catches quote-split commands like `'b''u''n' 'a'"d""d"`
- New: `nextfile-js` added to malicious npm package list (reported upstream issue #11 / PR #12)
- New: `aur_malware_menu.sh` — fzf TUI menu to run individual checks or view the last log; loops back to menu after each action
- New: `--no-notify` flag — suppresses desktop notification when called as subprocess (e.g. from the menu)
- Improved: notification prefers `notify-send.sh` (AUR) over plain `notify-send`; adds a **Show Menu** button that opens `aur_malware_menu.sh` in a terminal when clicked
- Package list refreshed to 1936 entries

## 2.3.3 (2026-06-13)
- Fix: prefix-matching bug in `check_current()` (Issue #2, confirmed via opencode/opencode-bin)
- New: `INFECTED_LOOKUP` associative array filters `pacman -Qmq` results to exact matches only
- `[[ -v INFECTED_LOOKUP["$pkg"] ]] || continue` prevents false positives on -bin/-git suffixed packages

## 2.3.2 (2026-06-13)
- New: `--all-time` flag (v2) — disable recency window for cross-campaign detection
- New: `custom_list_merge_aur_scan.sh` — fetch HedgeDoc + merge custom lists +
  dedup + run aur_check-v2.sh
  - `-l/--list=URL|FILE`: additional AUR package lists (repeatable)
  - `-m/--malicious-npm=URL|FILE`: additional npm lists (repeatable)
  - `--skip-hedgedoc`: exclude official HedgeDoc list
  - `-o/--output=FILE`: save merged list
  - `-v/--verbose`, `--debug`: verbosity control (+ set -x trace for debug)
  - `--list=`, `--malicious-npm=` value-consumption via `((++i))` (fix: `set -e`
    kill at `((0++))` on first iteration)
  - `info()`: `if $VERBOSE; then` instead of `$VERBOSE &&` (fix: non-zero return
    with `set -e` when not verbose)
  - `$PASSTHROUGH &&` → `[[ "$PASSTHROUGH" == true ]] &&` (fix: bare `false &&`
    fragile)
  - `append_source` loops: `&& counter++` instead of `; counter++` (fix: counts
    only successful sources)
  - Warning banner when `-l`/`-m` used: name-based match ≠ IOC verification
  - `--all-time` removed from hardcoded exec — user passes via `-- --all-time`
  - Edge cases: --skip-hedgedoc without -l → error; fetch timeout → skip

## 2.3.1 (2026-06-13)
- New: `--package-list=PATH` CLI flag — override infected AUR package list path
- New: `--malicious-npm-list=PATH` CLI flag — override malicious npm package list path
- Change: CLI flags override env vars override defaults (`PACKAGE_LIST_FILE`, `MALICIOUS_NPM_LIST`)
- Change: warn if `--package-list` and `--refresh` conflict, ignore `--refresh`
- New: `tests/run_matching_tests.sh` — 8-test matching test suite
  - suffix_ambiguity: `jd-gui` vs `jd-gui-bin` exact matching (regression guard for #2)
  - substring: short names don't match suffixed variants
  - empty list, comments, specials, CLI flag integration

## 2.3.0 (2026-06-13)
- New: `--refresh` flag — fetch live package list from Arch Linux HedgeDoc (1619 packages)
- New: `lockfile-js` added to npm+bun cache checks (3rd malicious npm package)
- PR #8 (drbbgh): package list refresh logic with `/download` endpoint
- PR #7 (liphiwolf): lockfile-js detection, package list expanded from CSCS paste
- Campaign banner updated: atomic-lockfile / js-digest / lockfile-js
- Package list: ~588 → 1619 (live via `--refresh`) / 512 (bundled fallback)

## 2.2.0 (2026-06-12)
- Correction: `arojas` was impersonated via git commit forgery, not a malicious maintainer
- `iocs.txt`: `arojas` moved to new "Impersonated Accounts" section
- New sources: mttaggart Mastodon thread, David Runge clarification
- Banner + attack vector text corrected in README

## 2.1.0 (2026-06-12)
- New attack wave: bun/js-digest variant (second malicious npm package)
- 29 new compromised packages (custodiatovar + veramagalhaes accounts)
- `--check-bun-cache`: scan bun cache for js-digest / atomic-lockfile
- `check_npm_cache` expanded: detects atomic-lockfile AND js-digest
- New IOC: js-digest ELF SHA256 7883BD...
- New attacker accounts custodiatovar, veramagalhaes in iocs.txt

## 2.0.0 (2026-06-12)
- `aur_check-v2.sh`: optimized log scanner (bash regex + O(1) assoc. array)
- Same detection logic as v1, ~150x faster for large pacman.log files
- v1 retained for completeness as reference implementation

## 1.1.0 (2026-06-12)
- Fix: `set -e` bug — non-verbose mode killed script (log_info always returns 0)
- Auto-logfile: full detail always written to `aur-check-<date>.log`
- Terminal output gated by `--verbose`; log always contains `[INFO]` detail
- `check_logs` output now visible on terminal via `tee` (was hidden in tempfile)
- Informative eBPF message on missing privileges
- `exit "$EXIT_CODE"` quoting, mktemp everywhere, trap for tempfile cleanup
- Pipe-to-subshell fixed: `while read` now uses process substitution

## 1.0.0 (2026-06-12)
- Consolidated aur_check.sh combining all 5 community forks
- Package list: ~588 known compromised AUR packages
- Detection: current install + pacman logs + date window
- Optional checks: systemd, eBPF, npm cache
- IOC reference document
- Full source attribution in README

### Integration History
- Base list: Kidev original (446 packages)
- Extended: commonsourcecs fork (+~140 packages)
- Efficiency: BrianCArnold, commonsourcecs batch query
- Log scanning: Kacper-Kondracki pacman.log parser
- Safety: quantenProjects comm approach
