# Changelog

## 3.0 (2026-06-16)
- New: `aur_check_py/` — Python 3.14+ port of `aur_check-v2.sh`, stdlib only
- All 6 checks preserved, `--merge` mode, compressed log support (gzip/xz/bz2/zstd)
- 75 unit tests, `unittest` + `unittest.mock`, laufen ohne Arch-System
- `developing.md` — coding conventions, `README.md` — use-case map
- Bash scripts remain at 2.3.x for legacy use

## 2.9.9 (2026-06-17) — personal fork
- Change: the DKMS allowlist is now a **single system-wide file** at `/etc/aur-malware-check/dkms_allowlist.conf`. After the system/user scan split the kmod audit only runs as root, so a per-user `~/.config` copy was vestigial and confusing (two files, only `/etc` authoritative). The script now reads only `/etc` (override with `DKMS_ALLOWLIST_FILE` for tests); `install.sh --system` seeds it (migrating any existing `~/.config` entries, then removing that per-user copy); base `install.sh` no longer creates a per-user allowlist; and the GUI **Edit DKMS allowlist** button now edits `/etc` and saves it back via pkexec. Edit it with the GUI button or `sudoedit /etc/aur-malware-check/dkms_allowlist.conf`.

## 2.9.8 (2026-06-17) — personal fork
- Fix: the GUI no longer marks **every** check ❌ when a full scan finds one problem. `_propagate_full_scan` used to stamp the single overall verdict onto all rows, so one `INFECTED` check (e.g. an unallowlisted DKMS module) lit up the whole list. It now parses each check's own `--- [N] ---` section in the scan output and sets that row from its own result (WARNING/INFECTED → ❌, Skipped/needs-root → ?, otherwise ✅) — a finding points at the check that found it.

## 2.9.7 (2026-06-17) — personal fork
- Change: automated scanning is split by context so neither half false-positives. The **root system** timer now runs only the system-level checks (`--check-systemd/--check-ebpf/--check-bpftool/--check-ldso/--check-kmod` + the always-on package/log checks); a new **user** timer (`aur-malware-check-user.{service,timer}`) runs the user-level checks (`--check-npm-cache/--check-bun-cache/--check-yarn-cache/--check-pnpm-cache/--check-pkgbuild/--check-autostart`) as your user, so they scan your real `~/.cache`/`~/.config` instead of `/root`. Fixes the root scan flagging root's own `/root/.config/autostart` session relics as a false `RESULT: INFECTED`. The user scan notifies itself (runs in your session); the root scan still uses the path-watched notifier. `install.sh --system` installs and enables both; `systemd.md` updated.
- Fix: the DKMS allowlist loader used `[[ -f ]]` and aborted the whole scan (`Permission denied`, exit 1, under `set -e`) when `/etc/aur-malware-check/dkms_allowlist.conf` existed but was not readable. It now tests `[[ -r ]]` and skips unreadable files, and `install.sh --system` installs the system allowlist mode `644` (the user-level scan reads it too, even if your `~/.config` copy is `600`).

## 2.9.6 (2026-06-17) — personal fork
- Fix: the root **system** scan flagged allowlisted DKMS modules (e.g. `tuxedo-drivers`) as "untracked source" → false `RESULT: INFECTED`. The DKMS allowlist lived only in the user's `~/.config`, which the root service (`HOME=/root`) can't see. The script now also reads a **system-wide** `/etc/aur-malware-check/dkms_allowlist.conf` (merged with the per-user file), and `install.sh --system` seeds it from your user allowlist. Re-run `install.sh --system` (or edit `/etc/...`) after changing the allowlist.

## 2.9.5 (2026-06-17) — personal fork
- Fix: the root **system** service failed with `HOME: unbound variable` (exit 1) at the cache-dir line. systemd system services start with no `$HOME`, and under `set -u` the `${XDG_CACHE_HOME:-$HOME/.cache}` fallback aborts. The script now defaults `$HOME` to the running user's home (`/root` for the system scan) when it is unset — complementing the `$SUDO_USER`/`$PKEXEC_UID` resolution, which only covers interactive sudo/pkexec. Regression from 2.9.1.

## 2.9.4 (2026-06-17) — personal fork
- Fix: `check_systemd` no longer flags a persistent `.timer` (`OnBootSec=` + `Persistent=true`) just for existing — it now vets the **service the timer triggers** and only warns when that target service is itself suspicious (ExecStart outside a standard prefix, not pacman-owned). This stops the scanner from flagging its own `/etc/systemd/system/aur-malware-check.timer` (installed by `install.sh --system`) as a malicious persistence unit, which produced a false `RESULT: INFECTED` and desktop alert. A malicious timer pointing at `/tmp`, `$HOME`, etc. is still caught.

## 2.9.3 (2026-06-17) — personal fork
- New: the systemd units are now shipped under `systemd/` and `install.sh --system` installs and enables them — no more hand-creating files. It drops the root system scan units (`aur-malware-check.{service,timer,path}` + `-onchange.service`) into `/etc/systemd/system/`, the user notifier (`aur-malware-check-notify.{path,service}`) into `~/.config/systemd/user/`, pre-creates `/var/lib/aur-malware-check/`, enables the timer + pacman trigger + notifier, and migrates away the old user-scope scan units. `uninstall --system` reverses all of it.
- Fix: the user notifier `.path` unit failed to start when `/var/lib/aur-malware-check/` did not exist yet (inotify watch on a missing directory). The install now pre-creates the directory.

## 2.9.2 (2026-06-17) — personal fork
- Fix: a scan that skips root-requiring checks no longer reports a misleading `RESULT: CLEAN`. When `--check-kmod` / `--check-ebpf` / `--check-bpftool` (or `--full`) is run without root, those checks now return a dedicated "skipped" code; the run is reported as `INCOMPLETE: N root check(s) skipped` and the result escalates from CLEAN (0) to WARNINGS (exit 1) so automation and the systemd user service can detect that the scan was not complete. Run with `sudo` for the full picture. Genuine findings (exit 2) are unchanged.
- Change: systemd model reworked so automated scans get the **full picture**. The scan now runs as a **root system** service+timer (writes `/var/lib/aur-malware-check/last-scan.log`), and a **user** `.path` unit watches that file and fires the desktop notification on a detection — replacing the old user-only service that silently skipped the root checks. `docs/systemd.md` rewritten with the new units and a migration note.
- Change: `install.sh --system` now also seeds the bundled package lists (`package_list.txt`, `malicious_npm_packages.txt`, `chaos_rat_packages.txt`) into `/usr/lib/aur-malware-check/` so the root system scan finds them (root's `$HOME` is `/root`, which is not seeded).

## 2.9.1 (2026-06-17) — personal fork
- Fix: `sudo aur-malware-check.sh --check-kmod` (and other root checks run directly with `sudo`) no longer fails with `Malicious npm package list not found: /root/.config/...`. When running as root via `sudo`, the script now resolves the invoking user's home from `$SUDO_USER` (and `$PKEXEC_UID` for the pkexec path) so package lists, the DKMS allowlist, and the log/cache dirs come from the user's `~/.config` / `~/.cache` instead of `/root`. Mirrors what the polkit root helper already did for the GUI.

## 2.9.0 (2026-06-17) — personal fork
- Removed: `aur_malware_menu.sh` (fzf TUI) — the yad GUI covers interactive desktop use and the CLI (`aur-malware-check.sh --full` / single `--check-*` flags) covers headless / SSH. The menu had drifted (missing yarn/pnpm checks) and its "View last log" used the abandoned journalctl path. Two surfaces now: GUI + CLI.
- Removed: `notify-send.sh` dependency and the notification action button. The exit-code-2 alert now uses plain `notify-send` (libnotify) with no button; open AUR Malware Check from the app launcher to review and remediate.
- Removed: "View last log" from the GUI — the per-session status column already shows pass/fail per check; re-run a check to see its detail.
- Removed: orphaned `IS_FULL_SCAN` header marker (only ever fed the now-deleted GUI log picker).
- Fix: `install.sh` used `local` outside a function in the uninstall path (runtime error on `bash`).
- Dependencies dropped: `fzf`, `notify-send.sh`.

## 2.8.5 (2026-06-16) — personal fork
- New: `DKMS_ALLOWLIST` env var (colon-separated module names) — DKMS modules installed outside pacman by proprietary hardware drivers (e.g. `tuxedo-drivers`) can be acknowledged without suppressing genuine unknown-module warnings. Allowlisted entries print INFO instead of WARNING and do not set exit 2.

## 2.8.4 (2026-06-16) — personal fork
- Fix: `check_kmod` module name matching — `lsmod` returns names with underscores (`snd_seq_dummy`) but pacman `.ko` filenames use hyphens (`snd-seq-dummy.ko.zst`); normalize both to underscores before comparison, eliminating 80+ false positives from standard kernel modules
- Fix: `check_autostart` when run as root (`sudo`) now uses the invoking user's home dir (`$SUDO_USER`) instead of `/root` — `/root/.config/autostart/` holds live-session relics whose bare command names are unresolvable in root's PATH
- Docs: eBPF `lsm` warning now mentions AppArmor/SELinux as a legitimate source (Manjaro enables AppArmor by default)

## 2.8.3 (2026-06-16) — personal fork
- Fix: `check_systemd` now also skips services whose `ExecStart=` binary lives under a standard system prefix (`/usr/`, `/opt/`, `/bin/`, `/sbin/`, `/usr/local/`) and actually exists on disk — handles proprietary installers (piavpn, forgejo) that write a `.service` file without registering it with pacman. Malware still gets caught because it points to binaries in `/tmp/`, `$HOME/`, `/dev/shm/`, etc.

## 2.8.2 (2026-06-16) — personal fork
- Fix: run logs now default to `~/.cache/aur-malware-check/` (`$XDG_CACHE_HOME`) instead of the current working directory — prevents log accumulation in the repo or install source dir

## 2.8.1 (2026-06-16) — personal fork
- Fix: `check_systemd` no longer flags pacman-owned `.service` / drop-in `.conf` files — legitimate system daemons from packages carry `Restart=on-failure` by design. Timer check is now skipped for user-space dirs (`~/.config/systemd/user/`) since `OnBootSec + Persistent=true` is standard for user timers (cron replacements, update schedulers).
- Fix: `check_autostart` desktop check now uses `command -v` to resolve bare names before flagging, and accepts all standard system prefixes (`/bin/`, `/sbin/`, `/usr/local/`) in addition to `/usr/` and `/opt/`.
- Fix: `check_autostart` user service check expands systemd `%h` to `$HOME` before querying `pacman -Qo`; skips `~/.local/bin/` and `~/bin/` (XDG user bin dirs, not tracked by pacman).
- Fix: `check_autostart` shell RC eval pattern now requires the subshell to open with a network/execution tool (`curl`, `wget`, `python`, `bash`, `sh`) — bare `eval $(dircolors ...)` and similar are no longer flagged.

## 2.8.0 (2026-06-16) — personal fork
- New: `--check-kmod` (included in `--full`) — audits loaded kernel modules against the full set of `.ko` files owned by pacman packages; flags any module with no traceable owner. Also checks `dkms status` for DKMS modules whose source package is not in `pacman -Q`. Requires root for reliable module attribution; skips gracefully otherwise. `LSMOD_CMD` / `DKMS_CMD` env vars injectable for testing.

## 2.7.1 (2026-06-16) — personal fork
- Improved: `--check-pkgbuild` now detects four additional obfuscation patterns beyond the original quote-stripping: base64-decode-to-shell (`base64 -d | bash`), `eval`+subshell (`eval $(...)`, eval+backtick), `printf` hex/octal escape sequences, and variable-split command reassembly (`a=bu; b=n; $a$b add`)
- `PKGBUILD_CACHE_DIRS` env var (colon-separated) overrides AUR helper cache locations for testing

## 2.7.0 (2026-06-16) — personal fork
- New: `--check-autostart` (included in `--full`) — detects low-privilege persistence requiring no root: suspicious XDG autostart `.desktop` files (`Exec=` outside `/usr/` or `/opt/`), user systemd services whose `ExecStart=` binary is untracked by pacman, and shell RC files (`.bashrc`, `.zshrc`, `.bash_profile`, `.profile`) containing download-and-execute or `eval`+subshell patterns
- Home dir injectable via `AUTOSTART_HOME` for testing

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
