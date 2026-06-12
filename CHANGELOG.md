# Changelog

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

## 1.1.0 (2026-06-12)
- Fix: `set -e` bug — non-verbose mode killed script (log_info always returns 0)
- Auto-logfile: full detail always written to `aur-check-<date>.log`
- Terminal output gated by `--verbose`; log always contains `[INFO]` detail
- `check_logs` output now visible on terminal via `tee` (was hidden in tempfile)
- Informative eBPF message on missing privileges
- `exit "$EXIT_CODE"` quoting, mktemp everywhere, trap for tempfile cleanup
- Pipe-to-subshell fixed: `while read` now uses process substitution

## 2.0.0 (2026-06-12)
- `aur_check-v2.sh`: optimized log scanner (bash regex + O(1) assoc. array)
- Same detection logic as v1, ~150x faster for large pacman.log files
- v1 retained for completeness as reference implementation
