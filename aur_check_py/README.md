# aur_check_py — Python 3.14+ AUR Malware Checker

Python-Äquivalent zu `aur_check-v2.sh` + `custom_list_merge_aur_scan.sh`.

## Quick Start (Äquivalente)

| Bash | Python |
|---|---|
| `./aur_check-v2.sh` | `python -m aur_check_py` |
| `./aur_check-v2.sh --full` | `python -m aur_check_py --full` |
| `./aur_check-v2.sh --all-time` | `python -m aur_check_py --all-time` |
| `./aur_check-v2.sh --check-bun-cache` | `python -m aur_check_py --check-bun-cache` |
| `./aur_check-v2.sh --refresh --full` | `python -m aur_check_py --refresh --full` |
| `./aur_check-v2.sh --package-list=FILE --malicious-npm-list=FILE` | `python -m aur_check_py --package-list=FILE --malicious-npm-list=FILE` |
| `./custom_list_merge_aur_scan.sh -l FILE` | `python -m aur_check_py --merge -l FILE` |
| `./custom_list_merge_aur_scan.sh -l URL1 -l FILE2 --skip-hedgedoc` | `python -m aur_check_py --merge -l URL1 -l FILE2 --skip-hedgedoc` |
| `./custom_list_merge_aur_scan.sh -l FILE -- --all-time` | `python -m aur_check_py --merge -l FILE --all-time` |
| `--verbose` / `--debug` | identisch |
| `--help` / `-h` | identisch |
| `--log-file=PATH` | identisch |
| `./aur_check-v2.sh --check-systemd` | `python -m aur_check_py --check-systemd` |
| `./aur_check-v2.sh --check-ebpf` | `python -m aur_check_py --check-ebpf` |
| `./aur_check-v2.sh --check-npm-cache` | `python -m aur_check_py --check-npm-cache` |

## Exit Codes (identisch)
- 0 = clean
- 1 = warnings (log issues)
- 2 = infected

## Tests
```bash
python -m unittest discover -s aur_check_py/tests/ -v
```
75 Tests, laufen ohne Arch-System/pacman/npm/bun.

## Unterschiede zu Bash-Version
- `--merge` ist ein Flag, kein separates Script (in-process, kein exec)
- Keine temporären Dateien für Merge-Zwischenergebnisse (in-memory)
- Logging: `--verbose` = Console INFO, Logfile immer DEBUG
