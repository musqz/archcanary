# archcanary_py — Python 3.14+ Archcanaryer

Python-Äquivalent zu `archcanary.sh` + `archcanary-merge-lists.sh`.

## Quick Start (Äquivalente)

| Bash | Python |
|---|---|
| `./archcanary.sh` | `python -m archcanary_py` |
| `./archcanary.sh --full` | `python -m archcanary_py --full` |
| `./archcanary.sh --all-time` | `python -m archcanary_py --all-time` |
| `./archcanary.sh --check-bun-cache` | `python -m archcanary_py --check-bun-cache` |
| `./archcanary.sh --refresh --full` | `python -m archcanary_py --refresh --full` |
| `./archcanary.sh --package-list=FILE --malicious-npm-list=FILE` | `python -m archcanary_py --package-list=FILE --malicious-npm-list=FILE` |
| `./archcanary-merge-lists.sh -l FILE` | `python -m archcanary_py --merge -l FILE` |
| `./archcanary-merge-lists.sh -l URL1 -l FILE2 --skip-hedgedoc` | `python -m archcanary_py --merge -l URL1 -l FILE2 --skip-hedgedoc` |
| `./archcanary-merge-lists.sh -l FILE -- --all-time` | `python -m archcanary_py --merge -l FILE --all-time` |
| `--verbose` / `--debug` | identisch |
| `--help` / `-h` | identisch |
| `--log-file=PATH` | identisch |
| `./archcanary.sh --check-systemd` | `python -m archcanary_py --check-systemd` |
| `./archcanary.sh --check-ebpf` | `python -m archcanary_py --check-ebpf` |
| `./archcanary.sh --check-npm-cache` | `python -m archcanary_py --check-npm-cache` |

## Exit Codes (identisch)
- 0 = clean
- 1 = warnings (log issues)
- 2 = infected

## Tests
```bash
python -m unittest discover -s archcanary_py/tests/ -v
```
75 Tests, laufen ohne Arch-System/pacman/npm/bun.

## Unterschiede zu Bash-Version
- `--merge` ist ein Flag, kein separates Script (in-process, kein exec)
- Keine temporären Dateien für Merge-Zwischenergebnisse (in-memory)
- Logging: `--verbose` = Console INFO, Logfile immer DEBUG
