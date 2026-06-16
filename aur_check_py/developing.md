# Developing — aur_check_py

## Tech Stack
- Python ≥3.14, stdlib only
- `argparse` CLI, `logging` dual output, `pathlib.Path`, `urllib.request`
- `gzip`/`lzma`/`bz2`/`compression.zstd` für komprimierte Logs
- `unittest` + `unittest.mock` für Tests
- `ruff` lint, `mypy --strict` types

## Typing & Data
- `str | None`, nicht `Optional[str]`
- `@dataclass(frozen=True)` für `PackageMatch`, `LogHit`, `NpmMatch`, `BunMatch`, `ScanResult`
- `Iterator[str]` oder `Generator[str, None, None]` für Zeilen-Streams

## Subprocess Policy
- Nur `pacman`, `npm`, `bun` als subprocess (kein stdlib-Binding)
- Immer `timeout=30`, `check=False`, `capture_output=True`, `text=True`
- Alles andere stdlib

## Defensive
- `try/except` eng um I/O (nie `except BaseException`)
- `.read_text(encoding='utf-8', errors='replace')`
- Jeder Generator liefert bei Fehler leere Liste, nicht raise
- Dispatch-Table für Komprimierung: `.suffix → gzip/lzma/bz2/zstd/open(path, 'rt')`

## Tests (Red/Green/Refactor)
- `tests/test_<module>.py`, `from unittest import TestCase`
- Jede Check-Funktion isoliert mocken: `@patch('aur_check_py.scanner.subprocess.run')`
- Assert Exit-Codes, Output-Strings, Date-Window-Edge-Cases
- Laufen ohne Arch-System, `pacman`, `npm`, `bun`

## CLI
- `main(argv: list[str] | None = None) -> int` für testbare Entry Points
- Exit: `sys.exit(0/1/2)`
