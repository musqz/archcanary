from __future__ import annotations

import locale
import logging
import os
import re
import subprocess
from collections.abc import Generator
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PackageMatch:
    name: str
    install_date: date | None


@dataclass(frozen=True)
class LogHit:
    package: str
    action: str
    date: date


@dataclass(frozen=True)
class NpmMatch:
    package: str
    location: str
    path: str


@dataclass(frozen=True)
class BunMatch:
    package: str
    location: str
    path: str


@dataclass(frozen=True)
class ScanResult:
    infected_found: int = 0
    current_packages: tuple[PackageMatch, ...] = ()
    log_hits: tuple[LogHit, ...] = ()
    log_warnings: bool = False
    systemd_hits: tuple[Path, ...] = ()
    ebpf_hits: tuple[Path, ...] = ()
    npm_hits: tuple[NpmMatch, ...] = ()
    bun_hits: tuple[BunMatch, ...] = ()

    def exit_code(self) -> int:
        if self.infected_found > 0:
            return 2
        if (
            self.current_packages
            or self.log_hits
            or self.systemd_hits
            or self.ebpf_hits
            or self.npm_hits
            or self.bun_hits
        ):
            return 2
        if self.log_warnings:
            return 1
        return 0


def _ensure_c_locale() -> None:
    try:
        locale.setlocale(locale.LC_TIME, 'C')
    except locale.Error:
        pass


def parse_pacman_date(raw: str) -> date | None:
    _ensure_c_locale()
    if not raw:
        return None
    raw = raw.strip()
    # Remove trailing timezone abbreviation (e.g. CEST, UTC, EST)
    # but keep AM/PM which is part of the time format
    if ' ' in raw:
        before, last = raw.rsplit(' ', 1)
        if last.isalpha() and last.upper() not in ('AM', 'PM'):
            raw = before
    try:
        dt = datetime.strptime(raw, '%a %d %b %Y %I:%M:%S %p')
        return dt.date()
    except (ValueError, OSError):
        return None


def read_compressed_lines(path: Path) -> Generator[str, None, None]:
    suffix = path.suffix.lower()
    try:
        if suffix == '.gz':
            import gzip
            with gzip.open(path, 'rt', encoding='utf-8', errors='replace') as f:
                yield from f
            return
        if suffix == '.xz':
            import lzma
            with lzma.open(path, 'rt', encoding='utf-8', errors='replace') as f:
                yield from f
            return
        if suffix == '.bz2':
            import bz2
            with bz2.open(path, 'rt', encoding='utf-8', errors='replace') as f:
                yield from f
            return
        if suffix == '.zst':
            try:
                from compression import zstd
                with zstd.open(path, 'rt', encoding='utf-8', errors='replace') as f:
                    yield from f
                return
            except ImportError:
                pass
            r = subprocess.run(
                ['zstdcat', '--', str(path)],
                capture_output=True, text=True, timeout=30,
            )
            for line in r.stdout.splitlines(keepends=True):
                yield line
            return
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            yield from f
    except Exception:
        return


def expand_log_glob(glob_pattern: str) -> list[Path]:
    import glob
    return sorted(Path(p) for p in glob.glob(glob_pattern))


class AurScanner:
    def __init__(
        self,
        infected_packages: set[str],
        malicious_npm_packages: set[str],
        start_date: str = '2026-06-09',
        end_date: str = '2026-06-12',
        all_time: bool = False,
    ) -> None:
        self.infected_packages = infected_packages
        self.malicious_npm_packages = malicious_npm_packages
        self._start = date.fromisoformat(start_date)
        self._end = date.fromisoformat(end_date)
        self.all_time = all_time

    def _in_window(self, d: date) -> bool:
        if self.all_time:
            return True
        return self._start <= d <= self._end

    def check_current(self) -> list[PackageMatch]:
        try:
            r = subprocess.run(
                ['pacman', '-Qmq', *sorted(self.infected_packages)],
                capture_output=True, text=True, timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []
        if r.returncode not in (0, 1):
            return []
        matches: list[PackageMatch] = []
        for pkg in r.stdout.splitlines():
            pkg = pkg.strip()
            if not pkg or pkg not in self.infected_packages:
                continue
            try:
                qi = subprocess.run(
                    ['pacman', '-Qi', '--', pkg],
                    capture_output=True, text=True, timeout=30,
                    env=os.environ | {'LC_ALL': 'C'},
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
            install_date: date | None = None
            for line in qi.stdout.splitlines():
                if line.startswith('Install Date'):
                    raw = line.split(':', 1)[1].strip()
                    install_date = parse_pacman_date(raw)
                    break
            if install_date is not None and self._in_window(install_date):
                matches.append(PackageMatch(pkg, install_date))
        return matches

    def check_logs(self, log_glob: str = '/var/log/pacman.log*') -> list[LogHit]:
        files = expand_log_glob(log_glob)
        if not files:
            return []
        hits: list[LogHit] = []
        date_re = re.compile(r'^\[(\d{4}-\d{2}-\d{2})')
        alpm_re = re.compile(r'\[ALPM\] (\w+) (\S+)')
        for file in files:
            try:
                for line in read_compressed_lines(file):
                    dm = date_re.match(line)
                    if not dm:
                        continue
                    date_str = dm.group(1)
                    if not self._in_window(date.fromisoformat(date_str)):
                        continue
                    am = alpm_re.search(line)
                    if not am:
                        continue
                    action = am.group(1)
                    pkg = am.group(2)
                    if pkg not in self.infected_packages:
                        continue
                    if action not in ('installed', 'upgraded', 'reinstalled'):
                        continue
                    hits.append(LogHit(
                        package=pkg,
                        action=action,
                        date=date.fromisoformat(date_str),
                    ))
            except (OSError, PermissionError):
                continue
        return hits

    def check_systemd(self) -> list[Path]:
        found: list[Path] = []
        dirs = [
            Path('/etc/systemd/system'),
            Path.home() / '.config' / 'systemd' / 'user',
        ]
        for d in dirs:
            if not d.is_dir():
                continue
            try:
                for svc in d.rglob('*.service'):
                    if not svc.is_file():
                        continue
                    try:
                        content = svc.read_text(encoding='utf-8', errors='replace')
                    except OSError:
                        continue
                    if 'Restart=always' in content and 'RestartSec=30' in content:
                        found.append(svc)
            except PermissionError:
                continue
        return found

    def check_ebpf(self) -> list[Path]:
        bpf_dir = Path('/sys/fs/bpf')
        if not bpf_dir.is_dir():
            return []
        found: list[Path] = []
        for name in ('hidden_pids', 'hidden_names', 'hidden_inodes'):
            p = bpf_dir / name
            if p.exists():
                found.append(p)
        return found

    def check_npm_cache(self) -> list[NpmMatch]:
        matches: list[NpmMatch] = []
        for pkg in sorted(self.malicious_npm_packages):
            try:
                r = subprocess.run(
                    ['npm', 'cache', 'ls'],
                    capture_output=True, text=True, timeout=30,
                )
                for line in r.stdout.splitlines():
                    if pkg in line:
                        matches.append(NpmMatch(
                            package=pkg, location='npm_cache_ls', path=line.strip(),
                        ))
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
            try:
                r = subprocess.run(
                    ['npm', 'root', '-g'],
                    capture_output=True, text=True, timeout=15,
                )
                global_mod = Path(r.stdout.strip()) / pkg
                if global_mod.is_dir():
                    matches.append(NpmMatch(
                        package=pkg, location='global_node_modules', path=str(global_mod),
                    ))
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
            try:
                r = subprocess.run(
                    ['npm', 'config', 'get', 'cache'],
                    capture_output=True, text=True, timeout=15,
                )
                cache_dir = Path(r.stdout.strip())
                if cache_dir.is_dir():
                    count = 0
                    for d in cache_dir.rglob(f'*{pkg}*'):
                        if d.is_dir():
                            matches.append(NpmMatch(
                                package=pkg, location='npm_cache_dir', path=str(d),
                            ))
                            count += 1
                            if count >= 5:
                                break
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
        return matches

    def check_bun_cache(self) -> list[BunMatch]:
        matches: list[BunMatch] = []
        for pkg in sorted(self.malicious_npm_packages):
            try:
                r = subprocess.run(
                    ['bun', 'pm', 'cache', 'ls'],
                    capture_output=True, text=True, timeout=30,
                )
                for line in r.stdout.splitlines():
                    if pkg in line:
                        matches.append(BunMatch(
                            package=pkg, location='bun_cache_ls', path=line.strip(),
                        ))
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
        try:
            r = subprocess.run(
                ['bun', 'pm', 'cache'],
                capture_output=True, text=True, timeout=15,
            )
            cache_dir = Path(r.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            cache_dir = Path.home() / '.bun' / 'install' / 'cache'
        if cache_dir.is_dir():
            for pkg in sorted(self.malicious_npm_packages):
                try:
                    count = 0
                    for d in cache_dir.rglob(f'*{pkg}*'):
                        if d.is_dir():
                            matches.append(BunMatch(
                                package=pkg, location='bun_cache_dir', path=str(d),
                            ))
                            count += 1
                            if count >= 5:
                                break
                except PermissionError:
                    continue
        return matches

    def run_all(
        self,
        *,
        systemd: bool = False,
        ebpf: bool = False,
        npm_cache: bool = False,
        bun_cache: bool = False,
    ) -> ScanResult:
        current = self.check_current()
        log_hits = self.check_logs()
        shits: list[Path] = []
        if systemd:
            shits = self.check_systemd()
        ehits: list[Path] = []
        if ebpf:
            ehits = self.check_ebpf()
        nhits: list[NpmMatch] = []
        if npm_cache:
            nhits = self.check_npm_cache()
        bhits: list[BunMatch] = []
        if bun_cache:
            bhits = self.check_bun_cache()
        infected_total = (
            len(current)
            + len(log_hits)
            + len(shits)
            + len(ehits)
            + len(nhits)
            + len(bhits)
        )
        return ScanResult(
            infected_found=infected_total,
            current_packages=tuple(current),
            log_hits=tuple(log_hits),
            systemd_hits=tuple(shits),
            ebpf_hits=tuple(ehits),
            npm_hits=tuple(nhits),
            bun_hits=tuple(bhits),
        )
