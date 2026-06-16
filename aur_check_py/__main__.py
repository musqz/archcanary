#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from datetime import date
from pathlib import Path

from aur_check_py.merger import (
    HEDGEDOC_URL,
    extract_package_names,
    fetch_url,
    merge_lists,
    read_file,
)
from aur_check_py.scanner import (
    AurScanner,
    BunMatch,
    LogHit,
    NpmMatch,
    PackageMatch,
)

SCRIPT_VERSION = '3.0'

logger = logging.getLogger('aur_check')


def setup_logging(log_file: str, debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    fh = logging.FileHandler(log_file)
    fh.setLevel(level)
    fh.setFormatter(logging.Formatter('%(message)s'))
    root.addHandler(fh)

    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.WARNING)  # stderr gets only warnings+errors
    ch.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    root.addHandler(ch)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='AUR Malware Check - scans for indicators of compromise',
    )
    parser.add_argument('--check-systemd', action='store_true',
        help='Scan for unknown systemd services (Restart=always)')
    parser.add_argument('--check-ebpf', action='store_true',
        help='Check for eBPF rootkit traces (/sys/fs/bpf/hidden_*)')
    parser.add_argument('--check-npm-cache', action='store_true',
        help='Check npm cache for packages in malicious_npm_packages.txt')
    parser.add_argument('--check-bun-cache', action='store_true',
        help='Check bun cache for packages in malicious_npm_packages.txt')
    parser.add_argument('--full', action='store_true', help='Enable all checks')
    parser.add_argument('--refresh', action='store_true',
        help='Download the latest package list before scanning')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--debug', action='store_true',
        help='Verbose output with debug logging')
    parser.add_argument('--log-file', type=str, default=None,
        help='Write full detail log to PATH (auto: aur-check-<date>.log)')
    parser.add_argument('--package-list', type=str, default=None,
        help='Custom infected AUR package list (default: ./package_list.txt)')
    parser.add_argument('--malicious-npm-list', type=str, default=None,
        help='Custom malicious npm package name list (default: ./malicious_npm_packages.txt)')
    parser.add_argument('--all-time', action='store_true',
        help='Disable recency window -- flag any installed infected package regardless of install date')

    # Merge mode options
    parser.add_argument('--merge', action='store_true',
        help='Enable merge mode (use merger.py logic)')
    parser.add_argument('-l', '--list', action='append', default=[], dest='lists',
        help='Additional AUR package list (repeatable, URL or FILE)')
    parser.add_argument('-m', '--malicious-npm', action='append', default=[], dest='npm_lists',
        help='Additional malicious npm list (repeatable, URL or FILE)')
    parser.add_argument('--skip-hedgedoc', action='store_true',
        help='Skip the official HedgeDoc list')
    parser.add_argument('-o', '--output', type=str, default=None,
        help='Save merged AUR list to FILE')
    return parser


def print_banner(infected_count: int, start_date: str, end_date: str, all_time: bool) -> None:
    print('============================================================')
    print(f' AUR Malware Check v{SCRIPT_VERSION}')
    print(' Campaign: malicious npm packages (malicious_npm_packages.txt) infostealer + eBPF rootkit')
    if all_time:
        print(' Date window: all-time (no recency filter)')
    else:
        print(f' Date window: {start_date} to {end_date}')
    print(f' Packages checked: {infected_count}')
    print('============================================================')
    print()


def print_section(num: int, title: str) -> None:
    print(f'--- [{num}] {title} ---')


def format_date(d: date) -> str:
    return d.strftime('%a %d %b %Y %I:%M:%S %p')


def print_current_packages(matches: list[PackageMatch], all_time: bool) -> None:
    if not matches:
        if all_time:
            print('  Clean: no infected packages currently installed.')
        else:
            print('  Clean: no infected packages installed within campaign window.')
    else:
        print(f'  WARNING: {len(matches)} possibly infected package(s):')
        for m in matches:
            ds = format_date(m.install_date) if m.install_date else 'unknown'
            print(f'  - {m.name} (installed: {ds})')


def print_log_hits(hits: list[LogHit], pacman_log_exists: bool) -> None:
    if not pacman_log_exists:
        print('  Skipped: /var/log/pacman.log not found.')
        return
    for h in hits:
        print(f'LOG_HIT: {h.package} ({h.action} on {h.date.isoformat()})')
    if hits:
        print('  WARNING: historical log matches:')
        for h in hits:
            print(f'  - {h.package} ({h.action} on {h.date.isoformat()})')
    else:
        print('  Clean: no historical log matches found.')


def print_systemd_hits(hits: list[Path]) -> None:
    if not hits:
        print('  Clean: no suspicious systemd services found.')
    else:
        print(f'  WARNING: {len(hits)} service(s) with Restart=always + RestartSec=30:')
        for p in hits:
            print(f'  - {p}')


def print_ebpf_hits(hits: list[Path], bpf_accessible: bool) -> None:
    if not bpf_accessible:
        print('  /sys/fs/bpf not accessible \u2014 BPF filesystem not mounted or insufficient privileges.')
        print('  \u2192 Requires root to scan for hidden BPF maps (e.g. hidden_pids, hidden_names).')
        print('  \u2192 Try: sudo ./aur_check.sh --check-ebpf')
        print('  \u2192 Skip this check if eBPF rootkit detection is not needed for your threat model.')
        return
    if not hits:
        print('  Clean: no eBPF rootkit traces detected.')
    else:
        print('  WARNING: eBPF rootkit traces found:')
        for p in hits:
            print(f'  - {p}')


def print_npm_hits(hits: list[NpmMatch]) -> None:
    if not hits:
        print('  Clean: no malicious packages in npm cache.')
        return
    for h in hits:
        print(f'  ALERT: {h.package} found in {h.location}:')
        print(f'    {h.path}')


def print_bun_hits(hits: list[BunMatch]) -> None:
    if not hits:
        print('  Clean: no malicious packages in bun cache.')
        return
    for h in hits:
        print(f'  ALERT: {h.package} found in {h.location}:')
        print(f'    {h.path}')


def print_result(exit_code: int) -> None:
    print('============================================================')
    if exit_code == 0:
        print(' RESULT: CLEAN - No indicators found.')
    elif exit_code == 1:
        print(' RESULT: WARNINGS - Review output above.')
    else:
        print(' RESULT: INFECTED - Indicators found! Follow incident response.')
    print('============================================================')


def main(argv: list[str] | None = None) -> int:
    args = create_parser().parse_args(argv)

    log_file = args.log_file or f'aur-check-{date.today().strftime("%Y%m%d-%H%M%S")}.log'
    try:
        Path(log_file).touch()
    except OSError:
        print(f'ERROR: Cannot write log file: {log_file}', file=sys.stderr)
        return 1

    setup_logging(log_file, debug=args.debug)

    infected_packages: set[str]
    malicious_npm_packages: set[str]

    if args.merge:
        extra_aur = tuple(args.lists)
        extra_npm = tuple(args.npm_lists)
        aur_set, npm_set = merge_lists(
            extra_aur=extra_aur,
            extra_npm=extra_npm,
            skip_hedgedoc=args.skip_hedgedoc,
        )

        if not aur_set:
            logger.error('No AUR package sources available.')
            return 1

        infected_packages = aur_set
        malicious_npm_packages = npm_set

        if args.output:
            try:
                with open(args.output, 'w') as f:
                    for p in sorted(aur_set):
                        f.write(f'{p}\n')
                logger.info('Merged AUR list saved to: %s', args.output)
            except OSError as e:
                logger.error('Cannot write output: %s', e)
                return 1

        if extra_aur or extra_npm:
            print(
                '============================================================',
                file=sys.stderr,
            )
            print(
                ' WARNING: Custom package list(s) loaded via -l or -m.',
                file=sys.stderr,
            )
            print(
                ' Detection is name-based only \u2014 matches mean the package name',
                file=sys.stderr,
            )
            print(
                ' appears in the list, NOT that campaign IOCs were found.',
                file=sys.stderr,
            )
            print(
                ' Optional checks (systemd, eBPF, npm/bun cache) target the',
                file=sys.stderr,
            )
            print(
                ' June 2026 campaign and may not correspond to the actual',
                file=sys.stderr,
            )
            print(
                ' threat vector of custom-list packages. Verify results manually.',
                file=sys.stderr,
            )
            print(
                '============================================================',
                file=sys.stderr,
            )
            print(file=sys.stderr)
    else:
        pkg_list_path = Path(args.package_list) if args.package_list else Path('package_list.txt')
        npm_list_path = Path(args.malicious_npm_list) if args.malicious_npm_list else Path('malicious_npm_packages.txt')

        if args.refresh:
            if args.package_list:
                logger.warning('--package-list overrides --refresh; using local file.')
            else:
                logger.info('Fetching infected package list...')
                text = fetch_url(HEDGEDOC_URL)
                if text is None:
                    logger.error('Failed to fetch %s', HEDGEDOC_URL)
                    return 1
                pkgs = extract_package_names(text)
                if not pkgs:
                    logger.error('Parsed 0 packages, something went wrong with the fetch/parse.')
                    return 1
                try:
                    raw = '\n'.join(sorted(set(pkgs)))
                    r = subprocess.run(
                        ['sort', '-u', '-o', str(pkg_list_path)],
                        input=raw, text=True, timeout=15,
                    )
                    if r.returncode != 0:
                        logger.error('sort failed with exit code %d', r.returncode)
                        return 1
                    logger.info('Updated %s with %d packages', pkg_list_path, len(pkgs))
                except OSError as e:
                    logger.error('Cannot write package list: %s', e)
                    return 1

        if not pkg_list_path.is_file():
            logger.error('Package list not found: %s', pkg_list_path)
            return 1
        if not npm_list_path.is_file():
            logger.error('Malicious npm package list not found: %s', npm_list_path)
            return 1

        pkg_lines = read_file(str(pkg_list_path))
        infected_packages = set(pkg_lines) if pkg_lines else set()

        npm_lines = read_file(str(npm_list_path))
        malicious_npm_packages = set(npm_lines) if npm_lines else set()

    if not infected_packages:
        logger.error('No infected packages loaded.')
        return 1

    start_date = '2026-06-09'
    end_date = '2026-06-12'

    scanner = AurScanner(
        infected_packages=infected_packages,
        malicious_npm_packages=malicious_npm_packages,
        start_date=start_date,
        end_date=end_date,
        all_time=args.all_time,
    )

    check_systemd = args.check_systemd or args.full
    check_ebpf = args.check_ebpf or args.full
    check_npm_cache = args.check_npm_cache or args.full
    check_bun_cache = args.check_bun_cache or args.full

    result = scanner.run_all(
        systemd=check_systemd,
        ebpf=check_ebpf,
        npm_cache=check_npm_cache,
        bun_cache=check_bun_cache,
    )

    pacman_log_exists = Path('/var/log/pacman.log').is_file()
    bpf_accessible = Path('/sys/fs/bpf').is_dir()

    print_banner(len(infected_packages), start_date, end_date, args.all_time)

    print_section(1, 'Currently installed foreign packages')
    print_current_packages(list(result.current_packages), args.all_time)
    print()

    print_section(2, 'Historical pacman logs')
    log_hits = list(result.log_hits)
    print_log_hits(log_hits, pacman_log_exists)
    print()

    if check_systemd:
        print_section(3, 'Systemd persistence check')
        print_systemd_hits(list(result.systemd_hits))
        print()

    if check_ebpf:
        print_section(4, 'eBPF rootkit check')
        print_ebpf_hits(list(result.ebpf_hits), bpf_accessible)
        print()

    if check_npm_cache:
        print_section(5, 'npm cache check')
        print_npm_hits(list(result.npm_hits))
        print()

    if check_bun_cache:
        print_section(6, 'bun cache check')
        print_bun_hits(list(result.bun_hits))
        print()

    ec = result.exit_code()
    print_result(ec)
    return ec


if __name__ == '__main__':
    sys.exit(main())
