from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

HEDGEDOC_URL = 'https://md.archlinux.org/s/SxbqukK6IA/download'

_PKG_RE = re.compile(r'^[a-z0-9][a-z0-9_.+\-]*[a-z0-9+]$', re.MULTILINE)


def fetch_url(url: str, timeout: int = 15) -> str | None:
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='replace')
    except Exception:
        return None


def read_file(path: str) -> list[str] | None:
    try:
        lines: list[str] = []
        with open(path, 'r') as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    lines.append(stripped)
        return lines
    except Exception:
        return None


def read_list_source(src: str) -> list[str]:
    if src.startswith(('http://', 'https://')):
        text = fetch_url(src)
        if text is None:
            return []
        return extract_package_names(text)
    lines = read_file(src)
    if lines is None:
        return []
    return lines


def extract_package_names(text: str) -> list[str]:
    return _PKG_RE.findall(text)


def merge_lists(
    hedgedoc_url: str = HEDGEDOC_URL,
    extra_aur: tuple[str, ...] = (),
    extra_npm: tuple[str, ...] = (),
    skip_hedgedoc: bool = False,
) -> tuple[set[str], set[str]]:
    aur_all: set[str] = set()
    npm_all: set[str] = set()
    if not skip_hedgedoc:
        text = fetch_url(hedgedoc_url)
        if text:
            aur_all.update(extract_package_names(text))
    for src in extra_aur:
        aur_all.update(read_list_source(src))
    for src in extra_npm:
        npm_all.update(read_list_source(src))
    if not extra_npm:
        default_npm = Path(__file__).resolve().parent.parent / 'malicious_npm_packages.txt'
        if default_npm.is_file():
            lines = read_file(str(default_npm))
            if lines:
                npm_all.update(lines)
    return aur_all, npm_all
