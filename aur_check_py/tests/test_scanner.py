import os
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from aur_check_py.scanner import (
    AurScanner,
    BunMatch,
    LogHit,
    NpmMatch,
    PackageMatch,
    ScanResult,
    expand_log_glob,
    parse_pacman_date,
    read_compressed_lines,
)


class TestParsePacmanDate(unittest.TestCase):
    def test_valid_date(self):
        d = parse_pacman_date('Sun 09 Jun 2026 03:21:05 PM CEST')
        self.assertEqual(d, date(2026, 6, 9))

    def test_valid_date_am(self):
        d = parse_pacman_date('Mon 10 Jun 2026 10:15:30 AM UTC')
        self.assertEqual(d, date(2026, 6, 10))

    def test_valid_date_night(self):
        d = parse_pacman_date('Tue 11 Jun 2026 11:59:59 PM EST')
        self.assertEqual(d, date(2026, 6, 11))

    def test_invalid_date_empty(self):
        self.assertIsNone(parse_pacman_date(''))

    def test_invalid_date_garbage(self):
        self.assertIsNone(parse_pacman_date('not a date'))

    def test_invalid_date_no_timezone(self):
        d = parse_pacman_date('Wed 12 Jun 2026 01:02:03 AM')
        self.assertEqual(d, date(2026, 6, 12))


class TestReadCompressedLines(unittest.TestCase):
    def setUp(self):
        self.temp_files = []

    def tearDown(self):
        for p in self.temp_files:
            if p.exists():
                p.unlink()

    def _write_temp(self, suffix: str, content: str, mode: str = 'wt') -> Path:
        fd, name = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        path = Path(name)
        self.temp_files.append(path)
        if suffix == '.gz':
            import gzip
            with gzip.open(path, mode) as f:
                f.write(content)
        elif suffix == '.xz':
            import lzma
            with lzma.open(path, mode) as f:
                f.write(content)
        elif suffix == '.bz2':
            import bz2
            with bz2.open(path, mode) as f:
                f.write(content)
        elif suffix == '':
            with open(path, 'w') as f:
                f.write(content)
        return path

    def test_plain_file(self):
        path = self._write_temp('', 'hello\nworld\n')
        result = list(read_compressed_lines(path))
        self.assertEqual(result, ['hello\n', 'world\n'])

    def test_gzip(self):
        path = self._write_temp('.gz', 'line1\nline2\n')
        result = list(read_compressed_lines(path))
        self.assertEqual(result, ['line1\n', 'line2\n'])

    def test_bzip2(self):
        path = self._write_temp('.bz2', 'bz_line1\nbz_line2\n')
        result = list(read_compressed_lines(path))
        self.assertEqual(result, ['bz_line1\n', 'bz_line2\n'])

    def test_lzma_xz(self):
        path = self._write_temp('.xz', 'xz_line1\nxz_line2\n')
        result = list(read_compressed_lines(path))
        self.assertEqual(result, ['xz_line1\n', 'xz_line2\n'])

    def test_empty_plain(self):
        path = self._write_temp('', '')
        result = list(read_compressed_lines(path))
        self.assertEqual(result, [])

    def test_nonexistent_file(self):
        result = list(read_compressed_lines(Path('/nonexistent/file')))
        self.assertEqual(result, [])


class TestExpandLogGlob(unittest.TestCase):
    @patch('glob.glob')
    def test_matches_exist(self, mock_glob):
        mock_glob.return_value = ['/var/log/pacman.log', '/var/log/pacman.log.1.gz']
        result = expand_log_glob('/var/log/pacman.log*')
        self.assertEqual(
            result,
            [Path('/var/log/pacman.log'), Path('/var/log/pacman.log.1.gz')],
        )

    @patch('glob.glob')
    def test_no_matches(self, mock_glob):
        mock_glob.return_value = []
        result = expand_log_glob('/var/log/pacman.log*')
        self.assertEqual(result, [])

    @patch('glob.glob')
    def test_sorting(self, mock_glob):
        mock_glob.return_value = ['b.log', 'a.log']
        result = expand_log_glob('*.log')
        self.assertEqual(result, [Path('a.log'), Path('b.log')])


class TestAurScannerInWindow(unittest.TestCase):
    def setUp(self):
        self.scanner = AurScanner(
            infected_packages={'pkg-a'},
            malicious_npm_packages=set(),
            start_date='2026-06-09',
            end_date='2026-06-12',
        )

    def test_within_window(self):
        self.assertTrue(self.scanner._in_window(date(2026, 6, 10)))

    def test_on_start(self):
        self.assertTrue(self.scanner._in_window(date(2026, 6, 9)))

    def test_on_end(self):
        self.assertTrue(self.scanner._in_window(date(2026, 6, 12)))

    def test_before_window(self):
        self.assertFalse(self.scanner._in_window(date(2026, 6, 8)))

    def test_after_window(self):
        self.assertFalse(self.scanner._in_window(date(2026, 6, 13)))


class TestAurScannerAllTime(unittest.TestCase):
    def setUp(self):
        self.scanner = AurScanner(
            infected_packages={'pkg-a'},
            malicious_npm_packages=set(),
            start_date='2026-06-09',
            end_date='2026-06-12',
            all_time=True,
        )

    def test_all_time_ignores_dates(self):
        self.assertTrue(self.scanner._in_window(date(2026, 1, 1)))
        self.assertTrue(self.scanner._in_window(date(2026, 12, 31)))
        self.assertTrue(self.scanner._in_window(date(2025, 6, 10)))


class TestAurScannerCheckCurrent(unittest.TestCase):
    @patch('subprocess.run')
    def test_no_matches(self, mock_run):
        mock_run.return_value = MagicMock(stdout='', returncode=0)
        scanner = AurScanner(
            infected_packages={'package-a', 'package-b'},
            malicious_npm_packages=set(),
        )
        result = scanner.check_current()
        self.assertEqual(result, [])

    @patch('subprocess.run')
    def test_with_matches(self, mock_run):
        mock_run.side_effect = [
            MagicMock(stdout='package-a\npackage-b\n', returncode=0),
            MagicMock(stdout='Install Date     : Sun 09 Jun 2026 03:21:05 PM CEST\n', returncode=0),
            MagicMock(stdout='Install Date     : Mon 10 Jun 2026 04:21:05 PM CEST\n', returncode=0),
        ]
        scanner = AurScanner(
            infected_packages={'package-a', 'package-b'},
            malicious_npm_packages=set(),
        )
        result = scanner.check_current()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].name, 'package-a')
        self.assertEqual(result[1].name, 'package-b')

    @patch('subprocess.run')
    def test_package_not_in_exact_list(self, mock_run):
        mock_run.return_value = MagicMock(stdout='package-extra\n', returncode=0)
        scanner = AurScanner(
            infected_packages={'package-a'},
            malicious_npm_packages=set(),
        )
        result = scanner.check_current()
        self.assertEqual(result, [])

    @patch('subprocess.run')
    def test_outside_window(self, mock_run):
        mock_run.side_effect = [
            MagicMock(stdout='package-a\n', returncode=0),
            MagicMock(stdout='Install Date     : Sun 01 Jan 2026 03:21:05 PM CEST\n', returncode=0),
        ]
        scanner = AurScanner(
            infected_packages={'package-a'},
            malicious_npm_packages=set(),
        )
        result = scanner.check_current()
        self.assertEqual(result, [])


class TestAurScannerCheckSystemd(unittest.TestCase):
    def test_no_service_dirs(self):
        scanner = AurScanner(
            infected_packages={'pkg-a'},
            malicious_npm_packages=set(),
        )
        real_is_dir = Path.is_dir

        def mock_is_dir(self):
            p = str(self)
            if p in ('/etc/systemd/system',):
                return False
            if p.endswith('/.config/systemd/user'):
                return False
            return real_is_dir(self)

        with patch.object(Path, 'is_dir', mock_is_dir):
            result = scanner.check_systemd()
        self.assertEqual(result, [])

    def test_with_suspicious_services(self):
        scanner = AurScanner(
            infected_packages={'pkg-a'},
            malicious_npm_packages=set(),
        )
        with tempfile.TemporaryDirectory() as td:
            user_dir = Path(td) / '.config' / 'systemd' / 'user'
            user_dir.mkdir(parents=True)
            svc = user_dir / 'malicious.service'
            svc.write_text('[Service]\nRestart=always\nRestartSec=30\n')
            (user_dir / 'benign.service').write_text('[Service]\nRestart=no\n')

            real_is_dir = Path.is_dir

            def mock_is_dir(self):
                if str(self) in (str(user_dir),):
                    return True
                if str(self) == '/etc/systemd/system':
                    return False
                return real_is_dir(self)

            with (
                patch.object(Path, 'home', return_value=Path(td)),
                patch.object(Path, 'is_dir', mock_is_dir),
            ):
                result = scanner.check_systemd()

        self.assertEqual(len(result), 1)
        self.assertIn('malicious.service', str(result[0]))


class TestAurScannerCheckEbpf(unittest.TestCase):
    def setUp(self):
        self.scanner = AurScanner(
            infected_packages={'pkg-a'},
            malicious_npm_packages=set(),
        )

    @patch('pathlib.Path.is_dir')
    @patch('pathlib.Path.exists')
    def test_no_ebpf_mount(self, mock_exists, mock_is_dir):
        mock_is_dir.return_value = False
        result = self.scanner.check_ebpf()
        self.assertEqual(result, [])

    @patch('pathlib.Path.is_dir')
    @patch('pathlib.Path.exists')
    def test_clean_no_hidden(self, mock_exists, mock_is_dir):
        mock_is_dir.return_value = True
        mock_exists.return_value = False
        result = self.scanner.check_ebpf()
        self.assertEqual(result, [])

    @patch('pathlib.Path.is_dir')
    @patch('pathlib.Path.exists')
    def test_hidden_pids_found(self, mock_exists, mock_is_dir):
        mock_is_dir.return_value = True
        mock_exists.side_effect = [True, False, False]
        result = self.scanner.check_ebpf()
        self.assertEqual(len(result), 1)
        self.assertIn('hidden_pids', str(result[0]))


class TestAurScannerCheckNpmCache(unittest.TestCase):
    @patch('subprocess.run')
    @patch('pathlib.Path.is_dir')
    def test_all_clean(self, mock_is_dir, mock_run):
        mock_run.return_value = MagicMock(stdout='', returncode=0)
        mock_is_dir.return_value = False
        scanner = AurScanner(
            infected_packages=set(),
            malicious_npm_packages={'atomic-lockfile'},
        )
        result = scanner.check_npm_cache()
        self.assertEqual(result, [])

    @patch('subprocess.run')
    @patch('pathlib.Path.is_dir')
    def test_npm_cache_ls_match(self, mock_is_dir, mock_run):
        mock_run.side_effect = [
            MagicMock(stdout='npm cache ls output with atomic-lockfile in it\n', returncode=0),
            MagicMock(stdout='/usr/lib/node_modules\n', returncode=0),
            MagicMock(stdout='/tmp/npm/cache\n', returncode=0),
        ]
        mock_is_dir.return_value = False
        scanner = AurScanner(
            infected_packages=set(),
            malicious_npm_packages={'atomic-lockfile'},
        )
        result = scanner.check_npm_cache()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].location, 'npm_cache_ls')


class TestAurScannerCheckBunCache(unittest.TestCase):
    @patch('subprocess.run')
    @patch('pathlib.Path.is_dir')
    @patch('pathlib.Path.home')
    def test_all_clean(self, mock_home, mock_is_dir, mock_run):
        mock_run.side_effect = [
            MagicMock(stdout='', returncode=0),  # bun pm cache ls
            FileNotFoundError(),                   # bun pm cache (fallback)
        ]
        mock_is_dir.return_value = False
        mock_home.return_value = Path('/fake/home')

        scanner = AurScanner(
            infected_packages=set(),
            malicious_npm_packages={'atomic-lockfile'},
        )
        result = scanner.check_bun_cache()
        self.assertEqual(result, [])

    @patch('subprocess.run')
    @patch('pathlib.Path.is_dir')
    def test_bun_cache_ls_match(self, mock_is_dir, mock_run):
        mock_run.side_effect = [
            MagicMock(stdout='bun cache with atomic-lockfile found\n', returncode=0),
            MagicMock(stdout='/home/user/.bun/install/cache\n', returncode=0),
        ]
        mock_is_dir.return_value = False
        scanner = AurScanner(
            infected_packages=set(),
            malicious_npm_packages={'atomic-lockfile'},
        )
        result = scanner.check_bun_cache()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].location, 'bun_cache_ls')


class TestScanResultExitCode(unittest.TestCase):
    def test_clean(self):
        r = ScanResult()
        self.assertEqual(r.exit_code(), 0)

    def test_infected_found(self):
        r = ScanResult(infected_found=1)
        self.assertEqual(r.exit_code(), 2)

    def test_current_packages(self):
        r = ScanResult(current_packages=(PackageMatch('pkg-a', None),))
        self.assertEqual(r.exit_code(), 2)

    def test_log_hits(self):
        r = ScanResult(log_hits=(LogHit('pkg-a', 'installed', date(2026, 6, 9)),))
        self.assertEqual(r.exit_code(), 2)

    def test_systemd_hits(self):
        r = ScanResult(systemd_hits=(Path('/etc/systemd/system/bad.service'),))
        self.assertEqual(r.exit_code(), 2)

    def test_ebpf_hits(self):
        r = ScanResult(ebpf_hits=(Path('/sys/fs/bpf/hidden_pids'),))
        self.assertEqual(r.exit_code(), 2)

    def test_npm_hits(self):
        r = ScanResult(npm_hits=(NpmMatch('atomic-lockfile', 'npm_cache_ls', '/path'),))
        self.assertEqual(r.exit_code(), 2)

    def test_bun_hits(self):
        r = ScanResult(bun_hits=(BunMatch('atomic-lockfile', 'bun_cache_ls', '/path'),))
        self.assertEqual(r.exit_code(), 2)

    def test_log_warnings(self):
        r = ScanResult(log_warnings=True)
        self.assertEqual(r.exit_code(), 1)
