import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from aur_check_py.__main__ import create_parser, main


class TestMainCreateParser(unittest.TestCase):
    def test_help_exits_zero(self):
        parser = create_parser()
        with self.assertRaises(SystemExit) as cm:
            parser.parse_args(['--help'])
        self.assertEqual(cm.exception.code, 0)

    def test_defaults(self):
        parser = create_parser()
        args = parser.parse_args([])
        self.assertFalse(args.check_systemd)
        self.assertFalse(args.check_ebpf)
        self.assertFalse(args.check_npm_cache)
        self.assertFalse(args.check_bun_cache)
        self.assertFalse(args.full)
        self.assertFalse(args.refresh)
        self.assertFalse(args.verbose)
        self.assertFalse(args.debug)
        self.assertIsNone(args.log_file)
        self.assertIsNone(args.package_list)
        self.assertIsNone(args.malicious_npm_list)
        self.assertFalse(args.all_time)
        self.assertFalse(args.merge)
        self.assertEqual(args.lists, [])
        self.assertEqual(args.npm_lists, [])
        self.assertFalse(args.skip_hedgedoc)
        self.assertIsNone(args.output)

    def test_full_sets_flag(self):
        parser = create_parser()
        args = parser.parse_args(['--full'])
        self.assertTrue(args.full)

    def test_all_time(self):
        parser = create_parser()
        args = parser.parse_args(['--all-time'])
        self.assertTrue(args.all_time)

    def test_merge_mode(self):
        parser = create_parser()
        args = parser.parse_args(['--merge', '-l', 'http://example.com/list'])
        self.assertTrue(args.merge)
        self.assertEqual(args.lists, ['http://example.com/list'])

    def test_malicious_npm_repeatable(self):
        parser = create_parser()
        args = parser.parse_args([
            '--merge', '-m', 'list1.txt', '-m', 'list2.txt',
        ])
        self.assertEqual(args.npm_lists, ['list1.txt', 'list2.txt'])

    def test_skip_hedgedoc(self):
        parser = create_parser()
        args = parser.parse_args(['--merge', '--skip-hedgedoc'])
        self.assertTrue(args.skip_hedgedoc)

    def test_output(self):
        parser = create_parser()
        args = parser.parse_args(['--merge', '-o', '/tmp/merged.txt'])
        self.assertEqual(args.output, '/tmp/merged.txt')


class TestMainExitCodes(unittest.TestCase):
    @patch('aur_check_py.__main__.setup_logging')
    @patch('aur_check_py.__main__.read_file')
    @patch('aur_check_py.__main__.AurScanner')
    def test_clean_exit(self, mock_scanner_cls, mock_read_file, mock_log):
        mock_read_file.side_effect = [
            ['package-a'],
            ['atomic-lockfile'],
        ]
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        mock_scanner.run_all.return_value = MagicMock(
            infected_found=0,
            current_packages=(),
            log_hits=(),
            log_warnings=False,
            systemd_hits=(),
            ebpf_hits=(),
            npm_hits=(),
            bun_hits=(),
            exit_code=lambda: 0,
        )

        ec = main([])
        self.assertEqual(ec, 0)

    @patch('aur_check_py.__main__.setup_logging')
    @patch('aur_check_py.__main__.read_file')
    @patch('aur_check_py.__main__.AurScanner')
    def test_infected_exit(self, mock_scanner_cls, mock_read_file, mock_log):
        mock_read_file.side_effect = [
            ['package-a'],
            ['atomic-lockfile'],
        ]
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        mock_scanner.run_all.return_value = MagicMock(
            infected_found=1,
            current_packages=(),
            log_hits=(),
            log_warnings=False,
            systemd_hits=(),
            ebpf_hits=(),
            npm_hits=(),
            bun_hits=(),
            exit_code=lambda: 2,
        )

        ec = main([])
        self.assertEqual(ec, 2)

    @patch('aur_check_py.__main__.setup_logging')
    @patch('aur_check_py.__main__.read_file')
    @patch('aur_check_py.__main__.AurScanner')
    def test_all_time_flag_passed(self, mock_scanner_cls, mock_read_file, mock_log):
        mock_read_file.side_effect = [
            ['package-a'],
            ['atomic-lockfile'],
        ]
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        mock_scanner.run_all.return_value = MagicMock(
            infected_found=0,
            current_packages=(),
            log_hits=(),
            log_warnings=False,
            systemd_hits=(),
            ebpf_hits=(),
            npm_hits=(),
            bun_hits=(),
            exit_code=lambda: 0,
        )

        ec = main(['--all-time'])
        self.assertEqual(ec, 0)
        self.assertEqual(mock_scanner_cls.call_args[1]['all_time'], True)

    @patch('aur_check_py.__main__.setup_logging')
    @patch('aur_check_py.__main__.merge_lists')
    @patch('aur_check_py.__main__.AurScanner')
    def test_merge_mode(self, mock_scanner_cls, mock_merge, mock_log):
        mock_merge.return_value = ({'merged-pkg'}, {'merged-npm'})
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        mock_scanner.run_all.return_value = MagicMock(
            infected_found=0,
            current_packages=(),
            log_hits=(),
            log_warnings=False,
            systemd_hits=(),
            ebpf_hits=(),
            npm_hits=(),
            bun_hits=(),
            exit_code=lambda: 0,
        )

        ec = main(['--merge', '-l', 'http://example.com/list'])
        self.assertEqual(ec, 0)
        mock_merge.assert_called_once()
        self.assertEqual(mock_scanner_cls.call_args[1]['infected_packages'], {'merged-pkg'})
        self.assertEqual(mock_scanner_cls.call_args[1]['malicious_npm_packages'], {'merged-npm'})
