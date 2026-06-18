import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from aur_check_py.merger import (
    extract_package_names,
    fetch_url,
    merge_lists,
    read_file,
    read_list_source,
)


class TestExtractPackageNames(unittest.TestCase):
    def test_simple_list(self):
        text = 'package-a\npackage-b\n123pan-bin\n'
        result = extract_package_names(text)
        self.assertEqual(result, ['package-a', 'package-b', '123pan-bin'])

    def test_with_comments_and_blanks(self):
        text = '# comment\npackage-a\n\npackage-b\n'
        result = extract_package_names(text)
        self.assertEqual(result, ['package-a', 'package-b'])

    def test_html_stripped(self):
        text = '<html><body><p>package-a</p></body></html>'
        result = extract_package_names(text)
        self.assertEqual(result, [])

    def test_invalid_names_ignored(self):
        text = 'PACKAGE-UPPER\n-invalid\nvalid-pkg\n'
        result = extract_package_names(text)
        self.assertEqual(result, ['valid-pkg'])

    def test_dedup(self):
        text = 'pkg-a\npkg-a\npkg-b\n'
        result = extract_package_names(text)
        self.assertEqual(result, ['pkg-a', 'pkg-a', 'pkg-b'])

    def test_empty(self):
        self.assertEqual(extract_package_names(''), [])

    def test_complex_pkgname(self):
        text = 'libc++-dev\npython3.14_rc1\npkg+extra\n'
        result = extract_package_names(text)
        self.assertEqual(result, ['libc++-dev', 'python3.14_rc1', 'pkg+extra'])


class TestFetchUrl(unittest.TestCase):
    @patch('urllib.request.urlopen')
    def test_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'pkg-a\npkg-b\n'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp
        result = fetch_url('http://example.com/list')
        self.assertEqual(result, 'pkg-a\npkg-b\n')

    @patch('urllib.request.urlopen')
    def test_failure(self, mock_urlopen):
        mock_urlopen.side_effect = Exception('timeout')
        result = fetch_url('http://example.com/list', timeout=1)
        self.assertIsNone(result)


class TestReadFile(unittest.TestCase):
    def test_read_success(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('# comment\npkg-a\npkg-b\n')
            f.flush()
            fname = f.name
        result = read_file(fname)
        self.assertEqual(result, ['pkg-a', 'pkg-b'])
        os.unlink(fname)

    def test_read_nonexistent(self):
        result = read_file('/nonexistent/path')
        self.assertIsNone(result)

    def test_read_empty_file(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            fname = f.name
        result = read_file(fname)
        self.assertEqual(result, [])
        os.unlink(fname)


class TestReadListSource(unittest.TestCase):
    @patch('aur_check_py.merger.fetch_url')
    def test_url(self, mock_fetch):
        mock_fetch.return_value = 'pkg-a\npkg-b\n'
        result = read_list_source('http://example.com/list')
        self.assertEqual(result, ['pkg-a', 'pkg-b'])

    def test_local_file(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('pkg-c\npkg-d\n')
            f.flush()
            fname = f.name
        result = read_list_source(fname)
        self.assertEqual(result, ['pkg-c', 'pkg-d'])
        os.unlink(fname)

    def test_nonexistent_file(self):
        result = read_list_source('/nonexistent/list.txt')
        self.assertEqual(result, [])


class TestMergeLists(unittest.TestCase):
    @patch('aur_check_py.merger.fetch_url')
    @patch.object(Path, 'is_file', return_value=False)
    def test_hedgedoc_only(self, mock_is_file, mock_fetch):
        mock_fetch.return_value = 'pkg-a\npkg-b\n'
        aur_set, npm_set = merge_lists(skip_hedgedoc=False)
        self.assertEqual(aur_set, {'pkg-a', 'pkg-b'})
        self.assertEqual(npm_set, set())

    @patch('aur_check_py.merger.fetch_url')
    @patch.object(Path, 'is_file', return_value=False)
    def test_skip_hedgedoc(self, mock_is_file, mock_fetch):
        aur_set, npm_set = merge_lists(skip_hedgedoc=True)
        self.assertEqual(aur_set, set())

    @patch('aur_check_py.merger.fetch_url')
    @patch.object(Path, 'is_file', return_value=False)
    def test_extra_aur_lists(self, mock_is_file, mock_fetch):
        def fake_fetch(url, timeout=15):
            if 'hedgedoc' in url:
                return 'pkg-a\npkg-b\n'
            return None
        mock_fetch.side_effect = fake_fetch
        aur_set, npm_set = merge_lists(
            hedgedoc_url='http://hedgedoc/list',
            skip_hedgedoc=False,
        )
        self.assertEqual(aur_set, {'pkg-a', 'pkg-b'})

    @patch('aur_check_py.merger.fetch_url')
    @patch.object(Path, 'is_file', return_value=False)
    def test_dedup(self, mock_is_file, mock_fetch):
        mock_fetch.return_value = 'pkg-a\npkg-a\npkg-b\n'
        aur_set, npm_set = merge_lists(skip_hedgedoc=False)
        self.assertEqual(aur_set, {'pkg-a', 'pkg-b'})

    @patch('aur_check_py.merger.fetch_url')
    def test_extra_npm_and_aur(self, mock_fetch):
        mock_fetch.return_value = 'pkg-a\n'
        mock_fetch.side_effect = None

        with (
            tempfile.NamedTemporaryFile(mode='w', delete=False) as fa,
            tempfile.NamedTemporaryFile(mode='w', delete=False) as fn,
        ):
            fa.write('pkg-b\npkg-c\n')
            fa.flush()
            fn.write('npm-pkg1\nnpm-pkg2\n')
            fn.flush()

        try:
            aur_set, npm_set = merge_lists(
                extra_aur=(fa.name,),
                extra_npm=(fn.name,),
                skip_hedgedoc=True,
            )
            self.assertEqual(aur_set, {'pkg-b', 'pkg-c'})
            self.assertEqual(npm_set, {'npm-pkg1', 'npm-pkg2'})
        finally:
            os.unlink(fa.name)
            os.unlink(fn.name)
