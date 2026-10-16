#!/usr/bin/env python3
"""
test_sftp_client.py — regression and unit tests for sftp_client.py

Run with:
    python3 -m unittest test_sftp_client -v
"""

import contextlib
import datetime
import io
import os
import sys
import tempfile
import signal as signal_module
import threading
import types
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import paramiko
import paramiko.ssh_exception

import sftp_client
from sftp_client import (
    SFTPClient,
    _Completer,
    _completion_text_from_line_fragment,
    _escape_completion,
    _parse_destination,
    _redact_command_for_log,
    _split_command_line,
    _split_completion_line,
    _unescape_completion,
    transform_text,
)


# Tests model downloads through sftp.get(); the readv fallback for paramiko
# without a prefetch cap has its own tests. Pin the capability so the suite
# behaves the same whichever paramiko is installed.
_prefetch_patch = patch.object(sftp_client, '_GET_SUPPORTS_PREFETCH_LIMIT', True)


def setUpModule():
    _prefetch_patch.start()


def tearDownModule():
    _prefetch_patch.stop()


# ── shared helpers ─────────────────────────────────────────────────────────────

def _make_client():
    """SFTPClient with a mocked SFTP session and a suppressed logger."""
    with patch('sftp_client._setup_logger') as m:
        m.return_value = (MagicMock(), '/dev/null')
        client = SFTPClient()
    client.sftp       = MagicMock()
    # Most tests configure stat(); mirror that behavior for the entry-level
    # existence check unless a test explicitly models a dangling symlink.
    client.sftp.lstat.side_effect = lambda path: client.sftp.stat(path)
    client.ssh        = MagicMock()
    client.connected  = True
    client.remote_cwd = '/home/testuser'
    client.local_cwd  = '/tmp'
    return client


def _capture(fn, *args):
    """Run fn(*args) and return everything written to stdout."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args)
    return buf.getvalue()


def _make_attr(filename, *, mode=0o100644, size=1024,
               mtime=1609459200, nlink=1, uid=1000, gid=1000):
    """Mock SFTPAttributes with sensible defaults."""
    a          = MagicMock()
    a.filename = filename
    a.st_mode  = mode
    a.st_size  = size
    a.st_mtime = mtime
    a.st_atime = mtime
    a.st_nlink = nlink
    a.st_uid   = uid
    a.st_gid   = gid
    return a


def _wire_remote_file(client, content: bytes):
    """
    Make client.sftp.open() act as a context manager that returns a file
    handle whose read() returns *content* and readline() yields lines.
    """
    stream = io.BytesIO(content)
    lines = content.splitlines(keepends=True) + [b'']
    fh = MagicMock()
    fh.read.side_effect = lambda size=-1: stream.read(size)
    fh.readline.side_effect = list(lines)
    fh.seek.side_effect = stream.seek
    fh.stat.return_value = _make_attr('remote-file', size=len(content))
    client.sftp.open.return_value.__enter__.return_value = fh
    return fh


def _wire_remote_dirs(client, initial_dirs):
    """Make stat/mkdir behave like a minimal remote directory tree."""
    remote_dirs = {path.rstrip('/') or '/' for path in initial_dirs}

    def stat(path):
        normalized = path.rstrip('/') or '/'
        if normalized in remote_dirs:
            return _make_attr(os.path.basename(normalized), mode=0o040755)
        raise IOError('not found')

    def mkdir(path):
        remote_dirs.add(path.rstrip('/') or '/')

    client.sftp.stat.side_effect = stat
    client.sftp.mkdir.side_effect = mkdir
    return remote_dirs


# ══════════════════════════════════════════════════════════════════════════════
# Pure-function tests
# ══════════════════════════════════════════════════════════════════════════════

class TestTransformText(unittest.TestCase):

    def test_date_token(self):
        self.assertEqual(transform_text('%DATE%'),
                         datetime.datetime.now().strftime('%Y-%m-%d'))

    def test_datetime_format(self):
        import re
        self.assertRegex(transform_text('%DATETIME%'),
                         r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')

    def test_gmtdate_format(self):
        import re
        self.assertRegex(transform_text('%GMTDATE%'),
                         r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')

    def test_guid_format(self):
        import re
        self.assertRegex(
            transform_text('%GUID%'),
            r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        )

    def test_guid_is_unique(self):
        self.assertNotEqual(transform_text('%GUID%'), transform_text('%GUID%'))

    def test_md5_format(self):
        import re
        self.assertRegex(transform_text('%MD5%'), r'^[0-9a-f]{32}$')

    def test_md5_is_unique(self):
        self.assertNotEqual(transform_text('%MD5%'), transform_text('%MD5%'))

    def test_rep_double_quoted(self):
        self.assertEqual(transform_text('%REP% "ab" 3'), 'ababab')

    def test_rep_single_quoted(self):
        self.assertEqual(transform_text("%REP% 'xy' 2"), 'xyxy')

    def test_rep_single_char(self):
        self.assertEqual(transform_text('%REP% - 5'), '-----')

    def test_rep_zero_count(self):
        self.assertEqual(transform_text('%REP% "hello" 0'), '')

    def test_rep_nested_date_token(self):
        today = datetime.datetime.now().strftime('%Y-%m-%d')
        self.assertEqual(transform_text('%REP% "%DATE%" 2'), today * 2)

    def test_escape_newline(self):
        self.assertEqual(transform_text(r'a\nb'), 'a\nb')

    def test_escape_tab(self):
        self.assertEqual(transform_text(r'a\tb'), 'a\tb')

    def test_escape_cr(self):
        self.assertEqual(transform_text(r'a\rb'), 'a\rb')

    def test_no_tokens_passthrough(self):
        self.assertEqual(transform_text('plain text'), 'plain text')

    def test_combined_guid_and_date(self):
        import re
        result = transform_text('id=%GUID% ts=%DATE%')
        self.assertRegex(result, r'^id=[0-9a-f-]+ ts=\d{4}-\d{2}-\d{2}$')


class TestParseDestination(unittest.TestCase):

    def _p(self, s, **kw):
        return _parse_destination(s, **kw)

    def test_plain_host(self):
        u, h, p, pe, ok = self._p('myhost')
        self.assertIsNone(u)
        self.assertEqual(h, 'myhost')
        self.assertEqual(p, 22)
        self.assertFalse(pe)
        self.assertTrue(ok)

    def test_user_at_host(self):
        u, h, p, pe, ok = self._p('bob@myhost')
        self.assertEqual(u, 'bob')
        self.assertEqual(h, 'myhost')
        self.assertTrue(ok)

    def test_host_colon_port(self):
        u, h, p, pe, ok = self._p('myhost:2222')
        self.assertEqual(h, 'myhost')
        self.assertEqual(p, 2222)
        self.assertTrue(pe)
        self.assertTrue(ok)

    def test_user_host_port(self):
        u, h, p, pe, ok = self._p('alice@myhost:2222')
        self.assertEqual(u, 'alice')
        self.assertEqual(h, 'myhost')
        self.assertEqual(p, 2222)
        self.assertTrue(ok)

    def test_default_user_applied(self):
        u, h, p, pe, ok = self._p('myhost', default_user='scott')
        self.assertEqual(u, 'scott')

    def test_default_port_applied_when_no_port_in_dest(self):
        u, h, p, pe, ok = self._p('myhost', default_port=2222)
        self.assertEqual(p, 2222)
        self.assertFalse(pe)

    def test_ipv6_bracketed(self):
        u, h, p, pe, ok = self._p('[::1]')
        self.assertEqual(h, '::1')
        self.assertEqual(p, 22)
        self.assertTrue(ok)

    def test_ipv6_bracketed_with_port(self):
        u, h, p, pe, ok = self._p('[::1]:2222')
        self.assertEqual(h, '::1')
        self.assertEqual(p, 2222)
        self.assertTrue(pe)
        self.assertTrue(ok)

    def test_ipv6_bare_treated_as_host(self):
        u, h, p, pe, ok = self._p('2001:db8::1')
        self.assertEqual(h, '2001:db8::1')
        self.assertTrue(ok)

    def test_invalid_port_not_numeric(self):
        u, h, p, pe, ok = self._p('host:notaport')
        self.assertFalse(ok)

    def test_empty_host_is_invalid(self):
        self.assertFalse(self._p(':2222')[4])
        self.assertFalse(self._p('user@')[4])

    def test_port_must_be_in_valid_range(self):
        self.assertFalse(self._p('host:0')[4])
        self.assertFalse(self._p('host:-1')[4])
        self.assertFalse(self._p('host:65536')[4])

    def test_unclosed_ipv6_bracket(self):
        u, h, p, pe, ok = self._p('[::1')
        self.assertFalse(ok)


class TestSplitCompletionLine(unittest.TestCase):

    def test_empty_string(self):
        self.assertEqual(_split_completion_line(''), [])

    def test_single_token(self):
        self.assertEqual(_split_completion_line('ls'), ['ls'])

    def test_two_tokens(self):
        self.assertEqual(_split_completion_line('get /foo/bar'), ['get', '/foo/bar'])

    def test_trailing_space_produces_no_extra_token(self):
        self.assertEqual(_split_completion_line('get '), ['get'])

    def test_double_quoted_space_in_path(self):
        self.assertEqual(_split_completion_line('put "file name"'), ['put', 'file name'])

    def test_single_quoted_space_in_path(self):
        self.assertEqual(_split_completion_line("put 'file name'"), ['put', 'file name'])

    def test_backslash_escaped_space(self):
        self.assertEqual(_split_completion_line(r'put file\ name'), ['put', 'file name'])

    def test_windows_path_backslashes_are_preserved(self):
        self.assertEqual(_split_completion_line(r'put C:\Temp\a.txt'),
                         ['put', r'C:\Temp\a.txt'])

    def test_windows_unc_prefix_is_preserved(self):
        unc = r'\\server\share\a.txt'
        self.assertEqual(_split_completion_line('put ' + unc), ['put', unc])
        self.assertEqual(_split_command_line('put ' + unc), ['put', unc])

    def test_quoted_windows_path_with_space_is_preserved(self):
        self.assertEqual(_split_completion_line(r'put "C:\Temp\a file.txt"'),
                         ['put', r'C:\Temp\a file.txt'])

    def test_command_parser_preserves_windows_path_backslashes(self):
        self.assertEqual(_split_command_line(r'put C:\Temp\a.txt'),
                         ['put', r'C:\Temp\a.txt'])

    def test_command_parser_preserves_single_quoted_windows_path(self):
        self.assertEqual(_split_command_line(r"put 'C:\Temp\a file.txt'"),
                         ['put', r'C:\Temp\a file.txt'])

    def test_unclosed_quote_keeps_partial_token(self):
        tokens = _split_completion_line('put "partial')
        self.assertEqual(tokens[0], 'put')
        self.assertEqual(tokens[1], 'partial')

    def test_multiple_spaces_between_tokens(self):
        self.assertEqual(_split_completion_line('ls  /foo'), ['ls', '/foo'])


class TestEscapeUnescape(unittest.TestCase):

    def test_escape_space(self):
        self.assertEqual(_escape_completion('file name'), 'file\\ name')

    def test_escape_backslash(self):
        self.assertEqual(_escape_completion('a\\b'), 'a\\b')

    def test_escape_double_quote(self):
        self.assertEqual(_escape_completion('a"b'), 'a\\"b')

    def test_escape_single_quote(self):
        self.assertEqual(_escape_completion("a'b"), "a\\'b")

    def test_unescape_escaped_space(self):
        self.assertEqual(_unescape_completion('file\\ name'), 'file name')

    def test_unescape_empty_string(self):
        self.assertEqual(_unescape_completion(''), '')

    def test_roundtrip(self):
        original = 'path with spaces/and"quotes'
        self.assertEqual(_unescape_completion(_escape_completion(original)), original)

    def test_unc_roundtrip(self):
        original = r'\\server\share\folder name\file.txt'
        self.assertEqual(_unescape_completion(_escape_completion(original)), original)


class TestRedactCommandForLog(unittest.TestCase):

    def test_redacts_content_creation_and_shell_arguments(self):
        for line in (
            'new /remote/config "opaque-payload-marker"',
            'new /remote/config "unterminated opaque-payload-marker',
            '"new" /remote/config "opaque-payload-marker"',
            '!printf opaque-payload-marker',
        ):
            with self.subTest(line=line):
                self.assertNotIn('opaque-payload-marker', _redact_command_for_log(line))

    def test_redacts_lowercase_p_value(self):
        self.assertNotIn('secret', _redact_command_for_log('open h -p secret'))

    def test_does_not_redact_uppercase_p_port_value(self):
        redacted = _redact_command_for_log('open h -P 2222')
        self.assertIn('2222', redacted)
        self.assertNotIn('<redacted>', redacted)

    def test_redacts_long_password_value(self):
        self.assertNotIn('secret', _redact_command_for_log('open h --password secret'))

    def test_redacts_inline_password_value(self):
        long_form = _redact_command_for_log('open h --password=secret')
        short_form = _redact_command_for_log('open h -p=secret')
        self.assertIn('<redacted>', long_form)
        self.assertIn('<redacted>', short_form)
        self.assertNotIn('secret', long_form)
        self.assertNotIn('secret', short_form)

    def test_redacts_long_password_in_malformed_line(self):
        redacted = _redact_command_for_log('open h --password secret "unterminated')
        self.assertIn('<redacted>', redacted)
        self.assertNotIn('secret', redacted)

    def test_redacts_unclosed_quoted_short_password_with_spaces(self):
        redacted = _redact_command_for_log('open h -p "super secret')
        self.assertIn('<redacted>', redacted)
        self.assertNotIn('super', redacted)
        self.assertNotIn('secret', redacted)

    def test_redacts_unclosed_quoted_inline_password_with_spaces(self):
        redacted = _redact_command_for_log('open h --password="super secret')
        self.assertIn('<redacted>', redacted)
        self.assertNotIn('super', redacted)
        self.assertNotIn('secret', redacted)


class TestSecurityHardening(unittest.TestCase):

    def test_save_history_redacts_passwords_and_restricts_file(self):
        if sftp_client.readline is None:
            self.skipTest("readline is not available")
        required = ('get_current_history_length', 'get_history_item', 'clear_history', 'add_history')
        if not all(hasattr(sftp_client.readline, name) for name in required):
            self.skipTest("readline history editing is not available")

        rl = sftp_client.readline
        saved_history = [
            rl.get_history_item(i) or ''
            for i in range(1, rl.get_current_history_length() + 1)
        ]
        with tempfile.TemporaryDirectory() as d:
            history_file = os.path.join(d, 'history')
            try:
                rl.clear_history()
                rl.add_history('open host -p supersecret')
                rl.add_history('open host -P 2222')
                rl.add_history('new /remote/config "opaque-payload-marker"')
                rl.add_history('!printf opaque-payload-marker')
                with patch('sftp_client.HISTORY_FILE', history_file):
                    client = _make_client()
                    client._save_history()
                with open(history_file, 'r', encoding='utf-8') as f:
                    text = f.read()
                self.assertNotIn('supersecret', text)
                self.assertNotIn('opaque-payload-marker', text)
                self.assertIn('<redacted>', text)
                self.assertIn('2222', text)
                if os.name != 'nt':
                    self.assertEqual(oct(os.stat(history_file).st_mode)[-3:], '600')
            finally:
                rl.clear_history()
                for item in saved_history:
                    rl.add_history(item)

    def test_save_history_logs_warning_on_write_failure(self):
        """A failed history write must be logged, not silently swallowed."""
        if sftp_client.readline is None:
            self.skipTest("readline is not available")
        if not hasattr(sftp_client.readline, 'get_current_history_length'):
            self.skipTest("readline history editing is not available")

        client = _make_client()
        with patch.object(sftp_client.readline, 'write_history_file',
                          side_effect=OSError('disk full')):
            client._save_history()

        client.logger.warning.assert_called_once()
        message = client.logger.warning.call_args[0][0]
        self.assertIn('Failed to save command history', message)
        self.assertIn('Disk full', message)

    def test_save_history_without_readline_is_noop(self):
        """Without readline there is no history to save or overwrite."""
        client = _make_client()
        with patch('sftp_client.readline', None), \
             patch('os.makedirs') as makedirs:
            client._save_history()

        makedirs.assert_not_called()
        client.logger.warning.assert_not_called()

    def test_readline_history_write_failure_preserves_previous_file(self):
        client = _make_client()
        fake_readline = MagicMock()
        fake_readline.get_current_history_length.return_value = 1
        fake_readline.get_history_item.return_value = 'pwd'

        def partial_write(path):
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('partial')
            raise OSError('disk full')

        fake_readline.write_history_file.side_effect = partial_write
        with tempfile.TemporaryDirectory() as d:
            history_file = os.path.join(d, 'history')
            with open(history_file, 'w', encoding='utf-8') as fh:
                fh.write('previous\n')
            with patch('sftp_client.HISTORY_FILE', history_file), \
                 patch('sftp_client.readline', fake_readline):
                client._save_history()
            with open(history_file, encoding='utf-8') as fh:
                self.assertEqual(fh.read(), 'previous\n')
            self.assertEqual(os.listdir(d), ['history'])
        client.logger.warning.assert_called_once()

    def test_history_sync_failure_preserves_previous_file(self):
        client = _make_client()
        fake_readline = MagicMock()
        fake_readline.get_current_history_length.return_value = 1
        fake_readline.get_history_item.return_value = 'pwd'

        def write(path):
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('pwd\n')

        fake_readline.write_history_file.side_effect = write
        with tempfile.TemporaryDirectory() as d:
            history_file = os.path.join(d, 'history')
            with open(history_file, 'w', encoding='utf-8') as fh:
                fh.write('previous\n')
            with patch('sftp_client.HISTORY_FILE', history_file), \
                 patch('sftp_client.readline', fake_readline), \
                 patch('sftp_client.os.fsync', side_effect=OSError('disk full')):
                client._save_history()
            with open(history_file, encoding='utf-8') as fh:
                self.assertEqual(fh.read(), 'previous\n')
            self.assertEqual(os.listdir(d), ['history'])
        client.logger.warning.assert_called_once()

    def test_history_directory_sync_failure_reports_completed_replace(self):
        client = _make_client()
        fake_readline = MagicMock()
        fake_readline.get_current_history_length.return_value = 1
        fake_readline.get_history_item.return_value = 'pwd'

        def write(path):
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('pwd\n')

        fake_readline.write_history_file.side_effect = write
        with tempfile.TemporaryDirectory() as d:
            history_file = os.path.join(d, 'history')
            with patch('sftp_client.HISTORY_FILE', history_file), \
                 patch('sftp_client.readline', fake_readline), \
                 patch('sftp_client._sync_directory', side_effect=OSError('sync failed')):
                client._save_history()
            with open(history_file, encoding='utf-8') as fh:
                self.assertEqual(fh.read(), 'pwd\n')
        self.assertIn('was replaced', client.logger.warning.call_args.args[0])

    def test_setup_logger_creates_private_log_file(self):
        if os.name == 'nt':
            self.skipTest("POSIX mode bits are not meaningful on Windows")
        import logging

        logger = logging.getLogger("sftp_client")
        old_handlers = list(logger.handlers)
        for handler in old_handlers:
            logger.removeHandler(handler)
        new_handlers = []
        try:
            with tempfile.TemporaryDirectory() as d:
                log_dir = os.path.join(d, 'logs')
                with patch('sftp_client.LOG_DIR', log_dir):
                    logger, log_file = sftp_client._setup_logger()
                new_handlers = list(logger.handlers)
                logger.info('security test')
                for handler in new_handlers:
                    handler.flush()
                self.assertEqual(oct(os.stat(log_dir).st_mode)[-3:], '700')
                self.assertEqual(oct(os.stat(log_file).st_mode)[-3:], '600')
        finally:
            for handler in list(logger.handlers):
                logger.removeHandler(handler)
                handler.close()
            for handler in old_handlers:
                logger.addHandler(handler)


class TestReadlineSetup(unittest.TestCase):

    def test_pyreadline3_shim_binds_tab_with_cmd_syntax(self):
        """pyreadline3 rejects '"\\t": complete' and leaves Tab inserting a tab."""
        shim = types.SimpleNamespace(backend='pyreadline', __doc__=None)
        self.assertEqual(sftp_client._readline_tab_binds(shim), ('tab: complete',))
        shim = types.SimpleNamespace(__doc__='Importing this module enables command '
                                             'line editing using pyreadline3')
        self.assertEqual(sftp_client._readline_tab_binds(shim), ('tab: complete',))

    def test_gnu_and_libedit_tab_bindings(self):
        gnu = types.SimpleNamespace(backend='readline', __doc__='Importing this module '
                                                                'enables command line editing using GNU readline.')
        libedit = types.SimpleNamespace(backend='editline', __doc__='... libedit ...')
        self.assertEqual(sftp_client._readline_tab_binds(gnu), ('"\\t": complete',))
        self.assertEqual(sftp_client._readline_tab_binds(libedit), ('bind ^I rl_complete',))

    def test_setup_readline_falls_back_to_next_tab_binding(self):
        fake_readline = MagicMock()
        fake_readline.parse_and_bind.side_effect = [
            IndexError("Not a valid key"),
            None,
        ]
        client = _make_client()

        with tempfile.TemporaryDirectory() as d, \
             patch('sftp_client.readline', fake_readline), \
             patch('sftp_client._RL_TAB_BINDS', ('"\\t": complete', 'tab: complete')), \
             patch('sftp_client.HISTORY_FILE', os.path.join(d, 'history')):
            client._setup_readline()

        self.assertEqual(
            [call.args[0] for call in fake_readline.parse_and_bind.call_args_list],
            ['"\\t": complete', 'tab: complete'],
        )
        fake_readline.set_history_length.assert_called_once_with(2000)

    def test_setup_readline_does_not_crash_when_tab_bindings_fail(self):
        fake_readline = MagicMock()
        fake_readline.parse_and_bind.side_effect = IndexError("Not a valid key")
        client = _make_client()

        with tempfile.TemporaryDirectory() as d, \
             patch('sftp_client.readline', fake_readline), \
             patch('sftp_client._RL_TAB_BINDS', ('bad-binding',)), \
             patch('sftp_client.HISTORY_FILE', os.path.join(d, 'history')):
            client._setup_readline()

        fake_readline.set_completer.assert_called_once()
        fake_readline.set_history_length.assert_called_once_with(2000)


# ══════════════════════════════════════════════════════════════════════════════
# Connection tests
# ══════════════════════════════════════════════════════════════════════════════

class TestConnect(unittest.TestCase):

    def _bare(self):
        with patch('sftp_client._setup_logger') as m:
            m.return_value = (MagicMock(), '/dev/null')
            return SFTPClient()

    def _mock_ssh(self, mock_cls, home='/home/user'):
        ssh  = MagicMock()
        mock_cls.return_value = ssh
        sftp = MagicMock()
        ssh.open_sftp.return_value = sftp
        sftp.normalize.return_value = home
        return ssh, sftp

    @patch('sftp_client._CONNECT_PARAMETERS', None)
    @patch('paramiko.SSHClient')
    def test_successful_connect(self, mock_cls):
        ssh, sftp = self._mock_ssh(mock_cls)
        client = self._bare()
        client.connect('host', username='user', password='pass')
        self.assertTrue(client.connected)
        self.assertEqual(client._connected_host, 'host')
        self.assertEqual(client.remote_cwd, '/home/user')
        ssh.connect.assert_called_once()
        connect_kwargs = ssh.connect.call_args.kwargs
        self.assertEqual(connect_kwargs['banner_timeout'], sftp_client._SFTP_TIMEOUT)
        self.assertEqual(connect_kwargs['channel_timeout'], sftp_client._SFTP_TIMEOUT)
        sftp.get_channel.return_value.settimeout.assert_called_once_with(
            sftp_client._SFTP_TIMEOUT
        )
        client._close_connection()
        self.assertIsNone(client._connected_host)

    @patch('paramiko.SSHClient')
    def test_sftp_subsystem_negotiation_is_bounded(self, mock_cls):
        import threading

        ssh = MagicMock()
        mock_cls.return_value = ssh
        release = threading.Event()

        def delayed_open():
            release.wait(1)
            return MagicMock()

        ssh.open_sftp.side_effect = delayed_open
        ssh.close.side_effect = release.set
        client = self._bare()
        with patch('sftp_client._SFTP_TIMEOUT', 0.01):
            with self.assertRaises(TimeoutError):
                client.connect('host', username='user', password='pass')
        ssh.close.assert_called()

    def test_open_sftp_bounded_caps_abandoned_threads(self):
        """Repeated hung SFTP-open attempts must not spawn unbounded threads."""
        import threading

        client = self._bare()
        hang_forever = threading.Event()  # deliberately never set

        def make_stuck_ssh():
            ssh = MagicMock()
            ssh.open_sftp.side_effect = lambda: hang_forever.wait() or MagicMock()
            return ssh

        cap = sftp_client.SFTPClient._MAX_ABANDONED_SFTP_OPENS
        for _ in range(cap):
            with self.assertRaises(TimeoutError):
                client._open_sftp_bounded(make_stuck_ssh(), 0.01)

        self.assertEqual(len(client._abandoned_sftp_open_threads), cap)

        with self.assertRaises(RuntimeError) as ctx:
            client._open_sftp_bounded(make_stuck_ssh(), 0.01)
        self.assertIn('hung in the background', str(ctx.exception))
        # The refused attempt must not itself add another abandoned thread.
        self.assertEqual(len(client._abandoned_sftp_open_threads), cap)

    def test_open_sftp_bounded_reaps_finished_abandoned_threads(self):
        """Once a previously-abandoned worker finishes, it must be reaped and stop counting."""
        import threading

        client = self._bare()
        release = threading.Event()
        stuck_ssh = MagicMock()
        stuck_ssh.open_sftp.side_effect = lambda: (release.wait(5), MagicMock())[1]

        with self.assertRaises(TimeoutError):
            client._open_sftp_bounded(stuck_ssh, 0.01)
        self.assertEqual(len(client._abandoned_sftp_open_threads), 1)

        release.set()
        client._abandoned_sftp_open_threads[0].join(timeout=2)

        good_ssh = MagicMock()
        good_sftp = MagicMock()
        good_ssh.open_sftp.return_value = good_sftp

        result = client._open_sftp_bounded(good_ssh, 1.0)

        self.assertIs(result, good_sftp)
        self.assertEqual(client._abandoned_sftp_open_threads, [])

    def test_open_sftp_timeout_closes_handle_published_before_finish(self):
        client = self._bare()
        ssh = MagicMock()
        sftp = MagicMock()
        ssh.open_sftp.return_value = sftp
        published = threading.Event()
        resume = threading.Event()
        finished = threading.Event()

        class PausedFinishEvent:
            def set(self):
                published.set()
                resume.wait(2)
                finished.set()

            def wait(self, timeout=None):
                if timeout == 0.01:
                    self_test.assertTrue(published.wait(2))
                    return False
                resume.set()
                return finished.wait(timeout)

        self_test = self
        real_event_type = threading.Event
        first_event = True

        def event_factory():
            nonlocal first_event
            if first_event:
                first_event = False
                return PausedFinishEvent()
            return real_event_type()

        with patch('sftp_client.threading.Event', side_effect=event_factory):
            with self.assertRaises(TimeoutError):
                client._open_sftp_bounded(ssh, 0.01)
        sftp.close.assert_called_once()
        ssh.close.assert_called_once()

    @patch('paramiko.SSHClient')
    def test_keyboard_interrupt_during_ssh_connect_closes_provisional_client(self, mock_cls):
        ssh, _ = self._mock_ssh(mock_cls)
        ssh.connect.side_effect = KeyboardInterrupt()
        client = self._bare()
        with self.assertRaises(KeyboardInterrupt):
            client.connect('host', username='user')
        ssh.close.assert_called_once()
        self.assertFalse(client.connected)

    @patch('paramiko.SSHClient')
    def test_keyboard_interrupt_during_normalize_closes_provisional_resources(self, mock_cls):
        ssh, sftp = self._mock_ssh(mock_cls)
        sftp.normalize.side_effect = KeyboardInterrupt()
        client = self._bare()
        with self.assertRaises(KeyboardInterrupt):
            client.connect('host', username='user')
        sftp.close.assert_called_once()
        ssh.close.assert_called_once()
        self.assertFalse(client.connected)

    @patch('paramiko.SSHClient')
    def test_keyboard_interrupt_during_sftp_open_closes_provisional_client(self, mock_cls):
        ssh, _ = self._mock_ssh(mock_cls)
        client = self._bare()
        with patch.object(client, '_open_sftp_bounded', side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                client.connect('host', username='user')
        ssh.close.assert_called_once()
        self.assertFalse(client.connected)

    @patch('paramiko.SSHClient')
    def test_unknown_host_keys_are_rejected_by_default(self, mock_cls):
        ssh, _ = self._mock_ssh(mock_cls)
        client = self._bare()
        client.connect('host', username='user', password='pass')
        policy = ssh.set_missing_host_key_policy.call_args[0][0]
        self.assertIsInstance(policy, paramiko.RejectPolicy)

    @patch('paramiko.SSHClient')
    def test_ki_auth_fallback_uses_fresh_connection(self, mock_cls):
        """Password auth fails -> keyboard-interactive on a new connection.
        macOS sshd never answers keyboard-interactive on the connection whose
        password attempt failed, so reusing it hung until auth_timeout."""
        first, second = MagicMock(), MagicMock()
        mock_cls.side_effect = [first, second]
        first.connect.side_effect = paramiko.ssh_exception.AuthenticationException()
        second.open_sftp.return_value.normalize.return_value = '/home/user'

        client = self._bare()
        client.connect('host', username='user', password='pass')

        first.close.assert_called()
        first.get_transport.assert_not_called()
        policy = second.set_missing_host_key_policy.call_args[0][0]
        self.assertIsInstance(policy, paramiko.RejectPolicy)
        second.load_system_host_keys.assert_called_once()
        kwargs = second.connect.call_args.kwargs
        self.assertEqual(kwargs['password'], 'pass')
        self.assertIn('transport_factory', kwargs)
        self.assertTrue(client.connected)
        self.assertIs(client.ssh, second)

    def test_ki_transport_answers_password_step_interactively(self):
        transport = object.__new__(sftp_client._KeyboardInteractiveTransport)
        handler = MagicMock()
        transport._ki_handler = handler
        with patch.object(paramiko.Transport, 'auth_interactive', return_value=[]) as ki:
            transport.auth_password('user', 'pass')
        ki.assert_called_once_with('user', handler)

    @patch('paramiko.SSHClient')
    def test_ki_auth_failure_closes_both_connections(self, mock_cls):
        """REGRESSION BUG 1: SSH sockets must be closed when KI auth fails."""
        first, second = MagicMock(), MagicMock()
        mock_cls.side_effect = [first, second]
        first.connect.side_effect = paramiko.ssh_exception.AuthenticationException()
        second.connect.side_effect = paramiko.ssh_exception.AuthenticationException('KI denied')

        client = self._bare()
        with self.assertRaises(paramiko.ssh_exception.AuthenticationException):
            client.connect('host', username='user', password='wrong')

        first.close.assert_called()
        second.close.assert_called()
        self.assertFalse(client.connected)

    @patch('sftp_client._CONNECT_SUPPORTS_TRANSPORT_FACTORY', False)
    @patch('paramiko.SSHClient')
    def test_legacy_ki_fallback_reuses_transport(self, mock_cls):
        """Without transport_factory (paramiko < 3.2) the old path is kept."""
        ssh, _ = self._mock_ssh(mock_cls)
        ssh.connect.side_effect = paramiko.ssh_exception.AuthenticationException()
        transport = MagicMock()
        ssh.get_transport.return_value = transport

        client = self._bare()
        client.connect('host', username='user', password='pass')

        transport.auth_interactive.assert_called_once()
        self.assertTrue(client.connected)

    @patch('sftp_client._CONNECT_SUPPORTS_TRANSPORT_FACTORY', False)
    @patch('paramiko.SSHClient')
    def test_legacy_ki_failure_closes_ssh(self, mock_cls):
        ssh = MagicMock()
        mock_cls.return_value = ssh
        ssh.connect.side_effect = paramiko.ssh_exception.AuthenticationException()
        transport = MagicMock()
        ssh.get_transport.return_value = transport
        transport.auth_interactive.side_effect = \
            paramiko.ssh_exception.AuthenticationException('KI denied')

        client = self._bare()
        with self.assertRaises(paramiko.ssh_exception.AuthenticationException):
            client.connect('host', username='user', password='wrong')

        ssh.close.assert_called()

    @patch('sftp_client._CONNECT_SUPPORTS_TRANSPORT_FACTORY', False)
    @patch('paramiko.SSHClient')
    def test_none_transport_closes_ssh_and_reraises(self, mock_cls):
        """get_transport() returning None closes SSH and re-raises."""
        ssh = MagicMock()
        mock_cls.return_value = ssh
        ssh.connect.side_effect = paramiko.ssh_exception.AuthenticationException()
        ssh.get_transport.return_value = None

        client = self._bare()
        with self.assertRaises(paramiko.ssh_exception.AuthenticationException):
            client.connect('host', username='user', password='pass')

        ssh.close.assert_called()

    @patch('paramiko.SSHClient')
    def test_reconnect_closes_old_session_first(self, mock_cls):
        """Calling connect() while already connected closes the previous session."""
        ssh, _ = self._mock_ssh(mock_cls)
        client = self._bare()
        old_sftp, old_ssh = MagicMock(), MagicMock()
        client.sftp      = old_sftp
        client.ssh       = old_ssh
        client.connected = True

        client.connect('newhost', username='user', password='pass')

        old_sftp.close.assert_called()
        old_ssh.close.assert_called()

    @patch('paramiko.SSHClient')
    def test_open_sftp_failure_closes_ssh(self, mock_cls):
        """If open_sftp() fails, the SSH connection is still closed."""
        ssh = MagicMock()
        mock_cls.return_value = ssh
        ssh.open_sftp.side_effect = IOError('sftp not supported')

        client = self._bare()
        with self.assertRaises(IOError):
            client.connect('host', username='user', password='pass')

        ssh.close.assert_called()


# ══════════════════════════════════════════════════════════════════════════════
# SFTP command tests
# ══════════════════════════════════════════════════════════════════════════════

class TestCmdLs(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_lists_directory_entries(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('file.txt', mode=0o100644, size=512),
            _make_attr('subdir',   mode=0o040755, size=0),
        ]
        out = _capture(self.c.cmd_ls, [])
        self.assertIn('file.txt', out)
        self.assertIn('subdir', out)

    def test_falls_back_to_stat_when_path_is_a_file(self):
        self.c.sftp.listdir_attr.side_effect = IOError('not a directory')
        self.c.sftp.stat.return_value = _make_attr('only.txt', mode=0o100644)
        out = _capture(self.c.cmd_ls, ['only.txt'])
        self.assertIn('only.txt', out)

    def test_both_fail_shows_error(self):
        self.c.sftp.listdir_attr.side_effect = IOError('no such file')
        self.c.sftp.stat.side_effect         = IOError('no such file')
        out = _capture(self.c.cmd_ls, ['/nonexistent'])
        self.assertIn('ls:', out)

    def test_entry_with_all_none_fields_does_not_crash(self):
        attr = _make_attr('mystery')
        attr.st_mode = None; attr.st_size = None; attr.st_mtime = None
        attr.st_nlink = None; attr.st_uid = None; attr.st_gid = None
        self.c.sftp.listdir_attr.return_value = [attr]
        out = _capture(self.c.cmd_ls, [])
        self.assertIn('mystery', out)


class TestCmdCd(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_cd_to_valid_directory_updates_cwd(self):
        self.c.sftp.normalize.return_value = '/home/testuser/subdir'
        self.c.sftp.stat.return_value = _make_attr('subdir', mode=0o040755)
        self.c.cmd_cd(['subdir'])
        self.assertEqual(self.c.remote_cwd, '/home/testuser/subdir')

    def test_cd_to_file_reports_error_and_leaves_cwd_unchanged(self):
        self.c.sftp.normalize.return_value = '/home/testuser/file.txt'
        self.c.sftp.stat.return_value = _make_attr('file.txt', mode=0o100644)
        out = _capture(self.c.cmd_cd, ['file.txt'])
        self.assertIn('not a directory', out)
        self.assertEqual(self.c.remote_cwd, '/home/testuser')

    def test_cd_none_st_mode_treated_as_not_directory(self):
        """REGRESSION BUG 3: st_mode=None must not raise TypeError."""
        self.c.sftp.normalize.return_value = '/home/testuser/mystery'
        attr = _make_attr('mystery'); attr.st_mode = None
        self.c.sftp.stat.return_value = attr
        out = _capture(self.c.cmd_cd, ['mystery'])
        self.assertIn('not a directory', out)
        self.assertNotIn('TypeError', out)
        self.assertEqual(self.c.remote_cwd, '/home/testuser')

    def test_cd_nonexistent_path_reports_error(self):
        self.c.sftp.normalize.side_effect = IOError('no such file')
        out = _capture(self.c.cmd_cd, ['/bad'])
        self.assertIn('cd:', out)
        self.assertEqual(self.c.remote_cwd, '/home/testuser')


class TestCmdGet(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_get_to_explicit_local_path(self):
        with tempfile.TemporaryDirectory() as d:
            expected = os.path.join(d, 'file.txt')
            self.c.cmd_get(['/remote/file.txt', expected])
            remote, staged = self.c.sftp.get.call_args.args
            self.assertEqual(remote, '/remote/file.txt')
            self.assertEqual(os.path.dirname(staged), d)
            self.assertNotEqual(staged, expected)
            self.assertTrue(os.path.exists(expected))

    def test_get_to_local_directory_appends_filename(self):
        with tempfile.TemporaryDirectory() as d:
            self.c.cmd_get(['/remote/file.txt', d])
            expected = os.path.join(d, 'file.txt')
            remote, staged = self.c.sftp.get.call_args.args
            self.assertEqual(remote, '/remote/file.txt')
            self.assertEqual(os.path.dirname(staged), d)
            self.assertNotEqual(staged, expected)
            self.assertTrue(os.path.exists(expected))

    def test_get_no_args_shows_usage(self):
        out = _capture(self.c.cmd_get, [])
        self.assertIn('Usage', out)
        self.c.sftp.get.assert_not_called()

    def test_get_error_is_reported(self):
        self.c.sftp.get.side_effect = IOError('permission denied')
        out = _capture(self.c.cmd_get, ['/remote/file.txt'])
        self.assertIn('get:', out)


class TestCmdPut(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.atomic = False

    def test_put_to_explicit_remote_path(self):
        self.c.sftp.stat.side_effect = IOError('not found')
        with tempfile.NamedTemporaryFile() as f:
            self.c.cmd_put([f.name, '/remote/dest.txt'])
        remote, mode = self.c.sftp.open.call_args.args
        self.assertEqual(remote, '/remote/dest.txt')
        self.assertEqual(mode, 'wxb')

    def test_put_to_remote_directory_appends_filename(self):
        dir_attr = _make_attr('remotedir', mode=0o040755)
        self.c.sftp.stat.side_effect = [dir_attr, FileNotFoundError('not found')]
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            fname = f.name
        try:
            self.c.cmd_put([fname, '/remotedir'])
            remote, mode = self.c.sftp.open.call_args.args
            self.assertTrue(remote.startswith('/remotedir/'))
            self.assertTrue(remote.endswith(os.path.basename(fname)))
            self.assertEqual(mode, 'wxb')
        finally:
            os.unlink(fname)

    def test_put_remote_stat_none_st_mode_does_not_crash(self):
        """REGRESSION BUG 4: attr.st_mode=None must not raise TypeError."""
        attr = _make_attr('dest'); attr.st_mode = None
        self.c.sftp.stat.side_effect = [attr, FileNotFoundError('not found')]
        with tempfile.NamedTemporaryFile() as f:
            self.c.cmd_put([f.name, '/remote/dest.txt'])
        remote, mode = self.c.sftp.open.call_args.args
        self.assertEqual(remote, '/remote/dest.txt')
        self.assertEqual(mode, 'wxb')

    def test_put_trailing_slash_on_remote_appends_filename(self):
        self.c.sftp.stat.side_effect = IOError('not found')
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            fname = f.name
        try:
            self.c.cmd_put([fname, '/remotedir/'])
            remote, mode = self.c.sftp.open.call_args.args
            self.assertTrue(remote.startswith('/remotedir/'))
            self.assertEqual(mode, 'wxb')
        finally:
            os.unlink(fname)

    def test_put_error_is_reported(self):
        self.c.sftp.stat.side_effect = IOError('not found')
        self.c.sftp.open.return_value.__enter__.return_value.write.side_effect = IOError('disk full')
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'data'); f.flush()
            out = _capture(self.c.cmd_put, [f.name])
        self.assertIn('put:', out)

    def test_put_rejects_local_directory_before_remote_io(self):
        with tempfile.TemporaryDirectory() as d:
            out = _capture(self.c.cmd_put, [d, '/remote/dest'])
        self.assertIn('not a file', out)
        self.c.sftp.stat.assert_not_called()
        self.c.sftp.put.assert_not_called()

    def test_put_does_not_remove_new_remote_path_on_failure(self):
        self.c.sftp.stat.side_effect = [
            FileNotFoundError('/remote/dest.txt'),
            FileNotFoundError('/remote/dest.txt'),
            FileNotFoundError('/remote/dest.txt'),
        ]
        self.c.sftp.open.return_value.__enter__.return_value.write.side_effect = IOError('connection reset')
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'data'); f.flush()
            _capture(self.c.cmd_put, [f.name, '/remote/dest.txt'])
        self.c.sftp.remove.assert_not_called()

    def test_put_preserves_existing_remote_on_failure(self):
        """Overwriting an existing destination always goes through the atomic
        temp+rename path (even with atomic=False), so a failed upload only
        ever touches the temp file -- the existing dest.txt is never truncated."""
        self.c.sftp.stat.return_value = _make_attr('dest.txt', mode=0o100644)
        self.c.sftp.put.side_effect = IOError('connection reset')
        with tempfile.NamedTemporaryFile() as f:
            _capture(self.c.cmd_put, ['-f', f.name, '/remote/dest.txt'])
        self.c.sftp.remove.assert_called_once()
        removed = self.c.sftp.remove.call_args[0][0]
        self.assertTrue(removed.startswith('/remote/.sftp-'))
        self.assertNotEqual(removed, '/remote/dest.txt')

    def test_put_skips_dangling_remote_symlink_without_force(self):
        self.c.sftp.stat.side_effect = FileNotFoundError('missing target')
        self.c.sftp.lstat.side_effect = None
        self.c.sftp.lstat.return_value = _make_attr('link', mode=0o120777)
        with tempfile.NamedTemporaryFile() as f:
            out = _capture(self.c.cmd_put, [f.name, '/remote/link'])
        self.assertIn('already exists', out)
        self.c.sftp.open.assert_not_called()
        self.c.sftp.put.assert_not_called()

    def test_put_force_writes_through_dangling_remote_symlink(self):
        """Like OpenSSH sftp, put -f follows a dangling link and creates its
        target; the link itself is left in place."""
        link_attr = _make_attr('link', mode=0o120777)
        self.c.sftp.stat.side_effect = FileNotFoundError('missing target')
        self.c.sftp.lstat.side_effect = lambda path: (
            link_attr if path == '/remote/link' else (_ for _ in ()).throw(FileNotFoundError(path)))
        self.c.sftp.readlink.return_value = 'target.txt'
        with tempfile.NamedTemporaryFile() as f:
            self.c.cmd_put(['-f', f.name, '/remote/link'])
        staged = self.c.sftp.put.call_args.args[1]
        self.assertTrue(staged.startswith('/remote/.sftp-'))
        self.c.sftp.rename.assert_called_once_with(staged, '/remote/target.txt')
        self.c.sftp.posix_rename.assert_not_called()

    def test_direct_put_exclusive_creation_rejects_racing_destination(self):
        self.c.sftp.stat.side_effect = FileNotFoundError('not found')
        self.c.sftp.open.side_effect = FileExistsError('created by another client')
        with tempfile.NamedTemporaryFile() as f:
            out = _capture(self.c.cmd_put, [f.name, '/remote/new.txt'])
        self.assertIn('put:', out)
        self.c.sftp.open.assert_called_once_with('/remote/new.txt', 'wxb')
        self.c.sftp.remove.assert_not_called()

    def test_direct_put_writes_source_bytes_to_exclusive_remote_handle(self):
        self.c.sftp.stat.side_effect = FileNotFoundError('not found')
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'upload content'); f.flush()
            self.c.cmd_put([f.name, '/remote/new.txt'])
        target = self.c.sftp.open.return_value.__enter__.return_value
        target.write.assert_called_once_with(b'upload content')


class TestCmdMget(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_mget_downloads_matching_files(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('a.log', mode=0o100644),
            _make_attr('b.log', mode=0o100644),
            _make_attr('c.txt', mode=0o100644),
        ]
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            self.c.cmd_mget(['*.log'])
        self.assertEqual(self.c.sftp.get.call_count, 2)

    def test_mget_skips_directories(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('file.log', mode=0o100644),
            _make_attr('dir.log',  mode=0o040755),
        ]
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            self.c.cmd_mget(['*.log'])
        self.assertEqual(self.c.sftp.get.call_count, 1)

    def test_mget_no_matches_reports_message(self):
        self.c.sftp.listdir_attr.return_value = [_make_attr('readme.txt')]
        out = _capture(self.c.cmd_mget, ['*.log'])
        self.assertIn('no files match', out)

    def test_mget_listdir_error_is_reported(self):
        self.c.sftp.listdir_attr.side_effect = IOError('permission denied')
        out = _capture(self.c.cmd_mget, ['*.log'])
        self.assertIn('mget:', out)
        self.c.sftp.get.assert_not_called()

    def test_mget_remote_subdirectory_pattern(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('a.log', mode=0o100644),
            _make_attr('b.txt', mode=0o100644),
        ]
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            self.c.cmd_mget(['logs/*.log'])
            remote, staged = self.c.sftp.get.call_args.args
            self.assertEqual(remote, '/home/testuser/logs/a.log')
            self.assertEqual(os.path.dirname(staged), d)
            self.assertTrue(os.path.exists(os.path.join(d, 'a.log')))
        self.c.sftp.listdir_attr.assert_called_once_with('/home/testuser/logs')

    def test_mget_rejects_remote_parent_traversal(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('../victim.log', mode=0o100644),
        ]
        with tempfile.TemporaryDirectory() as d:
            downloads = os.path.join(d, 'downloads')
            os.mkdir(downloads)
            victim = os.path.join(d, 'victim.log')
            with open(victim, 'w') as f:
                f.write('original')
            self.c.local_cwd = downloads
            out = _capture(self.c.cmd_mget, ['*.log'])
            with open(victim) as f:
                self.assertEqual(f.read(), 'original')
        self.assertIn('unsafe remote filename', out)
        self.c.sftp.get.assert_not_called()

    def test_mget_rejects_absolute_names(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('/tmp/absolute.log', mode=0o100644),
        ]
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            out = _capture(self.c.cmd_mget, ['*.log'])
        self.assertEqual(out.count('unsafe remote filename'), 1)
        self.c.sftp.get.assert_not_called()

    def test_mget_rejects_backslash_names_on_windows(self):
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            with patch.object(sftp_client.os, 'name', 'nt'):
                with self.assertRaises(ValueError):
                    self.c._safe_mget_local_path(r'..\victim.log')

    @unittest.skipIf(os.name == 'nt', 'backslash is a path separator on Windows')
    def test_mget_downloads_backslash_names_literally_on_posix(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr(r'..\victim.log', mode=0o100644),
        ]
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            out = _capture(self.c.cmd_mget, ['*.log'])
            self.assertNotIn('unsafe', out)
            staged = self.c.sftp.get.call_args.args[1]
            self.assertEqual(os.path.dirname(staged), d)
            self.assertTrue(os.path.lexists(os.path.join(d, r'..\victim.log')))

    def test_mget_skips_symlinks_to_directories(self):
        link = _make_attr('dirlink', mode=0o120777)
        self.c.sftp.listdir_attr.return_value = [link]
        self.c.sftp.stat.return_value = _make_attr('dirlink', mode=0o040755)
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            out = _capture(self.c.cmd_mget, ['*'])
        self.c.sftp.get.assert_not_called()
        self.assertNotIn('mget dirlink', out)


class TestUploadSourcePreservation(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.remote_cwd = '/remote'
        self.remote_files = {}

        def remote_stat(path):
            if path not in self.remote_files:
                raise FileNotFoundError(path)
            return _make_attr(os.path.basename(path), size=len(self.remote_files[path]))

        def upload(local, staged, **kwargs):
            with open(local, 'rb') as fh:
                self.remote_files[staged] = fh.read()

        def publish(staged, remote):
            self.remote_files[remote] = self.remote_files.pop(staged)

        self.c.sftp.stat.side_effect = remote_stat
        self.c.sftp.lstat.side_effect = remote_stat
        self.c.sftp.put.side_effect = upload
        self.c.sftp.posix_rename.side_effect = publish

    def _source_snapshot(self, path):
        with open(path, 'rb') as fh:
            content = fh.read()
        info = os.stat(path)
        return content, info.st_ino, info.st_mode, info.st_mtime_ns

    def test_put_force_replaces_remote_destination_and_preserves_local_source(self):
        with tempfile.TemporaryDirectory() as d:
            source = os.path.join(d, 'source.txt')
            with open(source, 'wb') as fh:
                fh.write(b'new remote content')
            before = self._source_snapshot(source)
            self.remote_files['/remote/dest.txt'] = b'old remote content'
            self.c.atomic = False
            self.c.cmd_put(['-f', source, '/remote/dest.txt'])
            self.assertEqual(self.remote_files['/remote/dest.txt'], b'new remote content')
            self.assertEqual(self._source_snapshot(source), before)
        self.c.sftp.posix_rename.assert_called_once()
        self.c.sftp.open.assert_not_called()

    def test_mput_force_replaces_remote_destinations_and_preserves_sources(self):
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            sources = {}
            for name in ('a.txt', 'b.txt'):
                source = os.path.join(d, name)
                with open(source, 'wb') as fh:
                    fh.write(f'new {name}'.encode())
                sources[source] = self._source_snapshot(source)
                self.remote_files['/remote/' + name] = b'old remote content'
            self.c.atomic = False
            self.c.cmd_mput(['-f', '*.txt'])
            for source, before in sources.items():
                self.assertEqual(self._source_snapshot(source), before)
                self.assertEqual(
                    self.remote_files['/remote/' + os.path.basename(source)], before[0]
                )
        self.assertEqual(self.c.sftp.posix_rename.call_count, 2)
        self.c.sftp.open.assert_not_called()

    def test_put_refuses_same_localhost_source_and_destination(self):
        with tempfile.TemporaryDirectory() as d:
            source = os.path.join(d, 'same.txt')
            with open(source, 'wb') as fh:
                fh.write(b'original')
            before = self._source_snapshot(source)
            self.remote_files[source] = b'original'
            self.c._connected_host = '127.0.0.1'
            out = _capture(self.c.cmd_put, ['-f', source, source])
            self.assertIn('upload refused', out)
            self.assertEqual(self._source_snapshot(source), before)
        self.c.sftp.put.assert_not_called()

    def test_put_refuses_same_path_when_connected_by_local_hostname(self):
        with tempfile.TemporaryDirectory() as d:
            source = os.path.join(d, 'same.txt')
            with open(source, 'wb') as fh:
                fh.write(b'original')
            self.remote_files[source] = b'original'
            self.c._connected_host = 'my-workstation'
            with patch('sftp_client.socket.gethostname', return_value='my-workstation'):
                out = _capture(self.c.cmd_put, ['-f', source, source])
            self.assertIn('upload refused', out)
        self.c.sftp.put.assert_not_called()

    def test_mput_refuses_same_localhost_source_and_destination(self):
        with tempfile.TemporaryDirectory() as d:
            source = os.path.join(d, 'same.txt')
            with open(source, 'wb') as fh:
                fh.write(b'original')
            before = self._source_snapshot(source)
            self.remote_files[source] = b'original'
            self.c.local_cwd = d
            self.c.remote_cwd = d
            self.c._connected_host = 'localhost'
            out = _capture(self.c.cmd_mput, ['-f', '*.txt'])
            self.assertIn('upload refused', out)
            self.assertEqual(self._source_snapshot(source), before)
        self.c.sftp.put.assert_not_called()

    def test_put_refuses_same_path_through_local_lan_alias(self):
        with tempfile.TemporaryDirectory() as d:
            source = os.path.join(d, 'same.txt')
            with open(source, 'wb') as fh:
                fh.write(b'original')
            before = self._source_snapshot(source)
            self.remote_files[source] = b'original'
            self.c._connected_host = 'sftp-alias.example'
            sock = self.c.ssh.get_transport.return_value.sock
            sock.getsockname.return_value = ('192.0.2.10', 52000)
            sock.getpeername.return_value = ('192.0.2.10', 22)
            out = _capture(self.c.cmd_put, ['-f', source, source])
            self.assertIn('upload refused', out)
            self.assertEqual(self._source_snapshot(source), before)
        self.c.sftp.put.assert_not_called()

    def test_mput_refuses_same_path_through_local_lan_alias(self):
        with tempfile.TemporaryDirectory() as d:
            source = os.path.join(d, 'same.txt')
            with open(source, 'wb') as fh:
                fh.write(b'original')
            self.remote_files[source] = b'original'
            self.c.local_cwd = self.c.remote_cwd = d
            self.c._connected_host = 'sftp-alias.example'
            sock = self.c.ssh.get_transport.return_value.sock
            sock.getsockname.return_value = ('192.0.2.10', 52000)
            sock.getpeername.return_value = ('192.0.2.10', 22)
            out = _capture(self.c.cmd_mput, ['-f', '*.txt'])
            self.assertIn('upload refused', out)
        self.c.sftp.put.assert_not_called()

    def test_put_allows_same_path_on_different_server(self):
        with tempfile.TemporaryDirectory() as d:
            source = os.path.join(d, 'same.txt')
            with open(source, 'wb') as fh:
                fh.write(b'local content')
            self.remote_files[source] = b'remote content'
            self.c._connected_host = 'remote.example'
            sock = self.c.ssh.get_transport.return_value.sock
            sock.getsockname.return_value = ('192.0.2.10', 52000)
            sock.getpeername.return_value = ('198.51.100.20', 22)
            self.c.cmd_put(['-f', source, source])
            self.assertEqual(self.remote_files[source], b'local content')
        self.c.sftp.posix_rename.assert_called_once()

    def test_put_refuses_source_symlink_pointing_at_destination(self):
        with tempfile.TemporaryDirectory() as d:
            destination = os.path.join(d, 'target.txt')
            source = os.path.join(d, 'source-link.txt')
            with open(destination, 'wb') as fh:
                fh.write(b'original')
            try:
                os.symlink(destination, source)
            except (OSError, NotImplementedError):
                self.skipTest('symlinks are not available')
            self.remote_files[destination] = b'original'
            self.c._connected_host = '::1'
            out = _capture(self.c.cmd_put, ['-f', source, destination])
            self.assertIn('upload refused', out)
            self.assertEqual(self._source_snapshot(source)[0], b'original')
        self.c.sftp.put.assert_not_called()

    def test_put_allows_distinct_hardlink_destination(self):
        with tempfile.TemporaryDirectory() as d:
            source = os.path.join(d, 'source.txt')
            destination = os.path.join(d, 'destination.txt')
            with open(source, 'wb') as fh:
                fh.write(b'original')
            try:
                os.link(source, destination)
            except OSError:
                self.skipTest('hard links are not available')
            self.remote_files[destination] = b'original'
            self.c._connected_host = 'localhost'
            self.c.cmd_put(['-f', source, destination])
            self.assertEqual(self._source_snapshot(source)[0], b'original')
        self.c.sftp.put.assert_called_once()

    def test_disconnected_put_and_mput_leave_sources_alone(self):
        with tempfile.TemporaryDirectory() as d:
            source = os.path.join(d, 'source.txt')
            with open(source, 'wb') as fh:
                fh.write(b'original')
            before = self._source_snapshot(source)
            self.c.local_cwd = d
            self.c.connected = False
            for command in ('put -f source.txt /remote/source.txt', 'mput -f *.txt'):
                with self.subTest(command=command):
                    out = _capture(self.c._dispatch, command)
                    self.assertIn('Not connected', out)
                    self.assertEqual(self._source_snapshot(source), before)
            self.c.sftp.put.assert_not_called()


class TestCmdMput(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_mput_uploads_matching_files(self):
        self.c.sftp.stat.side_effect = IOError('not found')
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            for name in ('a.log', 'b.log', 'c.txt'):
                with open(os.path.join(d, name), 'w') as f:
                    f.write('')
            self.c.cmd_mput(['*.log'])
        self.assertEqual(self.c.sftp.put.call_count, 2)

    def test_mput_expands_user_path_patterns(self):
        self.c.sftp.stat.side_effect = IOError('not found')
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, 'home')
            os.mkdir(home)
            with open(os.path.join(home, 'a.log'), 'w') as f:
                f.write('')
            original_expanduser = os.path.expanduser

            def fake_expanduser(path):
                if path.startswith('~/'):
                    return path.replace('~', home, 1)
                return original_expanduser(path)

            with patch('sftp_client.os.path.expanduser', side_effect=fake_expanduser):
                self.c.cmd_mput(['~/a*.log'])

        self.c.sftp.put.assert_called_once()

    def test_mput_no_matches_reports_message(self):
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            out = _capture(self.c.cmd_mput, ['*.log'])
        self.assertIn('no files match', out)
        self.c.sftp.put.assert_not_called()

    def test_mput_stops_after_first_error_in_play(self):
        self.c.sftp.stat.side_effect = IOError('not found')
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            for name in ('a.log', 'b.log'):
                with open(os.path.join(d, name), 'w') as f:
                    f.write('')
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as script:
                script.write('mput *.log\n')
                script_name = script.name
            try:
                self.c.sftp.put.side_effect = IOError('connection reset')
                _capture(self.c.cmd_play, [script_name])
            finally:
                os.unlink(script_name)
        self.assertEqual(self.c.sftp.put.call_count, 1)


class TestCmdDirPut(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.atomic = False

    def _make_tree(self, base):
        root = os.path.join(base, 'srcdir')
        os.mkdir(root)
        os.mkdir(os.path.join(root, 'subdir'))
        with open(os.path.join(root, 'a.txt'), 'w') as f:
            f.write('a')
        with open(os.path.join(root, 'subdir', 'b.txt'), 'w') as f:
            f.write('b')
        return root

    def test_dirput_reuses_parent_listing_on_generic_missing_errors(self):
        remote_dirs = {'/remote'}

        def stat(path):
            if path in remote_dirs:
                return _make_attr(os.path.basename(path), mode=0o040755)
            raise IOError('Failure')

        self.c.sftp.stat.side_effect = stat
        self.c.sftp.mkdir.side_effect = remote_dirs.add
        self.c.sftp.listdir.return_value = []
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, 'srcdir')
            os.mkdir(root)
            for name in ('a.txt', 'b.txt'):
                with open(os.path.join(root, name), 'w') as fh:
                    fh.write(name)
            self.c.cmd_dirput([root, '/remote/copy'])

        self.c.sftp.listdir.assert_called_once_with('/remote/copy')
        self.assertEqual(self.c.sftp.open.call_count, 2)

    def test_dirput_uploads_nested_tree_to_explicit_destination(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._make_tree(d)
            remote_dirs = _wire_remote_dirs(self.c, {'/remote'})
            self.c.cmd_dirput([root, '/remote/copy'])

        self.assertIn('/remote/copy', remote_dirs)
        self.assertIn('/remote/copy/subdir', remote_dirs)
        remote_paths = {call.args[0] for call in self.c.sftp.open.call_args_list}
        self.assertEqual(remote_paths, {
            '/remote/copy/a.txt',
            '/remote/copy/subdir/b.txt',
        })

    def test_dirput_default_destination_uses_local_basename(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._make_tree(d)
            self.c.local_cwd = d
            _wire_remote_dirs(self.c, {'/home', '/home/testuser'})
            self.c.cmd_dirput(['srcdir'])

        remote_paths = {call.args[0] for call in self.c.sftp.open.call_args_list}
        self.assertIn('/home/testuser/srcdir/a.txt', remote_paths)

    def test_dirput_existing_remote_directory_appends_local_basename(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._make_tree(d)
            _wire_remote_dirs(self.c, {'/uploads'})
            self.c.cmd_dirput([root, '/uploads'])

        remote_paths = {call.args[0] for call in self.c.sftp.open.call_args_list}
        self.assertIn('/uploads/srcdir/a.txt', remote_paths)

    def test_dirput_trailing_remote_slash_appends_local_basename(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._make_tree(d)
            _wire_remote_dirs(self.c, {'/uploads'})
            self.c.cmd_dirput([root, '/uploads/'])

        remote_paths = {call.args[0] for call in self.c.sftp.open.call_args_list}
        self.assertIn('/uploads/srcdir/subdir/b.txt', remote_paths)

    def test_dirput_local_path_must_be_directory(self):
        with tempfile.NamedTemporaryFile() as f:
            out = _capture(self.c.cmd_dirput, [f.name])
        self.assertIn('not a directory', out)
        self.c.sftp.put.assert_not_called()

    def test_dirput_missing_args_shows_usage(self):
        out = _capture(self.c.cmd_dirput, [])
        self.assertIn('Usage', out)
        self.c.sftp.put.assert_not_called()

    def test_dirput_reports_local_walk_errors(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._make_tree(d)
            _wire_remote_dirs(self.c, {'/remote'})

            def fail_walk(path, onerror=None):
                if onerror:
                    onerror(OSError('permission denied'))
                if False:
                    yield path, [], []

            with patch('sftp_client.os.walk', side_effect=fail_walk):
                out = _capture(self.c.cmd_dirput, [root, '/remote/copy'])

        self.assertIn('dirput:', out)
        self.assertIn('Permission denied', out)
        self.assertTrue(self.c._batch_had_error)
        self.c.sftp.put.assert_not_called()


class TestCmdMkdirRmdirRm(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_mkdir_calls_sftp_mkdir(self):
        self.c.cmd_mkdir(['/remote/newdir'])
        self.c.sftp.mkdir.assert_called_once_with('/remote/newdir')

    def test_mkdir_error_is_reported(self):
        self.c.sftp.mkdir.side_effect = IOError('already exists')
        out = _capture(self.c.cmd_mkdir, ['/remote/newdir'])
        self.assertIn('mkdir:', out)

    def test_rmdir_calls_sftp_rmdir(self):
        self.c.cmd_rmdir(['/remote/dir'])
        self.c.sftp.rmdir.assert_called_once_with('/remote/dir')

    def test_rm_calls_sftp_remove(self):
        self.c.cmd_rm(['/remote/file.txt'])
        self.c.sftp.remove.assert_called_once_with('/remote/file.txt')

    def test_rm_error_is_reported(self):
        self.c.sftp.remove.side_effect = IOError('not found')
        out = _capture(self.c.cmd_rm, ['/remote/missing.txt'])
        self.assertIn('rm:', out)


class TestCmdRename(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_rename_calls_sftp_rename(self):
        self.c.sftp.stat.side_effect = IOError('not found')
        self.c.cmd_rename(['/remote/old.txt', '/remote/new.txt'])
        self.c.sftp.rename.assert_called_once_with('/remote/old.txt', '/remote/new.txt')

    def test_rename_missing_dest_shows_usage(self):
        out = _capture(self.c.cmd_rename, ['/remote/only-one'])
        self.assertIn('Usage', out)
        self.c.sftp.rename.assert_not_called()

    def test_rename_error_is_reported(self):
        self.c.sftp.stat.side_effect = IOError('not found')
        self.c.sftp.rename.side_effect = IOError('no such file')
        out = _capture(self.c.cmd_rename, ['/remote/old', '/remote/new'])
        self.assertIn('rename:', out)

    def test_rename_force_overwrites_existing_destination(self):
        self.c.sftp.stat.return_value = _make_attr('new.txt')
        self.c.cmd_rename(['-f', '/remote/old.txt', '/remote/new.txt'])
        self.c.sftp.posix_rename.assert_called_once_with('/remote/old.txt', '/remote/new.txt')
        self.c.sftp.rename.assert_not_called()

    def test_rename_existing_destination_skipped_without_flag(self):
        self.c.sftp.stat.return_value = _make_attr('new.txt')
        out = _capture(self.c.cmd_rename, ['/remote/old.txt', '/remote/new.txt'])
        self.assertIn('already exists', out)
        self.c.sftp.rename.assert_not_called()
        self.c.sftp.posix_rename.assert_not_called()

    def test_rename_dangling_destination_skipped_without_force(self):
        self.c.sftp.stat.side_effect = FileNotFoundError('missing target')
        self.c.sftp.lstat.side_effect = None
        self.c.sftp.lstat.return_value = _make_attr('link', mode=0o120777)
        out = _capture(self.c.cmd_rename, ['/remote/old.txt', '/remote/link'])
        self.assertIn('already exists', out)
        self.c.sftp.rename.assert_not_called()

    def test_rename_force_overwrite_fallback_failure_gives_actionable_message(self):
        """A failed overwrite asks the user to verify remote state before retrying."""
        self.c.sftp.stat.return_value = _make_attr('new.txt')
        self.c.sftp.posix_rename.side_effect = IOError('not supported')
        self.c.sftp.rename.side_effect = IOError('file already exists')
        out = _capture(self.c.cmd_rename, ['-f', '/remote/old.txt', '/remote/new.txt'])
        self.assertIn('could not overwrite', out)
        self.assertIn('Check', out)
        self.assertNotIn('left unchanged', out)

    def test_rename_timeout_after_commit_is_not_retried(self):
        self.c.sftp.stat.return_value = _make_attr('new.txt')
        remote_files = {'/remote/old.txt': b'new', '/remote/new.txt': b'old'}

        def committed_but_timed_out(old, new):
            remote_files[new] = remote_files.pop(old)
            raise TimeoutError('response timed out')

        self.c.sftp.posix_rename.side_effect = committed_but_timed_out
        out = _capture(self.c.cmd_rename, ['-f', '/remote/old.txt', '/remote/new.txt'])
        self.assertEqual(remote_files, {'/remote/new.txt': b'new'})
        self.c.sftp.rename.assert_not_called()
        self.assertIn('may already have completed', out)


class TestCmdChmod(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_chmod_valid_octal_mode(self):
        self.c.cmd_chmod(['644', '/remote/file.txt'])
        self.c.sftp.chmod.assert_called_once_with('/remote/file.txt', 0o644)

    def test_chmod_non_octal_string_shows_error(self):
        out = _capture(self.c.cmd_chmod, ['notoctal', '/remote/file.txt'])
        self.assertIn('octal', out)
        self.c.sftp.chmod.assert_not_called()

    def test_chmod_error_is_reported(self):
        self.c.sftp.chmod.side_effect = IOError('permission denied')
        out = _capture(self.c.cmd_chmod, ['755', '/remote/file.txt'])
        self.assertIn('chmod:', out)


class TestCmdChownChgrp(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_chown_passes_new_uid_with_existing_gid(self):
        self.c.sftp.stat.return_value = _make_attr('f', uid=1000, gid=500)
        self.c.cmd_chown(['2000', '/file.txt'])
        self.c.sftp.chown.assert_called_once_with('/file.txt', 2000, 500)

    def test_chown_none_gid_reports_error_and_does_not_call_chown(self):
        """REGRESSION BUG 6: st_gid=None must not be forwarded to sftp.chown()."""
        attr = _make_attr('f'); attr.st_gid = None
        self.c.sftp.stat.return_value = attr
        out = _capture(self.c.cmd_chown, ['2000', '/file.txt'])
        self.c.sftp.chown.assert_not_called()
        self.assertIn('gid', out)

    def test_chown_non_numeric_uid_shows_error(self):
        out = _capture(self.c.cmd_chown, ['NaN', '/file.txt'])
        self.assertIn('uid must be a number', out)
        self.c.sftp.chown.assert_not_called()

    def test_chgrp_passes_new_gid_with_existing_uid(self):
        self.c.sftp.stat.return_value = _make_attr('f', uid=1000, gid=500)
        self.c.cmd_chgrp(['2000', '/file.txt'])
        self.c.sftp.chown.assert_called_once_with('/file.txt', 1000, 2000)

    def test_chgrp_none_uid_reports_error_and_does_not_call_chown(self):
        """REGRESSION BUG 7: st_uid=None must not be forwarded to sftp.chown()."""
        attr = _make_attr('f'); attr.st_uid = None
        self.c.sftp.stat.return_value = attr
        out = _capture(self.c.cmd_chgrp, ['2000', '/file.txt'])
        self.c.sftp.chown.assert_not_called()
        self.assertIn('uid', out)

    def test_chgrp_non_numeric_gid_shows_error(self):
        out = _capture(self.c.cmd_chgrp, ['NaN', '/file.txt'])
        self.assertIn('gid must be a number', out)
        self.c.sftp.chown.assert_not_called()


class TestCmdStat(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_stat_shows_all_fields(self):
        attr = _make_attr('file.txt', mode=0o100644, size=4096, uid=1001, gid=1001)
        self.c.sftp.stat.return_value = attr
        out = _capture(self.c.cmd_stat, ['file.txt'])
        self.assertIn('4096', out)
        self.assertIn('1001', out)
        self.assertIn('644', out)

    def test_stat_none_size_not_printed(self):
        """REGRESSION BUG 5: st_size=None must not appear as 'Size: None'."""
        attr = _make_attr('f'); attr.st_size = None
        self.c.sftp.stat.return_value = attr
        out = _capture(self.c.cmd_stat, ['f'])
        self.assertNotIn('None', out)

    def test_stat_none_uid_gid_shows_question_mark(self):
        """REGRESSION BUG 5: st_uid/st_gid=None must show '?' not 'None'."""
        attr = _make_attr('f'); attr.st_uid = None; attr.st_gid = None
        self.c.sftp.stat.return_value = attr
        out = _capture(self.c.cmd_stat, ['f'])
        self.assertIn('?', out)
        self.assertNotIn('None', out)

    def test_stat_error_is_reported(self):
        self.c.sftp.stat.side_effect = IOError('no such file')
        out = _capture(self.c.cmd_stat, ['missing.txt'])
        self.assertIn('stat:', out)


class TestCmdViewRemote(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_rcat_prints_file_content(self):
        _wire_remote_file(self.c, b'hello world\n')
        out = _capture(self.c.cmd_rcat, ['/remote/file.txt'])
        self.assertIn('hello world', out)

    def test_rcat_streams_in_chunks(self):
        fh = _wire_remote_file(self.c, b'a' * (70 * 1024 - 1) + b'\n')
        out = _capture(self.c.cmd_rcat, ['/remote/file.txt'])
        self.assertEqual(len(out), 70 * 1024)
        self.assertGreater(fh.read.call_count, 1)

    def test_rcat_preserves_utf8_split_across_chunks(self):
        fh = MagicMock()
        fh.read.side_effect = [b'\xe2\x82', b'\xac\n', b'']
        self.c.sftp.open.return_value.__enter__.return_value = fh
        out = _capture(self.c.cmd_rcat, ['/remote/file.txt'])
        self.assertEqual(out, '€\n')

    def test_rcat_error_is_reported(self):
        self.c.sftp.open.side_effect = IOError('not found')
        out = _capture(self.c.cmd_rcat, ['/remote/missing.txt'])
        self.assertIn('rcat:', out)

    def test_rhead_reads_default_10_lines(self):
        _wire_remote_file(self.c, b''.join(f'line{i}\n'.encode() for i in range(20)))
        out = _capture(self.c.cmd_rhead, ['/remote/file.txt'])
        self.assertEqual(out.count('line'), 10)

    def test_rhead_n_flag_overrides_default(self):
        _wire_remote_file(self.c, b''.join(f'line{i}\n'.encode() for i in range(20)))
        out = _capture(self.c.cmd_rhead, ['-n', '3', '/remote/file.txt'])
        self.assertEqual(out, 'line0\nline1\nline2\n')

    def test_rhead_stops_early_at_eof(self):
        _wire_remote_file(self.c, b'only\ntwo\n')
        out = _capture(self.c.cmd_rhead, ['/remote/file.txt'])
        self.assertEqual(out, 'only\ntwo\n')

    def test_rtail_returns_last_n_lines(self):
        content = b''.join(f'line{i}\n'.encode() for i in range(20))
        _wire_remote_file(self.c, content)
        out = _capture(self.c.cmd_rtail, ['/remote/file.txt'])
        self.assertIn('line19', out)
        # line0 through line9 must not appear (they are in the first half)
        self.assertNotIn('line0\n', out)

    def test_rtail_n_flag(self):
        content = b''.join(f'line{i}\n'.encode() for i in range(20))
        fh = _wire_remote_file(self.c, content)
        out = _capture(self.c.cmd_rtail, ['-n', '2', '/remote/file.txt'])
        self.assertEqual(out.count('line'), 2)
        self.assertIn('line19', out)
        fh.seek.assert_called()

    def test_rtail_falls_back_to_streaming_when_size_unavailable(self):
        content = b''.join(f'line{i}\n'.encode() for i in range(20))
        fh = _wire_remote_file(self.c, content)
        fh.stat.side_effect = IOError('no size')
        out = _capture(self.c.cmd_rtail, ['-n', '3', '/remote/file.txt'])
        self.assertEqual(out.count('line'), 3)
        self.assertIn('line19', out)

    def test_rtail_stale_oversized_stat_falls_back_after_empty_read(self):
        content = b''.join(f'line{i}\n'.encode() for i in range(20))
        fh = _wire_remote_file(self.c, content)
        fh.stat.return_value.st_size = len(content) + 1024 * 1024
        out = _capture(self.c.cmd_rtail, ['-n', '3', '/remote/file.txt'])
        self.assertIn('line19', out)
        self.assertLessEqual(fh.read.call_count, 3)

    def test_rtail_forward_keeps_crlf_together_across_chunks(self):
        lines = self.c._tail_remote_lines_forward(io.BytesIO(b'ab\r\ncd\r\n'), 2, 3)
        self.assertEqual(lines, ['ab\r\n', 'cd\r\n'])

    def test_rtail_rejects_unbounded_line_when_seeking_backward(self):
        _wire_remote_file(self.c, b'x' * 100)
        with patch('sftp_client._MAX_TAIL_BUFFER_BYTES', 64):
            out = _capture(self.c.cmd_rtail, ['/remote/file.txt'])
        self.assertIn('Tail output exceeds 64 buffered bytes', out)

    def test_rtail_rejects_unbounded_line_when_streaming_forward(self):
        fh = _wire_remote_file(self.c, b'x' * 100)
        fh.stat.side_effect = OSError('size unavailable')
        with patch('sftp_client._MAX_TAIL_BUFFER_BYTES', 64):
            out = _capture(self.c.cmd_rtail, ['/remote/file.txt'])
        self.assertIn('Tail output exceeds 64 buffered bytes', out)

    def test_rtail_rejects_excessive_line_count_before_reading(self):
        fh = _wire_remote_file(self.c, b'one\n')
        with patch('sftp_client._MAX_TAIL_LINES', 2):
            out = _capture(self.c.cmd_rtail, ['-n', '3', '/remote/file.txt'])
        self.assertIn('Tail line count exceeds 2', out)
        fh.read.assert_not_called()


class TestCmdViewLocal(unittest.TestCase):

    def test_cat_reads_in_bounded_chunks(self):
        c = _make_client()

        class BoundedReadFile(io.StringIO):
            def read(self, size=-1):
                if size != 64 * 1024:
                    raise AssertionError('cat must use bounded reads')
                return super().read(size)

        data = 'x' * (128 * 1024 + 6) + '\n'
        with patch('builtins.open', return_value=BoundedReadFile(data)):
            out = _capture(c.cmd_cat, ['/tmp/large.txt'])
        self.assertEqual(out, data)

    def test_tail_streams_lines_without_readlines(self):
        c = _make_client()

        class IterOnlyFile(io.StringIO):
            def readlines(self, *args):
                raise AssertionError('tail must not read every line')

        with patch('builtins.open', return_value=IterOnlyFile('first\nsecond\nthird\n')):
            out = _capture(c.cmd_tail, ['-n', '2', '/tmp/file.txt'])
        self.assertEqual(out, 'second\nthird\n')

    def test_cat_prints_local_file(self):
        c = _make_client()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('cat test content\n'); fname = f.name
        try:
            out = _capture(c.cmd_cat, [fname])
            self.assertIn('cat test content', out)
        finally:
            os.unlink(fname)

    def test_head_default_10_lines(self):
        c = _make_client()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for i in range(20): f.write(f'line{i}\n')
            fname = f.name
        try:
            out = _capture(c.cmd_head, [fname])
            self.assertEqual(out.count('line'), 10)
        finally:
            os.unlink(fname)

    def test_tail_default_10_lines_returns_last(self):
        c = _make_client()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for i in range(20): f.write(f'line{i}\n')
            fname = f.name
        try:
            out = _capture(c.cmd_tail, [fname])
            self.assertIn('line19', out)
            self.assertNotIn('line0\n', out)
        finally:
            os.unlink(fname)

    def test_lls_lists_local_directory(self):
        c = _make_client()
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'local.txt'), 'w') as f: f.write('')
            c.local_cwd = d
            out = _capture(c.cmd_lls, [])
            self.assertIn('local.txt', out)

    def test_lls_missing_path_reports_error(self):
        c = _make_client()
        out = _capture(c.cmd_lls, ['/definitely/not/here'])
        self.assertIn('lls:', out)
        self.assertTrue(c._batch_had_error)


class TestCmdNew(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.sftp.lstat.side_effect = FileNotFoundError('not found')

    def test_new_plain_content(self):
        self.c.cmd_new(['/remote/file.txt', 'hello world'])
        fh = self.c.sftp.open.return_value.__enter__.return_value
        fh.write.assert_called_once_with(b'hello world')
        staged = self.c.sftp.open.call_args.args[0]
        self.assertNotEqual(staged, '/remote/file.txt')
        self.assertTrue(staged.endswith('.tmp'))
        self.c.sftp.rename.assert_called_once_with(staged, '/remote/file.txt')
        self.c.sftp.posix_rename.assert_not_called()

    def test_new_skips_existing_destination_without_overwrite_flag(self):
        self.c.sftp.lstat.side_effect = None
        self.c.sftp.lstat.return_value = _make_attr('file.txt')
        out = _capture(self.c.cmd_new, ['/remote/file.txt', 'replacement'])
        self.assertIn('already exists', out)
        self.c.sftp.open.assert_not_called()

    def test_new_force_replaces_existing_destination(self):
        self.c.sftp.lstat.side_effect = None
        self.c.sftp.lstat.return_value = _make_attr('file.txt')
        self.c.cmd_new(['-f', '/remote/file.txt', 'replacement'])
        staged = self.c.sftp.open.call_args.args[0]
        self.c.sftp.posix_rename.assert_called_once_with(staged, '/remote/file.txt')

    def test_new_does_not_clobber_destination_created_during_write(self):
        self.c.sftp.rename.side_effect = FileExistsError('created concurrently')
        out = _capture(self.c.cmd_new, ['/remote/file.txt', 'content'])
        staged = self.c.sftp.open.call_args.args[0]
        self.assertIn('new:', out)
        self.c.sftp.posix_rename.assert_not_called()
        self.c.sftp.remove.assert_called_once_with(staged)

    def test_new_repeat_syntax_survives_command_parsing(self):
        self.c._dispatch('new /remote/file.txt %REP% "abc def" 2')
        fh = self.c.sftp.open.return_value.__enter__.return_value
        fh.write.assert_called_once_with(b'abc defabc def')

    def test_new_repeat_preserves_unicode_and_escapes(self):
        self.c._dispatch(r'new /remote/file.txt %REP% "é\n" 2')
        fh = self.c.sftp.open.return_value.__enter__.return_value
        fh.write.assert_called_once_with('é\né\n'.encode('utf-8'))

    def test_new_interrupt_cleans_up_staged_remote_file(self):
        fh = self.c.sftp.open.return_value.__enter__.return_value
        fh.write.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.c.cmd_new(['/remote/file.txt', 'content'])
        staged = self.c.sftp.open.call_args.args[0]
        self.c.sftp.remove.assert_called_once_with(staged)

    def test_new_with_date_token(self):
        today = datetime.datetime.now().strftime('%Y-%m-%d')
        self.c.cmd_new(['/remote/file.txt', '%DATE%'])
        fh = self.c.sftp.open.return_value.__enter__.return_value
        fh.write.assert_called_once_with(today.encode('utf-8'))

    def test_new_with_escape_sequence(self):
        self.c.cmd_new(['/remote/file.txt', r'line1\nline2'])
        fh = self.c.sftp.open.return_value.__enter__.return_value
        fh.write.assert_called_once_with(b'line1\nline2')

    def test_new_too_few_args_shows_usage(self):
        out = _capture(self.c.cmd_new, ['/remote/file.txt'])
        self.assertIn('Usage', out)
        self.c.sftp.open.assert_not_called()

    def test_new_write_error_is_reported(self):
        fh = self.c.sftp.open.return_value.__enter__.return_value
        fh.write.side_effect = IOError('disk full')
        out = _capture(self.c.cmd_new, ['/remote/file.txt', 'content'])
        self.assertIn('new:', out)
        staged = self.c.sftp.open.call_args.args[0]
        self.c.sftp.remove.assert_called_once_with(staged)
        self.c.sftp.posix_rename.assert_not_called()

    def test_new_rejects_large_standalone_repeat_before_remote_write(self):
        with patch('sftp_client._MAX_NEW_CONTENT_BYTES', 64):
            out = _capture(self.c.cmd_new, ['/remote/file.txt', '%REP%', 'x', '65'])
        self.assertIn('Content exceeds 64 bytes', out)
        self.c.sftp.open.assert_not_called()

    def test_new_rejects_large_inline_repeat_before_remote_write(self):
        with patch('sftp_client._MAX_NEW_CONTENT_BYTES', 64):
            out = _capture(self.c.cmd_new, ['/remote/file.txt', '%REP% "x" 65'])
        self.assertIn('Content exceeds 64 bytes', out)
        self.c.sftp.open.assert_not_called()

    def test_new_rejects_encoded_content_beyond_limit(self):
        with patch('sftp_client._MAX_NEW_CONTENT_BYTES', 64):
            out = _capture(self.c.cmd_new, ['/remote/file.txt', 'é' * 33])
        self.assertIn('Content exceeds 64 bytes', out)
        self.c.sftp.open.assert_not_called()

    def test_new_reports_unremoved_temporary_file(self):
        fh = self.c.sftp.open.return_value.__enter__.return_value
        fh.write.side_effect = OSError('disk full')
        self.c.sftp.remove.side_effect = OSError('connection lost')
        out = _capture(self.c.cmd_new, ['/remote/file.txt', 'content'])
        tmp = self.c.sftp.open.call_args.args[0]
        self.assertIn(tmp, out)
        self.assertIn('could not be removed', out)


class TestCmdSymlink(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_symlink_calls_sftp_symlink(self):
        self.c.sftp.stat.side_effect = IOError('not found')
        self.c.cmd_symlink(['../target', '/remote/link'])
        self.c.sftp.symlink.assert_called_once_with('../target', '/remote/link')

    def test_ln_s_is_alias_for_symlink(self):
        self.c.sftp.stat.side_effect = IOError('not found')
        self.c.cmd_ln(['-s', '../target', '/remote/link'])
        self.c.sftp.symlink.assert_called_once_with('../target', '/remote/link')

    def test_symlink_missing_dest_shows_usage(self):
        out = _capture(self.c.cmd_symlink, ['/only-one'])
        self.assertIn('Usage', out)
        self.c.sftp.symlink.assert_not_called()

    def test_symlink_force_overwrites_via_atomic_temp_swap(self):
        """Overwrite must create the new link at a temp path and atomically swap
        it into place, never remove()-ing the destination directly: a failed
        symlink() must not leave the destination missing."""
        self.c.sftp.stat.return_value = _make_attr('link')
        self.c.cmd_symlink(['-f', '../target', '/remote/link'])
        tmp = self.c.sftp.symlink.call_args[0][1]
        self.assertTrue(tmp.startswith('/remote/.sftp-'))
        self.assertNotEqual(tmp, '/remote/link')
        self.c.sftp.posix_rename.assert_called_once_with(tmp, '/remote/link')
        self.c.sftp.remove.assert_not_called()

    def test_symlink_force_cleans_up_temp_and_preserves_destination_on_failure(self):
        self.c.sftp.stat.return_value = _make_attr('link')
        self.c.sftp.symlink.side_effect = IOError('permission denied')
        out = _capture(self.c.cmd_symlink, ['-f', '../target', '/remote/link'])
        self.assertIn('symlink:', out)
        # The original /remote/link is never touched by remove() -- only the
        # (never-created) temp path cleanup is attempted.
        self.c.sftp.remove.assert_called_once()
        removed = self.c.sftp.remove.call_args[0][0]
        self.assertTrue(removed.startswith('/remote/.sftp-'))
        self.assertNotEqual(removed, '/remote/link')

    def test_symlink_interrupt_cleans_up_staged_link(self):
        self.c.sftp.stat.return_value = _make_attr('link')
        self.c.sftp.symlink.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.c.cmd_symlink(['-f', '../target', '/remote/link'])
        staged = self.c.sftp.symlink.call_args.args[1]
        self.c.sftp.remove.assert_called_once_with(staged)

    def test_symlink_existing_destination_skipped_without_flag(self):
        self.c.sftp.stat.return_value = _make_attr('link')
        out = _capture(self.c.cmd_symlink, ['../target', '/remote/link'])
        self.assertIn('already exists', out)
        self.c.sftp.symlink.assert_not_called()
        self.c.sftp.remove.assert_not_called()

    def test_symlink_force_replaces_dangling_destination(self):
        self.c.sftp.stat.side_effect = FileNotFoundError('missing target')
        self.c.sftp.lstat.side_effect = None
        self.c.sftp.lstat.return_value = _make_attr('link', mode=0o120777)
        self.c.cmd_symlink(['-f', '../target', '/remote/link'])
        staged = self.c.sftp.symlink.call_args.args[1]
        self.assertNotEqual(staged, '/remote/link')
        self.c.sftp.posix_rename.assert_called_once_with(staged, '/remote/link')


class TestOverwriteProtection(unittest.TestCase):
    """-f / -i flags shared by get/put/dirput/mget/mput/rename/symlink."""

    def setUp(self):
        self.c = _make_client()
        # -i's prompt requires an interactive terminal; tests that exercise the
        # prompt itself run as if stdin were a tty, individual tests override
        # this to verify the non-interactive guard.
        patcher = patch('sys.stdin.isatty', return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_get_default_skips_existing_local_destination(self):
        with tempfile.NamedTemporaryFile() as f:
            out = _capture(self.c.cmd_get, ['/remote/file.txt', f.name])
        self.assertIn('already exists', out)
        self.c.sftp.get.assert_not_called()

    def test_get_force_overwrites_existing_local_destination(self):
        with tempfile.NamedTemporaryFile() as f:
            self.c.cmd_get(['-f', '/remote/file.txt', f.name])
        self.c.sftp.get.assert_called_once()

    def test_get_confirm_yes_overwrites(self):
        with tempfile.NamedTemporaryFile() as f:
            with patch('builtins.input', return_value='y'):
                self.c.cmd_get(['-i', '/remote/file.txt', f.name])
        self.c.sftp.get.assert_called_once()

    def test_get_confirm_no_skips(self):
        with tempfile.NamedTemporaryFile() as f:
            with patch('builtins.input', return_value='n'):
                self.c.cmd_get(['-i', '/remote/file.txt', f.name])
        self.c.sftp.get.assert_not_called()

    def test_get_confirm_reprompts_on_invalid_answer(self):
        with tempfile.NamedTemporaryFile() as f:
            with patch('builtins.input', side_effect=['bogus', 'y']) as mock_input:
                self.c.cmd_get(['-i', '/remote/file.txt', f.name])
        self.c.sftp.get.assert_called_once()
        self.assertEqual(mock_input.call_count, 2)

    def test_confirm_prompt_aborts_without_blocking_when_stdin_is_not_a_tty(self):
        """-i must never call input() when stdin isn't a terminal -- on a
        still-open, never-written-to pipe (e.g. launched from a supervisor)
        that would block forever instead of aborting."""
        with tempfile.NamedTemporaryFile() as f:
            with patch('sys.stdin.isatty', return_value=False), \
                 patch('builtins.input') as mock_input:
                out = _capture(self.c.cmd_get, ['-i', '/remote/file.txt', f.name])
        mock_input.assert_not_called()
        self.assertIn('interactive terminal', out)
        self.c.sftp.get.assert_not_called()

    def test_mget_confirm_aborts_entire_batch_when_stdin_is_not_a_tty(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('a.log', mode=0o100644),
            _make_attr('b.log', mode=0o100644),
        ]
        with tempfile.TemporaryDirectory() as d:
            for name in ('a.log', 'b.log'):
                with open(os.path.join(d, name), 'w') as f:
                    f.write('existing')
            self.c.local_cwd = d
            with patch('sys.stdin.isatty', return_value=False), \
                 patch('builtins.input') as mock_input:
                self.c.cmd_mget(['-i', '*.log'])
        mock_input.assert_not_called()
        self.c.sftp.get.assert_not_called()

    def test_put_default_skips_existing_remote_destination(self):
        self.c.sftp.stat.return_value = _make_attr('dest.txt')
        with tempfile.NamedTemporaryFile() as f:
            out = _capture(self.c.cmd_put, [f.name, '/remote/dest.txt'])
        self.assertIn('already exists', out)
        self.c.sftp.put.assert_not_called()

    def test_put_force_overwrites_existing_remote_destination(self):
        self.c.sftp.stat.return_value = _make_attr('dest.txt')
        self.c.atomic = False
        with tempfile.NamedTemporaryFile() as f:
            self.c.cmd_put(['-f', f.name, '/remote/dest.txt'])
        self.c.sftp.put.assert_called_once()

    def test_put_generic_stat_failure_checks_remote_parent_for_missing_file(self):
        """Servers that report SSH_FX_FAILURE for a missing path must not make
        every local source file look like an existing remote destination."""
        self.c.atomic = False
        self.c.sftp.stat.side_effect = IOError('Failure')
        self.c.sftp.listdir.return_value = []
        with tempfile.NamedTemporaryFile() as f:
            out = _capture(self.c.cmd_put, [f.name, '/remote/new.txt'])
        self.assertNotIn('already exists', out)
        self.c.sftp.listdir.assert_called_once_with('/remote')
        self.c.sftp.open.assert_called_once_with('/remote/new.txt', 'wxb')

    def test_put_generic_stat_failure_still_detects_remote_existing_file(self):
        self.c.sftp.stat.side_effect = IOError('Failure')
        self.c.sftp.listdir.return_value = ['dest.txt']
        with tempfile.NamedTemporaryFile() as f:
            out = _capture(self.c.cmd_put, [f.name, '/remote/dest.txt'])
        self.assertIn('already exists', out)
        self.c.sftp.put.assert_not_called()

    def test_put_does_not_claim_file_exists_when_remote_checks_both_fail(self):
        self.c.sftp.stat.side_effect = IOError('Failure')
        self.c.sftp.listdir.side_effect = IOError('permission denied')
        with tempfile.NamedTemporaryFile() as f:
            out = _capture(self.c.cmd_put, [f.name, '/remote/new.txt'])
        self.assertIn('could not check remote destination', out)
        self.assertNotIn('already exists', out)
        self.c.sftp.put.assert_not_called()

    def test_mget_confirm_all_overwrites_remaining_matches(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('a.log', mode=0o100644),
            _make_attr('b.log', mode=0o100644),
        ]
        with tempfile.TemporaryDirectory() as d:
            for name in ('a.log', 'b.log'):
                with open(os.path.join(d, name), 'w') as f:
                    f.write('existing')
            self.c.local_cwd = d
            with patch('builtins.input', side_effect=['a']):
                self.c.cmd_mget(['-i', '*.log'])
        self.assertEqual(self.c.sftp.get.call_count, 2)

    def test_mget_confirm_quit_stops_remaining_matches(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('a.log', mode=0o100644),
            _make_attr('b.log', mode=0o100644),
        ]
        with tempfile.TemporaryDirectory() as d:
            for name in ('a.log', 'b.log'):
                with open(os.path.join(d, name), 'w') as f:
                    f.write('existing')
            self.c.local_cwd = d
            with patch('builtins.input', side_effect=['q']):
                self.c.cmd_mget(['-i', '*.log'])
        self.c.sftp.get.assert_not_called()

    def test_mput_default_skips_existing_and_reports_count(self):
        self.c.sftp.stat.return_value = _make_attr('a.log')
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            with open(os.path.join(d, 'a.log'), 'w') as f:
                f.write('')
            out = _capture(self.c.cmd_mput, ['*.log'])
        self.assertIn('skipped 1 existing file', out)
        self.c.sftp.put.assert_not_called()

    def test_mput_force_overwrites_existing_matches(self):
        self.c.sftp.stat.return_value = _make_attr('a.log')
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            with open(os.path.join(d, 'a.log'), 'w') as f:
                f.write('')
            self.c.cmd_mput(['-f', '*.log'])
        self.c.sftp.put.assert_called_once()

    def test_mput_generic_stat_failure_checks_remote_parent_for_each_match(self):
        self.c.sftp.stat.side_effect = IOError('Failure')
        self.c.sftp.listdir.return_value = []
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            for name in ('a.log', 'b.log'):
                with open(os.path.join(d, name), 'w') as f:
                    f.write('')
            out = _capture(self.c.cmd_mput, ['*.log'])
        self.assertNotIn('already exists', out)
        self.c.sftp.listdir.assert_called_once_with('/home/testuser')
        self.assertEqual(self.c.sftp.put.call_count, 2)

    def test_mput_force_overwrite_uses_atomic_path_even_with_atomic_off(self):
        """Overwriting an existing match must go through the temp+rename path
        regardless of the global atomic setting, so a failed upload can't
        truncate the file that was already there."""
        self.c.atomic = False
        self.c.sftp.stat.return_value = _make_attr('a.log')
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            with open(os.path.join(d, 'a.log'), 'w') as f:
                f.write('')
            self.c.cmd_mput(['-f', '*.log'])
        tmp = self.c.sftp.put.call_args[0][1]
        self.assertTrue(tmp.endswith('.tmp'))
        self.c.sftp.posix_rename.assert_called_once()

    def test_dirput_confirm_all_overwrites_remaining_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, 'srcdir')
            os.mkdir(root)
            with open(os.path.join(root, 'a.txt'), 'w') as f:
                f.write('a')
            with open(os.path.join(root, 'b.txt'), 'w') as f:
                f.write('b')

            remote_dirs = {'/remote'}
            existing_files = {'/remote/copy/a.txt', '/remote/copy/b.txt'}

            def stat(path):
                normalized = path.rstrip('/') or '/'
                if normalized in remote_dirs:
                    return _make_attr(os.path.basename(normalized), mode=0o040755)
                if normalized in existing_files:
                    return _make_attr(os.path.basename(normalized), mode=0o100644)
                raise IOError('not found')

            def mkdir(path):
                remote_dirs.add(path.rstrip('/') or '/')

            self.c.sftp.stat.side_effect = stat
            self.c.sftp.mkdir.side_effect = mkdir

            with patch('builtins.input', side_effect=['a']):
                self.c.cmd_dirput(['-i', root, '/remote/copy'])

        self.assertEqual(self.c.sftp.put.call_count, 2)

    def test_dirput_default_skips_existing_files_and_reports_count(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, 'srcdir')
            os.mkdir(root)
            with open(os.path.join(root, 'a.txt'), 'w') as f:
                f.write('a')

            remote_dirs = {'/remote'}
            existing_files = {'/remote/copy/a.txt'}

            def stat(path):
                normalized = path.rstrip('/') or '/'
                if normalized in remote_dirs:
                    return _make_attr(os.path.basename(normalized), mode=0o040755)
                if normalized in existing_files:
                    return _make_attr(os.path.basename(normalized), mode=0o100644)
                raise IOError('not found')

            self.c.sftp.stat.side_effect = stat
            self.c.sftp.mkdir.side_effect = lambda path: remote_dirs.add(path.rstrip('/') or '/')

            out = _capture(self.c.cmd_dirput, [root, '/remote/copy'])

        self.assertIn('skipped 1 existing file', out)
        self.c.sftp.put.assert_not_called()

    def test_dirput_force_overwrite_uses_atomic_path_even_with_atomic_off(self):
        self.c.atomic = False
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, 'srcdir')
            os.mkdir(root)
            with open(os.path.join(root, 'a.txt'), 'w') as f:
                f.write('a')

            remote_dirs = {'/remote'}
            existing_files = {'/remote/copy/a.txt'}

            def stat(path):
                normalized = path.rstrip('/') or '/'
                if normalized in remote_dirs:
                    return _make_attr(os.path.basename(normalized), mode=0o040755)
                if normalized in existing_files:
                    return _make_attr(os.path.basename(normalized), mode=0o100644)
                raise IOError('not found')

            self.c.sftp.stat.side_effect = stat
            self.c.sftp.mkdir.side_effect = lambda path: remote_dirs.add(path.rstrip('/') or '/')

            self.c.cmd_dirput(['-f', root, '/remote/copy'])

        tmp = self.c.sftp.put.call_args[0][1]
        self.assertTrue(tmp.startswith('/remote/copy/.sftp-'))
        self.assertTrue(tmp.endswith('.tmp'))
        self.c.sftp.posix_rename.assert_called_once()


class TestCmdPlay(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_play_does_not_echo_content_or_shell_arguments(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as script:
            script.write('new /remote/config "opaque-payload-marker"\n')
            script.write('!printf opaque-payload-marker\n')
            path = script.name
        try:
            self.c.sftp.lstat.side_effect = FileNotFoundError('not found')
            with patch.object(self.c, 'cmd_shell'):
                out = _capture(self.c.cmd_play, [path])
            self.assertNotIn('opaque-payload-marker', out)
            logged = ' '.join(str(call) for call in self.c.logger.info.call_args_list)
            self.assertNotIn('opaque-payload-marker', logged)
        finally:
            os.unlink(path)

    def test_play_executes_commands_from_script(self):
        self.c.sftp.listdir_attr.return_value = [_make_attr('f.txt', mode=0o100644)]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('# comment\n\nls\n'); fname = f.name
        try:
            out = _capture(self.c.cmd_play, [fname])
            self.assertIn('f.txt', out)
        finally:
            os.unlink(fname)

    def test_play_skips_comments_and_blank_lines(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('# only a comment\n\n'); fname = f.name
        try:
            _capture(self.c.cmd_play, [fname])
            self.c.sftp.listdir_attr.assert_not_called()
        finally:
            os.unlink(fname)

    def test_play_missing_script_file_is_reported(self):
        out = _capture(self.c.cmd_play, ['/nonexistent/script.sftp'])
        self.assertIn('play:', out)

    def test_nested_play_resolves_relative_to_parent_script(self):
        with tempfile.TemporaryDirectory() as script_dir:
            main_script = os.path.join(script_dir, 'main.sftp')
            child_script = os.path.join(script_dir, 'child.sftp')
            with open(main_script, 'w', encoding='utf-8') as f:
                f.write('play child.sftp\n')
            with open(child_script, 'w', encoding='utf-8') as f:
                f.write('atomic on\n')
            self.c.local_cwd = tempfile.gettempdir()

            _capture(self.c.cmd_play, [main_script])

        self.assertTrue(self.c.atomic)

    def test_play_streams_script_without_readlines(self):
        class IterOnlyFile(io.StringIO):
            def readlines(self, *args):
                raise AssertionError('play must not read the whole script')

        with patch('builtins.open', return_value=IterOnlyFile('version\nhelp\n')):
            with patch.object(self.c, '_dispatch') as dispatch:
                self.c.cmd_play(['/tmp/script.sftp'])
        self.assertEqual([call.args[0] for call in dispatch.call_args_list], ['version', 'help'])

    def test_play_stream_read_error_restores_script_state(self):
        with tempfile.NamedTemporaryFile(suffix='.sftp', delete=False) as script:
            script.write(b'version\n\xff')
            path = script.name
        try:
            out = _capture(self.c.cmd_play, [path])
        finally:
            os.unlink(path)
        self.assertIn('play:', out)
        self.assertTrue(self.c._batch_had_error)
        self.assertEqual(self.c._play_depth, 0)
        self.assertEqual(self.c._script_dir_stack, [])


# ══════════════════════════════════════════════════════════════════════════════
# Tab-completion tests
# ══════════════════════════════════════════════════════════════════════════════

class TestCompleter(unittest.TestCase):
    def setUp(self):
        self.c   = _make_client()
        self.cmp = _Completer(self.c)

    def _route_for(self, line, text):
        local_matches = ['LOCAL ']
        remote_matches = ['REMOTE ']
        with patch.object(self.cmp, '_local', return_value=local_matches), \
             patch.object(self.cmp, '_remote', return_value=remote_matches):
            results = self.cmp._build_from_line(line, text)
        if results == local_matches:
            return 'local'
        if results == remote_matches:
            return 'remote'
        if results == []:
            return None
        return results

    def _readline_matches(self, line, text, beg, end):
        fake_readline = MagicMock()
        fake_readline.get_line_buffer.return_value = line
        fake_readline.get_begidx.return_value = beg
        fake_readline.get_endidx.return_value = end
        with patch.object(sftp_client, 'readline', fake_readline):
            return self.cmp._build(text)

    def test_local_first_commands_complete_first_arg_locally(self):
        commands = {'put', 'dirput', 'mput', 'lls', 'lcd', 'lmkdir', 'play', 'cat'}
        for cmd in sorted(commands):
            with self.subTest(cmd=cmd):
                self.assertEqual(self._route_for(f'{cmd} pa', 'pa'), 'local')

    def test_remote_first_commands_complete_first_arg_remotely(self):
        commands = {
            'get', 'mget', 'ls', 'dir', 'cd', 'mkdir', 'rmdir', 'rm', 'delete',
            'rename', 'stat', 'ln', 'symlink', 'new', 'rcat',
        }
        for cmd in sorted(commands):
            with self.subTest(cmd=cmd):
                self.assertEqual(self._route_for(f'{cmd} pa', 'pa'), 'remote')

    def test_mixed_local_remote_commands_complete_later_path_args_correctly(self):
        self.assertEqual(self._route_for('get remote lo', 'lo'), 'local')
        for cmd in ('put', 'dirput'):
            with self.subTest(cmd=cmd):
                self.assertEqual(self._route_for(f'{cmd} local re', 're'), 'remote')
                self.assertEqual(self._route_for(f'{cmd} local ', ''), 'remote')

    def test_quoted_and_escaped_trailing_spaces_stay_on_current_argument(self):
        self.assertEqual(self._route_for('put "foo ', ''), 'local')
        self.assertEqual(self._route_for(r'put foo\ ', ''), 'local')
        self.assertEqual(self._route_for('put\t', ''), 'local')

    def test_remote_later_arg_commands_complete_remotely(self):
        cases = {
            'rename': 'rename old ne',
            'symlink': 'symlink src de',
            'ln': 'ln src de',
            'chmod': 'chmod 644 pa',
            'chown': 'chown 1000 pa',
            'chgrp': 'chgrp 1000 pa',
        }
        for cmd, line in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(self._route_for(line, line.rsplit(' ', 1)[1]), 'remote')

    def test_ln_optional_s_flag_routes_only_path_args(self):
        self.assertIsNone(self._route_for('ln -', '-'))
        self.assertEqual(self._route_for('ln -s sr', 'sr'), 'remote')
        self.assertEqual(self._route_for('ln -s src de', 'de'), 'remote')

    def test_overwrite_flags_do_not_shift_positional_completion(self):
        self.assertEqual(self._route_for('get -f re', 're'), 'remote')
        self.assertEqual(self._route_for('get -f remote lo', 'lo'), 'local')
        self.assertEqual(self._route_for('get -i --force remote lo', 'lo'), 'local')
        self.assertEqual(self._route_for('put -i lo', 'lo'), 'local')
        self.assertEqual(self._route_for('put --force local re', 're'), 'remote')
        self.assertEqual(self._route_for('mget -f pa', 'pa'), 'remote')
        self.assertEqual(self._route_for('mput -i pa', 'pa'), 'local')
        self.assertEqual(self._route_for('rename -f old ne', 'ne'), 'remote')
        self.assertEqual(self._route_for('symlink -i src de', 'de'), 'remote')
        self.assertEqual(self._route_for('ln -f -s src de', 'de'), 'remote')

    def test_overwrite_flag_still_typing_yields_no_path_completions(self):
        self.assertIsNone(self._route_for('get -', '-'))
        self.assertIsNone(self._route_for('put -', '-'))
        self.assertIsNone(self._route_for('mget -', '-'))

    def test_overwrite_flags_compose_with_windows_case_insensitive_local_matching(self):
        """The flag-stripping arg_pos fix must not interfere with the existing
        Windows-only casefold matching path used by _local()."""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'Report.txt'), 'w') as f:
                f.write('')
            self.c.local_cwd = d
            with patch('sftp_client.os.name', 'nt'):
                self.assertEqual(self._route_for('put -f rep', 'rep'), 'local')
                matches = self.cmp._build_from_line('put -f rep', 'rep')
        self.assertIn('Report.txt ', matches)

    def test_extract_overwrite_flags_preserves_windows_style_paths(self):
        """Flag extraction must not mangle backslash-heavy Windows paths that
        happen to be adjacent to -f/-i on the command line."""
        args, force, confirm = self.c._extract_overwrite_flags(
            ['-f', r'C:\Users\bob\Report.txt', '/remote/report.txt']
        )
        self.assertEqual(args, [r'C:\Users\bob\Report.txt', '/remote/report.txt'])
        self.assertTrue(force)
        self.assertFalse(confirm)

    def test_head_tail_commands_skip_n_option_and_complete_file_arg(self):
        cases = {
            'head': 'local',
            'tail': 'local',
            'rhead': 'remote',
            'rtail': 'remote',
        }
        for cmd, route in cases.items():
            with self.subTest(cmd=cmd):
                self.assertIsNone(self._route_for(f'{cmd} -', '-'))
                self.assertIsNone(self._route_for(f'{cmd} -n ', ''))
                self.assertEqual(self._route_for(f'{cmd} -n 5 pa', 'pa'), route)
                self.assertIsNone(self._route_for(f'{cmd} file extra', 'extra'))

    def test_open_and_connect_complete_identity_file_locally(self):
        with patch.object(sftp_client, 'readline') as rl, \
             patch.object(self.cmp, '_local', return_value=['id_rsa ']) as local, \
             patch.object(self.cmp, '_remote', return_value=['REMOTE ']):
            rl.get_line_buffer.return_value = 'open host -i id'
            self.assertEqual(self.cmp._build('id'), ['id_rsa '])
            local.assert_called_with('id')

            local.reset_mock()
            rl.get_line_buffer.return_value = 'connect --identity id'
            self.assertEqual(self.cmp._build('id'), ['id_rsa '])
            local.assert_called_with('id')

            local.reset_mock()
            rl.get_line_buffer.return_value = 'open --identity=id'
            self.assertEqual(self.cmp._build('--identity=id'), ['--identity=id_rsa '])
            local.assert_called_with('id')

            local.reset_mock()
            rl.get_line_buffer.return_value = 'open -i=id'
            self.assertEqual(self.cmp._build('-i=id'), ['-i=id_rsa '])
            local.assert_called_with('id')

            local.reset_mock()
            rl.get_line_buffer.return_value = 'open host'
            self.assertEqual(self.cmp._build('host'), [])
            local.assert_not_called()

    def test_build_from_explicit_line_buffer_does_not_need_readline(self):
        with patch.object(self.cmp, '_local', return_value=['LOCAL ']) as local, \
             patch.object(self.cmp, '_remote', return_value=['REMOTE ']) as remote:
            self.assertEqual(self.cmp._build_from_line('put local re', 're'), ['REMOTE '])
            remote.assert_called_once_with('re')

            self.assertEqual(self.cmp._build_from_line('get remote lo', 'lo'), ['LOCAL '])
            local.assert_called_once_with('lo')

    def test_completion_text_from_line_fragment(self):
        self.assertEqual(_completion_text_from_line_fragment('lp'), 'lp')
        self.assertEqual(_completion_text_from_line_fragment('put local re'), 're')
        self.assertEqual(_completion_text_from_line_fragment('put local '), '')
        self.assertEqual(_completion_text_from_line_fragment('put "my fi'), '"my fi')

    def test_readline_completes_inside_quoted_and_escaped_paths(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'my file.txt'), 'w') as f:
                f.write('')
            self.c.local_cwd = d

            quoted = 'put "my fi'
            self.assertIn(
                'file.txt" ',
                self._readline_matches(quoted, 'fi', 8, len(quoted)),
            )

            escaped = r'put my\ fi'
            self.assertIn(
                'file.txt ',
                self._readline_matches(escaped, 'fi', 8, len(escaped)),
            )

            trailing_quote = 'put "my '
            self.assertIn(
                'file.txt" ',
                self._readline_matches(trailing_quote, '', len(trailing_quote), len(trailing_quote)),
            )

    def test_readline_routes_using_text_before_cursor_only(self):
        fake_readline = MagicMock()
        fake_readline.get_line_buffer.return_value = 'get rem local'
        fake_readline.get_begidx.return_value = 4
        fake_readline.get_endidx.return_value = 7
        with patch.object(sftp_client, 'readline', fake_readline), \
             patch.object(self.cmp, '_remote', return_value=['remote ']) as remote, \
             patch.object(self.cmp, '_local', return_value=['local ']) as local:
            self.assertEqual(self.cmp._build('rem'), ['remote'])
        remote.assert_called_once()
        local.assert_not_called()

    def test_readline_reuses_closing_quote_and_separator_after_cursor(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'my file.txt'), 'w') as f:
                f.write('')
            self.c.local_cwd = d
            line = 'put "my fi" next'
            cursor = len('put "my fi')
            self.assertEqual(
                self._readline_matches(line, 'fi', 8, cursor),
                ['file.txt'],
            )

    def test_remote_none_st_mode_does_not_crash(self):
        """REGRESSION BUG 2: _stat.S_ISDIR(None) must not raise TypeError."""
        attr = _make_attr('mystery'); attr.st_mode = None
        self.c.sftp.listdir_attr.return_value = [attr]
        results = self.cmp._remote('')
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

    def test_remote_directory_gets_slash_suffix(self):
        self.c.sftp.listdir_attr.return_value = [_make_attr('mydir', mode=0o040755)]
        results = self.cmp._remote('')
        self.assertTrue(any(r.endswith('/') for r in results))

    def test_remote_file_gets_space_suffix(self):
        self.c.sftp.listdir_attr.return_value = [_make_attr('myfile.txt', mode=0o100644)]
        results = self.cmp._remote('')
        self.assertTrue(any(r.endswith(' ') for r in results))

    def test_remote_stat_exception_yields_space_suffix(self):
        self.c.sftp.listdir_attr.return_value = [_make_attr('file', mode=0o120777)]
        self.c.sftp.stat.side_effect = IOError('permission denied')
        results = self.cmp._remote('')
        self.assertTrue(any(r.endswith(' ') for r in results))

    def test_remote_no_sftp_returns_empty_list(self):
        self.c.sftp = None
        self.assertEqual(self.cmp._remote('anything'), [])

    def test_remote_filters_completions_by_prefix(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('alpha.txt', mode=0o100644),
            _make_attr('beta.txt', mode=0o100644),
            _make_attr('also.log', mode=0o100644),
        ]
        results = self.cmp._remote('al')
        names = {r.rstrip('/ ') for r in results}
        self.assertIn('alpha.txt', names)
        self.assertNotIn('beta.txt', names)

    def test_remote_user_home_completion_uses_remote_home(self):
        self.c.remote_cwd = '/work'
        self.c.remote_home = '/home/testuser'
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('alpha.txt', mode=0o100644),
            _make_attr('beta.txt', mode=0o100644),
        ]

        results = self.cmp._remote('~/a')

        self.c.sftp.listdir_attr.assert_called_once_with('/home/testuser')
        self.assertIn('~/alpha.txt ', results)
        self.assertNotIn('~/beta.txt ', results)

    def test_local_directory_gets_slash_suffix(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, 'subdir'))
            self.c.local_cwd = d
            results = self.cmp._local('')
            self.assertTrue(any(r.endswith('/') for r in results))

    def test_local_file_gets_space_suffix(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'file.txt'), 'w') as f: f.write('')
            self.c.local_cwd = d
            results = self.cmp._local('')
            self.assertTrue(any(r.endswith(' ') for r in results))

    def test_control_character_names_are_not_offered(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ('safe.txt', 'tab\tname.txt', 'line\nname.txt', 'escape\x1bname.txt'):
                with open(os.path.join(d, name), 'w') as f:
                    f.write('')
            self.c.local_cwd = d
            self.assertEqual(self.cmp._local(''), ['safe.txt ', 'tab\\\tname.txt '])

        self.c.sftp.listdir_attr.return_value = [
            _make_attr('safe.txt'),
            _make_attr('tab\tname.txt'),
            _make_attr('escape\x1bname.txt'),
        ]
        offered = self.cmp._remote('')
        self.assertEqual(offered, ['safe.txt ', 'tab\\\tname.txt '])
        # A tab is escaped, so the completed word parses back to the name.
        self.assertEqual(_split_command_line('rcat ' + offered[1]), ['rcat', 'tab\tname.txt'])

    def test_windows_local_prefix_matching_is_case_insensitive(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'Report.txt'), 'w') as f:
                f.write('')
            self.c.local_cwd = d
            with patch('sftp_client.os.name', 'nt'):
                self.assertIn('Report.txt ', self.cmp._local('rep'))

    def test_short_identity_equals_completion_is_accepted_by_open(self):
        with tempfile.TemporaryDirectory() as d:
            key = os.path.join(d, 'id key')
            with open(key, 'w') as f:
                f.write('')
            self.c.connected = False
            with patch.object(self.c, 'connect') as connect:
                self.c.cmd_open(['host', '-i=' + key])
        connect.assert_called_once()
        self.assertEqual(connect.call_args.args[4], key)


# ══════════════════════════════════════════════════════════════════════════════
# Error-handling and recovery tests
# ══════════════════════════════════════════════════════════════════════════════

class TestConnectionLossDetection(unittest.TestCase):
    """Verify that a dropped transport is detected and state is cleaned up."""

    def setUp(self):
        self.c = _make_client()

    def _kill_transport(self):
        """Make the mock SSH transport look dead."""
        transport = MagicMock()
        transport.is_active.return_value = False
        self.c.ssh.get_transport.return_value = transport

    def test_connection_is_dead_live_transport(self):
        transport = MagicMock()
        transport.is_active.return_value = True
        self.c.ssh.get_transport.return_value = transport
        self.assertFalse(self.c._connection_is_dead())

    def test_connection_is_dead_dead_transport(self):
        self._kill_transport()
        self.assertTrue(self.c._connection_is_dead())

    def test_connection_is_dead_none_transport(self):
        self.c.ssh.get_transport.return_value = None
        self.assertTrue(self.c._connection_is_dead())

    def test_connection_is_dead_none_ssh(self):
        self.c.ssh = None
        self.assertTrue(self.c._connection_is_dead())

    def test_dispatch_detects_dead_transport_after_failed_command(self):
        """After a command fails due to a network error, dispatch closes the session."""
        self.c.sftp.listdir_attr.side_effect = IOError('Connection reset')
        self.c.sftp.stat.side_effect         = IOError('Connection reset')
        self._kill_transport()

        out = _capture(self.c._dispatch, 'ls')

        self.assertFalse(self.c.connected)
        self.assertIsNone(self.c.sftp)
        self.assertIn('Connection lost', out)

    def test_dispatch_shows_reconnect_hint_on_loss(self):
        """'open' is mentioned so the user knows how to recover."""
        self.c.sftp.listdir_attr.side_effect = IOError('Broken pipe')
        self.c.sftp.stat.side_effect         = IOError('Broken pipe')
        self._kill_transport()
        out = _capture(self.c._dispatch, 'ls')
        self.assertIn('open', out)

    def test_dispatch_does_not_falsely_report_loss_on_normal_error(self):
        """A regular SFTP error (no such file) must not trigger connection-loss logic."""
        transport = MagicMock()
        transport.is_active.return_value = True
        self.c.ssh.get_transport.return_value = transport
        self.c.sftp.listdir_attr.side_effect = IOError('[Errno 2] No such file')
        self.c.sftp.stat.side_effect         = IOError('[Errno 2] No such file')

        out = _capture(self.c._dispatch, 'ls /nonexistent')

        self.assertTrue(self.c.connected)   # still connected
        self.assertNotIn('Connection lost', out)


class TestCmdGetErrorHandling(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    @patch('sftp_client._GET_SUPPORTS_PREFETCH_LIMIT', True)
    def test_download_uses_bounded_prefetch(self):
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, 'download.txt')

            def write_download(remote, staged, **kwargs):
                with open(staged, 'wb') as fh:
                    fh.write(b'data')

            self.c.sftp.get.side_effect = write_download
            self.c._download_file('/remote/file.txt', dest)
            with open(dest, 'rb') as fh:
                self.assertEqual(fh.read(), b'data')
        kwargs = self.c.sftp.get.call_args.kwargs
        self.assertTrue(callable(kwargs.pop('callback')))
        self.assertEqual(kwargs, {'prefetch': True, 'max_concurrent_prefetch_requests': 64})

    @unittest.skipIf(os.name == 'nt', 'Windows path-length rules vary by filesystem')
    def test_download_accepts_long_valid_destination_name(self):
        with tempfile.TemporaryDirectory() as d:
            if os.pathconf(d, 'PC_NAME_MAX') < 245:
                self.skipTest('filesystem does not support 245-byte names')
            dest = os.path.join(d, 'x' * 245)

            def write_download(remote, staged, **kwargs):
                with open(staged, 'wb') as fh:
                    fh.write(b'data')

            self.c.sftp.get.side_effect = write_download
            self.c._download_file('/remote/file.txt', dest)
            with open(dest, 'rb') as fh:
                self.assertEqual(fh.read(), b'data')

    def test_remote_staging_name_stays_short_for_long_destination(self):
        remote = '/remote/' + 'x' * 245
        staged = self.c._remote_temp_path(remote)
        self.assertEqual(os.path.dirname(staged), '/remote')
        self.assertLessEqual(len(os.path.basename(staged).encode('utf-8')), 255)
        self.assertNotEqual(staged, remote)

    def test_get_removes_partial_file_on_failure(self):
        """A file created by a failed get must be cleaned up."""
        self.c.sftp.get.side_effect = IOError('Connection reset')
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, 'download.txt')
            self.assertFalse(os.path.exists(dest))
            _capture(self.c.cmd_get, ['/remote/file.txt', dest])
            self.assertFalse(os.path.exists(dest))

    def test_get_preserves_existing_file_contents_on_failure(self):
        """A failed staged download must not alter an existing destination."""
        def fail_after_partial_write(remote, staged, **kwargs):
            with open(staged, 'wb') as f:
                f.write(b'partial')
            raise IOError('Connection reset')

        self.c.sftp.get.side_effect = fail_after_partial_write
        with tempfile.TemporaryDirectory() as d:
            fname = os.path.join(d, 'download.txt')
            with open(fname, 'wb') as f:
                f.write(b'original')
            _capture(self.c.cmd_get, ['-f', '/remote/file.txt', fname])
            with open(fname, 'rb') as f:
                self.assertEqual(f.read(), b'original')
            self.assertEqual(os.listdir(d), ['download.txt'])

    def test_get_empty_basename_shows_error(self):
        """get of a root-like path with no derivable filename must not crash."""
        # Simulate remote path resolving to bare '/'
        self.c.sftp.normalize.return_value = '/'
        out = _capture(self.c.cmd_get, ['/'])
        self.assertIn('cannot determine', out)
        self.c.sftp.get.assert_not_called()

    def test_get_uses_resolved_remote_basename(self):
        """Local filename is derived from the resolved remote path, not the raw argument."""
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            # normalize('.') returns the home dir; ~/data.csv becomes /home/testuser/data.csv
            self.c.sftp.normalize.return_value = '/home/testuser'
            self.c.cmd_get(['~/data.csv'])
            staged = self.c.sftp.get.call_args[0][1]
            self.assertTrue(os.path.basename(staged).startswith('.sftp-'))
            self.assertTrue(os.path.exists(os.path.join(d, 'data.csv')))

    def test_get_preserves_existing_dangling_symlink_on_failure(self):
        """A pre-existing dangling symlink must not be treated as cleanup-owned."""
        self.c.sftp.get.side_effect = IOError('Connection reset')
        with tempfile.TemporaryDirectory() as d:
            link = os.path.join(d, 'data.csv')
            try:
                os.symlink(os.path.join(d, 'missing-target'), link)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not supported on this platform")
            _capture(self.c.cmd_get, ['-f', '/remote/data.csv', link])
            self.assertTrue(os.path.lexists(link))

    def test_get_does_not_replace_destination_created_during_download(self):
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, 'data.csv')

            def create_racing_destination(remote, staged, **kwargs):
                with open(staged, 'wb') as fh:
                    fh.write(b'download')
                with open(dest, 'wb') as fh:
                    fh.write(b'other writer')

            self.c.sftp.get.side_effect = create_racing_destination
            out = _capture(self.c.cmd_get, ['/remote/data.csv', dest])
            with open(dest, 'rb') as fh:
                self.assertEqual(fh.read(), b'other writer')
            self.assertEqual(os.listdir(d), ['data.csv'])
        self.assertIn('get:', out)


class TestCmdMgetErrorHandling(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_mget_removes_partial_file_on_failure(self):
        """A partially downloaded file from a failed mget must be cleaned up."""
        self.c.sftp.listdir_attr.return_value = [_make_attr('data.csv', mode=0o100644)]
        self.c.sftp.get.side_effect = IOError('Connection reset')
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            _capture(self.c.cmd_mget, ['*.csv'])
            self.assertFalse(os.path.exists(os.path.join(d, 'data.csv')))

    def test_mget_preserves_existing_file_contents_on_failure(self):
        """A failed staged mget must not alter a pre-existing local file."""
        self.c.sftp.listdir_attr.return_value = [_make_attr('data.csv', mode=0o100644)]

        def fail_after_partial_write(remote, staged, **kwargs):
            with open(staged, 'w') as f:
                f.write('partial')
            raise IOError('Connection reset')

        self.c.sftp.get.side_effect = fail_after_partial_write
        with tempfile.TemporaryDirectory() as d:
            existing = os.path.join(d, 'data.csv')
            with open(existing, 'w') as f: f.write('original')
            self.c.local_cwd = d
            _capture(self.c.cmd_mget, ['-f', '*.csv'])
            with open(existing) as f:
                self.assertEqual(f.read(), 'original')
            self.assertEqual(os.listdir(d), ['data.csv'])

    def test_mget_preserves_existing_dangling_symlink_on_failure(self):
        """mget must not delete a pre-existing dangling symlink on failure."""
        self.c.sftp.listdir_attr.return_value = [_make_attr('data.csv', mode=0o100644)]
        self.c.sftp.get.side_effect = IOError('Connection reset')
        with tempfile.TemporaryDirectory() as d:
            existing = os.path.join(d, 'data.csv')
            try:
                os.symlink(os.path.join(d, 'missing-target'), existing)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not supported on this platform")
            self.c.local_cwd = d
            _capture(self.c.cmd_mget, ['-f', '*.csv'])
            self.assertTrue(os.path.lexists(existing))

    def test_mget_stops_after_first_error_in_play(self):
        self.c.sftp.listdir_attr.return_value = [
            _make_attr('a.csv', mode=0o100644),
            _make_attr('b.csv', mode=0o100644),
        ]
        self.c.sftp.get.side_effect = IOError('Connection reset')
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as script:
                script.write('mget *.csv\n')
                script_name = script.name
            try:
                _capture(self.c.cmd_play, [script_name])
            finally:
                os.unlink(script_name)
        self.assertEqual(self.c.sftp.get.call_count, 1)


class TestCmdLcd(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self._saved_cwd = os.getcwd()

    def tearDown(self):
        # cmd_lcd calls os.chdir(); restore the process CWD after each test
        # so that subsequent setUp calls (which use os.getcwd()) don't fail.
        try:
            os.chdir(self._saved_cwd)
        except OSError:
            os.chdir(tempfile.gettempdir())

    def test_lcd_changes_local_cwd(self):
        with tempfile.TemporaryDirectory() as d:
            _capture(self.c.cmd_lcd, [d])
            self.assertEqual(self.c.local_cwd, os.path.realpath(d))
            os.chdir(self._saved_cwd)   # restore now, before d is deleted

    def test_lcd_nonexistent_path_reports_error(self):
        out = _capture(self.c.cmd_lcd, ['/nonexistent/path'])
        self.assertIn('lcd:', out)

    def test_lcd_file_path_reports_error(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            fname = f.name
        try:
            original_cwd = self.c.local_cwd
            out = _capture(self.c.cmd_lcd, [fname])
            self.assertIn('lcd:', out)
            self.assertEqual(self.c.local_cwd, original_cwd)
        finally:
            os.unlink(fname)

    def test_lcd_local_cwd_not_updated_on_failure(self):
        """local_cwd must remain unchanged when chdir fails."""
        original = self.c.local_cwd
        _capture(self.c.cmd_lcd, ['/does/not/exist'])
        self.assertEqual(self.c.local_cwd, original)


class TestCmdCdErrorPath(unittest.TestCase):
    """Ensure sftp calls in cmd_cd are all inside the try block."""

    def setUp(self):
        self.c = _make_client()

    def test_cd_home_normalize_failure_shows_cd_error(self):
        """normalize('.') failing for 'cd' with no args shows 'cd: ...' not 'Error in cd'."""
        self.c.sftp.normalize.side_effect = IOError('Connection reset')
        out = _capture(self.c._dispatch, 'cd')
        self.assertIn('cd:', out)
        self.assertNotIn("Error in 'cd':", out)


# ══════════════════════════════════════════════════════════════════════════════
# Batch mode (-b) tests
# ══════════════════════════════════════════════════════════════════════════════

class TestBatchMode(unittest.TestCase):
    """Tests for run() batch-file behaviour."""

    def _bare(self):
        with patch('sftp_client._setup_logger') as m:
            m.return_value = (MagicMock(), '/dev/null')
            return SFTPClient()

    def _run_batch(self, script_lines, *, connected=True):
        """Write *script_lines* to a temp file and run it through run() in batch mode."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('\n'.join(script_lines) + '\n')
            fname = f.name
        try:
            client = self._bare()
            if connected:
                client.sftp       = MagicMock()
                client.ssh        = MagicMock()
                client.connected  = True
                client.remote_cwd = '/home/testuser'
                # Make transport look alive so connection-loss check is quiet
                transport = MagicMock()
                transport.is_active.return_value = True
                client.ssh.get_transport.return_value = transport
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    client.run(batch_file=fname)
                except SystemExit as exc:
                    return buf.getvalue(), exc.code
            return buf.getvalue(), 0
        finally:
            os.unlink(fname)

    def test_batch_interrupt_closes_connection(self):
        client = self._bare()
        client.sftp = MagicMock()
        client.ssh = MagicMock()
        client.connected = True
        sftp = client.sftp
        ssh = client.ssh
        with patch.object(client, 'cmd_play', side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                with contextlib.redirect_stdout(io.StringIO()):
                    client.run(batch_file='/tmp/interrupted.sftp')
        sftp.close.assert_called_once()
        ssh.close.assert_called_once()
        self.assertFalse(client.connected)

    # ── banner behaviour ───────────────────────────────────────────────────────

    def test_batch_suppresses_interactive_hint(self):
        """'Type help or ?' must not appear in batch output."""
        out, _ = self._run_batch(['# empty script'])
        self.assertNotIn("Type 'help'", out)
        self.assertNotIn("'exit' to quit", out)

    def test_batch_still_shows_version_line(self):
        """Version/log line is shown even in batch mode (useful in logs)."""
        out, _ = self._run_batch(['# empty script'])
        self.assertIn('sftp_client.py', out)

    # ── history-file safety ────────────────────────────────────────────────────

    def test_batch_does_not_save_history(self):
        """readline is never initialised in batch mode — _save_history must not be called."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('# empty\n'); fname = f.name
        try:
            client = self._bare()
            client.sftp       = MagicMock()
            client.ssh        = MagicMock()
            client.connected  = True
            client.remote_cwd = '/home/testuser'
            transport = MagicMock()
            transport.is_active.return_value = True
            client.ssh.get_transport.return_value = transport

            with patch.object(client, '_save_history') as mock_save:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    try:
                        client.run(batch_file=fname)
                    except SystemExit:
                        pass
                mock_save.assert_not_called()
        finally:
            os.unlink(fname)

    # ── exit codes ────────────────────────────────────────────────────────────

    def test_batch_exits_0_when_all_commands_succeed(self):
        """A batch run with no errors must exit with code 0."""
        client = self._bare()
        client.sftp = MagicMock()
        client.ssh  = MagicMock()
        client.connected  = True
        client.remote_cwd = '/home/testuser'
        transport = MagicMock()
        transport.is_active.return_value = True
        client.ssh.get_transport.return_value = transport
        client.sftp.listdir_attr.return_value = [_make_attr('ok.txt', mode=0o100644)]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('ls\n'); fname = f.name
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    client.run(batch_file=fname)
                    exit_code = 0
                except SystemExit as exc:
                    exit_code = exc.code
            self.assertEqual(exit_code, 0)
        finally:
            os.unlink(fname)

    def test_batch_exits_1_when_a_command_fails(self):
        """Any error-level output during batch must produce exit code 1."""
        out, code = self._run_batch(['get /remote/missing.txt /tmp/out.txt'])
        # sftp.get raises (default MagicMock side_effect is None, but the
        # real error path: make sftp.get raise)
        # Re-run with an explicit failure:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('get /remote/missing.txt\n'); fname = f.name
        try:
            client = self._bare()
            sftp = MagicMock()
            client.sftp = sftp
            client.ssh  = MagicMock()
            client.connected  = True
            client.remote_cwd = '/home/testuser'
            transport = MagicMock()
            transport.is_active.return_value = True
            client.ssh.get_transport.return_value = transport
            client.sftp.get.side_effect = IOError('No such file')

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    client.run(batch_file=fname)
                    exit_code = 0
                except SystemExit as exc:
                    exit_code = exc.code
            self.assertEqual(exit_code, 1)
        finally:
            os.unlink(fname)

    def test_batch_exits_1_on_connection_loss(self):
        """Connection loss during batch produces exit code 1."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('ls\n'); fname = f.name
        try:
            client = self._bare()
            sftp = MagicMock()
            client.sftp = sftp
            client.ssh  = MagicMock()
            client.connected  = True
            client.remote_cwd = '/home/testuser'
            # Transport looks dead after ls fails
            transport = MagicMock()
            transport.is_active.return_value = False
            client.ssh.get_transport.return_value = transport
            client.sftp.listdir_attr.side_effect = IOError('Connection reset')
            client.sftp.stat.side_effect         = IOError('Connection reset')

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    client.run(batch_file=fname)
                    exit_code = 0
                except SystemExit as exc:
                    exit_code = exc.code
            self.assertEqual(exit_code, 1)
        finally:
            os.unlink(fname)

    def test_batch_exits_1_when_script_file_missing(self):
        """A missing batch script file itself counts as an error."""
        client = self._bare()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                client.run(batch_file='/nonexistent/script.sftp')
                exit_code = 0
            except SystemExit as exc:
                exit_code = exc.code
        self.assertEqual(exit_code, 1)
        self.assertIn('play:', buf.getvalue())

    def test_batch_exits_0_on_empty_script(self):
        """An empty (comments-only) script with no errors exits 0."""
        out, code = self._run_batch(['# just a comment', ''], connected=False)
        self.assertEqual(code, 0)

    def test_batch_usage_error_exits_1(self):
        """Malformed commands that only show usage still fail batch mode."""
        out, code = self._run_batch(['get'])
        self.assertEqual(code, 1)
        self.assertIn('Usage: get', out)

    def test_batch_stops_after_first_error(self):
        """A failed command must not let later destructive commands run."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('cd /missing\nrm victim.txt\n')
            fname = f.name
        try:
            client = self._bare()
            sftp = MagicMock()
            client.sftp = sftp
            client.ssh  = MagicMock()
            client.connected  = True
            client.remote_cwd = '/safe'
            transport = MagicMock()
            transport.is_active.return_value = True
            client.ssh.get_transport.return_value = transport
            sftp.normalize.side_effect = IOError('Missing')

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    client.run(batch_file=fname)
                    exit_code = 0
                except SystemExit as exc:
                    exit_code = exc.code
            self.assertEqual(exit_code, 1)
            sftp.remove.assert_not_called()
            self.assertNotIn('[play:2]', buf.getvalue())
        finally:
            os.unlink(fname)

    def test_play_stops_after_first_error_even_if_client_already_had_error(self):
        """A prior interactive error must not disable fail-fast behavior in play."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('cd /missing\nrm victim.txt\n')
            fname = f.name
        try:
            client = self._bare()
            sftp = MagicMock()
            client.sftp = sftp
            client.ssh  = MagicMock()
            client.connected  = True
            client.remote_cwd = '/safe'
            transport = MagicMock()
            transport.is_active.return_value = True
            client.ssh.get_transport.return_value = transport
            sftp.normalize.side_effect = IOError('Missing')
            client._batch_had_error = True

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                client.cmd_play([fname])
            sftp.remove.assert_not_called()
            self.assertNotIn('[play:2]', buf.getvalue())
            self.assertTrue(client._batch_had_error)
        finally:
            os.unlink(fname)

    def test_batch_redacts_inline_passwords_in_play_echo(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('open user@example.com -p supersecret\n')
            fname = f.name
        try:
            client = self._bare()
            with patch.object(client, 'connect'):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    client.cmd_play([fname])
            out = buf.getvalue()
            self.assertIn("-p '<redacted>'", out)
            self.assertNotIn('supersecret', out)
        finally:
            os.unlink(fname)

    def test_repl_debug_log_redacts_inline_passwords(self):
        client = self._bare()
        with patch.object(client, '_setup_readline'), \
             patch.object(client, '_save_history'), \
             patch.object(client, 'connect'), \
             patch('builtins.input', side_effect=['open user@example.com -p supersecret', 'exit']):
            _capture(client.run)

        debug_messages = ' '.join(str(call.args[0]) for call in client.logger.debug.call_args_list)
        self.assertIn('<redacted>', debug_messages)
        self.assertNotIn('supersecret', debug_messages)

    def test_repl_keyboard_interrupt_during_dispatch_does_not_crash(self):
        """Ctrl-C mid-command must be swallowed like Ctrl-C at the prompt, not crash run()."""
        client = self._bare()
        calls = []

        def fake_dispatch(line):
            calls.append(line)
            if line == 'slow-command':
                raise KeyboardInterrupt
            if line == 'exit':
                client._should_exit = True

        client._dispatch = fake_dispatch
        with patch.object(client, '_setup_readline'), \
             patch.object(client, '_save_history'), \
             patch('builtins.input', side_effect=['slow-command', 'exit']):
            out = _capture(client.run)

        self.assertEqual(calls, ['slow-command', 'exit'])
        self.assertNotIn('Traceback', out)
        self.assertIn('Goodbye.', out)

    def test_run_initial_connect_keyboard_interrupt_reports_cancellation(self):
        """Ctrl-C during the initial connect() in run() must exit cleanly, not crash."""
        client = self._bare()
        with patch.object(client, 'connect', side_effect=KeyboardInterrupt):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                with self.assertRaises(SystemExit) as ctx:
                    client.run(host='host')

        self.assertEqual(ctx.exception.code, 1)
        self.assertIn('Connection cancelled', buf.getvalue())


class TestCmdShell(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_shell_reports_subprocess_return_code(self):
        completed = MagicMock()
        completed.returncode = 1
        with patch('subprocess.run', return_value=completed) as run:
            out = _capture(self.c.cmd_shell, ['false'])
        run.assert_called_once_with('false', shell=True)
        self.assertIn('status 1', out)
        self.assertNotIn('status 256', out)

    def test_shell_reports_subprocess_launch_error(self):
        with patch('subprocess.run', side_effect=ValueError('embedded null byte')):
            out = _capture(self.c._dispatch, '!\x00')
        self.assertIn('shell:', out)
        self.assertIn('Embedded null byte', out)
        self.assertTrue(self.c._batch_had_error)


# ══════════════════════════════════════════════════════════════════════════════
# Atomic upload tests
# ══════════════════════════════════════════════════════════════════════════════

class TestAtomicPut(unittest.TestCase):
    """Tests for _atomic_put and the atomic flag wiring into cmd_put/cmd_mput."""

    def setUp(self):
        self.c = _make_client()

    # ── _atomic_put internals ─────────────────────────────────────────────────

    def test_atomic_put_uploads_to_tmp_then_posix_renames(self):
        with tempfile.NamedTemporaryFile() as f:
            self.c._atomic_put(f.name, '/remote/dest.txt')

        put_args  = self.c.sftp.put.call_args[0]
        self.assertEqual(put_args[0], f.name)
        tmp = put_args[1]
        self.assertTrue(tmp.startswith('/remote/.sftp-'))
        self.assertTrue(tmp.endswith('.tmp'))

        rename_args = self.c.sftp.posix_rename.call_args[0]
        self.assertEqual(rename_args, (tmp, '/remote/dest.txt'))

    def test_atomic_put_falls_back_to_rename_when_posix_rename_unavailable(self):
        del self.c.sftp.posix_rename
        with tempfile.NamedTemporaryFile() as f:
            self.c._atomic_put(f.name, '/remote/dest.txt')

        tmp = self.c.sftp.put.call_args[0][1]
        self.c.sftp.rename.assert_called_once_with(tmp, '/remote/dest.txt')

    def test_atomic_put_does_not_retry_internal_attribute_error(self):
        self.c.sftp.posix_rename.side_effect = AttributeError('failure after request')
        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaisesRegex(AttributeError, 'failure after request'):
                self.c._atomic_put(f.name, '/remote/dest.txt')
        self.c.sftp.rename.assert_not_called()

    def test_atomic_put_falls_back_to_rename_when_posix_rename_raises_ioerror(self):
        self.c.sftp.posix_rename.side_effect = IOError('not supported')
        with tempfile.NamedTemporaryFile() as f:
            self.c._atomic_put(f.name, '/remote/dest.txt')

        tmp = self.c.sftp.put.call_args[0][1]
        self.c.sftp.rename.assert_called_once_with(tmp, '/remote/dest.txt')

    def test_atomic_put_removes_tmp_when_put_fails(self):
        self.c.sftp.put.side_effect = IOError('disk full')
        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaises(IOError):
                self.c._atomic_put(f.name, '/remote/dest.txt')

        # tmp name was never put (put raised), but remove is still attempted
        self.c.sftp.remove.assert_called_once()
        removed = self.c.sftp.remove.call_args[0][0]
        self.assertTrue(removed.startswith('/remote/.sftp-'))

    def test_atomic_put_removes_tmp_when_rename_fails(self):
        self.c.sftp.posix_rename.side_effect = IOError('permission denied')
        self.c.sftp.rename.side_effect       = IOError('permission denied')
        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaises(IOError):
                self.c._atomic_put(f.name, '/remote/dest.txt')

        self.c.sftp.remove.assert_called_once()

    def test_atomic_put_reports_orphan_and_retries_cleanup_after_reconnect(self):
        identity = ('host.example', 22, 'user')
        self.c._connection_identity = identity
        self.c.sftp.put.side_effect = OSError('disk full')
        self.c.sftp.remove.side_effect = OSError('connection lost')
        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaisesRegex(RuntimeError, 'could not be removed') as raised:
                self.c._atomic_put(f.name, '/remote/dest.txt')
        tmp = self.c.sftp.put.call_args.args[1]
        self.assertIn(tmp, str(raised.exception))
        self.assertEqual(self.c._orphaned_remote_temps[identity], {tmp})

        self.c.sftp.remove.side_effect = None
        self.c._retry_orphan_cleanup()
        self.assertNotIn(identity, self.c._orphaned_remote_temps)
        self.c.sftp.remove.assert_called_with(tmp)

    def test_atomic_put_timeout_does_not_fallback_to_second_rename(self):
        self.c.sftp.posix_rename.side_effect = TimeoutError('response timed out')
        self.c.sftp.remove.side_effect = FileNotFoundError('already committed')
        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaises(TimeoutError):
                self.c._atomic_put(f.name, '/remote/dest.txt')
        self.c.sftp.rename.assert_not_called()

    def test_atomic_put_interrupt_reports_failed_cleanup(self):
        self.c.sftp.put.side_effect = KeyboardInterrupt()
        self.c.sftp.remove.side_effect = OSError('connection lost')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with tempfile.NamedTemporaryFile() as f:
                with self.assertRaises(KeyboardInterrupt):
                    self.c._atomic_put(f.name, '/remote/dest.txt')
        self.assertIn('could not be removed', output.getvalue())

    def test_orphan_cleanup_per_connection_is_bounded(self):
        identity = ('host.example', 22, 'user')
        self.c._connection_identity = identity
        self.c._orphaned_remote_temps[identity] = {f'/remote/.sftp-{i}.tmp' for i in range(12)}
        out = _capture(self.c._retry_orphan_cleanup)
        self.assertEqual(self.c.sftp.remove.call_count, 10)
        self.assertEqual(len(self.c._orphaned_remote_temps[identity]), 2)
        self.assertIn('still need cleanup', out)

    def test_atomic_put_tmp_name_is_unique(self):
        """Two concurrent uploads must use distinct temp names."""
        names = set()
        for _ in range(10):
            with tempfile.NamedTemporaryFile() as f:
                self.c._atomic_put(f.name, '/remote/dest.txt')
            names.add(self.c.sftp.put.call_args[0][1])
        self.assertEqual(len(names), 10)

    # ── cmd_put wiring ────────────────────────────────────────────────────────

    def test_cmd_put_uses_direct_put_when_atomic_off(self):
        self.c.atomic = False
        self.c.sftp.stat.side_effect = IOError('not found')
        with tempfile.NamedTemporaryFile() as f:
            self.c.cmd_put([f.name, '/remote/dest.txt'])
        self.c.sftp.open.assert_called_once_with('/remote/dest.txt', 'wxb')
        self.c.sftp.put.assert_not_called()
        self.c.sftp.posix_rename.assert_not_called()

    def test_cmd_put_uses_atomic_put_when_atomic_on(self):
        self.c.atomic = True
        self.c.sftp.stat.side_effect = IOError('not found')
        with tempfile.NamedTemporaryFile() as f:
            self.c.cmd_put([f.name, '/remote/dest.txt'])

        # put() stages to a .tmp path, then standard rename commits without overwrite.
        tmp = self.c.sftp.put.call_args[0][1]
        self.assertTrue(tmp.endswith('.tmp'))
        self.c.sftp.rename.assert_called_once_with(tmp, '/remote/dest.txt')
        self.c.sftp.posix_rename.assert_not_called()

    def test_atomic_put_rejects_destination_created_after_check(self):
        self.c.sftp.stat.side_effect = FileNotFoundError('not found')
        self.c.sftp.rename.side_effect = FileExistsError('created by another client')
        with tempfile.NamedTemporaryFile() as f:
            out = _capture(self.c.cmd_put, [f.name, '/remote/dest.txt'])
        staged = self.c.sftp.put.call_args.args[1]
        self.assertIn('put:', out)
        self.c.sftp.rename.assert_called_once_with(staged, '/remote/dest.txt')
        self.c.sftp.posix_rename.assert_not_called()
        self.c.sftp.remove.assert_called_once_with(staged)

    # ── cmd_mput wiring ───────────────────────────────────────────────────────

    def test_cmd_mput_uses_direct_put_when_atomic_off(self):
        self.c.atomic = False
        self.c.sftp.stat.side_effect = IOError('not found')
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            with open(os.path.join(d, 'a.log'), 'w') as f: f.write('')
            self.c.cmd_mput(['*.log'])
        self.c.sftp.open.assert_called_once_with('/home/testuser/a.log', 'wxb')
        self.c.sftp.put.assert_not_called()
        self.c.sftp.posix_rename.assert_not_called()

    def test_cmd_mput_uses_atomic_put_when_atomic_on(self):
        self.c.atomic = True
        self.c.sftp.stat.side_effect = IOError('not found')
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            with open(os.path.join(d, 'a.log'), 'w') as f: f.write('')
            self.c.cmd_mput(['*.log'])

        tmp = self.c.sftp.put.call_args[0][1]
        self.assertTrue(tmp.endswith('.tmp'))
        self.c.sftp.rename.assert_called_once_with(tmp, '/home/testuser/a.log')
        self.c.sftp.posix_rename.assert_not_called()

    def test_cmd_dirput_uses_atomic_put_when_atomic_on(self):
        self.c.atomic = True
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, 'srcdir')
            os.mkdir(root)
            with open(os.path.join(root, 'a.txt'), 'w') as f:
                f.write('')
            _wire_remote_dirs(self.c, {'/remote'})
            self.c.cmd_dirput([root, '/remote/copy'])

        tmp = self.c.sftp.put.call_args[0][1]
        self.assertTrue(tmp.startswith('/remote/copy/.sftp-'))
        self.assertTrue(tmp.endswith('.tmp'))
        self.c.sftp.rename.assert_called_once_with(tmp, '/remote/copy/a.txt')
        self.c.sftp.posix_rename.assert_not_called()

    # ── cmd_atomic command ────────────────────────────────────────────────────

    def test_cmd_atomic_shows_on_by_default(self):
        out = _capture(self.c.cmd_atomic, [])
        self.assertIn('on', out)

    def test_cmd_atomic_on_enables_flag(self):
        self.c.cmd_atomic(['on'])
        self.assertTrue(self.c.atomic)

    def test_cmd_atomic_off_disables_flag(self):
        self.c.atomic = True
        self.c.cmd_atomic(['off'])
        self.assertFalse(self.c.atomic)

    def test_cmd_atomic_shows_on_when_enabled(self):
        self.c.atomic = True
        out = _capture(self.c.cmd_atomic, [])
        self.assertIn('on', out)

    def test_cmd_atomic_invalid_arg_shows_usage(self):
        out = _capture(self.c.cmd_atomic, ['maybe'])
        self.assertIn('Usage', out)
        self.assertTrue(self.c.atomic)

    def test_cmd_atomic_works_without_connection(self):
        """atomic is in _NO_CONNECTION_NEEDED — must work when disconnected."""
        self.c.connected = False
        out = _capture(self.c._dispatch, 'atomic on')
        self.assertTrue(self.c.atomic)
        self.assertNotIn('Not connected', out)

    # ── batch script wiring ───────────────────────────────────────────────────

    def test_atomic_toggled_in_batch_script_affects_subsequent_puts(self):
        """atomic on/off inside a play script changes behaviour for later puts."""
        self.c.sftp.stat.side_effect = IOError('not found')
        with tempfile.TemporaryDirectory() as d:
            local = os.path.join(d, 'file.txt')
            with open(local, 'w') as f: f.write('data')
            script = os.path.join(d, 'upload.sftp')
            with open(script, 'w') as f:
                f.write(f'atomic on\nput {local} /remote/file.txt\n')
            _capture(self.c.cmd_play, [script])

        tmp = self.c.sftp.put.call_args[0][1]
        self.assertTrue(tmp.endswith('.tmp'))
        self.c.sftp.rename.assert_called_once_with(tmp, '/remote/file.txt')
        self.c.sftp.posix_rename.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# Vault tests
# ══════════════════════════════════════════════════════════════════════════════

class TestPasswordVault(unittest.TestCase):
    """Tests for the PasswordVault class and vault integration."""

    def setUp(self):
        import sftp_client as _sc
        # Capture the real class before any test patches replace it.
        self._VaultClass = _sc.PasswordVault
        self._tmpdir    = tempfile.mkdtemp()
        self.vault_path = os.path.join(self._tmpdir, 'vault.json')
        self.key_path   = os.path.join(self._tmpdir, 'vault.key')

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _vault(self):
        return self._VaultClass(self.vault_path, self.key_path)

    def _patch_vault(self):
        """Context manager: redirect any PasswordVault() construction to the test vault."""
        vp, kp, VC = self.vault_path, self.key_path, self._VaultClass
        return patch('sftp_client.PasswordVault', lambda *a, **kw: VC(vp, kp))

    def _skip_if_no_cryptography(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography package not installed")

    # ── PasswordVault unit tests ──────────────────────────────────────────────

    def test_add_and_get_roundtrip(self):
        self._skip_if_no_cryptography()
        v = self._vault()
        v.add('mypass', 's3cr3t')
        self.assertEqual(v.get('mypass'), 's3cr3t')

    def test_key_and_vault_are_synced_before_and_after_replace(self):
        self._skip_if_no_cryptography()
        events = []
        real_fsync = os.fsync
        real_replace = os.replace

        def syncing(fd):
            events.append(('sync', fd))
            return real_fsync(fd)

        def replacing(source, destination):
            events.append(('replace', destination))
            return real_replace(source, destination)

        with patch('sftp_client.os.fsync', side_effect=syncing), \
             patch('sftp_client.os.replace', side_effect=replacing):
            self._vault().add('entry', 'value')
        replacements = [i for i, event in enumerate(events) if event[0] == 'replace']
        self.assertEqual(len(replacements), 2)
        for index in replacements:
            self.assertEqual(events[index - 1][0], 'sync')
            if os.name != 'nt':
                self.assertEqual(events[index + 1][0], 'sync')

    def test_failed_vault_sync_preserves_previous_entry(self):
        self._skip_if_no_cryptography()
        vault = self._vault()
        vault.add('entry', 'old')
        with patch('sftp_client.os.fsync', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(RuntimeError, 'Cannot save vault'):
                vault.add('entry', 'new')
        self.assertEqual(vault.get('entry'), 'old')
        self.assertEqual(sorted(os.listdir(self._tmpdir)),
                         ['vault.json', 'vault.json.lock', 'vault.key'])

    def test_vault_directory_sync_failure_reports_completed_replace(self):
        self._skip_if_no_cryptography()
        vault = self._vault()
        vault.add('entry', 'old')
        with patch('sftp_client._sync_directory', side_effect=OSError('sync failed')):
            with self.assertRaisesRegex(RuntimeError, 'Vault was replaced'):
                vault.add('entry', 'new')
        self.assertEqual(vault.get('entry'), 'new')

    def test_get_missing_entry_returns_none(self):
        self._skip_if_no_cryptography()
        v = self._vault()
        self.assertIsNone(v.get('nonexistent'))

    def test_invalid_nonempty_key_raises_vault_error(self):
        self._skip_if_no_cryptography()
        with open(self.key_path, 'wb') as fh:
            fh.write(b'invalid-key')
        with self.assertRaisesRegex(RuntimeError, 'Vault key file is invalid'):
            self._vault().add('entry', 'value')
        self.assertFalse(os.path.exists(self.vault_path))

    def test_non_utf8_vault_raises_vault_error(self):
        with open(self.vault_path, 'wb') as fh:
            fh.write(b'\xff')
        with self.assertRaisesRegex(RuntimeError, 'Vault file is corrupt'):
            self._vault().list_entries()

    def test_list_returns_stored_names(self):
        self._skip_if_no_cryptography()
        v = self._vault()
        v.add('alpha', 'a')
        v.add('beta',  'b')
        self.assertIn('alpha', v.list_entries())
        self.assertIn('beta',  v.list_entries())

    def test_delete_removes_entry(self):
        self._skip_if_no_cryptography()
        v = self._vault()
        v.add('tmp', 'value')
        self.assertTrue(v.delete('tmp'))
        self.assertIsNone(v.get('tmp'))

    def test_delete_missing_returns_false(self):
        self._skip_if_no_cryptography()
        v = self._vault()
        self.assertFalse(v.delete('ghost'))

    def test_overwrite_entry(self):
        self._skip_if_no_cryptography()
        v = self._vault()
        v.add('pw', 'old')
        v.add('pw', 'new')
        self.assertEqual(v.get('pw'), 'new')

    def test_key_file_created_with_restricted_permissions(self):
        self._skip_if_no_cryptography()
        self._vault().add('x', 'y')
        mode = oct(os.stat(self.key_path).st_mode)[-3:]
        self.assertEqual(mode, '600')

    def test_vault_file_created_with_restricted_permissions(self):
        self._skip_if_no_cryptography()
        self._vault().add('x', 'y')
        mode = oct(os.stat(self.vault_path).st_mode)[-3:]
        self.assertEqual(mode, '600')

    def test_vault_directory_created_with_restricted_permissions(self):
        if os.name == 'nt':
            self.skipTest("POSIX mode bits are not meaningful on Windows")
        self._skip_if_no_cryptography()
        vault_dir = os.path.join(self._tmpdir, 'private-vault')
        v = self._VaultClass(
            os.path.join(vault_dir, 'vault.json'),
            os.path.join(vault_dir, 'vault.key'),
        )
        v.add('x', 'y')
        mode = oct(os.stat(vault_dir).st_mode)[-3:]
        self.assertEqual(mode, '700')

    def test_missing_cryptography_raises_runtime_error(self):
        """PasswordVault raises RuntimeError (not ImportError) when cryptography absent."""
        v = self._vault()
        import unittest.mock as _mock
        with _mock.patch.dict('sys.modules', {'cryptography': None,
                                               'cryptography.fernet': None}):
            with self.assertRaises(RuntimeError):
                v.add('x', 'y')

    # ── _resolve_vault_refs ───────────────────────────────────────────────────

    def test_resolve_vault_ref_returns_plaintext(self):
        self._skip_if_no_cryptography()
        from sftp_client import _resolve_vault_refs
        v = self._vault()
        v.add('dbpass', 'hunter2')
        self.assertEqual(_resolve_vault_refs('vault:dbpass', v), 'hunter2')

    def test_resolve_non_vault_string_passthrough(self):
        from sftp_client import _resolve_vault_refs
        self.assertEqual(_resolve_vault_refs('plaintext', self._vault()), 'plaintext')

    def test_resolve_missing_ref_raises_value_error(self):
        from sftp_client import _resolve_vault_refs
        with self.assertRaises(ValueError):
            _resolve_vault_refs('vault:ghost', self._vault())

    # ── cmd_vault interactive command ─────────────────────────────────────────

    def test_cmd_vault_list_empty(self):
        self._skip_if_no_cryptography()
        c = _make_client()
        with self._patch_vault():
            out = _capture(c.cmd_vault, [])
        self.assertIn('empty', out.lower())

    def test_cmd_vault_list_shows_names(self):
        self._skip_if_no_cryptography()
        self._vault().add('prod_pw', 's3cr3t')
        c = _make_client()
        with self._patch_vault():
            out = _capture(c.cmd_vault, ['list'])
        self.assertIn('prod_pw', out)

    def test_cmd_vault_add_stores_entry(self):
        self._skip_if_no_cryptography()
        c = _make_client()
        with self._patch_vault():
            with patch('getpass.getpass', return_value='s3cr3t'):
                _capture(c.cmd_vault, ['add', 'mykey'])
        self.assertEqual(self._vault().get('mykey'), 's3cr3t')

    def test_cmd_vault_delete_removes_entry(self):
        self._skip_if_no_cryptography()
        self._vault().add('gone', 'bye')
        c = _make_client()
        with self._patch_vault():
            _capture(c.cmd_vault, ['delete', 'gone'])
        self.assertIsNone(self._vault().get('gone'))

    def test_cmd_vault_delete_missing_reports_error(self):
        self._skip_if_no_cryptography()
        c = _make_client()
        with self._patch_vault():
            out = _capture(c.cmd_vault, ['delete', 'ghost'])
        self.assertIn('not found', out)

    def test_cmd_vault_invalid_subcommand_shows_usage(self):
        c = _make_client()
        with self._patch_vault():
            out = _capture(c.cmd_vault, ['frobnicate'])
        self.assertIn('Usage', out)

    def test_cmd_vault_works_without_connection(self):
        """vault is in _NO_CONNECTION_NEEDED."""
        c = _make_client()
        c.connected = False
        with self._patch_vault():
            out = _capture(c._dispatch, 'vault list')
        self.assertNotIn('Not connected', out)

    # ── cmd_open -p flag ──────────────────────────────────────────────────────

    def test_cmd_open_p_flag_uses_plain_password(self):
        """open -p plaintext passes the password directly to connect()."""
        c = _make_client()
        c.connected = False
        with patch.object(c, 'connect') as mock_connect:
            with self._patch_vault():
                _capture(c.cmd_open, ['user@host', '-p', 'mypassword'])
        mock_connect.assert_called_once()
        # connect(host, port, username, password, key_file) — password is index 3
        self.assertEqual(mock_connect.call_args[0][3], 'mypassword')

    def test_cmd_open_long_password_flag_uses_plain_password(self):
        c = _make_client()
        c.connected = False
        with patch.object(c, 'connect') as mock_connect:
            _capture(c.cmd_open, ['user@host', '--password=mypassword'])
        mock_connect.assert_called_once()
        self.assertEqual(mock_connect.call_args[0][3], 'mypassword')

    def test_cmd_open_port_flag_sets_port(self):
        c = _make_client()
        c.connected = False
        with patch.object(c, 'connect') as mock_connect:
            _capture(c.cmd_open, ['user@host', '-P', '2222', '-p', 'pw'])
        mock_connect.assert_called_once()
        self.assertEqual(mock_connect.call_args[0][1], 2222)
        self.assertEqual(mock_connect.call_args[0][3], 'pw')

    def test_cmd_open_user_flag_sets_default_user(self):
        c = _make_client()
        c.connected = False
        with patch.object(c, 'connect') as mock_connect:
            _capture(c.cmd_open, ['host', '-l', 'alice', '-p', 'pw'])
        mock_connect.assert_called_once()
        self.assertEqual(mock_connect.call_args[0][2], 'alice')

    def test_cmd_open_destination_user_overrides_user_flag(self):
        c = _make_client()
        c.connected = False
        with patch.object(c, 'connect') as mock_connect:
            _capture(c.cmd_open, ['bob@host', '-l', 'alice', '-p', 'pw'])
        mock_connect.assert_called_once()
        self.assertEqual(mock_connect.call_args[0][2], 'bob')

    def test_cmd_open_invalid_port_does_not_connect(self):
        c = _make_client()
        c.connected = False
        with patch.object(c, 'connect') as mock_connect:
            out = _capture(c.cmd_open, ['host', '-P', 'bad', '-p', 'pw'])
        mock_connect.assert_not_called()
        self.assertIn('port must be a number', out)

    def test_cmd_open_p_empty_string_is_explicit_password(self):
        """open -p '' must pass an empty password, not prompt again."""
        c = _make_client()
        c.connected = False
        with patch.object(c, 'connect') as mock_connect:
            with patch('getpass.getpass') as mock_getpass:
                _capture(c.cmd_open, ['user@host', '-p', ''])
        mock_connect.assert_called_once()
        self.assertEqual(mock_connect.call_args[0][3], '')
        mock_getpass.assert_not_called()

    def test_cmd_open_p_flag_resolves_vault_ref(self):
        """open -p vault:name resolves the credential before connecting."""
        self._skip_if_no_cryptography()
        self._vault().add('srvpass', 'topsecret')
        c = _make_client()
        c.connected = False
        with patch.object(c, 'connect') as mock_connect:
            with self._patch_vault():
                _capture(c.cmd_open, ['user@host', '-p', 'vault:srvpass'])
        mock_connect.assert_called_once()
        self.assertEqual(mock_connect.call_args[0][3], 'topsecret')

    def test_cmd_open_p_vault_missing_entry_reports_error(self):
        """open -p vault:ghost with no such entry shows an error, does not connect."""
        c = _make_client()
        c.connected = False
        with patch.object(c, 'connect') as mock_connect:
            with self._patch_vault():
                out = _capture(c.cmd_open, ['user@host', '-p', 'vault:ghost'])
        mock_connect.assert_not_called()
        self.assertIn('open:', out)

    def test_cmd_open_in_play_requires_noninteractive_credentials(self):
        """Scripted open must not block on an interactive password prompt."""
        c = _make_client()
        c.connected = False
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('open user@host\n')
            fname = f.name
        try:
            with patch.object(c, 'connect') as mock_connect:
                with patch('getpass.getpass') as mock_getpass:
                    out = _capture(c.cmd_play, [fname])
            mock_connect.assert_not_called()
            mock_getpass.assert_not_called()
            self.assertIn('scripted connections require -p or -i', out)
        finally:
            os.unlink(fname)

    # ── vault ref in batch script (via cmd_open -p) ───────────────────────────

    def test_vault_ref_usable_in_batch_script(self):
        """A batch script can use 'open host -p vault:name' to avoid plaintext passwords."""
        self._skip_if_no_cryptography()
        self._vault().add('batchpw', 'secret123')
        c = _make_client()
        c.connected = False

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('open testuser@testhost -p vault:batchpw\n')
            fname = f.name
        try:
            with patch.object(c, 'connect') as mock_connect:
                with self._patch_vault():
                    _capture(c.cmd_play, [fname])
            mock_connect.assert_called_once()
            self.assertEqual(mock_connect.call_args[0][3], 'secret123')
        finally:
            os.unlink(fname)


class TestMain(unittest.TestCase):

    def test_cli_atomic_uploads_are_enabled_by_default(self):
        with patch.object(sys, 'argv', ['sftp_client.py']):
            args = sftp_client._parse_args()
        self.assertTrue(args.atomic)

    def test_cli_can_explicitly_disable_atomic_uploads(self):
        with patch.object(sys, 'argv', ['sftp_client.py', '--no-atomic']):
            args = sftp_client._parse_args()
        self.assertFalse(args.atomic)

    def test_cli_empty_password_is_explicit_password(self):
        argv = ['sftp_client.py', 'user@host', '-p', '']
        with patch.object(sys, 'argv', argv):
            with patch('getpass.getpass') as mock_getpass:
                with patch('sftp_client.SFTPClient') as mock_client_cls:
                    client = mock_client_cls.return_value
                    sftp_client.main()
        client.run.assert_called_once()
        self.assertEqual(client.run.call_args.kwargs['password'], '')
        mock_getpass.assert_not_called()

    def test_cli_batch_with_destination_requires_noninteractive_credentials(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('# empty\n')
            batch_path = f.name
        try:
            argv = ['sftp_client.py', 'user@host', '-b', batch_path]
            with patch.object(sys, 'argv', argv):
                with patch('getpass.getpass') as mock_getpass:
                    with patch('sftp_client.SFTPClient') as mock_client_cls:
                        with self.assertRaises(SystemExit) as cm:
                            sftp_client.main()
            self.assertEqual(cm.exception.code, 1)
            mock_getpass.assert_not_called()
            mock_client_cls.assert_not_called()
        finally:
            os.unlink(batch_path)

    def test_cli_batch_expands_user_path_before_existence_check(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sftp', delete=False) as f:
            f.write('# empty\n')
            batch_path = f.name
        original_expanduser = os.path.expanduser

        def fake_expanduser(path):
            if path == '~/batch.sftp':
                return batch_path
            return original_expanduser(path)

        argv = ['sftp_client.py', '-b', '~/batch.sftp']
        try:
            with patch.object(sys, 'argv', argv):
                with patch('sftp_client.os.path.expanduser', side_effect=fake_expanduser):
                    with patch('sftp_client.SFTPClient') as mock_client_cls:
                        client = mock_client_cls.return_value
                        sftp_client.main()
            client.run.assert_called_once()
            self.assertEqual(client.run.call_args.kwargs['batch_file'], batch_path)
        finally:
            os.unlink(batch_path)


class TestVaultBugRegression(unittest.TestCase):
    """Regression tests for the 5 vault bugs found in the bug-review pass."""

    def setUp(self):
        import sftp_client as _sc
        self._VaultClass = _sc.PasswordVault
        self._tmpdir    = tempfile.mkdtemp()
        self.vault_path = os.path.join(self._tmpdir, 'vault.json')
        self.key_path   = os.path.join(self._tmpdir, 'vault.key')

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _vault(self):
        return self._VaultClass(self.vault_path, self.key_path)

    def _skip_if_no_cryptography(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography package not installed")

    # ── Bug 1: misleading error message in _resolve_vault_refs ───────────────

    def test_resolve_missing_entry_error_does_not_mention_password_arg(self):
        """BUG 1: Error for missing vault ref must not suggest '--vault-add NAME <password>'."""
        from sftp_client import _resolve_vault_refs
        try:
            _resolve_vault_refs('vault:ghost', self._vault())
        except ValueError as e:
            msg = str(e)
            self.assertNotIn('<password>', msg)
            self.assertIn('--vault-add', msg)
            self.assertIn('ghost', msg)

    # ── Bug 2: OSError from _load_vault not converted to RuntimeError ─────────

    def test_load_vault_permission_error_raises_runtime_error(self):
        """BUG 2: Unreadable vault file must raise RuntimeError, not raw OSError."""
        self._skip_if_no_cryptography()
        # Create a valid vault first, then revoke read permission
        v = self._vault()
        v.add('x', 'y')
        os.chmod(self.vault_path, 0o000)
        try:
            with self.assertRaises(RuntimeError) as cm:
                self._vault().list_entries()
            self.assertIn('Cannot read vault file', str(cm.exception))
        finally:
            os.chmod(self.vault_path, 0o600)

    # ── Bug 3: OSError from _save_vault not converted + tmp file leak ─────────

    def test_save_vault_write_error_raises_runtime_error(self):
        """BUG 3: Failed vault save must raise RuntimeError, not raw OSError."""
        self._skip_if_no_cryptography()
        v = self._vault()
        v.add('first', 'ok')           # creates vault and key files normally
        # Make the vault DIRECTORY read-only so the .tmp write fails
        os.chmod(self._tmpdir, 0o500)
        try:
            with self.assertRaises(RuntimeError) as cm:
                v.add('second', 'fail')
            self.assertIn('Cannot save vault', str(cm.exception))
        finally:
            os.chmod(self._tmpdir, 0o700)

    def test_save_vault_no_tmp_file_left_on_write_failure(self):
        """BUG 3: Failed vault save must not leave a .tmp file behind."""
        self._skip_if_no_cryptography()
        v = self._vault()
        v.add('first', 'ok')
        os.chmod(self._tmpdir, 0o500)
        try:
            try:
                v.add('second', 'fail')
            except RuntimeError:
                pass
        finally:
            os.chmod(self._tmpdir, 0o700)
        leftover = [f for f in os.listdir(self._tmpdir) if f.endswith('.tmp')]
        self.assertEqual(leftover, [])

    # ── Bug 4: OSError from _load_or_create_key not converted + tmp file leak ─

    def test_create_key_write_error_raises_runtime_error(self):
        """BUG 4: Failed key creation must raise RuntimeError, not raw OSError."""
        self._skip_if_no_cryptography()
        # Make the vault dir read-only before any key is created
        os.makedirs(self._tmpdir, exist_ok=True)
        with open(self.vault_path + '.lock', 'wb'):
            pass
        os.chmod(self.vault_path + '.lock', 0o600)
        os.chmod(self._tmpdir, 0o500)
        try:
            with self.assertRaises(RuntimeError) as cm:
                self._vault().add('x', 'y')
            self.assertIn('Cannot create vault key', str(cm.exception))
        finally:
            os.chmod(self._tmpdir, 0o700)

    def test_create_key_no_tmp_file_left_on_write_failure(self):
        """BUG 4: Failed key creation must not leave a .tmp key file behind."""
        self._skip_if_no_cryptography()
        os.makedirs(self._tmpdir, exist_ok=True)
        os.chmod(self._tmpdir, 0o500)
        try:
            try:
                self._vault().add('x', 'y')
            except RuntimeError:
                pass
        finally:
            os.chmod(self._tmpdir, 0o700)
        leftover = [f for f in os.listdir(self._tmpdir) if f.endswith('.tmp')]
        self.assertEqual(leftover, [])

    def test_create_key_permission_failure_does_not_leave_final_key(self):
        """Failed permission hardening must not expose a final key file."""
        self._skip_if_no_cryptography()
        with patch('sftp_client._set_private_file_permissions', side_effect=OSError('acl failed')):
            with self.assertRaises(RuntimeError):
                self._vault().add('x', 'y')
        self.assertFalse(os.path.exists(self.key_path))
        self.assertFalse(os.path.exists(self.key_path + '.tmp'))

    def test_save_vault_permission_failure_does_not_leave_new_vault(self):
        """Failed permission hardening must not expose a final vault file."""
        self._skip_if_no_cryptography()
        v = self._vault()
        # Create the key normally so only the vault save path is under test.
        v._fernet()
        self.assertTrue(os.path.exists(self.key_path))
        with patch('sftp_client._set_private_file_permissions', side_effect=OSError('acl failed')):
            with self.assertRaises(RuntimeError):
                v.add('x', 'y')
        self.assertFalse(os.path.exists(self.vault_path))
        self.assertFalse(os.path.exists(self.vault_path + '.tmp'))

    # ── Bug 5: missing key with existing vault silently creates a new key ─────

    def test_missing_key_with_existing_vault_raises_runtime_error(self):
        """BUG 5: key file missing when vault exists must error, not create a new key."""
        self._skip_if_no_cryptography()
        v = self._vault()
        v.add('secret', 'password123')
        self.assertTrue(os.path.exists(self.key_path))
        self.assertTrue(os.path.exists(self.vault_path))

        # Simulate key file loss
        os.unlink(self.key_path)

        with self.assertRaises(RuntimeError) as cm:
            self._vault().get('secret')
        msg = str(cm.exception)
        self.assertIn('key', msg.lower())
        self.assertIn('vault', msg.lower())

    def test_missing_key_does_not_overwrite_with_new_key(self):
        """BUG 5: A failed get/add after key loss must not write a new key file."""
        self._skip_if_no_cryptography()
        v = self._vault()
        v.add('secret', 'password123')
        os.unlink(self.key_path)

        try:
            self._vault().get('secret')
        except RuntimeError:
            pass

        # Key file must NOT have been recreated
        self.assertFalse(os.path.exists(self.key_path))

    def test_fresh_vault_and_key_both_absent_creates_key_normally(self):
        """BUG 5 fix must not break the normal first-use case (both files absent)."""
        self._skip_if_no_cryptography()
        self.assertFalse(os.path.exists(self.key_path))
        self.assertFalse(os.path.exists(self.vault_path))

        self._vault().add('new_entry', 'value')

        self.assertTrue(os.path.exists(self.key_path))
        self.assertTrue(os.path.exists(self.vault_path))
        self.assertEqual(self._vault().get('new_entry'), 'value')

    def test_concurrent_vault_adds_preserve_every_entry(self):
        """The vault lock must serialize complete load-modify-save transactions."""
        self._skip_if_no_cryptography()
        import threading

        worker_count = 8
        barrier = threading.Barrier(worker_count)
        errors = []

        def add_entry(index):
            try:
                barrier.wait()
                self._vault().add(f'entry-{index}', f'value-{index}')
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_entry, args=(index,))
                   for index in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(
            set(self._vault().list_entries()),
            {f'entry-{index}' for index in range(worker_count)},
        )
        for index in range(worker_count):
            self.assertEqual(self._vault().get(f'entry-{index}'), f'value-{index}')


# ── regressions found by live-server fuzzing ─────────────────────────────────

class TestDirectPutMode(unittest.TestCase):
    def test_direct_put_mode_grants_write_access(self):
        """paramiko's 'x' alone means create-exclusive without write access;
        the server created an empty file and the write then failed."""
        c = _make_client()
        c.atomic = False
        c.sftp.stat.side_effect = FileNotFoundError('not found')
        with tempfile.NamedTemporaryFile() as f:
            c.cmd_put([f.name, '/remote/new.txt'])
        mode = c.sftp.open.call_args.args[1]
        bf = paramiko.file.BufferedFile()
        bf._set_mode(mode)
        self.assertTrue(bf._flags & paramiko.file.BufferedFile.FLAG_WRITE)
        self.assertIn('x', mode)


class TestTransformTextFreshTokens(unittest.TestCase):
    GUID_RE = r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'

    def test_each_guid_and_md5_occurrence_is_fresh(self):
        guids = transform_text('%GUID% %GUID% %GUID%').split()
        self.assertEqual(len(set(guids)), 3)
        md5s = transform_text('%MD5% %MD5%').split()
        self.assertEqual(len(set(md5s)), 2)

    def test_rep_gives_each_copy_a_fresh_guid(self):
        rows = transform_text('%REP% "%GUID%," 50').rstrip(',').split(',')
        self.assertEqual(len(rows), 50)
        self.assertEqual(len(set(rows)), 50)

    def test_rep_of_static_text_still_multiplies(self):
        self.assertEqual(transform_text('%REP% "ab" 3'), 'ababab')
        self.assertEqual(transform_text('%REP% "%DATE%|" 2').count('|'), 2)

    def test_dynamic_rep_respects_size_limit(self):
        with self.assertRaises(ValueError):
            transform_text('%REP% "%GUID%" 1000000000000', max_chars=1024)

    def test_readme_rows_example_yields_distinct_guids(self):
        c = _make_client()
        c.sftp.lstat.side_effect = FileNotFoundError('missing')
        handle = c.sftp.open.return_value.__enter__.return_value
        c.cmd_new(['rows.csv', '%REP%', '%GUID%,%DATE%\\n', '1000'])
        rows = handle.write.call_args.args[0].decode().splitlines()
        self.assertEqual(len(rows), 1000)
        self.assertEqual(len({row.split(',')[0] for row in rows}), 1000)


class TestTransformTextEscapes(unittest.TestCase):
    def test_double_backslash_is_a_literal_backslash(self):
        self.assertEqual(transform_text(r'C:\\temp\\new'), 'C:\\temp\\new')
        self.assertEqual(transform_text(r'\\n'), '\\n')

    def test_expanded_text_is_not_rescanned(self):
        # %REP% "\\" 2 yields two backslashes; the following "n" stays literal.
        self.assertEqual(transform_text(r'%REP% "\\" 2n'), '\\\\n')

    def test_new_does_not_unescape_rep_output_twice(self):
        c = _make_client()
        c.sftp.lstat.side_effect = FileNotFoundError('missing')
        handle = c.sftp.open.return_value.__enter__.return_value
        c.cmd_new(['f', '%REP%', r'a\\n', '2'])
        self.assertEqual(handle.write.call_args.args[0], b'a\\na\\n')

    def test_unknown_escape_is_preserved(self):
        self.assertEqual(transform_text(r'\x41'), r'\x41')


class TestRtailSplitsOnLinefeedOnly(unittest.TestCase):
    CONTENT = 'a\x0cb\nc\x0bd\ne\rf\nx\u2028y\nlast\n'.encode()

    def _tail(self, content, n, with_size=True):
        c = _make_client()
        fh = _wire_remote_file(c, content)
        if not with_size:
            fh.stat.side_effect = IOError('no stat')
        return _capture(c.cmd_rtail, ['-n', str(n), '/remote/f'])

    def _expected(self, content, n):
        lines = content.split(b'\n')
        lines = [l + b'\n' for l in lines[:-1]] + ([lines[-1]] if lines[-1] else [])
        return b''.join(lines[-n:]).decode()

    def test_reverse_and_forward_paths_match_unix_tail(self):
        for with_size in (True, False):
            for n in range(1, 7):
                with self.subTest(with_size=with_size, n=n):
                    self.assertEqual(self._tail(self.CONTENT, n, with_size),
                                     self._expected(self.CONTENT, n))

    def test_cr_only_file_is_a_single_line(self):
        content = b'one\rtwo\rthree'
        self.assertEqual(self._tail(content, 1), 'one\rtwo\rthree\n')

    def test_chunk_boundary_keeps_last_lines_intact(self):
        content = b''.join(b'line %d\n' % i for i in range(30000))
        self.assertEqual(self._tail(content, 3), 'line 29997\nline 29998\nline 29999\n')
        self.assertEqual(self._tail(content, 3, with_size=False),
                         'line 29997\nline 29998\nline 29999\n')


class TestTrailingEscapedWhitespace(unittest.TestCase):
    def _dispatch_args(self, line):
        c = _make_client()
        seen = []
        with patch.dict(sftp_client.COMMANDS, {'echoargs': lambda self, args: seen.append(args)}):
            c._dispatch(line)
        return seen[0]

    def test_dispatch_keeps_escaped_trailing_space(self):
        self.assertEqual(self._dispatch_args('echoargs name\\ '), ['name '])
        self.assertEqual(self._dispatch_args('echoargs name\\\t'), ['name\t'])

    def test_dispatch_still_ignores_unescaped_whitespace(self):
        self.assertEqual(self._dispatch_args('  echoargs a b   '), ['a', 'b'])

    def test_play_keeps_escaped_trailing_space_with_crlf(self):
        c = _make_client()
        seen = []
        with tempfile.NamedTemporaryFile('w', suffix='.sftp', delete=False, newline='') as f:
            f.write('echoargs name\\ \r\n')
        try:
            with patch.dict(sftp_client.COMMANDS, {'echoargs': lambda self, args: seen.append(args)}):
                _capture(c.cmd_play, [f.name])
        finally:
            os.unlink(f.name)
        self.assertEqual(seen, [['name ']])


class TestTrailingBackslashNames(unittest.TestCase):
    def test_doubled_backslash_before_separator_is_one_backslash(self):
        self.assertEqual(_split_command_line('put a\\\\ b'), ['put', 'a\\', 'b'])
        self.assertEqual(_split_command_line('put a\\\\'), ['put', 'a\\'])
        self.assertEqual(_split_command_line('put "a b\\\\" c'), ['put', 'a b\\', 'c'])
        self.assertEqual(_split_command_line("put 'a\\\\' c"), ['put', 'a\\', 'c'])

    def test_windows_paths_keep_their_backslashes(self):
        self.assertEqual(_split_command_line(r'lcd \\server\share x'), ['lcd', r'\\server\share', 'x'])
        self.assertEqual(_split_command_line(r'lcd "C:\Program Files\x"'), ['lcd', r'C:\Program Files\x'])

    def test_completion_escaping_round_trips_awkward_names(self):
        import random
        rng = random.Random(5)
        alphabet = 'ab \t\\"\'%*é'
        for _ in range(2000):
            name = ''.join(rng.choice(alphabet) for _ in range(rng.randint(1, 8)))
            with self.subTest(name=name):
                self.assertEqual(_split_command_line(_escape_completion(name) + ' next'),
                                 [name, 'next'])


class TestOverwriteKeepsRemoteFileIdentity(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.atomic = True
        self.attrs = {}
        self.c.sftp.lstat.side_effect = self._lstat
        self.c.sftp.stat.side_effect = self._lstat
        self.c.sftp.readlink.side_effect = lambda p: self.links[p]
        self.links = {}

    def _lstat(self, path):
        if path in self.attrs:
            return self.attrs[path]
        if path.startswith('/remote/.sftp-'):
            return _make_attr('tmp', mode=0o100600, uid=1000, gid=1000)
        raise FileNotFoundError(path)

    def _put(self, *args):
        with tempfile.NamedTemporaryFile() as f:
            return _capture(self.c.cmd_put, list(args[:-1]) + [f.name, args[-1]])

    def test_put_force_keeps_mode_of_replaced_file(self):
        self.attrs['/remote/run.sh'] = _make_attr('run.sh', mode=0o100755)
        self._put('-f', '/remote/run.sh')
        staged = self.c.sftp.put.call_args.args[1]
        self.c.sftp.chmod.assert_called_once_with(staged, 0o755)
        self.c.sftp.posix_rename.assert_called_once_with(staged, '/remote/run.sh')
        self.c.sftp.chown.assert_not_called()

    def test_put_force_tries_to_keep_owner(self):
        self.attrs['/remote/f'] = _make_attr('f', mode=0o100644, uid=0, gid=0)
        self.c.sftp.chown.side_effect = PermissionError('not root')
        out = self._put('-f', '/remote/f')
        self.assertNotIn('put:', out)
        staged = self.c.sftp.put.call_args.args[1]
        self.c.sftp.chown.assert_called_once_with(staged, 0, 0)
        self.c.sftp.posix_rename.assert_called_once_with(staged, '/remote/f')

    def test_put_force_writes_through_symlink(self):
        self.attrs['/remote/link'] = _make_attr('link', mode=0o120777)
        self.attrs['/remote/real/target.txt'] = _make_attr('target.txt', mode=0o100640)
        self.links['/remote/link'] = 'real/target.txt'
        self._put('-f', '/remote/link')
        staged = self.c.sftp.put.call_args.args[1]
        self.assertTrue(staged.startswith('/remote/real/.sftp-'))
        self.c.sftp.posix_rename.assert_called_once_with(staged, '/remote/real/target.txt')
        self.c.sftp.chmod.assert_called_once_with(staged, 0o640)

    def test_put_force_refuses_read_only_file(self):
        self.attrs['/remote/ro.txt'] = _make_attr('ro.txt', mode=0o100444)
        out = self._put('-f', '/remote/ro.txt')
        self.assertIn('read-only', out)
        self.c.sftp.put.assert_not_called()

    def test_put_force_detects_symlink_loops(self):
        self.attrs['/remote/a'] = _make_attr('a', mode=0o120777)
        self.attrs['/remote/b'] = _make_attr('b', mode=0o120777)
        self.links.update({'/remote/a': 'b', '/remote/b': 'a'})
        out = self._put('-f', '/remote/a')
        self.assertIn('too many levels of symbolic links', out)
        self.c.sftp.put.assert_not_called()

    def test_new_force_keeps_mode_and_follows_symlink(self):
        self.attrs['/home/testuser/link'] = _make_attr('link', mode=0o120777)
        self.attrs['/data/report.txt'] = _make_attr('report.txt', mode=0o100664)
        self.links['/home/testuser/link'] = '/data/report.txt'
        self.c.sftp.stat.side_effect = lambda p: (
            _make_attr('tmp', mode=0o100600) if p.startswith('/data/.sftp-') else self._lstat(p))
        out = _capture(self.c.cmd_new, ['-f', 'link', 'hello'])
        self.assertIn('Created', out)
        staged = self.c.sftp.open.call_args.args[0]
        self.assertTrue(staged.startswith('/data/.sftp-'))
        self.c.sftp.chmod.assert_called_once_with(staged, 0o664)
        self.c.sftp.posix_rename.assert_called_once_with(staged, '/data/report.txt')


@unittest.skipIf(os.name == 'nt', 'POSIX permission bits')
class TestDownloadLocalFileIdentity(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.c.local_cwd = self.dir.name
        self.remote_mode = 0o100644

        def fake_get(remote, staged, **kwargs):
            with open(staged, 'wb') as fh:
                fh.write(b'remote data')

        self.c.sftp.get.side_effect = fake_get
        self.c.sftp.stat.side_effect = lambda p: _make_attr('f', mode=self.remote_mode)
        old = os.umask(0o022)
        self.addCleanup(os.umask, old)

    def _path(self, name):
        return os.path.join(self.dir.name, name)

    def test_new_file_gets_remote_mode_filtered_by_umask(self):
        for remote_mode, expected in ((0o100755, 0o755), (0o100666, 0o644), (0o100600, 0o600)):
            with self.subTest(remote_mode=oct(remote_mode)):
                self.remote_mode = remote_mode
                dest = self._path(f'f{remote_mode:o}')
                self.c._download_file('/remote/f', dest)
                self.assertEqual(os.stat(dest).st_mode & 0o777, expected)

    def test_overwrite_keeps_local_mode(self):
        dest = self._path('f')
        with open(dest, 'wb') as fh:
            fh.write(b'old')
        os.chmod(dest, 0o750)
        self.c._download_file('/remote/f', dest, overwrite=True)
        self.assertEqual(os.stat(dest).st_mode & 0o777, 0o750)

    def test_overwrite_writes_through_local_symlink(self):
        target = self._path('target')
        with open(target, 'wb') as fh:
            fh.write(b'old')
        link = self._path('link')
        os.symlink('target', link)
        _capture(self.c.cmd_get, ['-f', '/remote/f', link])
        self.assertTrue(os.path.islink(link))
        with open(target, 'rb') as fh:
            self.assertEqual(fh.read(), b'remote data')

    def test_dangling_local_symlink_is_refused(self):
        link = self._path('link')
        os.symlink('missing', link)
        out = _capture(self.c.cmd_get, ['-f', '/remote/f', link])
        self.assertIn('dangling symlink', out)
        self.assertFalse(os.path.lexists(self._path('missing')))

    def test_get_of_directory_reports_it(self):
        self.remote_mode = 0o040755
        out = _capture(self.c.cmd_get, ['/remote/dir'])
        self.assertIn('get: /remote/dir is a directory', out)
        self.c.sftp.get.assert_not_called()
        self.assertEqual(os.listdir(self.dir.name), [])

    def _wire_readv_file(self, data, reported_size=None):
        fh = MagicMock()
        fh.stat.return_value = _make_attr('f', size=len(data) if reported_size is None else reported_size)
        self.readv_calls = []

        def readv(chunks):
            self.readv_calls.append(list(chunks))
            for offset, length in chunks:
                yield data[offset:offset + length]

        fh.readv.side_effect = readv
        self.c.sftp.open.return_value.__enter__.return_value = fh

    def test_windowed_readv_without_prefetch_cap(self):
        """paramiko < 3.3 has no prefetch cap: pipeline one bounded window of
        readv requests at a time instead of reading serially."""
        data = os.urandom(2 * 64 * 32768 + 100)
        self._wire_readv_file(data)
        progress = []
        with patch.object(sftp_client, '_GET_SUPPORTS_PREFETCH_LIMIT', False):
            self.c._sftp_get('/remote/f', self._path('f'), callback=lambda done, total: progress.append(done))
        with open(self._path('f'), 'rb') as fh:
            self.assertEqual(fh.read(), data)
        self.c.sftp.get.assert_not_called()
        self.assertEqual([len(call) for call in self.readv_calls], [64, 64, 1])
        self.assertTrue(all(length <= 32768 for call in self.readv_calls for _, length in call))
        self.assertEqual(progress, [64 * 32768, 2 * 64 * 32768, len(data)])

    def test_windowed_readv_detects_short_file(self):
        self._wire_readv_file(b'abc', reported_size=10)
        with patch.object(sftp_client, '_GET_SUPPORTS_PREFETCH_LIMIT', False):
            with self.assertRaises(IOError):
                self.c._sftp_get('/remote/f', self._path('f'))


class TestNonUtf8LocalNames(unittest.TestCase):
    def test_put_rejects_remote_name_that_is_not_utf8(self):
        c = _make_client()
        out = io.StringIO()
        with self.assertRaises(ValueError) as cm:
            c._put_file('/tmp/caf\udce9.txt', '/remote/caf\udce9.txt', remote_existed=False)
        self.assertIn('not valid UTF-8', str(cm.exception))
        c.sftp.put.assert_not_called()
        c.sftp.open.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith('linux'), 'needs a filesystem that accepts non-UTF-8 names')
    def test_mput_reports_non_utf8_name_cleanly(self):
        c = _make_client()
        c.sftp.lstat.side_effect = FileNotFoundError('missing')
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d.encode(), b'caf\xe9.txt'), 'wb') as fh:
                fh.write(b'x')
            c.local_cwd = d
            out = _capture(c.cmd_mput, ['caf*'])
        self.assertIn('not valid UTF-8', out)
        c.sftp.put.assert_not_called()

    def test_log_handler_escapes_surrogates(self):
        with tempfile.TemporaryDirectory() as d, \
                patch.object(sftp_client, 'LOG_DIR', d), \
                patch('logging.getLogger', return_value=sftp_client.logging.Logger('t')):
            logger, path = sftp_client._setup_logger()
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                logger.info('Uploading caf\udce9.txt')
            for handler in logger.handlers:
                handler.close()
            with open(path, encoding='utf-8') as fh:
                self.assertIn('caf\\udce9.txt', fh.read())
        self.assertEqual(stderr.getvalue(), '')

    def test_main_makes_console_output_tolerate_surrogates(self):
        stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
        stderr = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
        vault = MagicMock()
        vault.return_value.list_entries.return_value = []
        with patch.object(sys, 'argv', ['sftp_client.py', '--vault-list']), \
                patch.object(sys, 'stdout', stdout), patch.object(sys, 'stderr', stderr), \
                patch.object(sftp_client, 'PasswordVault', vault):
            with self.assertRaises(SystemExit):
                sftp_client.main()
            print('caf\udce9')
        self.assertEqual(stdout.errors, 'backslashreplace')


class TestIdAndModeValidation(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()

    def test_chmod_rejects_out_of_range_modes(self):
        for mode in ('17777', '-1', '77777777777'):
            with self.subTest(mode=mode):
                out = _capture(self.c.cmd_chmod, [mode, 'f'])
                self.assertIn('between 0 and 7777', out)
        self.c.sftp.chmod.assert_not_called()
        _capture(self.c.cmd_chmod, ['7777', 'f'])
        self.c.sftp.chmod.assert_called_once_with('/home/testuser/f', 0o7777)

    def test_chown_and_chgrp_reject_out_of_range_ids(self):
        for cmd in (self.c.cmd_chown, self.c.cmd_chgrp):
            for value in ('-5', '4294967296'):
                with self.subTest(cmd=cmd.__name__, value=value):
                    out = _capture(cmd, [value, 'f'])
                    self.assertIn('between 0 and 4294967295', out)
        self.c.sftp.chown.assert_not_called()


class TestGenericFailureExplained(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.sftp.stat.side_effect = lambda p: _make_attr(
            'x', mode=0o040755 if p.endswith('dir') else 0o100644)

    def test_rmdir_of_non_empty_directory(self):
        self.c.sftp.rmdir.side_effect = IOError('Failure')
        self.c.sftp.listdir.return_value = ['child']
        self.assertIn('rmdir: Directory not empty', _capture(self.c.cmd_rmdir, ['dir']))

    def test_rmdir_of_file(self):
        self.c.sftp.rmdir.side_effect = IOError('Failure')
        self.assertIn('rmdir: Not a directory', _capture(self.c.cmd_rmdir, ['file']))

    def test_mkdir_of_existing_path(self):
        self.c.sftp.mkdir.side_effect = IOError('Failure')
        self.assertIn('mkdir: File exists', _capture(self.c.cmd_mkdir, ['dir']))

    def test_rm_of_directory(self):
        self.c.sftp.remove.side_effect = PermissionError('Permission denied')
        self.assertIn('rm: Is a directory (use rmdir)', _capture(self.c.cmd_rm, ['dir']))

    def test_rcat_of_directory(self):
        self.c.sftp.open.side_effect = IOError('Failure')
        self.assertIn('rcat: Is a directory', _capture(self.c.cmd_rcat, ['dir']))

    def test_missing_path_keeps_server_message(self):
        self.c.sftp.stat.side_effect = FileNotFoundError('No such file')
        self.c.sftp.rmdir.side_effect = FileNotFoundError('No such file')
        self.assertIn('rmdir: No such file', _capture(self.c.cmd_rmdir, ['dir']))


class TestCaseOnlyRename(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.remote_cwd = '/remote'
        self.c.sftp.stat.return_value = _make_attr('r2')  # case-insensitive lookup hits

    def test_case_only_rename_on_case_insensitive_server(self):
        self.c.sftp.listdir.return_value = ['r2', 'other']
        out = _capture(self.c.cmd_rename, ['r2', 'R2'])
        self.assertNotIn('already exists', out)
        self.c.sftp.posix_rename.assert_called_once_with('/remote/r2', '/remote/R2')

    def test_distinct_entries_on_case_sensitive_server_are_protected(self):
        self.c.sftp.listdir.return_value = ['r2', 'R2']
        out = _capture(self.c.cmd_rename, ['r2', 'R2'])
        self.assertIn('already exists', out)
        self.c.sftp.posix_rename.assert_not_called()
        self.c.sftp.rename.assert_not_called()


class TestLsFlagsAndGlobs(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.remote_cwd = '/remote'
        self.entries = [_make_attr(n) for n in ('a.txt', 'b.log', 'c.txt')]

        def listdir_attr(path):
            if path == '/remote':
                return list(self.entries)
            raise FileNotFoundError(path)

        self.c.sftp.listdir_attr.side_effect = listdir_attr
        self.c.sftp.stat.side_effect = FileNotFoundError('missing')

    def _names(self, out):
        return [line.split()[-1] for line in out.splitlines()]

    def test_flags_are_accepted(self):
        for args in (['-l'], ['-la'], ['-l', '/remote'], ['-1']):
            with self.subTest(args=args):
                self.assertEqual(self._names(_capture(self.c.cmd_ls, args)), ['a.txt', 'b.log', 'c.txt'])

    def test_glob_in_last_component(self):
        self.assertEqual(self._names(_capture(self.c.cmd_ls, ['*.txt'])), ['a.txt', 'c.txt'])
        self.assertEqual(self._names(_capture(self.c.cmd_ls, ['-l', '/remote/?.log'])), ['b.log'])

    def test_glob_without_match_is_an_error(self):
        out = _capture(self.c.cmd_ls, ['*.zip'])
        self.assertIn("ls: no match for '*.zip'", out)

    def test_missing_plain_path_keeps_server_error(self):
        self.assertIn('ls: ', _capture(self.c.cmd_ls, ['nope']))


class TestViewerEndsUnterminatedLine(unittest.TestCase):
    def test_rcat_rhead_rtail_end_with_newline_once(self):
        for content in (b'abc', b'abc\n', b'one\ntwo'):
            for cmd, extra in (('cmd_rcat', []), ('cmd_rhead', ['-n', '5']), ('cmd_rtail', ['-n', '5'])):
                with self.subTest(cmd=cmd, content=content):
                    c = _make_client()
                    _wire_remote_file(c, content)
                    out = _capture(getattr(c, cmd), extra + ['/remote/f'])
                    expected = content.decode()
                    self.assertEqual(out, expected if expected.endswith('\n') else expected + '\n')

    def test_empty_file_prints_nothing(self):
        c = _make_client()
        _wire_remote_file(c, b'')
        self.assertEqual(_capture(c.cmd_rcat, ['/remote/f']), '')

    def test_local_viewers_end_with_newline(self):
        c = _make_client()
        with tempfile.NamedTemporaryFile('w', delete=False) as f:
            f.write('x\ny')
        try:
            for cmd in (c.cmd_cat, c.cmd_head, c.cmd_tail):
                with self.subTest(cmd=cmd.__name__):
                    self.assertEqual(_capture(cmd, [f.name]), 'x\ny\n')
        finally:
            os.unlink(f.name)



class TestDeadSftpChannel(unittest.TestCase):
    def test_closed_sftp_channel_counts_as_dead_connection(self):
        c = _make_client()
        c.ssh.get_transport.return_value.is_active.return_value = True
        c.sftp.sock.closed = False
        self.assertFalse(c._connection_is_dead())
        c.sftp.sock.closed = True
        self.assertTrue(c._connection_is_dead())

    def test_dispatch_drops_session_when_channel_closes(self):
        c = _make_client()
        c.ssh.get_transport.return_value.is_active.return_value = True
        c.sftp.sock.closed = True
        out = _capture(c._dispatch, 'pwd')
        self.assertIn('Connection lost', out)
        self.assertFalse(c.connected)

    def test_nul_in_arguments_is_rejected_before_any_request(self):
        c = _make_client()
        out = _capture(c._dispatch, 'rm "a\x00b"')
        self.assertIn('cannot contain NUL', out)
        c.sftp.remove.assert_not_called()



class TestRound2Regressions(unittest.TestCase):
    def test_play_accepts_utf8_bom(self):
        c = _make_client()
        seen = []
        with tempfile.NamedTemporaryFile('wb', suffix='.sftp', delete=False) as f:
            f.write(b'\xef\xbb\xbfechoargs a\r\necho2 b\n')
        try:
            with patch.dict(sftp_client.COMMANDS, {'echoargs': lambda self, args: seen.append(args),
                                                   'echo2': lambda self, args: seen.append(args)}):
                out = _capture(c.cmd_play, [f.name])
        finally:
            os.unlink(f.name)
        self.assertNotIn('Unknown command', out)
        self.assertEqual(seen, [['a'], ['b']])

    def test_fmt_err_strips_errno_none(self):
        e = paramiko.ssh_exception.NoValidConnectionsError({('1.2.3.4', 2): OSError('refused')})
        self.assertFalse(sftp_client._fmt_err(e).startswith('[Errno'))
        self.assertEqual(sftp_client._fmt_err(OSError(None, 'Unable to connect')), 'Unable to connect')

    def test_failed_open_says_previous_session_is_kept(self):
        c = _make_client()
        c._connected_host = 'oldhost'
        with patch.object(c, 'connect', side_effect=paramiko.ssh_exception.AuthenticationException('Authentication failed.')):
            out = _capture(c.cmd_open, ['user@newhost', '-p', 'pw'])
        self.assertIn('Authentication failed. (still connected to oldhost)', out)
        self.assertTrue(c.connected)



class TestOldParamikoCompatibility(unittest.TestCase):
    @patch('paramiko.SSHClient')
    def test_connect_drops_keywords_older_paramiko_lacks(self, mock_cls):
        ssh = MagicMock()
        mock_cls.return_value = ssh
        ssh.open_sftp.return_value.normalize.return_value = '/home/user'
        supported = frozenset({'self', 'hostname', 'port', 'username', 'password', 'look_for_keys',
                               'allow_agent', 'timeout', 'banner_timeout', 'auth_timeout'})
        with patch.object(sftp_client, '_CONNECT_PARAMETERS', supported):
            with patch('sftp_client._setup_logger', return_value=(MagicMock(), '/dev/null')):
                client = SFTPClient()
            client.connect('host', username='user', password='pass')
        kwargs = ssh.connect.call_args.kwargs
        self.assertNotIn('channel_timeout', kwargs)
        self.assertEqual(kwargs['auth_timeout'], sftp_client._SFTP_TIMEOUT)



@unittest.skipUnless(hasattr(signal_module, 'raise_signal') and os.name != 'nt', 'POSIX signals')
class TestCtrlCDeferredToChunkBoundary(unittest.TestCase):
    """A SIGINT that lands mid-packet desynchronizes the SFTP stream and
    loses the session, so transfers raise it only between chunks."""

    def setUp(self):
        self.c = _make_client()
        self.c.atomic = True
        self.c.sftp.lstat.side_effect = FileNotFoundError('missing')
        self.events = []

    def _fake_put(self, local, remote, callback=None, **kwargs):
        signal_module.raise_signal(signal_module.SIGINT)   # arrives "mid-packet"
        self.events.append('packet finished')                # not interrupted here
        callback(32768, 65536)                              # chunk boundary
        self.events.append('second chunk')

    def test_sigint_during_put_is_raised_at_chunk_boundary(self):
        self.c.sftp.put.side_effect = self._fake_put
        previous = signal_module.getsignal(signal_module.SIGINT)
        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaises(KeyboardInterrupt):
                self.c._put_file(f.name, '/remote/x', remote_existed=False)
        self.assertEqual(self.events, ['packet finished'])
        staged = self.c.sftp.put.call_args.args[1]
        self.c.sftp.remove.assert_called_once_with(staged)
        self.assertIs(signal_module.getsignal(signal_module.SIGINT), previous)

    def test_second_sigint_interrupts_immediately(self):
        def stuck_put(local, remote, callback=None, **kwargs):
            signal_module.raise_signal(signal_module.SIGINT)
            self.events.append('first deferred')
            signal_module.raise_signal(signal_module.SIGINT)
            self.events.append('UNREACHABLE')
        self.c.sftp.put.side_effect = stuck_put
        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaises(KeyboardInterrupt):
                self.c._put_file(f.name, '/remote/x', remote_existed=False)
        self.assertEqual(self.events, ['first deferred'])

    def test_sigint_after_last_chunk_raises_after_commit(self):
        def put_then_signal(local, remote, callback=None, **kwargs):
            callback(10, 10)
            signal_module.raise_signal(signal_module.SIGINT)
        self.c.sftp.put.side_effect = put_then_signal
        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaises(KeyboardInterrupt):
                self.c._put_file(f.name, '/remote/x', remote_existed=False)
        staged = self.c.sftp.put.call_args.args[1]
        self.c.sftp.rename.assert_called_once_with(staged, '/remote/x')
        self.c.sftp.remove.assert_not_called()

    def test_sigint_during_get_is_raised_at_chunk_boundary(self):
        self.c.sftp.stat.side_effect = None
        self.c.sftp.stat.return_value = _make_attr('f')

        def fake_get(remote, staged, callback=None, **kwargs):
            with open(staged, 'wb') as fh:
                fh.write(b'partial')
            signal_module.raise_signal(signal_module.SIGINT)
            self.events.append('packet finished')
            callback(7, 100)

        self.c.sftp.get.side_effect = fake_get
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(KeyboardInterrupt):
                self.c._download_file('/remote/f', os.path.join(d, 'f'))
            self.assertEqual(os.listdir(d), [])
        self.assertEqual(self.events, ['packet finished'])

    def test_non_atomic_put_checks_between_chunks(self):
        self.c.atomic = False
        handle = self.c.sftp.open.return_value.__enter__.return_value
        writes = []

        def write(chunk):
            writes.append(len(chunk))
            if len(writes) == 1:
                signal_module.raise_signal(signal_module.SIGINT)

        handle.write.side_effect = write
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'x' * (200 * 1024)); f.flush()
            with self.assertRaises(KeyboardInterrupt):
                self.c._put_file(f.name, '/remote/x', remote_existed=False)
        self.assertEqual(writes, [64 * 1024])



class TestDestinationWithAtInUsername(unittest.TestCase):
    def test_splits_at_last_at_sign_like_openssh(self):
        self.assertEqual(_parse_destination('john@corp.com@host', 'me', 22),
                         ('john@corp.com', 'host', 22, False, True))
        self.assertEqual(_parse_destination('john@corp.com@host:2222', 'me', 22),
                         ('john@corp.com', 'host', 2222, True, True))
        self.assertEqual(_parse_destination('a@b@[::1]:2200', 'me', 22),
                         ('a@b', '::1', 2200, True, True))



class TestRound3ErrorMessages(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.remote_cwd = '/remote'

    def test_bad_message_is_explained(self):
        self.assertEqual(sftp_client._fmt_err(IOError('Bad message')),
                         'Bad message (name too long or invalid argument)')
        err = IOError('Bad message')
        self.assertEqual(self.c._describe_remote_error(err, '/remote/' + 'a' * 256, 'write'),
                         'File name too long')
        self.assertEqual(self.c._describe_remote_error(err, '/remote/' + 'é' * 128, 'write'),
                         'File name too long')
        self.assertEqual(self.c._describe_remote_error(err, '/r' + '/d' * 600, 'write'), 'Path too long')
        self.assertEqual(self.c._describe_remote_error(err, '/remote/ok', 'write'),
                         'Bad message (name too long or invalid argument)')

    def test_new_reports_name_too_long(self):
        self.c.sftp.lstat.side_effect = FileNotFoundError('missing')
        self.c.sftp.open.side_effect = IOError('Bad message')
        out = _capture(self.c.cmd_new, ['a' * 256, 'x'])
        self.assertIn('new: File name too long', out)

    def test_dirput_reports_the_failing_path(self):
        self.c.sftp.stat.side_effect = FileNotFoundError('missing')
        self.c.sftp.lstat.side_effect = FileNotFoundError('missing')
        self.c.sftp.listdir.return_value = []
        self.c.sftp.mkdir.side_effect = lambda p: (_ for _ in ()).throw(IOError('Bad message')) \
            if len(p.rsplit('/', 1)[-1]) > 255 else None
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, 'tree', 'b' * 200))
            with patch.object(self.c, '_remote_join', lambda base, name: base.rstrip('/') + '/' + (
                    name * 2 if name.startswith('b') else name)):
                out = _capture(self.c.cmd_dirput, [os.path.join(d, 'tree')])
        self.assertIn('dirput: File name too long', out)

    def test_race_loser_on_plain_rename_is_explained(self):
        self.c.sftp.rename.side_effect = IOError('Failure')
        self.c.sftp.lstat.side_effect = [FileNotFoundError('missing'), _make_attr('x')]
        self.c.sftp.stat.side_effect = FileNotFoundError('missing')
        with tempfile.NamedTemporaryFile() as f:
            out = _capture(self.c.cmd_put, [f.name, '/remote/x'])
        self.assertIn('was created by another client during the upload', out)
        self.c.sftp.remove.assert_called_once()

    def test_race_loser_on_exclusive_open_is_explained(self):
        self.c.atomic = False
        self.c.sftp.open.side_effect = IOError('Failure')
        self.c.sftp.lstat.side_effect = [FileNotFoundError('missing'), _make_attr('x')]
        self.c.sftp.stat.side_effect = FileNotFoundError('missing')
        with tempfile.NamedTemporaryFile() as f:
            out = _capture(self.c.cmd_put, [f.name, '/remote/x'])
        self.assertIn('was created by another client during the upload', out)

    def test_rename_failure_explained_from_both_paths(self):
        kinds = {'/remote/dir': 0o040755, '/remote/file': 0o100644, '/remote/dir2': 0o040755}
        self.c.sftp.stat.side_effect = lambda p: _make_attr(p, mode=kinds[p]) if p in kinds \
            else (_ for _ in ()).throw(FileNotFoundError(p))
        self.c.sftp.posix_rename.side_effect = IOError('Failure')
        self.assertEqual(self.c._describe_rename_error(IOError('Failure'), '/remote/dir', '/remote/file'),
                         'Cannot replace a file with a directory')
        self.assertEqual(self.c._describe_rename_error(IOError('Failure'), '/remote/dir', '/remote/dir2'),
                         'Directory not empty')
        # OpenSSH maps ENOTDIR to NO_SUCH_FILE even though both paths exist.
        self.assertEqual(self.c._describe_rename_error(FileNotFoundError('No such file'), '/remote/dir', '/remote/file'),
                         'Cannot replace a file with a directory')
        self.assertEqual(self.c._describe_rename_error(FileNotFoundError('No such file'), '/remote/missing', '/remote/file'),
                         'No such file')


class TestRenameIntoDirectory(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.remote_cwd = '/remote'
        self.kinds = {'/remote/f': 0o100644, '/remote/dir': 0o040755}
        self.c.sftp.stat.side_effect = lambda p: _make_attr(p, mode=self.kinds[p]) if p in self.kinds \
            else (_ for _ in ()).throw(FileNotFoundError(p))
        self.c.sftp.listdir.return_value = ['f', 'dir']

    def test_existing_directory_receives_the_source(self):
        _capture(self.c.cmd_rename, ['f', 'dir'])
        self.c.sftp.rename.assert_called_once_with('/remote/f', '/remote/dir/f')

    def test_trailing_slash_receives_the_source(self):
        _capture(self.c.cmd_rename, ['f', 'dir/'])
        self.c.sftp.rename.assert_called_once_with('/remote/f', '/remote/dir/f')

    def test_existing_file_inside_directory_is_protected(self):
        self.kinds['/remote/dir/f'] = 0o100644
        out = _capture(self.c.cmd_rename, ['f', 'dir'])
        self.assertIn('already exists', out)
        self.c.sftp.rename.assert_not_called()

    def test_plain_rename_unchanged(self):
        _capture(self.c.cmd_rename, ['f', 'g'])
        self.c.sftp.rename.assert_called_once_with('/remote/f', '/remote/g')

    def test_case_only_rename_of_a_directory_is_not_moved_into_itself(self):
        self.c.sftp.listdir.return_value = ['dir']
        self.kinds['/remote/DIR'] = 0o040755  # case-insensitive lookup hits itself
        _capture(self.c.cmd_rename, ['dir', 'DIR'])
        self.c.sftp.posix_rename.assert_called_once_with('/remote/dir', '/remote/DIR')


class TestMgetBrokenSymlinks(unittest.TestCase):
    def test_broken_link_is_skipped_with_warning(self):
        c = _make_client()
        c.remote_cwd = '/remote'
        c.sftp.listdir_attr.return_value = [_make_attr('loop', mode=0o120777), _make_attr('ok.txt')]
        c.sftp.stat.side_effect = lambda p: (_ for _ in ()).throw(FileNotFoundError(p)) \
            if p.endswith('loop') else _make_attr('ok.txt')

        def fake_get(remote, staged, **kwargs):
            with open(staged, 'wb') as fh:
                fh.write(b'ok')

        c.sftp.get.side_effect = fake_get
        c._play_depth = 1  # batch mode: a hard error would abort the script
        with tempfile.TemporaryDirectory() as d:
            c.local_cwd = d
            out = _capture(c.cmd_mget, ['*'])
            self.assertEqual(sorted(os.listdir(d)), ['ok.txt'])
        self.assertIn("skipping broken symlink 'loop'", out)
        self.assertFalse(c._batch_had_error)



class TestChannelTimeoutEndsSession(unittest.TestCase):
    class _Channel:
        def __init__(self):
            self.calls = 0
            self.closed = False

        def recv(self, n):
            self.calls += 1
            raise sftp_client.socket.timeout()

        def send(self, data):
            self.calls += 1
            return len(data)

        def sendall(self, data):
            self.calls += 1

    def test_later_io_fails_fast_after_a_timeout(self):
        channel = self._Channel()
        sftp_client._fail_fast_after_timeout(channel)
        with self.assertRaises(TimeoutError):
            channel.recv(4)
        self.assertTrue(channel.sftp_timed_out)
        for op in (lambda: channel.recv(4), lambda: channel.send(b'x'), lambda: channel.sendall(b'x')):
            with self.assertRaises(TimeoutError):
                op()
        self.assertEqual(channel.calls, 1)  # nothing after the timeout reached the socket

    def test_dispatch_ends_session_after_timeout(self):
        c = _make_client()
        c.ssh.get_transport.return_value.is_active.return_value = True
        c.sftp.sock.closed = False
        c.sftp.sock.sftp_timed_out = True
        out = _capture(c._dispatch, 'pwd')
        self.assertIn('Connection timed out.', out)
        self.assertFalse(c.connected)

    def test_dangling_colon_is_dropped(self):
        self.assertEqual(sftp_client._fmt_err(paramiko.SSHException('Server connection dropped: ')),
                         'Server connection dropped')

    def test_bare_timeout_message(self):
        self.assertEqual(sftp_client._fmt_err(TimeoutError()),
                         f'Timed out: no response from the server for {sftp_client._SFTP_TIMEOUT} seconds')


class TestParamikoLogging(unittest.TestCase):
    def test_paramiko_errors_go_to_the_log_file_not_stderr(self):
        loggers = {}

        def get_logger(name=None):
            return loggers.setdefault(name, sftp_client.logging.Logger(name or 'root'))

        with tempfile.TemporaryDirectory() as d, \
                patch.object(sftp_client, 'LOG_DIR', d), \
                patch('logging.getLogger', side_effect=get_logger):
            logger, path = sftp_client._setup_logger()
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                loggers['paramiko'].error('Socket exception: Connection reset by peer (104)')
            for handler in logger.handlers:
                handler.close()
            with open(path, encoding='utf-8') as fh:
                self.assertIn('Connection reset by peer', fh.read())
        self.assertEqual(stderr.getvalue(), '')
        self.assertFalse(loggers['paramiko'].propagate)


class TestNonRegularRemoteFiles(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.sftp.stat.return_value = _make_attr('zero', mode=0o020666, size=0)  # char device

    def test_get_refuses_device(self):
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            out = _capture(self.c.cmd_get, ['/dev/zero'])
            self.assertEqual(os.listdir(d), [])
        self.assertIn('/dev/zero is not a regular file', out)
        self.c.sftp.get.assert_not_called()

    def test_viewers_refuse_device(self):
        for cmd in (self.c.cmd_rcat, self.c.cmd_rhead, self.c.cmd_rtail):
            with self.subTest(cmd=cmd.__name__):
                out = _capture(cmd, ['/dev/zero'])
                self.assertIn('is not a regular file', out)
        self.c.sftp.open.assert_not_called()

    def test_mget_skips_non_regular_with_warning(self):
        self.c.sftp.listdir_attr.return_value = [_make_attr('zero', mode=0o020666), _make_attr('ok')]
        self.c.sftp.stat.side_effect = lambda p: _make_attr('ok')

        def fake_get(remote, staged, **kwargs):
            with open(staged, 'wb') as fh:
                fh.write(b'ok')

        self.c.sftp.get.side_effect = fake_get
        self.c._play_depth = 1
        with tempfile.TemporaryDirectory() as d:
            self.c.local_cwd = d
            out = _capture(self.c.cmd_mget, ['*'])
            self.assertEqual(os.listdir(d), ['ok'])
        self.assertIn("skipping non-regular file 'zero'", out)
        self.assertFalse(self.c._batch_had_error)


class TestRheadBounded(unittest.TestCase):
    def test_endless_line_is_an_error_not_unbounded_memory(self):
        c = _make_client()
        fh = MagicMock()
        fh.read.side_effect = lambda size=-1: b'\0' * size
        c.sftp.open.return_value.__enter__.return_value = fh
        with patch.object(sftp_client, '_MAX_TAIL_BUFFER_BYTES', 1024 * 1024):
            out = _capture(c.cmd_rhead, ['-n', '1', '/dev/zero-like'])
        self.assertIn('rhead: Line exceeds 1048576 bytes', out)
        self.assertLess(fh.read.call_count, 20)

    def test_lines_split_across_reads(self):
        c = _make_client()
        data = b''.join(b'%d:' % i + b'x' * 50000 + b'\n' for i in range(5))
        _wire_remote_file(c, data)
        out = _capture(c.cmd_rhead, ['-n', '3', '/remote/f'])
        self.assertEqual(out, b''.join(data.split(b'\n')[i] + b'\n' for i in range(3)).decode())


@unittest.skipUnless(hasattr(signal_module, 'raise_signal') and os.name != 'nt', 'POSIX signals')
class TestViewerCtrlC(unittest.TestCase):
    def test_rcat_stops_at_chunk_boundary_on_ctrl_c(self):
        c = _make_client()
        fh = MagicMock()
        reads = []

        def read(size=-1):
            reads.append(size)
            if len(reads) == 2:
                signal_module.raise_signal(signal_module.SIGINT)
            return b'a' * size

        fh.read.side_effect = read
        c.sftp.open.return_value.__enter__.return_value = fh
        with self.assertRaises(KeyboardInterrupt):
            _capture(c.cmd_rcat, ['/remote/endless'])
        self.assertEqual(len(reads), 2)



class TestParamikoThreadDisconnects(unittest.TestCase):
    def _run_thread(self, filename, exc):
        namespace = {}
        exec(compile(f"def target():\n    raise {exc}\n", filename, 'exec'), namespace)
        stderr = io.StringIO()
        with patch.object(threading, 'excepthook', threading.excepthook), \
                patch.object(sys, 'stderr', stderr):
            sftp_client._log_paramiko_thread_disconnects()
            worker = threading.Thread(target=namespace['target'])
            worker.start()
            worker.join()
        return stderr.getvalue()

    def test_paramiko_thread_disconnect_is_not_printed(self):
        paramiko_dir = os.path.dirname(os.path.abspath(paramiko.__file__))
        with patch('logging.Logger.warning') as warning:
            out = self._run_thread(os.path.join(paramiko_dir, 'sftp_file.py'), 'EOFError()')
        self.assertEqual(out, '')
        warning.assert_called_once()

    def test_other_thread_errors_are_still_reported(self):
        out = self._run_thread('/elsewhere/module.py', 'EOFError()')
        self.assertIn('EOFError', out)
        paramiko_dir = os.path.dirname(os.path.abspath(paramiko.__file__))
        out = self._run_thread(os.path.join(paramiko_dir, 'sftp_file.py'), 'ValueError("bug")')
        self.assertIn('ValueError', out)



class TestSourceChangedDuringUpload(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.sftp.lstat.side_effect = FileNotFoundError('missing')
        self.c.sftp.stat.side_effect = FileNotFoundError('missing')
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.src = os.path.join(self.dir.name, 'src.bin')
        with open(self.src, 'wb') as fh:
            fh.write(b'x' * 1000)

    def _put_that(self, mutate):
        def fake_put(local, remote, callback=None, **kwargs):
            mutate()
        self.c.sftp.put.side_effect = fake_put
        return _capture(self.c.cmd_put, [self.src, '/remote/src.bin'])

    def test_truncated_source_is_not_published(self):
        out = self._put_that(lambda: os.truncate(self.src, 10))
        self.assertIn('changed during the upload; not published', out)
        self.c.sftp.rename.assert_not_called()
        self.c.sftp.posix_rename.assert_not_called()
        self.c.sftp.remove.assert_called_once()

    def test_appended_source_is_not_published(self):
        def grow():
            with open(self.src, 'ab') as fh:
                fh.write(b'more')
        out = self._put_that(grow)
        self.assertIn('changed during the upload', out)
        self.c.sftp.rename.assert_not_called()

    def test_source_replaced_by_rename_is_published(self):
        def editor_save():
            replacement = self.src + '.new'
            with open(replacement, 'wb') as fh:
                fh.write(b'y' * 5)
            os.replace(replacement, self.src)
        out = self._put_that(editor_save)
        self.assertNotIn('changed during', out)
        self.c.sftp.rename.assert_called_once()

    def test_direct_upload_reports_change(self):
        self.c.atomic = False
        handle = self.c.sftp.open.return_value.__enter__.return_value
        handle.write.side_effect = lambda chunk: os.truncate(self.src, 10)
        out = _capture(self.c.cmd_put, [self.src, '/remote/src.bin'])
        self.assertIn('may mix old and new data', out)


class TestLogWriteFailures(unittest.TestCase):
    def test_log_write_errors_warn_once(self):
        with tempfile.TemporaryDirectory() as d:
            handler = sftp_client._PrivateTimedRotatingFileHandler(os.path.join(d, 'log'), when='midnight')
            handler.stream = MagicMock()
            handler.stream.write.side_effect = OSError(27, 'File too large')
            stderr = io.StringIO()
            record = sftp_client.logging.LogRecord('t', 20, __file__, 1, 'msg', None, None)
            with contextlib.redirect_stderr(stderr):
                for _ in range(3):
                    handler.emit(record)
            handler.stream = None
            handler.close()
        self.assertEqual(stderr.getvalue().count('cannot write log file'), 1)
        self.assertNotIn('Traceback', stderr.getvalue())



class TestBatchInputs(unittest.TestCase):
    def test_play_dash_reads_stdin_without_closing_it(self):
        c = _make_client()
        seen = []
        stdin = io.TextIOWrapper(io.BytesIO(b'\xef\xbb\xbfechoargs a\n# c\nechoargs b\n'), encoding='utf-8')
        with patch.object(sys, 'stdin', stdin), \
                patch.dict(sftp_client.COMMANDS, {'echoargs': lambda self, args: seen.append(args)}):
            _capture(c.cmd_play, ['-'])
            self.assertFalse(stdin.buffer.closed)
        self.assertEqual(seen, [['a'], ['b']])

    def _main(self, *argv):
        stderr = io.StringIO()
        with patch.object(sys, 'argv', ['sftp_client.py', *argv]), \
                patch.object(sftp_client.SFTPClient, 'run') as run, \
                patch.object(sftp_client, '_setup_logger', return_value=(MagicMock(), '/dev/null')), \
                contextlib.redirect_stderr(stderr):
            try:
                sftp_client.main()
                code = 0
            except SystemExit as e:
                code = e.code
        return code, stderr.getvalue(), run

    def test_main_accepts_dash_and_non_regular_batch_files(self):
        code, err, run = self._main('-b', '-')
        self.assertEqual(code, 0, err)
        self.assertEqual(run.call_args.kwargs['batch_file'], '-')
        if os.path.exists('/dev/null'):
            code, err, run = self._main('-b', '/dev/null')
            self.assertEqual(code, 0, err)

    def test_main_rejects_directory_and_missing_batch_file(self):
        with tempfile.TemporaryDirectory() as d:
            code, err, _ = self._main('-b', d)
            self.assertEqual(code, 2)
            self.assertIn('is a directory', err)
            code, err, _ = self._main('-b', os.path.join(d, 'missing'))
            self.assertIn('not found', err)

    def test_main_reports_invalid_port(self):
        for port in ('0', '70000'):
            code, err, _ = self._main('user@host', '-P', port)
            self.assertEqual(code, 2)
            self.assertIn(f'Invalid port: {port}', err)



class TestDestinationCheckFailures(unittest.TestCase):
    def setUp(self):
        self.c = _make_client()
        self.c.sftp.lstat.side_effect = PermissionError(13, 'Permission denied')
        self.c.sftp.stat.side_effect = PermissionError(13, 'Permission denied')
        self.c.sftp.listdir.side_effect = PermissionError(13, 'Permission denied')

    def test_symlink_reports_unreadable_destination(self):
        out = _capture(self.c._dispatch, 'ln -s target locked/link')
        self.assertIn("symlink: could not check remote destination", out)
        self.assertNotIn("Error in", out)
        self.c.sftp.symlink.assert_not_called()

    def test_rename_reports_unreadable_destination(self):
        out = _capture(self.c._dispatch, 'rename a locked/b')
        self.assertIn("rename: could not check remote destination", out)
        self.assertNotIn("Error in", out)
        self.c.sftp.rename.assert_not_called()



if __name__ == '__main__':
    unittest.main()
