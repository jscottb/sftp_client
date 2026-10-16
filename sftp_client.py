#!/usr/bin/env python3
"""
sftp_client.py  — Interactive SFTP client with history, tab-completion,
                   file-creation templates, play-back scripting, and daily logs.

Usage:
  sftp_client.py [user@]host[:port] [-P port] [-i keyfile] [-b batchfile]

Requires:  pip install paramiko
"""

import os
import sys
import re
import errno
import glob as _glob
import uuid
import hashlib
import shlex
# readline powers history and tab completion; on Windows it comes from
# pyreadline3, which installs a top-level ``readline`` shim.  Catch everything:
# a pyreadline3 that breaks on a new Python version must degrade to
# no-completion, not stop the client from starting.
def _readline_tab_binds(module) -> tuple:
    doc = module.__doc__ or ''
    if getattr(module, 'backend', '') == 'pyreadline' or 'pyreadline' in doc:
        # pyreadline3's emacs mode leaves Tab unbound (it inserts a tab) and
        # rejects GNU's '"\t": complete' syntax; cmd.Cmd uses this form.
        return ('tab: complete',)
    if 'libedit' in doc:
        return ('bind ^I rl_complete',)             # macOS libedit
    return ('"\\t": complete',)                     # GNU readline (Linux / Homebrew)

try:
    import readline
    _RL_TAB_BINDS = _readline_tab_binds(readline)
except Exception:
    readline    = None                              # type: ignore[assignment]
    _RL_TAB_BINDS = ()
import logging
from logging.handlers import TimedRotatingFileHandler
import datetime
import stat as _stat
import fnmatch
import getpass
import argparse
import io
import ipaddress
import json
import subprocess
import codecs
import tempfile
import inspect
import time
import unicodedata
import threading
import traceback
import shutil
import signal
import socket
from collections import deque
from contextlib import contextmanager
from typing import Optional, List, Dict, Any, Tuple, NamedTuple

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(errors="replace")
        except Exception:
            pass

try:
    import paramiko
except ImportError:
    print("Error: paramiko is required.  Run:  pip install paramiko")
    sys.exit(1)

VERSION     = "1.1.0"
HISTORY_FILE = os.path.expanduser("~/.sftp_client_history")
LOG_DIR      = os.path.expanduser("~/.sftp_logs")

_VAULT_REF_PREFIX = "vault:"
_ENV_REF_PREFIX   = "env:"
_DEFAULT_VAULT_DIR = os.path.expanduser("~/.sftpclient")
_DEFAULT_VAULT_FILE = os.path.join(_DEFAULT_VAULT_DIR, "vault.json")
_DEFAULT_KEY_FILE = os.path.join(_DEFAULT_VAULT_DIR, "vault.key")
_VAULT_LOCK_TIMEOUT = 10.0
_SFTP_TIMEOUT = 30
_MAX_NEW_CONTENT_BYTES = 16 * 1024 * 1024
_MAX_TAIL_BUFFER_BYTES = 16 * 1024 * 1024
_MAX_TAIL_LINES = 100_000
_MAX_ORPHAN_CLEANUP_PER_CONNECT = 10
_MAX_PREFETCH_REQUESTS = 64
_MAX_ID = 0xFFFFFFFF  # uid/gid are uint32 on the wire

try:
    _GET_SUPPORTS_PREFETCH_LIMIT = 'max_concurrent_prefetch_requests' in inspect.signature(
        paramiko.SFTPClient.get).parameters
except (TypeError, ValueError):
    _GET_SUPPORTS_PREFETCH_LIMIT = False


def _current_umask() -> int:
    mask = os.umask(0)
    os.umask(mask)
    return mask


def _sync_directory(path: str) -> None:
    """Make a completed replacement durable on filesystems that support it."""
    if os.name == 'nt':
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _set_private_file_permissions(path: str) -> None:
    """Restrict a credential file to the current user where the platform allows it."""
    if os.name != 'nt':
        os.chmod(path, 0o600)
        return

    # Windows does not honor POSIX mode bits for ACL privacy. Use a protected
    # DACL granting full access to the owner, SYSTEM, and Administrators.
    try:
        import ctypes
        from ctypes import wintypes

        sddl = "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)"
        sd = wintypes.LPVOID()
        if not ctypes.windll.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(sd), None
        ):
            raise OSError(ctypes.get_last_error())
        try:
            DACL_SECURITY_INFORMATION = 0x00000004
            if not ctypes.windll.advapi32.SetFileSecurityW(path, DACL_SECURITY_INFORMATION, sd):
                raise OSError(ctypes.get_last_error())
        finally:
            ctypes.windll.kernel32.LocalFree(sd)
    except Exception as e:
        raise OSError(f"cannot restrict Windows ACL for {path}: {e}") from e


def _set_private_dir_permissions(path: str) -> None:
    """Restrict a directory to the current user where the platform allows it."""
    if os.name != 'nt':
        os.chmod(path, 0o700)
        return
    _set_private_file_permissions(path)


def _ensure_private_dir(path: str) -> None:
    if os.name == 'nt':
        os.makedirs(path, exist_ok=True)
        _set_private_dir_permissions(path)
        return
    if not os.path.exists(path):
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
        return
    mode = os.stat(path).st_mode & 0o777
    os.chmod(path, mode & 0o700)


@contextmanager
def _exclusive_file_lock(path: str, timeout: float = _VAULT_LOCK_TIMEOUT):
    """Hold a bounded, cross-process exclusive lock on *path*."""
    lock_dir = os.path.dirname(path) or '.'
    fd = None
    acquired = False
    unlock = None
    try:
        _ensure_private_dir(lock_dir)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        _set_private_file_permissions(path)
        deadline = time.monotonic() + timeout

        if os.name == 'nt':
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b'\0')

            while True:
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    acquired = True
                    unlock = lambda: (
                        os.lseek(fd, 0, os.SEEK_SET),
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1),
                    )
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"timed out waiting for {path}")
                    time.sleep(0.05)
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    unlock = lambda: fcntl.flock(fd, fcntl.LOCK_UN)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"timed out waiting for {path}")
                    time.sleep(0.05)
    except (OSError, TimeoutError) as e:
        if fd is not None:
            os.close(fd)
        raise RuntimeError(f"Cannot lock vault ({path}): {e}") from e

    try:
        yield
    finally:
        try:
            if acquired and unlock is not None:
                unlock()
        finally:
            if fd is not None:
                os.close(fd)


class _PrivateTimedRotatingFileHandler(TimedRotatingFileHandler):
    """Timed rotating log handler that creates the active log as 0600."""

    def _open(self):
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self.baseFilename, flags, 0o600)
        return io.open(fd, self.mode, encoding=self.encoding, errors=self.errors)

    def handleError(self, record):
        # A full disk fails every log write; warn once instead of printing
        # a "--- Logging error ---" traceback for each line.
        if getattr(self, '_reported_error', False):
            return
        self._reported_error = True
        try:
            sys.stderr.write(f"Warning: cannot write log file {self.baseFilename}: "
                             f"{sys.exc_info()[1]}\n")
        except Exception:
            pass


def _local_file_version(path: str, fallback=None):
    """(size, mtime) of a local file, to detect it changing during an upload.

    Only in-place changes matter: a file deleted or replaced by rename (as
    editors save) was still read whole through the open handle, so those
    return fallback, which callers pass as the version taken before."""
    try:
        info = os.stat(path)
    except OSError:
        return fallback
    if fallback is not None and (info.st_dev, info.st_ino) != fallback[2:]:
        return fallback
    return (info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino)


def _fail_fast_after_timeout(channel) -> None:
    """Once an SFTP read or write times out, the stream still owes the
    server's replies, so the session cannot be trusted. Remember that on the
    channel and fail every later read or write at once: otherwise each
    follow-up request (temp cleanup, fallbacks, the next command) waited
    out the timeout again."""
    channel.sftp_timed_out = False
    for name in ('recv', 'send', 'sendall'):
        original = getattr(channel, name)

        def guarded(*args, _original=original, **kwargs):
            if channel.sftp_timed_out:
                raise socket.timeout("the SFTP connection timed out")
            try:
                return _original(*args, **kwargs)
            except socket.timeout:
                channel.sftp_timed_out = True
                raise

        setattr(channel, name, guarded)


class _KeyboardInteractiveTransport(paramiko.Transport):
    """Transport that answers SSHClient's password step with
    keyboard-interactive, so the fallback gets SSHClient's host-key checks."""

    def __init__(self, sock, ki_handler=None, **kwargs):
        super().__init__(sock, **kwargs)
        self._ki_handler = ki_handler

    def auth_password(self, username, password, event=None, fallback=True):
        return self.auth_interactive(username, self._ki_handler)


try:
    _CONNECT_PARAMETERS = frozenset(inspect.signature(paramiko.SSHClient.connect).parameters)
except (TypeError, ValueError):
    _CONNECT_PARAMETERS = None
_CONNECT_SUPPORTS_TRANSPORT_FACTORY = bool(_CONNECT_PARAMETERS) and 'transport_factory' in _CONNECT_PARAMETERS


class PasswordVault:
    """Encrypted credential store. Entries are referenced as 'vault:<name>'."""

    def __init__(self, vault_path: str = _DEFAULT_VAULT_FILE, key_path: str = _DEFAULT_KEY_FILE):
        self.vault_path = vault_path
        self.key_path = key_path
        self.lock_path = vault_path + '.lock'

    def _fernet(self):
        with _exclusive_file_lock(self.lock_path):
            return self._fernet_unlocked()

    def _fernet_unlocked(self):
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            raise RuntimeError(
                "The 'cryptography' package is required for vault support. "
                "Install with: pip install cryptography"
            )
        key = self._load_or_create_key(Fernet)
        try:
            return Fernet(key)
        except ValueError as e:
            raise RuntimeError(
                f"Vault key file is invalid: {self.key_path}. Restore the original key."
            ) from e

    def _load_or_create_key(self, Fernet) -> bytes:
        if os.path.exists(self.key_path):
            try:
                with open(self.key_path, 'rb') as f:
                    key = f.read().strip()
            except OSError as e:
                raise RuntimeError(f"Cannot read vault key ({self.key_path}): {e}") from e
            if not key:
                raise RuntimeError(
                    f"Vault key file is empty or corrupt: {self.key_path}. "
                    "Delete it to generate a new key (existing vault entries will be unrecoverable)."
                )
            return key

        # BUG GUARD: if the vault file already exists, creating a fresh key would
        # silently make every stored entry permanently unrecoverable.  Refuse and
        # tell the user exactly what happened instead.
        if os.path.exists(self.vault_path):
            raise RuntimeError(
                f"Vault key not found: {self.key_path}\n"
                f"The vault file exists ({self.vault_path}) but its key is missing.\n"
                "Restore the key file, or delete the vault file to start fresh "
                "(all stored entries will be lost)."
            )

        key     = Fernet.generate_key()
        key_dir = os.path.dirname(self.key_path) or '.'
        tmp_key = None
        published = False
        try:
            _ensure_private_dir(key_dir)
            fd, tmp_key = tempfile.mkstemp(
                prefix=os.path.basename(self.key_path) + '.',
                suffix='.tmp',
                dir=key_dir,
            )
            with os.fdopen(fd, 'wb') as f:
                f.write(key)
                f.flush()
                os.fsync(f.fileno())
            _set_private_file_permissions(tmp_key)
            os.replace(tmp_key, self.key_path)
            published = True
            _sync_directory(key_dir)
        except OSError as e:
            if tmp_key is not None:
                try:
                    os.unlink(tmp_key)
                except OSError:
                    pass
            if published:
                raise RuntimeError(
                    f"Vault key was created, but its directory could not be synced "
                    f"({self.key_path}): {e}. Verify the key before retrying."
                ) from e
            raise RuntimeError(f"Cannot create vault key ({self.key_path}): {e}") from e
        return key

    def _load_vault(self) -> Dict[str, str]:
        if not os.path.exists(self.vault_path):
            return {}
        try:
            with open(self.vault_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except OSError as e:
            raise RuntimeError(f"Cannot read vault file ({self.vault_path}): {e}") from e
        except (UnicodeError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Vault file is corrupt ({self.vault_path}): {e}") from e
        if not isinstance(data, dict):
            raise RuntimeError(f"Vault file has unexpected format ({self.vault_path}): expected object, got {type(data).__name__}")
        return data

    def _save_vault(self, data: Dict[str, str]) -> None:
        vault_dir = os.path.dirname(self.vault_path) or '.'
        tmp_vault = None
        published = False
        try:
            _ensure_private_dir(vault_dir)
            fd, tmp_vault = tempfile.mkstemp(
                prefix=os.path.basename(self.vault_path) + '.',
                suffix='.tmp',
                dir=vault_dir,
            )
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            _set_private_file_permissions(tmp_vault)
            os.replace(tmp_vault, self.vault_path)
            published = True
            _sync_directory(vault_dir)
        except OSError as e:
            if tmp_vault is not None:
                try:
                    os.unlink(tmp_vault)
                except OSError:
                    pass
            if published:
                raise RuntimeError(
                    f"Vault was replaced, but its directory could not be synced "
                    f"({self.vault_path}): {e}. Verify the entry before retrying."
                ) from e
            raise RuntimeError(f"Cannot save vault ({self.vault_path}): {e}") from e

    def add(self, name: str, plaintext: str) -> None:
        """Encrypt and store a credential under the given name."""
        with _exclusive_file_lock(self.lock_path):
            f = self._fernet_unlocked()
            token = f.encrypt(plaintext.encode()).decode()
            vault = self._load_vault()
            vault[name] = token
            self._save_vault(vault)

    def get(self, name: str) -> Optional[str]:
        """Decrypt and return a stored credential, or None if not found."""
        with _exclusive_file_lock(self.lock_path):
            vault = self._load_vault()
            if name not in vault:
                return None
            f = self._fernet_unlocked()  # raises RuntimeError if cryptography not installed
            try:
                from cryptography.fernet import InvalidToken
                return f.decrypt(vault[name].encode()).decode()
            except InvalidToken:
                raise RuntimeError(
                    f"Failed to decrypt vault entry '{name}'. "
                    "The vault key may have changed or the entry may be corrupt."
                )
            except (AttributeError, TypeError) as e:
                raise RuntimeError(f"Vault entry '{name}' is corrupt: {e}") from e

    def delete(self, name: str) -> bool:
        """Remove a stored credential. Returns True if it existed."""
        with _exclusive_file_lock(self.lock_path):
            vault = self._load_vault()
            if name not in vault:
                return False
            del vault[name]
            self._save_vault(vault)
            return True

    def list_entries(self) -> List[str]:
        """Return all stored entry names."""
        with _exclusive_file_lock(self.lock_path):
            return list(self._load_vault().keys())


def _resolve_vault_refs(obj: Any, vault: PasswordVault) -> Any:
    """Walk a config structure and replace 'vault:<name>' / 'env:<VAR>' strings."""
    if isinstance(obj, dict):
        return {k: _resolve_vault_refs(v, vault) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_vault_refs(item, vault) for item in obj]
    if isinstance(obj, str):
        if obj.startswith(_ENV_REF_PREFIX):
            var = obj[len(_ENV_REF_PREFIX):]
            value = os.environ.get(var)
            if value is None:
                raise ValueError(f"Environment variable '{var}' is not set")
            return value
        if obj.startswith(_VAULT_REF_PREFIX):
            name = obj[len(_VAULT_REF_PREFIX):]
            value = vault.get(name)
            if value is None:
                raise ValueError(f"Vault entry '{name}' not found. Add it with: vault add {name}  (or --vault-add {name} on the command line)")
            return value
    return obj


# ──────────────────────────────────────────────────────────────────────────────
# Daily rotating log
# ──────────────────────────────────────────────────────────────────────────────

def _setup_logger():
    log_file = os.path.join(LOG_DIR, "sftp_client.log")

    logger = logging.getLogger("sftp_client")
    logger.setLevel(logging.DEBUG)

    if logger.handlers and all(isinstance(h, logging.NullHandler) for h in logger.handlers):
        for handler in list(logger.handlers):
            logger.removeHandler(handler)

    if not logger.handlers:
        try:
            _ensure_private_dir(LOG_DIR)
            fh = _PrivateTimedRotatingFileHandler(
                log_file,
                when="midnight",
                interval=1,
                backupCount=30,
                encoding="utf-8",
                # Local names that are not valid UTF-8 arrive as surrogate
                # escapes; log them instead of raising "--- Logging error ---".
                errors="backslashreplace",
            )
            _set_private_file_permissions(log_file)
            fh.suffix = "%Y-%m-%d.log"
        except OSError:
            logger.addHandler(logging.NullHandler())
            log_file = "(logging disabled)"
        else:
            fh.setLevel(logging.DEBUG)
            fmt = logging.Formatter("%(asctime)s  %(levelname)-7s  %(message)s",
                                    datefmt="%Y-%m-%d %H:%M:%S")
            fh.setFormatter(fmt)
            logger.addHandler(fh)

    # paramiko logs transport failures ("Socket exception: Connection reset
    # by peer") at ERROR; with no handler of its own Python's last-resort
    # handler printed them on stderr in the middle of the session.
    paramiko_logger = logging.getLogger("paramiko")
    if not paramiko_logger.handlers:
        paramiko_logger.addHandler(logger.handlers[0] if logger.handlers else logging.NullHandler())
        paramiko_logger.setLevel(logging.WARNING)
        paramiko_logger.propagate = False

    return logger, log_file


# ──────────────────────────────────────────────────────────────────────────────
# Text-transform engine  (%TOKEN% substitution + escape sequences)
# ──────────────────────────────────────────────────────────────────────────────

_TRANSFORM_RE = re.compile(
    r'%REP%\s+"(?P<dq>(?:[^"\\]|\\.)*)"\s+(?P<dq_n>\d+)'
    r"|%REP%\s+'(?P<sq>(?:[^'\\]|\\.)*)'\s+(?P<sq_n>\d+)"
    r'|%REP%\s+(?P<ch>\S)\s+(?P<ch_n>\d+)'
    r'|(?P<tok>%(?:DATETIME|DATE|GMTDATE|GUID|MD5)%)'
    r'|\\(?P<esc>.)'
)
# Tokens that must produce a fresh value at every occurrence, including in
# every copy made by %REP%.
_DYNAMIC_TOKEN_RE = re.compile(r'%(?:GUID|MD5)%')
_TEXT_ESCAPES = {'n': '\n', 'r': '\r', 't': '\t', '\\': '\\'}


def _content_too_large(max_chars: int) -> ValueError:
    return ValueError(f"content exceeds {max_chars} bytes")


def transform_text(text: str, max_chars: Optional[int] = None) -> str:
    """
    Expand %TOKEN% substitutions and \\n / \\r / \\t / \\\\ escapes in one pass.

    Tokens:
        %DATE%       current local date          (YYYY-MM-DD)
        %DATETIME%   current local date+time     (YYYY-MM-DD HH:MM:SS)
        %GMTDATE%    UTC ISO-8601 timestamp       (YYYY-MM-DDTHH:MM:SSZ)
        %GUID%       random UUID4 (fresh at every occurrence)
        %MD5%        MD5 hex digest of a fresh UUID4 (fresh at every occurrence)
        %REP% "s" n  repeat string s n times (may nest other tokens)
                     also: %REP% 's' n  or  %REP% c n  (single bare char)

    Escapes:  \\n → newline   \\r → CR   \\t → tab   \\\\ → backslash
              (unknown \\X is kept as-is)

    Expanded text is never rescanned, so a backslash or token produced by an
    expansion is emitted literally.
    """
    return _transform_text(text, max_chars, None)


def _repeat_text(inner: str, count: int, max_chars: Optional[int],
                 clock: Optional[Tuple[datetime.datetime, datetime.datetime]] = None) -> str:
    """Expand inner count times. Dynamic tokens get fresh values in every copy."""
    if count <= 0:
        return ''
    if not _DYNAMIC_TOKEN_RE.search(inner):
        expanded = _transform_text(inner, max_chars, clock)
        if max_chars is not None and expanded and count > max_chars // len(expanded):
            raise _content_too_large(max_chars)
        return expanded * count
    pieces = []
    total = 0
    for _ in range(count):
        piece = _transform_text(inner, max_chars, clock)
        total += len(piece)
        if max_chars is not None and total > max_chars:
            raise _content_too_large(max_chars)
        pieces.append(piece)
    return ''.join(pieces)


def _transform_text(text: str, max_chars: Optional[int],
                    clock: Optional[Tuple[datetime.datetime, datetime.datetime]]) -> str:
    if max_chars is not None and len(text) > max_chars:
        raise _content_too_large(max_chars)
    if clock is None:
        clock = (datetime.datetime.now(), datetime.datetime.now(datetime.timezone.utc))
    now, now_utc = clock

    out: List[str] = []
    total = 0

    def emit(piece: str) -> None:
        nonlocal total
        total += len(piece)
        if max_chars is not None and total > max_chars:
            raise _content_too_large(max_chars)
        out.append(piece)

    pos = 0
    for m in _TRANSFORM_RE.finditer(text):
        emit(text[pos:m.start()])
        pos = m.end()
        for inner_group, count_group in (('dq', 'dq_n'), ('sq', 'sq_n'), ('ch', 'ch_n')):
            if m.group(count_group) is not None:
                emit(_repeat_text(m.group(inner_group), int(m.group(count_group)), max_chars, clock))
                break
        else:
            token = m.group('tok')
            if token == '%DATETIME%':
                emit(now.strftime("%Y-%m-%d %H:%M:%S"))
            elif token == '%DATE%':
                emit(now.strftime("%Y-%m-%d"))
            elif token == '%GMTDATE%':
                emit(now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"))
            elif token == '%GUID%':
                emit(str(uuid.uuid4()))
            elif token == '%MD5%':
                emit(hashlib.md5(uuid.uuid4().bytes).hexdigest())
            else:
                ch = m.group('esc')
                emit(_TEXT_ESCAPES.get(ch, '\\' + ch))
    emit(text[pos:])
    return ''.join(out)


# ──────────────────────────────────────────────────────────────────────────────
# Tab-completion
# ──────────────────────────────────────────────────────────────────────────────

# Commands whose *first* positional argument is a LOCAL path
_LOCAL_FIRST  = {'put', 'dirput', 'mput', 'lls', 'lcd', 'lmkdir', 'play', 'cat'}
# Commands whose *first* positional argument is a REMOTE path
_REMOTE_FIRST = {'get', 'ls', 'dir', 'cd', 'mkdir', 'rmdir', 'rm', 'delete',
                 'rename', 'stat', 'symlink', 'new', 'mget',
                 'rcat'}
# Commands that take a file path but may have -n N before it
_LOCAL_N_FIRST  = {'head', 'tail'}
_REMOTE_N_FIRST = {'rhead', 'rtail'}
# Commands accepting the -f/-i overwrite-protection flags anywhere before their
# positional args — completion must not let those flags shift arg positions.
_OVERWRITE_FLAGS = {'-f', '--force', '-i', '--confirm'}
_OVERWRITE_FLAG_COMMANDS = {'get', 'put', 'dirput', 'mget', 'mput', 'rename', 'symlink', 'ln', 'new'}


class _Completer:
    def __init__(self, client: "SFTPClient"):
        self.client  = client
        self._matches: List[str] = []

    # readline calls complete(text, state) repeatedly starting at state=0
    def complete(self, text: str, state: int) -> Optional[str]:
        if state == 0:
            self._matches = self._build(text)
        try:
            return self._matches[state]
        except IndexError:
            return None

    def _build(self, text: str) -> List[str]:
        line = readline.get_line_buffer() if readline else ''
        end = len(line)
        if readline is not None:
            try:
                value = readline.get_endidx()
                if isinstance(value, int):
                    end = max(0, min(value, len(line)))
            except (AttributeError, RuntimeError):
                pass
        prefix = line[:end]
        scan = _scan_portable_line(prefix, allow_unclosed_quote=True)
        matches = self._build_from_line(prefix, text)

        right = ''
        token_continues_right = False
        separator_right = False
        if scan.token_active and end < len(line):
            full_scan = _scan_portable_line(line, allow_unclosed_quote=True)
            for index, (start, stop) in enumerate(full_scan.spans):
                if start == scan.current_start and stop >= end:
                    token_continues_right = stop > end
                    separator_right = stop == end and line[end].isspace()
                    full_value = full_scan.tokens[index]
                    if full_value.startswith(scan.current_value):
                        right = full_value[len(scan.current_value):]
                    break

        return self._adapt_readline_matches(
            text,
            scan,
            matches,
            right,
            token_continues_right,
            separator_right,
        )

    def _adapt_readline_matches(
        self,
        text: str,
        scan: "_LineScan",
        matches: List[str],
        right: str,
        token_continues_right: bool,
        separator_right: bool,
    ) -> List[str]:
        """Convert whole-token matches to replacements for readline's scope."""
        current = scan.current_value
        adapted = []
        for match in matches:
            match_scan = _scan_portable_line(match, allow_unclosed_quote=True)
            if len(match_scan.tokens) != 1:
                continue
            candidate = match_scan.tokens[0]
            if not candidate.casefold().startswith(current.casefold()):
                continue

            suffix_end = len(candidate)
            if right:
                if not candidate.casefold().endswith(right.casefold()):
                    continue
                suffix_end -= len(right)
                if suffix_end < len(current):
                    continue

            suffix = candidate[len(current):suffix_end]
            replacement = text + _escape_completion_suffix(suffix, scan.quote)
            terminal = not match_scan.token_active
            if terminal:
                if scan.quote is not None and not token_continues_right:
                    replacement += scan.quote
                if not token_continues_right and not separator_right:
                    replacement += ' '
            adapted.append(replacement)
        return adapted

    def _build_from_line(self, line: str, text: str) -> List[str]:
        scan = _scan_portable_line(line, allow_unclosed_quote=True)
        tokens = scan.tokens

        # completing the command name itself
        if not tokens or (len(tokens) == 1 and scan.token_active):
            pfx = scan.current_value.lower()
            return [c + ' ' for c in sorted(COMMANDS) if c.startswith(pfx)]

        cmd       = tokens[0].lower()
        arg_pos   = len(tokens) - (1 if scan.token_active else 0)
        completion_text = _escape_completion(scan.current_value)
        # arg_pos == 1 → completing first arg, 2 → second, …

        # Destination-writing commands accept -f/-i before their positional
        # args. Don't let those flags shift arg_pos, and don't
        # offer path completions while a flag is still being typed.
        if cmd in _OVERWRITE_FLAG_COMMANDS:
            prior = tokens[1:arg_pos]
            arg_pos -= sum(1 for t in prior if t in _OVERWRITE_FLAGS)
            if scan.token_active and scan.current_value.startswith('-'):
                return []

        # open/connect host options — only identity-file option values are local paths.
        if cmd in {'open', 'connect'}:
            identity = self._open_identity_completion(scan.current_value, tokens, arg_pos)
            if identity is not None:
                return identity
            return []

        # get remote [local]  — second arg is local
        if cmd == 'get' and arg_pos == 2:
            return self._local(completion_text)

        # put/dirput local [remote]  — second arg is remote
        if cmd in {'put', 'dirput'} and arg_pos == 2:
            return self._remote(completion_text)

        # rename old new  — both remote
        if cmd == 'rename' and arg_pos == 2:
            return self._remote(completion_text)

        # symlink/ln src dest — both remote, with ln optionally taking -s first
        if cmd == 'symlink' and arg_pos == 2:
            return self._remote(completion_text)

        # chmod/chown/chgrp mode-or-id path — second arg is remote
        if cmd in {'chmod', 'chown', 'chgrp'} and arg_pos == 2:
            return self._remote(completion_text)

        # ln [-s] src dest — only complete remote paths after the optional flag
        if cmd == 'ln':
            rest = [t for t in tokens[1:] if t not in _OVERWRITE_FLAGS]
            if arg_pos == 1 and scan.current_value.startswith('-'):
                return []
            if rest and rest[0] == '-s' and arg_pos in {2, 3}:
                return self._remote(completion_text)
            if (not rest or rest[0] != '-s') and arg_pos in {1, 2}:
                return self._remote(completion_text)

        # head/tail [-n N] file — skip the -n and its value, complete the path
        if cmd in _LOCAL_N_FIRST:
            # tokens after cmd: [-n, N,] file
            # don't complete if we're on the -n flag or its number value
            rest = tokens[1:]
            if rest and rest[0] == '-n':
                if arg_pos == 3:
                    return self._local(completion_text)
                return []
            if arg_pos == 1 and not scan.current_value.startswith('-'):
                return self._local(completion_text)
            return []

        if cmd in _REMOTE_N_FIRST:
            rest = tokens[1:]
            if rest and rest[0] == '-n':
                if arg_pos == 3:
                    return self._remote(completion_text)
                return []
            if arg_pos == 1 and not scan.current_value.startswith('-'):
                return self._remote(completion_text)
            return []

        if cmd in _LOCAL_FIRST and arg_pos == 1:
            return self._local(completion_text)

        if cmd in _REMOTE_FIRST and arg_pos == 1:
            return self._remote(completion_text)

        return []

    def _open_identity_completion(
        self,
        value: str,
        tokens: List[str],
        arg_pos: int,
    ) -> Optional[List[str]]:
        for prefix in ('--identity=', '-i='):
            if value.startswith(prefix):
                path_text = _escape_completion(value[len(prefix):])
                return [prefix + match for match in self._local(path_text)]

        args = tokens[1:]
        current_index = arg_pos - 1
        if current_index <= 0:
            return None
        previous = args[current_index - 1] if current_index - 1 < len(args) else None
        if previous in {'-i', '--identity'}:
            return self._local(_escape_completion(value))
        return None

    # ── local completions ─────────────────────────────────────────────────────

    def _local_sep(self, text: str) -> str:
        if os.altsep and os.altsep in text:
            return os.altsep
        if os.sep in text:
            return os.sep
        return os.sep

    def _endswith_local_sep(self, text: str) -> bool:
        seps = [os.sep]
        if os.altsep:
            seps.append(os.altsep)
        return any(text.endswith(sep) for sep in seps)

    def _local(self, text: str) -> List[str]:
        raw_text = _unescape_completion(text)
        expanded = os.path.expanduser(raw_text) if raw_text else self.client.local_cwd
        sep = self._local_sep(raw_text)
        if os.path.isdir(expanded) and (self._endswith_local_sep(raw_text) or not raw_text):
            dir_path  = expanded
            dir_pfx   = raw_text.rstrip('/\\') + sep if raw_text else ''
            base      = ''
        else:
            dir_path  = os.path.dirname(expanded) or self.client.local_cwd
            base      = os.path.basename(expanded)
            dir_pfx   = os.path.dirname(raw_text)
            if dir_pfx and not self._endswith_local_sep(dir_pfx):
                dir_pfx += sep

        try:
            entries = os.listdir(dir_path)
        except OSError:
            return []

        results = []
        for e in sorted(entries):
            if not _safe_completion_name(e):
                continue
            if os.name == 'nt':
                matches_base = e.casefold().startswith(base.casefold())
            else:
                matches_base = e.startswith(base)
            if not matches_base:
                continue
            full   = os.path.join(dir_path, e)
            suffix = sep if os.path.isdir(full) else ' '
            results.append(_escape_completion(dir_pfx + e) + suffix)
        return results

    # ── remote completions ────────────────────────────────────────────────────

    def _remote(self, text: str) -> List[str]:
        raw_text = _unescape_completion(text)
        sftp = self.client.sftp
        if sftp is None:
            return []

        if '/' in raw_text:
            rdir_raw = raw_text.rsplit('/', 1)[0] or '/'
            rdir  = self.client._rpath(rdir_raw)
            pfx   = rdir_raw.rstrip('/') + '/'
            base  = raw_text.rsplit('/', 1)[1]
        else:
            rdir  = self.client.remote_cwd
            pfx   = ''
            base  = raw_text

        try:
            entries = sftp.listdir_attr(rdir)
        except Exception:
            return []

        results = []
        for e in sorted(entries, key=lambda a: a.filename):
            if not _safe_completion_name(e.filename):
                continue
            if not e.filename.startswith(base):
                continue
            mode = e.st_mode if isinstance(e.st_mode, int) else None
            if mode is None or _stat.S_ISLNK(mode):
                try:
                    stat_mode = sftp.stat(rdir.rstrip('/') + '/' + e.filename).st_mode
                    mode = stat_mode if isinstance(stat_mode, int) else None
                except Exception:
                    pass
            suffix = '/' if (mode is not None and _stat.S_ISDIR(mode)) else ' '
            results.append(_escape_completion(pfx + e.filename) + suffix)
        return results


def _parse_destination(destination: str, default_user: str = None, default_port: int = 22):
    """
    Parse [user@]host[:port], including bracketed IPv6 literals like [::1]:2222.
    A bare IPv6 literal without brackets is treated as a host, not host:port.
    """
    username = default_user
    hostport = destination
    port = default_port
    port_explicit = False

    def _valid_port(value: int) -> bool:
        return 1 <= value <= 65535

    def _result(host: str, value: int, explicit: bool):
        if not host or not _valid_port(value):
            return username, hostport, port, port_explicit, False
        return username, host, value, explicit, True

    if '@' in hostport:
        # Split at the last '@' like OpenSSH: usernames may contain '@'
        # (e.g. user@example.com@sftp.example.net).
        username, hostport = hostport.rsplit('@', 1)

    if hostport.startswith('['):
        end = hostport.find(']')
        if end == -1:
            return username, hostport, port, port_explicit, False
        host = hostport[1:end]
        rest = hostport[end + 1:]
        if rest and not rest.startswith(':'):
            return username, hostport, port, port_explicit, False
        if rest.startswith(':'):
            try:
                port = int(rest[1:])
                port_explicit = True
            except ValueError:
                return username, hostport, port, port_explicit, False
        return _result(host, port, port_explicit)

    if hostport.count(':') == 1:
        host, port_str = hostport.rsplit(':', 1)
        try:
            return _result(host, int(port_str), True)
        except ValueError:
            return username, hostport, port, port_explicit, False

    if ':' in hostport:
        try:
            ipaddress.IPv6Address(hostport)
        except ValueError:
            return username, hostport, port, port_explicit, False

    return _result(hostport, port, port_explicit)


class _LineScan(NamedTuple):
    tokens: List[str]
    spans: List[Tuple[int, int]]
    token_active: bool
    current_value: str
    current_start: int
    quote: Optional[str]


def _scan_portable_line(line: str, *, allow_unclosed_quote: bool = False) -> _LineScan:
    """Parse command text and retain the active token's source span."""
    tokens: List[str] = []
    spans: List[Tuple[int, int]] = []
    buf: List[str] = []
    quote: Optional[str] = None
    token_started = False
    token_start = len(line)
    i = 0

    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else None

        if ch == '\\':
            if not token_started:
                token_started = True
                token_start = i
            # A run of backslashes is literal unless it precedes a character
            # it can escape (whitespace or a quote outside quotes, the open
            # quote inside them) or, outside quotes, the end of the line.
            # There 2n backslashes are n literal ones and an odd one escapes
            # the next character. So \\server\share and C:\dir stay intact,
            # while "name\\ " ends a token with a literal backslash.
            run_end = i
            while run_end < len(line) and line[run_end] == '\\':
                run_end += 1
            run = run_end - i
            after = line[run_end] if run_end < len(line) else None
            if quote:
                special = after == quote
            else:
                special = after is None or after.isspace() or after in ("'", '"')
            if not special:
                buf.append('\\' * run)
                i = run_end
                continue
            buf.append('\\' * (run // 2))
            i = run_end
            if run % 2:
                # An odd trailing backslash at line end has nothing to escape.
                buf.append(after if after is not None else '\\')
                i += 1
            continue

        if quote:
            if ch == quote:
                quote = None
            else:
                buf.append(ch)
            i += 1
            continue

        if ch in ("'", '"'):
            if not token_started:
                token_started = True
                token_start = i
            quote = ch
            i += 1
            continue

        if ch.isspace():
            if token_started:
                tokens.append(''.join(buf))
                spans.append((token_start, i))
                buf = []
                token_started = False
                token_start = len(line)
            i += 1
            continue

        if not token_started:
            token_started = True
            token_start = i
        buf.append(ch)
        i += 1

    if quote and not allow_unclosed_quote:
        raise ValueError("No closing quotation")
    if token_started:
        tokens.append(''.join(buf))
        spans.append((token_start, len(line)))

    return _LineScan(
        tokens=tokens,
        spans=spans,
        token_active=token_started,
        current_value=''.join(buf) if token_started else '',
        current_start=token_start if token_started else len(line),
        quote=quote,
    )


def _split_portable_line(line: str, *, allow_unclosed_quote: bool = False) -> List[str]:
    """Split command text while preserving native Windows and UNC paths."""
    return _scan_portable_line(
        line,
        allow_unclosed_quote=allow_unclosed_quote,
    ).tokens


def _split_command_line(line: str) -> List[str]:
    return _split_portable_line(line, allow_unclosed_quote=False)


def _split_completion_line(line: str) -> List[str]:
    """
    Split an in-progress readline buffer like the command parser, but keep a
    partially typed final token together when quotes are still open.
    """
    return _split_portable_line(line, allow_unclosed_quote=True)


def _escape_backslash_runs(value: str, special) -> str:
    """Escape value for _scan_portable_line: special(ch) says which characters
    need a backslash; backslash runs before those (or the end) are doubled."""
    escaped = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == '\\':
            run_end = i
            while run_end < len(value) and value[run_end] == '\\':
                run_end += 1
            after = value[run_end] if run_end < len(value) else None
            run = run_end - i
            escaped.append('\\' * (run * 2 if after is None or special(after) else run))
            i = run_end
            continue
        if special(ch):
            escaped.append('\\')
        escaped.append(ch)
        i += 1
    return ''.join(escaped)


def _escape_completion(value: str) -> str:
    return _escape_backslash_runs(value, lambda ch: ch.isspace() or ch in ('"', "'"))


def _escape_completion_suffix(value: str, quote: Optional[str]) -> str:
    if quote is None:
        return _escape_completion(value)
    return _escape_backslash_runs(value, lambda ch: ch == quote)


def _safe_completion_name(value: str) -> bool:
    # Control characters could inject terminal escapes and cannot be typed
    # back anyway. Tab is the exception: it is harmless and escapes as "\<TAB>".
    return bool(value) and all((ord(ch) >= 32 and ord(ch) != 127) or ch == '\t' for ch in value)


def _unescape_completion(value: str) -> str:
    try:
        parts = _split_portable_line(value, allow_unclosed_quote=True)
        return parts[0] if parts else value
    except ValueError:
        return value.replace('\\ ', ' ').replace('\\"', '"').replace("\\'", "'").replace('\\\\', '\\')


def _completion_text_from_line_fragment(line: str) -> str:
    scan = _scan_portable_line(line, allow_unclosed_quote=True)
    return line[scan.current_start:] if scan.token_active else ''


def _split_lf_lines(data: bytes) -> List[bytes]:
    """Split on LF only, keeping line ends, like rhead and Unix tail. \r,
    form feeds and Unicode separators are ordinary line content."""
    lines = data.split(b'\n')
    result = [line + b'\n' for line in lines[:-1]]
    if lines[-1]:
        result.append(lines[-1])
    return result


def _fmt_err(e: Exception) -> str:
    """Return a clean, user-facing error string.

    Strips OS errno codes ('[Errno N] '), Windows error tags ('[WinError N] '),
    and capitalises the first letter so messages read like plain English.
    Paramiko messages are already clean; this mainly tidies up IOError/OSError
    strings that come back from remote SFTP operations.
    """
    import re
    msg = str(e).strip()
    msg = re.sub(r'^\[(?:Errno|WinError)\s+(?:-?\d+|None)\]\s*', '', msg)
    msg = msg.rstrip(':').rstrip()  # paramiko: "Server connection dropped: " with no detail
    if not msg and isinstance(e, TimeoutError):
        return f"Timed out: no response from the server for {_SFTP_TIMEOUT} seconds"
    if msg == 'Bad message':
        # OpenSSH's sftp-server reports ENAMETOOLONG and EINVAL as BAD_MESSAGE.
        msg = 'Bad message (name too long or invalid argument)'
    return (msg[0].upper() + msg[1:]) if msg else type(e).__name__


def _redact_command_for_log(line: str) -> str:
    """Hide credentials and content before commands are echoed or logged."""
    stripped = line.lstrip()
    if stripped.startswith('!'):
        return '!<arguments redacted>'
    if re.match(r'''["']?new["']?(?:\s|$)''', stripped, re.IGNORECASE):
        return 'new <arguments redacted>'
    try:
        tokens = _split_command_line(line)
    except ValueError:
        match = re.search(r'(^|\s)(?:-p|--password)(?:=|\s+)', line)
        if match:
            return line[:match.end()] + '<redacted>'
        return line

    if tokens and tokens[0].lower() == 'new':
        return 'new <arguments redacted>'

    redacted = list(tokens)
    password_flags = {'-p', '--password'}
    for i, token in enumerate(redacted):
        if token in password_flags and i + 1 < len(redacted):
            redacted[i + 1] = '<redacted>'
        elif any(token.startswith(flag + '=') for flag in password_flags):
            redacted[i] = token.split('=', 1)[0] + '=<redacted>'
    return ' '.join(shlex.quote(token) for token in redacted)


# ──────────────────────────────────────────────────────────────────────────────
# SFTP Client
# ──────────────────────────────────────────────────────────────────────────────

class SFTPClient:
    def __init__(self):
        self.ssh:         Optional[paramiko.SSHClient]  = None
        self.sftp:        Optional[paramiko.SFTPClient] = None
        self.remote_cwd:  str  = '/'
        self.remote_home: str  = '/'
        self.local_cwd:   str  = os.getcwd()
        self.connected:        bool = False
        self._connected_host:  Optional[str] = None
        self._connection_identity: Optional[Tuple[str, int, str]] = None
        self._orphaned_remote_temps: Dict[Tuple[str, int, str], set] = {}
        self._orphan_cleanup_cursor: Dict[Tuple[str, int, str], int] = {}
        self._should_exit:     bool = False
        self._batch_had_error: bool = False
        self._play_depth:      int  = 0
        self._script_dir_stack: List[str] = []
        self.atomic:           bool = True
        self._abandoned_sftp_open_threads: List[threading.Thread] = []

        self.logger, self.log_file = _setup_logger()

        # Silence paramiko's chatty transport/channel debug noise so it doesn't
        # bleed onto the terminal, but keep WARNING so host-key alerts are logged.
        logging.getLogger('paramiko').setLevel(logging.WARNING)

    # ── readline setup ────────────────────────────────────────────────────────
    # Called lazily just before the interactive REPL starts so that the
    # terminal is fully settled (getpass echo-restore is done, paramiko
    # channel setup is done) before readline touches terminal state.

    def _setup_readline(self):
        if readline is None:
            return
        readline.set_completer_delims(' \t\n')
        readline.set_completer(_Completer(self).complete)
        for binding in _RL_TAB_BINDS:
            try:
                readline.parse_and_bind(binding)
                break
            except Exception as e:
                self._log('debug', f"readline tab binding failed for {binding!r}: {_fmt_err(e)}")
        else:
            self._log('warning', f"Tab completion unavailable: no readline tab binding "
                      f"accepted (tried {_RL_TAB_BINDS!r})")
        if os.path.isfile(HISTORY_FILE):
            try:
                readline.read_history_file(HISTORY_FILE)
            except Exception:
                pass
        readline.set_history_length(2000)

    def _save_history(self):
        if readline is None:
            return
        tmp = None
        published = False
        try:
            history_dir = os.path.dirname(HISTORY_FILE) or '.'
            os.makedirs(history_dir, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix='.sftp-history-', suffix='.tmp', dir=history_dir)
            os.close(fd)
            _set_private_file_permissions(tmp)
            if hasattr(readline, 'get_current_history_length'):
                history = [
                    _redact_command_for_log(readline.get_history_item(i) or '')
                    for i in range(1, readline.get_current_history_length() + 1)
                ]
                if hasattr(readline, 'clear_history') and hasattr(readline, 'add_history'):
                    readline.clear_history()
                    for item in history:
                        readline.add_history(item)
            readline.write_history_file(tmp)
            # Windows rejects fsync on a read-only handle (EBADF).
            with open(tmp, 'r+b') as fh:
                os.fsync(fh.fileno())
            _set_private_file_permissions(tmp)
            os.replace(tmp, HISTORY_FILE)
            published = True
            tmp = None
            _sync_directory(history_dir)
        except Exception as e:
            if published:
                self._log('warning', f"Command history was replaced, but its directory "
                          f"could not be synced ({HISTORY_FILE}): {_fmt_err(e)}")
            else:
                self._log('warning', f"Failed to save command history ({HISTORY_FILE}): {_fmt_err(e)}")
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    # ── logging helpers ───────────────────────────────────────────────────────

    def _log(self, level: str, msg: str):
        getattr(self.logger, level, self.logger.info)(msg)

    def _out(self, msg: str, level: str = 'info'):
        """Print to console and write to the daily log."""
        print(msg, flush=True)
        self._log(level, msg)
        if level == 'error':
            self._batch_had_error = True

    # ── connection ────────────────────────────────────────────────────────────

    _MAX_ABANDONED_SFTP_OPENS = 3

    def _open_sftp_bounded(self, ssh, timeout: float):
        """Open an SFTP subsystem without allowing negotiation to hang forever."""
        self._abandoned_sftp_open_threads = [
            t for t in self._abandoned_sftp_open_threads if t.is_alive()
        ]
        if len(self._abandoned_sftp_open_threads) >= self._MAX_ABANDONED_SFTP_OPENS:
            raise RuntimeError(
                f"{len(self._abandoned_sftp_open_threads)} previous SFTP-open attempt(s) are "
                "still hung in the background; refusing to start another until one clears. "
                "This usually means the server (or network path) is not responding to SFTP "
                "subsystem requests."
            )

        result = {}
        finished = threading.Event()
        state_lock = threading.Lock()
        state = {'abandoned': False}

        def _open():
            try:
                sftp = ssh.open_sftp()
                with state_lock:
                    close_late = state['abandoned']
                    if not close_late:
                        result['sftp'] = sftp
                if close_late:
                    try:
                        sftp.close()
                    except Exception:
                        pass
            except BaseException as e:
                with state_lock:
                    result['error'] = e
            finally:
                finished.set()

        def _abandon_open():
            with state_lock:
                state['abandoned'] = True
                late_sftp = result.pop('sftp', None)
            if late_sftp is not None:
                try:
                    late_sftp.close()
                except Exception:
                    pass
            try:
                ssh.close()
            except Exception:
                pass
            finished.wait(1.0)
            if worker.is_alive():
                self._abandoned_sftp_open_threads.append(worker)

        worker = threading.Thread(target=_open, name='sftp-open', daemon=True)
        worker.start()
        try:
            completed = finished.wait(timeout)
        except BaseException:
            _abandon_open()
            raise
        if not completed:
            _abandon_open()
            raise TimeoutError(f"SFTP subsystem did not respond within {timeout:g} seconds")
        if 'error' in result:
            raise result['error']

        sftp = result['sftp']
        try:
            channel = sftp.get_channel()
            channel.settimeout(timeout)
            _fail_fast_after_timeout(channel)
        except Exception:
            try:
                sftp.close()
            except Exception:
                pass
            raise
        return sftp

    def connect(self, host: str, port: int = 22,
                username: str = None,
                password: str = None,
                key_file: str = None):
        self._log('debug', f"DBG connect() start  host={host} port={port} user={username}")

        new_ssh = paramiko.SSHClient()
        new_ssh.load_system_host_keys()
        new_ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

        kwargs: dict = dict(hostname=host, port=port, username=username)
        if key_file:
            kwargs['key_filename'] = os.path.expanduser(key_file)
        if password is not None:
            kwargs['password'] = password

        # When a password is supplied don't let paramiko waste time probing
        # the SSH agent or scanning ~/.ssh/id_* files — that can block for a
        # long time on some servers.
        if password is not None:
            kwargs['look_for_keys'] = False
            kwargs['allow_agent']   = False

        # Hard timeouts so a non-responsive server fails fast.
        kwargs.setdefault('timeout',        _SFTP_TIMEOUT)  # TCP connect
        kwargs.setdefault('banner_timeout', _SFTP_TIMEOUT)  # SSH banner
        kwargs.setdefault('auth_timeout',   _SFTP_TIMEOUT)  # auth exchange
        kwargs.setdefault('channel_timeout', _SFTP_TIMEOUT) # channel open
        if _CONNECT_PARAMETERS is not None:
            # Older paramiko (e.g. 2.12 from distro packages) lacks some of
            # these, e.g. channel_timeout, and rejects unknown keywords.
            kwargs = {k: v for k, v in kwargs.items() if k in _CONNECT_PARAMETERS}

        self._log('debug', f"DBG calling ssh.connect() kwargs keys={list(kwargs.keys())}")
        try:
            new_ssh.connect(**kwargs)
            self._log('debug', "DBG ssh.connect() returned OK")
        except paramiko.ssh_exception.AuthenticationException:
            # Plain password auth failed — try keyboard-interactive fallback
            if password is None:
                try:
                    new_ssh.close()
                except Exception:
                    pass
                raise
            def _ki_handler(title, instructions, fields):
                responses = []
                for prompt_text, echo in fields:
                    if not echo:
                        responses.append(password or '')
                    else:
                        if not sys.stdin.isatty():
                            raise EOFError(
                                "Server requested interactive input but stdin is not a terminal. "
                                "Use -p or -i to supply credentials non-interactively."
                            )
                        responses.append(input(prompt_text))
                return responses
            if _CONNECT_SUPPORTS_TRANSPORT_FACTORY:
                # Some servers (macOS sshd) never answer keyboard-interactive
                # on a connection whose password attempt just failed, so a
                # wrong password hung until auth_timeout. Retry on a fresh
                # connection; SSHClient still verifies the host key.
                self._log('debug', "DBG password auth failed, retrying with keyboard-interactive")
                try:
                    new_ssh.close()
                except Exception:
                    pass
                new_ssh = paramiko.SSHClient()
                new_ssh.load_system_host_keys()
                new_ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
                try:
                    new_ssh.connect(**kwargs, transport_factory=lambda sock, **kw:
                                    _KeyboardInteractiveTransport(sock, ki_handler=_ki_handler, **kw))
                except BaseException:
                    try:
                        new_ssh.close()
                    except Exception:
                        pass
                    raise
            else:
                self._log('debug', "DBG password auth failed, trying keyboard-interactive")
                transport = new_ssh.get_transport()
                if transport is None:
                    try:
                        new_ssh.close()
                    except Exception:
                        pass
                    raise
                try:
                    transport.auth_interactive(username, _ki_handler)
                except BaseException:
                    try:
                        new_ssh.close()
                    except Exception:
                        pass
                    raise
            self._log('debug', "DBG keyboard-interactive auth OK")
        except BaseException:
            try:
                new_ssh.close()
            except Exception:
                pass
            raise

        self._log('debug', "DBG calling open_sftp()")
        try:
            new_sftp = self._open_sftp_bounded(new_ssh, _SFTP_TIMEOUT)
        except BaseException:
            try:
                new_ssh.close()
            except Exception:
                pass
            raise
        self._log('debug', "DBG open_sftp() returned OK")

        self._log('debug', "DBG calling sftp.normalize('.')")
        try:
            new_remote_cwd = new_sftp.normalize('.')
        except BaseException:
            try:
                new_sftp.close()
            except Exception:
                pass
            try:
                new_ssh.close()
            except Exception:
                pass
            raise
        self._log('debug', f"DBG normalize() returned: {new_remote_cwd!r}")

        if self.connected:
            self._close_connection()

        self.ssh = new_ssh
        self.sftp = new_sftp
        self.remote_cwd  = new_remote_cwd
        self.remote_home = new_remote_cwd
        self._connected_host = host
        self._connection_identity = (host.casefold(), port, username or getpass.getuser())

        self.connected  = True

        self._retry_orphan_cleanup()

        display_user = username or getpass.getuser()
        self._out(f"Connected to {host}:{port}  (user: {display_user})")
        self._log('info', f"SESSION START  host={host} port={port} user={display_user}")

    def _connection_is_dead(self) -> bool:
        """Return True if the SSH transport or the SFTP channel has gone away
        behind our back. The server's SFTP subsystem can exit (e.g. on a
        malformed request) while the transport itself stays up."""
        try:
            t = self.ssh.get_transport() if self.ssh else None
            if t is None or not t.is_active():
                return True
            channel = getattr(self.sftp, 'sock', None)
            return (getattr(channel, 'closed', False) is True
                    or getattr(channel, 'sftp_timed_out', False) is True)
        except Exception:
            return True

    def _close_connection(self):
        if self.sftp:
            try:
                self.sftp.close()
            except Exception:
                pass
        if self.ssh:
            try:
                self.ssh.close()
            except Exception:
                pass
        self.sftp      = None
        self.ssh       = None
        self.connected = False
        self._connected_host = None
        self._connection_identity = None
        self._log('info', "SESSION END")

    # ── path helpers ──────────────────────────────────────────────────────────

    def _rpath(self, path: str) -> str:
        """Resolve a (possibly relative) remote path. Pure string manipulation — no network calls."""
        if path.startswith('/'):
            return path
        if path == '~':
            return self.remote_home
        if path.startswith('~/'):
            return self.remote_home.rstrip('/') + '/' + path[2:]
        return self.remote_cwd.rstrip('/') + '/' + path

    def _lpath(self, path: str) -> str:
        """Resolve a (possibly relative) local path."""
        path = os.path.expanduser(path)
        if os.path.isabs(path):
            return path
        return os.path.join(self.local_cwd, path)

    def _script_path(self, path: str) -> str:
        """Resolve a script path, nesting relative plays under the parent script."""
        path = os.path.expanduser(path)
        if os.path.isabs(path):
            return path
        if self._script_dir_stack:
            return os.path.join(self._script_dir_stack[-1], path)
        return os.path.join(self.local_cwd, path)

    def _remote_join(self, base: str, name: str) -> str:
        return base.rstrip('/') + '/' + name if base != '/' else '/' + name

    def _remote_parent(self, path: str) -> str:
        stripped = path.rstrip('/')
        if not stripped or stripped == '/':
            return '/'
        return stripped.rsplit('/', 1)[0] or '/'

    def _remote_relpath(self, base: str, rel: str) -> str:
        remote_rel = rel.replace(os.sep, '/')
        if os.altsep:
            remote_rel = remote_rel.replace(os.altsep, '/')
        return self._remote_join(base, remote_rel)

    def _remote_attr_is_dir(self, attr) -> bool:
        mode = getattr(attr, 'st_mode', None)
        return isinstance(mode, int) and _stat.S_ISDIR(mode)

    def _remote_path_is_dir(self, path: str) -> bool:
        try:
            return self._remote_attr_is_dir(self.sftp.stat(path))
        except Exception:
            return False

    def _remote_path_missing(self, path: str) -> bool:
        """Return True only when lstat confirms the remote entry is absent."""
        try:
            self.sftp.lstat(path)
            return False
        except Exception as e:
            return self._remote_error_is_missing(e)

    def _remote_error_is_missing(self, error: Exception) -> bool:
        """Whether an SFTP error unambiguously means a missing remote path."""
        if isinstance(error, FileNotFoundError):
            return True
        if isinstance(error, OSError) and getattr(error, 'errno', None) == errno.ENOENT:
            return True
        msg = str(error).lower()
        return "no such file" in msg or "not found" in msg

    def _ensure_remote_dir(self, path: str):
        if not path or path == '/':
            return
        path = path.rstrip('/') or '/'
        try:
            attr = self.sftp.stat(path)
        except Exception:
            pass
        else:
            if self._remote_attr_is_dir(attr):
                return
            raise IOError(f"{path}: remote path exists and is not a directory")

        parent = self._remote_parent(path)
        if parent != path:
            self._ensure_remote_dir(parent)
        try:
            self.sftp.mkdir(path)
            self._log('info', f"MKDIR {path}")
        except Exception as mkdir_error:
            try:
                attr = self.sftp.stat(path)
                if self._remote_attr_is_dir(attr):
                    return
            except Exception:
                pass
            raise mkdir_error

    def _local_dir_basename(self, path: str) -> str:
        return os.path.basename(os.path.normpath(path))

    def _dirput_destination(self, local: str, args: List[str]) -> Optional[str]:
        local_name = self._local_dir_basename(local)
        if len(args) > 1:
            remote = self._rpath(args[1])
            if args[1].endswith('/') or self._remote_path_is_dir(remote):
                if not local_name:
                    self._out("dirput: cannot determine remote directory name - specify a remote path", 'error')
                    return None
                return self._remote_join(remote.rstrip('/'), local_name)
            return remote
        if not local_name:
            self._out("dirput: cannot determine remote directory name - specify a remote path", 'error')
            return None
        return self._remote_join(self.remote_cwd, local_name)

    # ── command handlers ──────────────────────────────────────────────────────

    # --- directory listing ---------------------------------------------------

    _LS_FLAG_RE = re.compile(r'-[A-Za-z1]+')

    def cmd_ls(self, args: List[str]):
        # Output is always the long format; accept habitual flags (ls -l,
        # ls -la). Name a file such as "-l" as ./-l.
        args = [a for a in args if not self._LS_FLAG_RE.fullmatch(a)]
        path = self._rpath(args[0]) if args else self.remote_cwd
        try:
            entries = self.sftp.listdir_attr(path)
        except Exception as e:
            try:
                attr = self.sftp.stat(path)
            except Exception:
                entries = self._ls_glob(path)
                if entries is None:
                    self._out(f"ls: {_fmt_err(e)}", 'error'); return
                if not entries:
                    self._out(f"ls: no match for '{args[0]}'", 'error'); return
            else:
                attr.filename = os.path.basename(path.rstrip('/')) or path
                entries = [attr]

        entries.sort(key=lambda e: e.filename)
        for e in entries:
            mode  = _stat.filemode(e.st_mode) if e.st_mode else '?---------'
            size  = e.st_size  if e.st_size  is not None else 0
            mtime = (datetime.datetime.fromtimestamp(e.st_mtime).strftime("%b %d %H:%M")
                     if e.st_mtime else "           ")
            nlink = getattr(e, 'st_nlink', 1) or 1
            uid   = getattr(e, 'st_uid',   0) or 0
            gid   = getattr(e, 'st_gid',   0) or 0
            print(f"{mode} {nlink:3d} {uid:5d} {gid:5d} {size:10d} {mtime}  {e.filename}")

    def _ls_glob(self, path: str):
        """Entries matching a wildcard in the last path component, or None
        when that component has no wildcard."""
        pattern = path.rstrip('/').rsplit('/', 1)[-1]
        if not any(ch in pattern for ch in '*?['):
            return None
        try:
            entries = self.sftp.listdir_attr(self._remote_parent(path.rstrip('/')))
        except Exception:
            return None
        return [e for e in entries
                if isinstance(e.filename, str) and fnmatch.fnmatchcase(e.filename, pattern)]

    def cmd_lls(self, args: List[str]):
        path = self._lpath(args[0]) if args else self.local_cwd
        try:
            if os.path.isdir(path):
                entries = sorted(os.listdir(path))
                base_path = path
            elif not os.path.lexists(path):
                raise FileNotFoundError(path)
            else:
                entries = [os.path.basename(path)]
                base_path = os.path.dirname(path) or self.local_cwd
        except Exception as e:
            self._out(f"lls: {_fmt_err(e)}", 'error'); return
        for e in entries:
            full = os.path.join(base_path, e)
            try:
                s     = os.stat(full)
                mode  = _stat.filemode(s.st_mode)
                mtime = datetime.datetime.fromtimestamp(s.st_mtime).strftime("%b %d %H:%M")
                print(f"{mode} {s.st_nlink:3d} {s.st_uid:5d} {s.st_gid:5d} {s.st_size:10d} {mtime}  {e}")
            except OSError:
                print(f"??????????   0     0     0          0               {e}")

    # --- directory change ----------------------------------------------------

    def cmd_cd(self, args: List[str]):
        target = args[0] if args else '~'
        try:
            new_path = self._rpath(target) if target != '~' else self.sftp.normalize('.')
            norm = self.sftp.normalize(new_path)
            # Verify it's accessible / is a directory
            attr = self.sftp.stat(norm)
            if not attr.st_mode or not _stat.S_ISDIR(attr.st_mode):
                self._out(f"cd: {target}: not a directory", 'error'); return
            self.remote_cwd = norm
            self._log('info', f"cd {norm}")
        except Exception as e:
            self._out(f"cd: {_fmt_err(e)}", 'error')

    def cmd_lcd(self, args: List[str]):
        path = self._lpath(args[0]) if args else os.path.expanduser('~')
        try:
            os.chdir(path)
        except OSError as e:
            self._out(f"lcd: {_fmt_err(e)}", 'error'); return
        self.local_cwd = os.getcwd()
        print(f"Local directory: {self.local_cwd}")

    def cmd_pwd(self, args: List[str]):
        self._out(f"Remote working directory: {self.remote_cwd}")

    def cmd_lpwd(self, args: List[str]):
        print(f"Local working directory: {self.local_cwd}")

    # --- file transfer -------------------------------------------------------

    def _require_regular_file(self, path: str, attr) -> None:
        """Refuse directories and devices, FIFOs or sockets, like OpenSSH's
        "Cannot download non-regular file": /dev/zero reports size 0 but
        never ends, and a FIFO can block forever."""
        if self._remote_attr_is_dir(attr):
            raise IsADirectoryError(f"{path} is a directory")
        mode = getattr(attr, 'st_mode', None)
        if isinstance(mode, int) and not _stat.S_ISREG(mode):
            raise OSError(f"{path} is not a regular file")

    def _open_remote_regular(self, path: str):
        self._require_regular_file(path, self.sftp.stat(path))
        return self.sftp.open(path, 'rb')

    def _sftp_get(self, remote: str, local: str, callback=None) -> None:
        """Fetch with pipelined reads, but cap in-flight requests so memory
        stays bounded (~2 MiB)."""
        if _GET_SUPPORTS_PREFETCH_LIMIT:
            self.sftp.get(remote, local, callback=callback, prefetch=True,
                          max_concurrent_prefetch_requests=_MAX_PREFETCH_REQUESTS)
        else:
            self._windowed_get(remote, local, callback)

    _GET_CHUNK = 32768

    def _windowed_get(self, remote: str, local: str, callback=None) -> None:
        """Pipelined download for paramiko without a prefetch cap (< 3.3):
        readv one window of chunks at a time. Unbounded prefetch could buffer
        the whole file; serial reads pay a round trip per 32 KiB."""
        window = self._GET_CHUNK * _MAX_PREFETCH_REQUESTS
        with self.sftp.open(remote, 'rb') as source, open(local, 'wb') as target:
            size = source.stat().st_size
            offset = 0
            while offset < size:
                end = min(size, offset + window)
                chunks = [(start, min(self._GET_CHUNK, end - start))
                          for start in range(offset, end, self._GET_CHUNK)]
                for data in source.readv(chunks):
                    target.write(data)
                offset = end
                if callback is not None:
                    callback(offset, size)
        written = os.stat(local).st_size
        if written != size:
            raise IOError(f"size mismatch in get! {written} != {size}")

    @contextmanager
    def _interrupt_between_chunks(self):
        """Defer Ctrl-C during a transfer to the next chunk boundary.

        A KeyboardInterrupt raised while paramiko is mid-packet desynchronizes
        the SFTP stream and loses the session (leaving a remote temp file);
        raised from the transfer's progress callback it leaves the session
        usable. Yields the check to call between chunks. An interrupt that
        arrives after the last chunk is raised once the transfer completes,
        so a multi-file command still stops. A second Ctrl-C interrupts at
        once in case the transfer is stuck."""
        pending = []

        def check_interrupt(*_):
            if pending:
                raise KeyboardInterrupt

        def on_sigint(signum, frame):
            if pending:
                raise KeyboardInterrupt
            pending.append(signum)

        try:
            previous = signal.signal(signal.SIGINT, on_sigint)
        except ValueError:  # not the main thread
            yield check_interrupt
            return
        try:
            yield check_interrupt
        finally:
            signal.signal(signal.SIGINT, previous)
        check_interrupt()

    def _download_file(self, remote: str, local: str, overwrite: bool = False):
        """Download beside the destination and publish it only after success.

        Like cp, an existing local symlink is written through to its target,
        and the published file gets the mode of the file it replaces, or the
        remote mode filtered by the umask for a new file."""
        attr = self.sftp.stat(remote)
        self._require_regular_file(remote, attr)
        if os.path.islink(local):
            target = os.path.realpath(local)
            if not os.path.lexists(target):
                raise FileNotFoundError(f"{local}: refusing to write through dangling symlink")
            local = target
        if os.path.lexists(local):
            mode = _stat.S_IMODE(os.stat(local).st_mode)
        else:
            remote_mode = getattr(attr, 'st_mode', None)
            mode = (_stat.S_IMODE(remote_mode) & 0o777) if isinstance(remote_mode, int) else 0o666
            mode &= ~_current_umask()
        parent = os.path.dirname(local) or '.'
        fd, tmp = tempfile.mkstemp(prefix='.sftp-', suffix='.tmp', dir=parent)
        os.close(fd)
        try:
            with self._interrupt_between_chunks() as check_interrupt:
                self._sftp_get(remote, tmp, callback=check_interrupt)
            os.chmod(tmp, mode)
            if overwrite:
                os.replace(tmp, local)
            elif os.name == 'nt':
                # Windows rename fails when the destination already exists.
                os.rename(tmp, local)
            else:
                # A hard link publishes the completed file only if local is
                # still absent. Both names are in the same directory/filesystem.
                os.link(tmp, local)
                os.unlink(tmp)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _safe_mget_local_path(self, name: str) -> str:
        """Resolve an untrusted remote entry name beneath local_cwd."""
        if (
            not isinstance(name, str)
            or not name
            or name in {'.', '..'}
            or '\x00' in name
            or '/' in name
            # Backslash is an ordinary filename character on POSIX but a
            # path separator on Windows.
            or (os.name == 'nt' and '\\' in name)
            or os.path.isabs(name)
            or bool(os.path.splitdrive(name)[0])
        ):
            raise ValueError(f"unsafe remote filename: {name!r}")

        root = os.path.abspath(self.local_cwd)
        local = os.path.abspath(os.path.join(root, name))
        try:
            contained = os.path.commonpath([root, local]) == root
        except ValueError:
            contained = False
        if not contained:
            raise ValueError(f"unsafe remote filename: {name!r}")
        return local

    # --- overwrite protection -------------------------------------------------
    # Shared by every command that writes to a destination that might already
    # exist: get/put/dirput/mget/mput/rename/symlink(ln)/new. Two opt-in flags:
    #   -f / --force    overwrite without asking
    #   -i / --confirm  ask per destination; 'a' answers yes to the rest of
    #                   this command's batch (glob matches, dirput tree, ...)
    # With neither flag, an existing destination is left alone and skipped.

    _OVERWRITE_FLAG_KINDS = {'-f': 'force', '--force': 'force', '-i': 'confirm', '--confirm': 'confirm'}

    def _extract_overwrite_flags(self, args: List[str]) -> Tuple[List[str], bool, bool]:
        force = confirm = False
        remaining = []
        for a in args:
            kind = self._OVERWRITE_FLAG_KINDS.get(a)
            if kind == 'force':
                force = True
            elif kind == 'confirm':
                confirm = True
            else:
                remaining.append(a)
        return remaining, force, confirm

    def _remote_exists(self, path: str,
                       listing_cache: Optional[Dict[str, set]] = None) -> bool:
        """Check for an entry on the remote filesystem.

        Some SFTP servers return the generic SSH_FX_FAILURE status when stat is
        asked about a missing path.  Paramiko exposes that as ``OSError('Failure')``,
        which is not enough by itself to distinguish a missing file from a real
        access or connection error.  In that case, inspect the remote parent
        directory rather than treating every unclassified stat error as proof
        that the destination exists.
        """
        try:
            self.sftp.lstat(path)
            return True
        except Exception as stat_error:
            if self._remote_error_is_missing(stat_error):
                return False

            normalized = path.rstrip('/')
            if not normalized:
                raise
            parent = self._remote_parent(normalized)
            name = normalized.rsplit('/', 1)[-1]
            try:
                if listing_cache is not None:
                    if parent not in listing_cache:
                        listing_cache[parent] = set(self.sftp.listdir(parent))
                    return name in listing_cache[parent]
                return name in self.sftp.listdir(parent)
            except Exception:
                # Neither remote operation could establish whether the destination
                # exists.  Surface the original stat failure instead of falsely
                # reporting an overwrite collision or risking an unsafe overwrite.
                raise stat_error

    def _confirm_overwrite(self, display_path: str, force: bool, confirm: bool, state: dict) -> bool:
        """Return True if it's OK to overwrite display_path. `state` is a dict shared
        across one command's batch of destinations, tracking 'all' (yes-to-rest) and
        'quit' (abort-the-rest) once the user picks one of those."""
        if force or state.get('all'):
            return True
        if state.get('quit'):
            return False
        if not confirm:
            self._out(f"{display_path}: already exists, skipping (use -f to overwrite or -i to confirm)", 'error')
            return False
        if not sys.stdin.isatty():
            self._out(
                f"{display_path}: already exists and -i needs an interactive terminal to confirm; "
                "aborting the rest of this command (use -f to overwrite non-interactively)",
                'error',
            )
            state['quit'] = True
            return False
        while True:
            try:
                ans = input(f"{display_path} already exists. Overwrite? [y]es/[n]o/[a]ll/[q]uit: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = 'q'
                print()
            if ans in ('y', 'yes'):
                return True
            if ans in ('n', 'no'):
                return False
            if ans in ('a', 'all'):
                state['all'] = True
                return True
            if ans in ('q', 'quit'):
                state['quit'] = True
                return False
            print("Please answer y, n, a, or q.")

    def cmd_get(self, args: List[str]):
        args, force, confirm = self._extract_overwrite_flags(args)
        if not args:
            self._out("Usage: get [-f|-i] remote-path [local-path]", 'error'); return
        remote = self._rpath(args[0])
        if len(args) > 1:
            local = self._lpath(args[1])
            if os.path.isdir(local):
                local = os.path.join(local, os.path.basename(remote.rstrip('/')))
        else:
            local_name = os.path.basename(remote.rstrip('/'))
            if not local_name:
                self._out("get: cannot determine local filename - specify a local path", 'error'); return
            local = os.path.join(self.local_cwd, local_name)
        existed = os.path.lexists(local)
        if existed and not self._confirm_overwrite(local, force, confirm, {}):
            return
        try:
            self._out(f"Fetching {remote}  ->  {local}")
            self._download_file(remote, local, overwrite=force or existed)
            self._log('info', f"GET {remote} -> {local}")
        except Exception as e:
            self._out(f"get: {_fmt_err(e)}", 'error')

    def _remote_temp_path(self, remote: str) -> str:
        return self._remote_join(
            self._remote_parent(remote), f".sftp-{uuid.uuid4().hex}.tmp"
        )

    def _remove_remote_temp_after_failure(self, tmp: str) -> Optional[Exception]:
        try:
            self.sftp.remove(tmp)
        except Exception as cleanup_error:
            if self._remote_error_is_missing(cleanup_error):
                return None
            if self._connection_identity is not None:
                self._orphaned_remote_temps.setdefault(self._connection_identity, set()).add(tmp)
            return cleanup_error
        return None

    def _retry_orphan_cleanup(self) -> None:
        identity = self._connection_identity
        if identity is None:
            return
        pending = self._orphaned_remote_temps.get(identity)
        if not pending:
            return
        ordered = sorted(pending)
        start = self._orphan_cleanup_cursor.get(identity, 0) % len(ordered)
        candidates = (ordered[start:] + ordered[:start])[:_MAX_ORPHAN_CLEANUP_PER_CONNECT]
        for tmp in candidates:
            cleanup_error = self._remove_remote_temp_after_failure(tmp)
            if cleanup_error is None:
                pending.discard(tmp)
            else:
                self._out(f"Temporary remote file '{tmp}' still needs removal: "
                          f"{_fmt_err(cleanup_error)}", 'warning')
                if self._connection_is_dead():
                    break
        if pending:
            self._orphan_cleanup_cursor[identity] = (start + len(candidates)) % len(ordered)
            self._out(f"{len(pending)} temporary remote files still need cleanup; "
                      "retry 'open' or remove them manually.", 'warning')
        if not pending:
            del self._orphaned_remote_temps[identity]
            self._orphan_cleanup_cursor.pop(identity, None)

    def _raise_with_cleanup_error(self, original: BaseException, tmp: str) -> None:
        cleanup_error = self._remove_remote_temp_after_failure(tmp)
        if cleanup_error is not None:
            message = (f"temporary remote file '{tmp}' could not be removed "
                       f"({_fmt_err(cleanup_error)}). Remove it after reconnect.")
            if isinstance(original, Exception):
                raise RuntimeError(f"{_fmt_err(original)}; {message}") from original
            self._out(message, 'warning')
        raise original

    @staticmethod
    def _rename_extension_unsupported(error: OSError) -> bool:
        if getattr(error, 'errno', None) in (errno.ENOSYS, getattr(errno, 'EOPNOTSUPP', errno.ENOSYS)):
            return True
        message = str(error).lower()
        return any(marker in message for marker in (
            'not supported', 'unsupported', 'unknown extended request',
        ))

    def _raise_if_created_meanwhile(self, remote: str, error: Exception) -> None:
        """Explain a no-clobber create or rename that failed because another
        client created the destination after it was checked."""
        try:
            exists = self._remote_exists(remote)
        except Exception:
            return
        if exists:
            raise FileExistsError(
                f"{remote} was created by another client during the upload; "
                "it was not replaced (use -f to overwrite)") from error

    def _commit_remote_temp(self, tmp: str, remote: str, overwrite: bool = True):
        if not overwrite:
            try:
                self.sftp.rename(tmp, remote)
            except Exception as e:
                self._raise_if_created_meanwhile(remote, e)
                raise
            return
        posix_rename = getattr(self.sftp, 'posix_rename', None)
        if posix_rename is None:
            self.sftp.rename(tmp, remote)
            return
        try:
            posix_rename(tmp, remote)
        except OSError as e:
            if not self._rename_extension_unsupported(e):
                raise
            self.sftp.rename(tmp, remote)

    def _atomic_put(self, local: str, remote: str, overwrite: bool = True, replaced_attr=None):
        """Upload local to a .tmp file in the same remote directory, then rename
        into place. Use plain rename for new destinations so a concurrent
        creator cannot be overwritten. Approved overwrites use posix_rename
        where supported. Remove the temp file on failure. replaced_attr is the
        stat of the file being replaced, whose owner and mode are kept."""
        tmp = self._remote_temp_path(remote)
        before = _local_file_version(local)
        with self._interrupt_between_chunks() as check_interrupt:
            try:
                self.sftp.put(local, tmp, callback=check_interrupt)
                if _local_file_version(local, before) != before:
                    raise IOError(f"{local} changed during the upload; not published")
                if replaced_attr is not None:
                    self._copy_replaced_attrs(tmp, replaced_attr, remote)
                self._commit_remote_temp(tmp, remote, overwrite=overwrite)
            except BaseException as e:
                self._raise_with_cleanup_error(e, tmp)

    _MAX_SYMLINK_HOPS = 40

    def _resolve_overwrite_target(self, remote: str):
        """Return (path, attrs) of the file an overwrite of remote replaces.

        Matches OpenSSH sftp, which opens the existing file for writing: a
        symlink is written through to its target (attrs is None when that
        target does not exist yet, so it is created), and a file without any
        write permission bits is refused rather than replaced by rename."""
        path = remote
        for _ in range(self._MAX_SYMLINK_HOPS):
            try:
                attr = self.sftp.lstat(path)
            except Exception as e:
                if path != remote and self._remote_error_is_missing(e):
                    return path, None
                raise
            mode = getattr(attr, 'st_mode', None)
            if not (isinstance(mode, int) and _stat.S_ISLNK(mode)):
                break
            link = self.sftp.readlink(path)
            if not isinstance(link, str) or not link:
                raise IOError(f"{remote}: cannot read symlink target")
            path = link if link.startswith('/') else self._remote_join(self._remote_parent(path), link)
        else:
            raise IOError(f"{remote}: too many levels of symbolic links")
        if self._remote_attr_is_dir(attr):
            raise IsADirectoryError(f"{path} is a directory")
        if isinstance(mode, int) and not mode & 0o222:
            raise PermissionError(f"{path}: remote file is read-only; chmod it before overwriting")
        return path, attr

    def _copy_replaced_attrs(self, tmp: str, attr, display_path: str) -> None:
        """Give a replacement file the owner (where permitted) and mode of the
        file it replaces. Owner first: chown clears setuid/setgid bits."""
        uid = getattr(attr, 'st_uid', None)
        gid = getattr(attr, 'st_gid', None)
        if isinstance(uid, int) and isinstance(gid, int):
            try:
                current = self.sftp.stat(tmp)
                if (current.st_uid, current.st_gid) != (uid, gid):
                    self.sftp.chown(tmp, uid, gid)
            except Exception:
                pass  # only privileged users can give files away; keep ours
        mode = getattr(attr, 'st_mode', None)
        if isinstance(mode, int):
            try:
                self.sftp.chmod(tmp, _stat.S_IMODE(mode))
            except Exception as e:
                self._out(f"{display_path}: could not preserve permissions: {_fmt_err(e)}", 'warning')

    def _put_file(self, local: str, remote: str, remote_existed: Optional[bool] = None):
        """remote_existed is set when the caller already checked the destination.

        A known existing destination is always overwritten atomically because
        it already had good content: a direct (non-atomic) write would
        truncate it in place, corrupting it if the transfer fails partway."""
        try:
            remote.encode('utf-8')
        except UnicodeEncodeError:
            raise ValueError(
                f"{remote!r}: remote name is not valid UTF-8 (the local filename uses "
                "another encoding); upload it with an explicit remote name"
            ) from None
        self._guard_upload_source(local, remote)
        if remote_existed is True:
            target, attr = self._resolve_overwrite_target(remote)
            if target != remote:
                self._guard_upload_source(local, target)
            self._atomic_put(local, target, overwrite=attr is not None, replaced_attr=attr)
            return
        if self.atomic:
            self._atomic_put(local, remote, overwrite=remote_existed is not False)
            return
        # In non-atomic mode, exclusive creation still enforces no-clobber.
        # A failed direct upload may leave a partial file, as documented.
        # 'x' alone opens without write access in paramiko; 'w' adds it.
        try:
            remote_file = self.sftp.open(remote, 'wxb')
        except Exception as e:
            self._raise_if_created_meanwhile(remote, e)
            raise
        before = _local_file_version(local)
        with self._interrupt_between_chunks() as check_interrupt, \
                open(local, 'rb') as source, remote_file as target:
            while True:
                chunk = source.read(64 * 1024)
                if not chunk:
                    break
                target.write(chunk)
                check_interrupt()
        if _local_file_version(local, before) != before:
            raise IOError(f"{local} changed during the upload; {remote} may mix old and new data")

    def _guard_upload_source(self, local: str, remote: str) -> None:
        """Reject a localhost upload that would replace its own local source."""
        host = self._connected_host
        if not host:
            return
        local_names = {'localhost', 'localhost.localdomain', socket.gethostname().casefold()}
        local_connection = host.rstrip('.').casefold() in local_names
        if not local_connection:
            try:
                local_connection = ipaddress.ip_address(host).is_loopback
            except ValueError:
                pass
        if not local_connection:
            # A direct connection to this machine through its LAN address or
            # a DNS/SSH alias has the same local and peer socket address.
            try:
                sock = self.ssh.get_transport().sock
                local_ip = ipaddress.ip_address(str(sock.getsockname()[0]).split('%', 1)[0])
                peer_ip = ipaddress.ip_address(str(sock.getpeername()[0]).split('%', 1)[0])
                local_connection = local_ip == peer_ip
            except (AttributeError, IndexError, OSError, TypeError, ValueError):
                pass
        if not local_connection:
            return
        def entry_path(path):
            parent = os.path.realpath(os.path.dirname(path))
            return os.path.normcase(os.path.join(parent, os.path.basename(path)))

        destination_entry = entry_path(remote)
        source_path = local
        seen = set()
        while True:
            source_entry = entry_path(source_path)
            if source_entry == destination_entry:
                raise ValueError(
                    "local source and remote destination are the same path; "
                    "upload refused to preserve the source"
                )
            if source_entry in seen or not os.path.islink(source_path):
                break
            seen.add(source_entry)
            link_target = os.readlink(source_path)
            source_path = (link_target if os.path.isabs(link_target) else
                           os.path.join(os.path.dirname(source_path), link_target))

    def cmd_put(self, args: List[str]):
        args, force, confirm = self._extract_overwrite_flags(args)
        if not args:
            self._out("Usage: put [-f|-i] local-path [remote-path]", 'error'); return
        local  = self._lpath(args[0])
        if not os.path.isfile(local):
            self._out(f"put: local path is not a file: {local}", 'error'); return
        remote = self._rpath(args[1]) if len(args) > 1 else \
                 self._remote_join(self.remote_cwd, os.path.basename(local))
        if len(args) > 1:
            remote_arg = args[1]
            if remote_arg.endswith('/'):
                remote = self._remote_join(remote.rstrip('/'), os.path.basename(local))
            else:
                try:
                    attr = self.sftp.stat(remote)
                except Exception:
                    attr = None
                if attr and attr.st_mode and _stat.S_ISDIR(attr.st_mode):
                    remote = self._remote_join(remote, os.path.basename(local))
        try:
            existed = self._remote_exists(remote)
        except Exception as e:
            self._out(f"put: could not check remote destination '{remote}': {_fmt_err(e)}", 'error')
            return
        if existed and not self._confirm_overwrite(remote, force, confirm, {}):
            return
        try:
            self._guard_upload_source(local, remote)
            self._out(f"Uploading {local}  ->  {remote}")
            self._put_file(local, remote, remote_existed=existed)
            self._log('info', f"PUT {local} -> {remote}")
        except Exception as e:
            self._out(f"put: {self._describe_remote_error(e, remote, 'write')}", 'error')

    def cmd_dirput(self, args: List[str]):
        args, force, confirm = self._extract_overwrite_flags(args)
        if not args or len(args) > 2:
            self._out("Usage: dirput [-f|-i] local-directory [remote-directory]", 'error'); return
        local = self._lpath(args[0])
        if not os.path.isdir(local):
            self._out(f"dirput: local path is not a directory: {local}", 'error'); return
        remote = self._dirput_destination(local, args)
        if remote is None:
            return

        files_uploaded = 0
        files_skipped = 0
        dirs_created = 0
        state: dict = {}
        listing_cache: Dict[str, set] = {}
        current = remote  # the remote path being worked on, for error messages
        try:
            self._out(f"Replicating {local}  ->  {remote}")
            self._ensure_remote_dir(remote)

            def _raise_walk_error(error):
                raise error

            quit_requested = False
            for root, dirs, files in os.walk(local, onerror=_raise_walk_error):
                if quit_requested:
                    break
                dirs[:] = sorted(
                    name for name in dirs
                    if not os.path.islink(os.path.join(root, name))
                )
                files.sort()
                rel = os.path.relpath(root, local)
                remote_root = remote if rel == '.' else self._remote_relpath(remote, rel)
                for dirname in dirs:
                    remote_dir = current = self._remote_join(remote_root, dirname)
                    self._ensure_remote_dir(remote_dir)
                    dirs_created += 1
                for filename in files:
                    local_file = os.path.join(root, filename)
                    if not os.path.isfile(local_file):
                        continue
                    remote_file = current = self._remote_join(remote_root, filename)
                    existed = self._remote_exists(remote_file, listing_cache)
                    if existed and not self._confirm_overwrite(remote_file, force, confirm, state):
                        if state.get('quit'):
                            quit_requested = True
                            break
                        files_skipped += 1
                        continue
                    self._guard_upload_source(local_file, remote_file)
                    self._out(f"Uploading {local_file}  ->  {remote_file}")
                    self._put_file(local_file, remote_file, remote_existed=existed)
                    if remote_root in listing_cache:
                        listing_cache[remote_root].add(filename)
                    self._log('info', f"PUT {local_file} -> {remote_file}")
                    files_uploaded += 1
            self._log('info', f"DIRPUT {local} -> {remote} ({files_uploaded} files)")
            summary = f"dirput: uploaded {files_uploaded} file(s), ensured {dirs_created + 1} directories"
            if files_skipped:
                summary += f", skipped {files_skipped} existing file(s)"
            print(summary)
        except Exception as e:
            self._out(f"dirput: {self._describe_remote_error(e, current, 'write')}", 'error')

    def cmd_mget(self, args: List[str]):
        args, force, confirm = self._extract_overwrite_flags(args)
        if not args:
            self._out("Usage: mget [-f|-i] pattern", 'error'); return
        remote_pattern = self._rpath(args[0])
        remote_dir, pattern = remote_pattern.rsplit('/', 1)
        if not remote_dir:
            remote_dir = '/'
        try:
            entries = self.sftp.listdir_attr(remote_dir)
        except Exception as e:
            self._out(f"mget: {_fmt_err(e)}", 'error'); return
        matches = []
        matched_any = False
        for entry in entries:
            name = entry.filename
            if not isinstance(name, str):
                self._out(f"mget: unsafe remote filename: {name!r}", 'error')
                if self._play_depth:
                    return
                continue
            if not fnmatch.fnmatch(name, pattern):
                continue
            if entry.st_mode is not None and _stat.S_ISDIR(entry.st_mode):
                continue
            if entry.st_mode is not None and _stat.S_ISLNK(entry.st_mode):
                # listdir_attr reports the link itself; skip links to
                # directories like real directories, and broken links
                # (dangling or looping) with a warning rather than failing
                # the whole batch.
                try:
                    target = self.sftp.stat(self._remote_join(remote_dir, name))
                except Exception:
                    matched_any = True
                    self._out(f"mget: skipping broken symlink '{name}'", 'warning')
                    continue
                if self._remote_attr_is_dir(target):
                    continue
                entry_mode = target.st_mode
            else:
                entry_mode = entry.st_mode
            if isinstance(entry_mode, int) and not _stat.S_ISREG(entry_mode):
                matched_any = True
                self._out(f"mget: skipping non-regular file '{name}'", 'warning')
                continue
            matched_any = True
            try:
                local = self._safe_mget_local_path(name)
            except ValueError as e:
                self._out(f"mget: {e}", 'error')
                if self._play_depth:
                    return
                continue
            matches.append((name, local))
        if not matches:
            if not matched_any:
                print(f"mget: no files match '{args[0]}'")
            return
        state: dict = {}
        skipped = 0
        for name, local in matches:
            if state.get('quit'):
                break
            remote = self._remote_join(remote_dir, name)
            existed = os.path.lexists(local)
            if existed and not self._confirm_overwrite(local, force, confirm, state):
                if not state.get('quit'):
                    skipped += 1
                continue
            try:
                self._out(f"Fetching {remote}")
                self._download_file(remote, local, overwrite=force or existed or state.get('all', False))
                self._log('info', f"GET {remote} -> {local}")
            except Exception as e:
                self._out(f"mget {name}: {_fmt_err(e)}", 'error')
                if (self.connected and self._connection_is_dead()) or (self._play_depth and self._batch_had_error):
                    break
        if skipped:
            print(f"mget: skipped {skipped} existing file(s) (use -f to overwrite or -i to confirm)")

    def cmd_mput(self, args: List[str]):
        args, force, confirm = self._extract_overwrite_flags(args)
        if not args:
            self._out("Usage: mput [-f|-i] pattern", 'error'); return
        pattern = os.path.expanduser(args[0])
        if not os.path.isabs(pattern):
            pattern = os.path.join(self.local_cwd, pattern)
        matches = [
            path for path in _glob.glob(pattern)
            if os.path.isfile(path)
        ]
        if not matches:
            print(f"mput: no files match '{args[0]}'"); return
        state: dict = {}
        listing_cache: Dict[str, set] = {}
        skipped = 0
        for local in sorted(matches):
            if state.get('quit'):
                break
            name   = os.path.basename(local)
            remote = self.remote_cwd.rstrip('/') + '/' + name
            try:
                existed = self._remote_exists(remote, listing_cache)
                if existed and not self._confirm_overwrite(remote, force, confirm, state):
                    if not state.get('quit'):
                        skipped += 1
                    continue
                self._guard_upload_source(local, remote)
                self._out(f"Uploading {local}")
                self._put_file(local, remote, remote_existed=existed)
                if self.remote_cwd in listing_cache:
                    listing_cache[self.remote_cwd].add(name)
                self._log('info', f"PUT {local} -> {remote}")
            except Exception as e:
                self._out(f"mput {name}: {self._describe_remote_error(e, remote, 'write')}", 'error')
                if (self.connected and self._connection_is_dead()) or (self._play_depth and self._batch_had_error):
                    break
        if skipped:
            print(f"mput: skipped {skipped} existing file(s) (use -f to overwrite or -i to confirm)")

    # --- directory / file management ----------------------------------------

    def _describe_remote_error(self, error: Exception, path: str, op: str) -> str:
        """Explain a failed remote operation from the path's current state.

        Servers often answer with the bare SSH_FX_FAILURE status ("Failure"),
        and macOS reports removing a directory as "Permission denied"."""
        message = _fmt_err(error)
        if message.startswith('Bad message'):
            encoded = path.encode('utf-8', 'surrogateescape')
            if any(len(part) > 255 for part in encoded.split(b'/')):
                return "File name too long"
            if len(encoded) >= 1024:
                return "Path too long"
            return message
        try:
            is_dir = self._remote_attr_is_dir(self.sftp.stat(path))
        except Exception:
            return message
        if op == 'mkdir':
            return "File exists"
        if op == 'rm' and is_dir:
            return "Is a directory (use rmdir)"
        if op == 'read' and is_dir:
            return "Is a directory"
        if op == 'rmdir':
            if not is_dir:
                return "Not a directory"
            try:
                if self.sftp.listdir(path):
                    return "Directory not empty"
            except Exception:
                pass
        return message

    def cmd_mkdir(self, args: List[str]):
        if not args:
            self._out("Usage: mkdir path", 'error'); return
        path = self._rpath(args[0])
        try:
            self.sftp.mkdir(path)
            self._log('info', f"MKDIR {path}")
        except Exception as e:
            self._out(f"mkdir: {self._describe_remote_error(e, path, 'mkdir')}", 'error')

    def cmd_lmkdir(self, args: List[str]):
        if not args:
            self._out("Usage: lmkdir path", 'error'); return
        path = self._lpath(args[0])
        try:
            os.makedirs(path, exist_ok=True)
            print(f"Created local directory: {path}")
        except Exception as e:
            self._out(f"lmkdir: {_fmt_err(e)}", 'error')

    def cmd_rmdir(self, args: List[str]):
        if not args:
            self._out("Usage: rmdir path", 'error'); return
        path = self._rpath(args[0])
        try:
            self.sftp.rmdir(path)
            self._log('info', f"RMDIR {path}")
        except Exception as e:
            self._out(f"rmdir: {self._describe_remote_error(e, path, 'rmdir')}", 'error')

    def cmd_rm(self, args: List[str]):
        if not args:
            self._out("Usage: rm path", 'error'); return
        path = self._rpath(args[0])
        try:
            self.sftp.remove(path)
            self._log('info', f"RM {path}")
        except Exception as e:
            self._out(f"rm: {self._describe_remote_error(e, path, 'rm')}", 'error')

    def _is_case_only_rename(self, old: str, new: str) -> bool:
        """True when new names the same entry as old on a case- or
        normalization-insensitive server (macOS APFS): the names match after
        case folding and the directory lists old but not new."""
        parent = self._remote_parent(old)
        if old == new or parent != self._remote_parent(new):
            return False
        old_name = old.rstrip('/').rsplit('/', 1)[-1]
        new_name = new.rstrip('/').rsplit('/', 1)[-1]
        fold = lambda name: unicodedata.normalize('NFD', name).casefold()
        if fold(old_name) != fold(new_name):
            return False
        try:
            names = self.sftp.listdir(parent)
        except Exception:
            return False
        return old_name in names and new_name not in names

    def cmd_rename(self, args: List[str]):
        args, force, confirm = self._extract_overwrite_flags(args)
        if len(args) < 2:
            self._out("Usage: rename [-f|-i] oldpath newpath", 'error'); return
        old = self._rpath(args[0])
        new = self._rpath(args[1])
        if old.rstrip('/') != new.rstrip('/') and not self._is_case_only_rename(old, new) and (
                args[1].endswith('/') or self._remote_path_is_dir(new)):
            # Like mv: an existing directory (or a trailing '/') receives
            # the source under its own name.
            new = self._remote_join(new.rstrip('/') or '/', old.rstrip('/').rsplit('/', 1)[-1])
        overwrite = False
        try:
            exists = self._remote_exists(new)
        except Exception as e:
            self._out(f"rename: could not check remote destination '{new}': {_fmt_err(e)}", 'error')
            return
        if self._is_case_only_rename(old, new):
            # The "existing" destination is the source itself; plain rename
            # refuses it, posix_rename changes the case.
            overwrite = True
        elif exists:
            if not self._confirm_overwrite(new, force, confirm, {}):
                return
            overwrite = True
        try:
            if overwrite:
                # Plain SFTP rename fails when the destination exists; posix_rename
                # (with a plain-rename fallback for unsupported extensions) is
                # what actually overwrites it.
                self._commit_remote_temp(old, new)
            else:
                self.sftp.rename(old, new)
            self._log('info', f"RENAME {old} -> {new}")
        except Exception as e:
            reason = self._describe_rename_error(e, old, new)
            if overwrite:
                self._out(
                    f"rename: could not overwrite '{new}': {reason}. "
                    f"Check '{old}' and '{new}' before retrying; a timed-out "
                    "rename may already have completed.",
                    'error',
                )
            else:
                self._out(f"rename: {reason}", 'error')

    def _describe_rename_error(self, error: Exception, old: str, new: str) -> str:
        """Explain a rename failure using both paths' state. Besides the bare
        "Failure", OpenSSH reports ENOTDIR (directory over a file) as "No such
        file" although both paths exist."""
        message = _fmt_err(error)
        if message not in ('Failure', 'No such file'):
            return self._describe_remote_error(error, new, 'write')
        try:
            old_is_dir = self._remote_attr_is_dir(self.sftp.stat(old))
            new_is_dir = self._remote_attr_is_dir(self.sftp.stat(new))
        except Exception:
            return message
        if old_is_dir and not new_is_dir:
            return "Cannot replace a file with a directory"
        if new_is_dir and not old_is_dir:
            return "Cannot replace a directory with a file"
        if new_is_dir:
            return "Directory not empty"
        return message

    # --- permissions / ownership ---------------------------------------------

    def cmd_chmod(self, args: List[str]):
        if len(args) < 2:
            self._out("Usage: chmod mode path", 'error'); return
        try:
            mode = int(args[0], 8)
        except ValueError:
            self._out("chmod: mode must be octal (e.g. 644)", 'error'); return
        if not 0 <= mode <= 0o7777:
            self._out("chmod: mode must be between 0 and 7777", 'error'); return
        path = self._rpath(args[1])
        try:
            self.sftp.chmod(path, mode)
            self._log('info', f"CHMOD {oct(mode)} {path}")
        except Exception as e:
            self._out(f"chmod: {_fmt_err(e)}", 'error')

    def cmd_chown(self, args: List[str]):
        if len(args) < 2:
            self._out("Usage: chown uid path", 'error'); return
        try:
            uid = int(args[0])
        except ValueError:
            self._out("chown: uid must be a number", 'error'); return
        if not 0 <= uid <= _MAX_ID:
            self._out(f"chown: uid must be between 0 and {_MAX_ID}", 'error'); return
        path = self._rpath(args[1])
        try:
            a = self.sftp.stat(path)
            if a.st_gid is None:
                self._out("chown: server did not return current gid", 'error'); return
            self.sftp.chown(path, uid, a.st_gid)
            self._log('info', f"CHOWN {uid} {path}")
        except Exception as e:
            self._out(f"chown: {_fmt_err(e)}", 'error')

    def cmd_chgrp(self, args: List[str]):
        if len(args) < 2:
            self._out("Usage: chgrp gid path", 'error'); return
        try:
            gid = int(args[0])
        except ValueError:
            self._out("chgrp: gid must be a number", 'error'); return
        if not 0 <= gid <= _MAX_ID:
            self._out(f"chgrp: gid must be between 0 and {_MAX_ID}", 'error'); return
        path = self._rpath(args[1])
        try:
            a = self.sftp.stat(path)
            if a.st_uid is None:
                self._out("chgrp: server did not return current uid", 'error'); return
            self.sftp.chown(path, a.st_uid, gid)
            self._log('info', f"CHGRP {gid} {path}")
        except Exception as e:
            self._out(f"chgrp: {_fmt_err(e)}", 'error')

    # --- info ----------------------------------------------------------------

    def cmd_stat(self, args: List[str]):
        if not args:
            self._out("Usage: stat path", 'error'); return
        path = self._rpath(args[0])
        try:
            s = self.sftp.stat(path)
            print(f"  File: {path}")
            if s.st_size is not None:
                print(f"  Size: {s.st_size}")
            if s.st_mode:
                print(f"  Mode: {_stat.filemode(s.st_mode)}  ({oct(s.st_mode)})")
            uid = s.st_uid if s.st_uid is not None else '?'
            gid = s.st_gid if s.st_gid is not None else '?'
            print(f"   Uid: {uid}   Gid: {gid}")
            if s.st_atime is not None:
                print(f"Access: {datetime.datetime.fromtimestamp(s.st_atime)}")
            if s.st_mtime is not None:
                print(f"Modify: {datetime.datetime.fromtimestamp(s.st_mtime)}")
        except Exception as e:
            self._out(f"stat: {_fmt_err(e)}", 'error')

    # --- view file contents --------------------------------------------------

    def _parse_n(self, args: List[str], default: int = 10):
        """Pull an optional -n N from args; return (n, remaining_args)."""
        if args and args[0] == '-n':
            if len(args) < 2:
                raise ValueError("-n requires a line count")
            try:
                n = int(args[1])
            except ValueError:
                raise ValueError("line count must be an integer")
            if n < 0:
                raise ValueError("line count must be >= 0")
            return n, args[2:]
        return default, args

    @staticmethod
    def _end_view(last: str) -> None:
        """Finish a final unterminated line so the next prompt or [play:N]
        marker starts on a line of its own."""
        if last and not last.endswith('\n'):
            sys.stdout.write('\n')
        sys.stdout.flush()

    def cmd_rcat(self, args: List[str]):
        if not args:
            self._out("Usage: rcat remote-file", 'error'); return
        path = self._rpath(args[0])
        try:
            with self._open_remote_regular(path) as fh, \
                    self._interrupt_between_chunks() as check_interrupt:
                decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
                last = ''
                while True:
                    chunk = fh.read(64 * 1024)
                    check_interrupt()
                    if not chunk:
                        break
                    text = decoder.decode(chunk, final=False)
                    sys.stdout.write(text)
                    last = text or last
                text = decoder.decode(b'', final=True)
                sys.stdout.write(text)
                self._end_view(text or last)
        except Exception as e:
            self._out(f"rcat: {self._describe_remote_error(e, path, 'read')}", 'error')

    def cmd_cat(self, args: List[str]):
        if not args:
            self._out("Usage: cat local-file", 'error'); return
        path = self._lpath(args[0])
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                last = ''
                while True:
                    chunk = fh.read(64 * 1024)
                    if not chunk:
                        break
                    sys.stdout.write(chunk)
                    last = chunk
                self._end_view(last)
        except Exception as e:
            self._out(f"cat: {_fmt_err(e)}", 'error')

    def cmd_rhead(self, args: List[str]):
        try:
            n, args = self._parse_n(args)
        except ValueError as e:
            self._out(f"rhead: {e}", 'error'); return
        if not args:
            self._out("Usage: rhead [-n N] remote-file", 'error'); return
        path = self._rpath(args[0])
        try:
            with self._open_remote_regular(path) as fh, \
                    self._interrupt_between_chunks() as check_interrupt:
                last = ''
                for line in self._head_remote_lines(fh, n, check_interrupt):
                    last = line.decode('utf-8', errors='replace')
                    sys.stdout.write(last)
                self._end_view(last)
        except Exception as e:
            self._out(f"rhead: {self._describe_remote_error(e, path, 'read')}", 'error')

    def cmd_head(self, args: List[str]):
        try:
            n, args = self._parse_n(args)
        except ValueError as e:
            self._out(f"head: {e}", 'error'); return
        if not args:
            self._out("Usage: head [-n N] local-file", 'error'); return
        path = self._lpath(args[0])
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                last = ''
                for _ in range(n):
                    line = fh.readline()
                    if not line:
                        break
                    sys.stdout.write(line)
                    last = line
                self._end_view(last)
        except Exception as e:
            self._out(f"head: {_fmt_err(e)}", 'error')

    def cmd_rtail(self, args: List[str]):
        try:
            n, args = self._parse_n(args)
        except ValueError as e:
            self._out(f"rtail: {e}", 'error'); return
        if not args:
            self._out("Usage: rtail [-n N] remote-file", 'error'); return
        path = self._rpath(args[0])
        try:
            with self._open_remote_regular(path) as fh:
                lines = self._tail_remote_lines(fh, n)
            lines = lines[-n:] if n else []
            for line in lines:
                sys.stdout.write(line)
            self._end_view(lines[-1] if lines else '')
        except Exception as e:
            self._out(f"rtail: {self._describe_remote_error(e, path, 'read')}", 'error')

    @staticmethod
    def _head_remote_lines(fh, n: int, check_interrupt=lambda: None):
        """Yield the first n LF-terminated lines, reading in chunks. A line
        longer than the tail buffer limit is an error: readline() buffered
        without bound (rhead of /dev/zero grew until memory ran out)."""
        buffered = bytearray()
        scanned = 0
        produced = 0
        while produced < n:
            newline = buffered.find(b'\n', scanned)
            if newline >= 0:
                yield bytes(buffered[:newline + 1])
                del buffered[:newline + 1]
                scanned = 0
                produced += 1
                continue
            scanned = len(buffered)
            if scanned > _MAX_TAIL_BUFFER_BYTES:
                raise ValueError(f"line exceeds {_MAX_TAIL_BUFFER_BYTES} bytes")
            chunk = fh.read(64 * 1024)
            check_interrupt()
            if not chunk:
                if buffered:
                    yield bytes(buffered)
                return
            buffered.extend(chunk)

    def _tail_remote_lines(self, fh, n: int) -> List[str]:
        if n <= 0:
            return []
        if n > _MAX_TAIL_LINES:
            raise ValueError(f"tail line count exceeds {_MAX_TAIL_LINES}")

        chunk_size = 64 * 1024
        buffered = bytearray()
        try:
            size = fh.stat().st_size
        except Exception:
            size = None

        if isinstance(size, int) and size >= 0 and hasattr(fh, 'seek'):
            pos = size
            while pos > 0:
                read_size = min(chunk_size, pos)
                pos -= read_size
                fh.seek(pos)
                chunk = fh.read(read_size)
                if not chunk or len(chunk) != read_size:
                    fh.seek(0)
                    return self._tail_remote_lines_forward(fh, n, chunk_size)
                if len(buffered) + len(chunk) > _MAX_TAIL_BUFFER_BYTES:
                    raise ValueError(f"tail output exceeds {_MAX_TAIL_BUFFER_BYTES} buffered bytes")
                buffered[:0] = chunk
                if buffered.count(b'\n') > n:
                    break
            return [line.decode('utf-8', errors='replace')
                    for line in _split_lf_lines(bytes(buffered))[-n:]]

        return self._tail_remote_lines_forward(fh, n, chunk_size)

    def _tail_remote_lines_forward(self, fh, n: int, chunk_size: int = 64 * 1024) -> List[str]:
        if n <= 0:
            return []
        if n > _MAX_TAIL_LINES:
            raise ValueError(f"tail line count exceeds {_MAX_TAIL_LINES}")
        last_lines = deque(maxlen=n)
        buffered = bytearray()
        queued_bytes = 0

        def append_line(line: bytes) -> None:
            nonlocal queued_bytes
            if len(last_lines) == n:
                queued_bytes -= len(last_lines[0])
            if queued_bytes + len(line) > _MAX_TAIL_BUFFER_BYTES:
                raise ValueError(f"tail output exceeds {_MAX_TAIL_BUFFER_BYTES} buffered bytes")
            last_lines.append(line)
            queued_bytes += len(line)

        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            if len(buffered) + len(chunk) > _MAX_TAIL_BUFFER_BYTES:
                raise ValueError(f"tail output exceeds {_MAX_TAIL_BUFFER_BYTES} buffered bytes")
            buffered.extend(chunk)
            parts = _split_lf_lines(bytes(buffered))
            # Carry an unterminated final line over into the next read.
            if parts and not parts[-1].endswith(b'\n'):
                buffered = bytearray(parts.pop())
            else:
                buffered = bytearray()
            for part in parts:
                append_line(part)
        if buffered:
            append_line(bytes(buffered))
        return [line.decode('utf-8', errors='replace') for line in last_lines]

    def cmd_tail(self, args: List[str]):
        try:
            n, args = self._parse_n(args)
        except ValueError as e:
            self._out(f"tail: {e}", 'error'); return
        if not args:
            self._out("Usage: tail [-n N] local-file", 'error'); return
        path = self._lpath(args[0])
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                lines = deque(fh, maxlen=n) if n else ()
            for line in lines:
                sys.stdout.write(line)
            self._end_view(lines[-1] if lines else '')
        except Exception as e:
            self._out(f"tail: {_fmt_err(e)}", 'error')

    # --- symlinks ------------------------------------------------------------

    def cmd_symlink(self, args: List[str]):
        args, force, confirm = self._extract_overwrite_flags(args)
        if len(args) < 2:
            self._out("Usage: symlink [-f|-i] src dest", 'error'); return
        src  = args[0]
        dest = self._rpath(args[1])
        try:
            overwrite = self._remote_exists(dest)
        except Exception as e:
            self._out(f"symlink: could not check remote destination '{dest}': {_fmt_err(e)}", 'error')
            return
        if overwrite and not self._confirm_overwrite(dest, force, confirm, {}):
            return
        if overwrite:
            # Create the replacement link at a temp path first, then atomically
            # swap it into place — removing dest before symlink() succeeded would
            # leave nothing there at all if the create step then failed.
            tmp = self._remote_temp_path(dest)
            try:
                self.sftp.symlink(src, tmp)
                self._commit_remote_temp(tmp, dest)
                self._log('info', f"SYMLINK {src} -> {dest}")
            except BaseException as e:
                try:
                    self._raise_with_cleanup_error(e, tmp)
                except Exception as failure:
                    e = failure
                if not isinstance(e, Exception):
                    raise
                self._out(f"symlink: {_fmt_err(e)}", 'error')
            return
        try:
            self.sftp.symlink(src, dest)
            self._log('info', f"SYMLINK {src} -> {dest}")
        except Exception as e:
            self._out(f"symlink: {_fmt_err(e)}", 'error')

    def cmd_ln(self, args: List[str]):
        args, force, confirm = self._extract_overwrite_flags(args)
        if args and args[0] == '-s':
            args = args[1:]
        if confirm:
            args = ['-i'] + args
        if force:
            args = ['-f'] + args
        self.cmd_symlink(args)

    # ── new ──────────────────────────────────────────────────────────────────
    # Create a remote file whose content is supplied on the command line with
    # optional token substitutions and escape-sequence translation.
    #
    # Usage:  new [-f|-i] filename "content string"
    #
    # Tokens:  %DATE%  %DATETIME%  %GMTDATE%  %GUID%  %MD5%
    #          %REP% "str" n
    # Escapes: \n  \r  \t
    # ─────────────────────────────────────────────────────────────────────────

    def cmd_new(self, args: List[str]):
        force = confirm = False
        while args and args[0] in self._OVERWRITE_FLAG_KINDS:
            kind = self._OVERWRITE_FLAG_KINDS[args[0]]
            force |= kind == 'force'
            confirm |= kind == 'confirm'
            args = args[1:]
        if len(args) < 2:
            self._out(
                'Usage: new [-f|-i] remote-filename "content"\n'
                "  Tokens : %DATE% %DATETIME% %GMTDATE% %GUID% %MD5%\n"
                '           %REP% "str" n\n'
                "  Escapes: \\n  \\r  \\t",
                'error',
            )
            return

        remote = self._rpath(args[0])
        try:
            existed = self._remote_exists(remote)
        except Exception as e:
            self._out(f"new: could not check remote destination '{remote}': {_fmt_err(e)}", 'error')
            return
        if existed and not self._confirm_overwrite(remote, force, confirm, {}):
            return

        tmp = None

        try:
            # The scanner removes quotes but keeps each quoted operand as one
            # argument. Expand standalone repeats using those argument bounds.
            # Each argument is transformed exactly once: a second pass over
            # the joined text would unescape backslashes produced by the first.
            parts = args[1:]
            rebuilt = []
            rebuilt_length = 0
            i = 0
            while i < len(parts):
                if parts[i] == '%REP%' and i + 2 < len(parts) and parts[i + 2].isdecimal():
                    item = _repeat_text(parts[i + 1], int(parts[i + 2]), _MAX_NEW_CONTENT_BYTES)
                    i += 3
                else:
                    item = transform_text(parts[i], max_chars=_MAX_NEW_CONTENT_BYTES)
                    i += 1
                rebuilt_length += len(item) + (1 if rebuilt else 0)
                if rebuilt_length > _MAX_NEW_CONTENT_BYTES:
                    raise ValueError(f"content exceeds {_MAX_NEW_CONTENT_BYTES} bytes")
                rebuilt.append(item)
            content = ' '.join(rebuilt)
            encoded = content.encode('utf-8')
            if len(encoded) > _MAX_NEW_CONTENT_BYTES:
                raise ValueError(f"content exceeds {_MAX_NEW_CONTENT_BYTES} bytes")
            target, replaced_attr = remote, None
            if existed:
                target, replaced_attr = self._resolve_overwrite_target(remote)
            tmp = self._remote_temp_path(target)
            with self.sftp.open(tmp, 'wb') as fh:
                fh.write(encoded)
            if replaced_attr is not None:
                self._copy_replaced_attrs(tmp, replaced_attr, target)
            self._commit_remote_temp(tmp, target, overwrite=replaced_attr is not None)
            byte_count = len(encoded)
            self._out(f"Created {remote}  ({byte_count} bytes)")
            self._log('info', f"NEW {remote}  bytes={byte_count}")
        except BaseException as e:
            if tmp is not None:
                try:
                    self._raise_with_cleanup_error(e, tmp)
                except Exception as failure:
                    e = failure
            if not isinstance(e, Exception):
                raise
            self._out(f"new: {self._describe_remote_error(e, remote, 'write')}", 'error')

    # ── play ─────────────────────────────────────────────────────────────────
    # Execute SFTP commands from a local script file.
    # Lines beginning with '#' or empty lines are ignored.
    # ─────────────────────────────────────────────────────────────────────────

    _MAX_PLAY_DEPTH = 10

    def cmd_play(self, args: List[str]):
        if not args:
            self._out("Usage: play local-file", 'error'); return
        if self._play_depth >= self._MAX_PLAY_DEPTH:
            self._out(f"play: maximum script nesting depth ({self._MAX_PLAY_DEPTH}) exceeded", 'error'); return
        from_stdin = args[0] == '-'
        path = '<stdin>' if from_stdin else self._script_path(args[0])
        try:
            # utf-8-sig: Windows editors such as Notepad start files with a BOM.
            with (self._stdin_script() if from_stdin
                  else open(path, 'r', encoding='utf-8-sig')) as fh:
                self._log('info', f"PLAY {path}")
                had_error_before_play = self._batch_had_error
                self._batch_had_error = False
                self._play_depth += 1
                self._script_dir_stack.append(self.local_cwd if from_stdin
                                              else os.path.dirname(path) or self.local_cwd)
                try:
                    for lineno, raw in enumerate(fh, 1):
                        line = raw.rstrip('\r\n').lstrip()
                        if not line.strip() or line.startswith('#'):
                            continue
                        self._out(f"[play:{lineno}]  {_redact_command_for_log(line)}")
                        self._dispatch(line)
                        if self._should_exit or self._batch_had_error:
                            break
                finally:
                    self._script_dir_stack.pop()
                    self._play_depth -= 1
                    self._batch_had_error = had_error_before_play or self._batch_had_error
        except (OSError, UnicodeError) as e:
            self._out(f"play: {_fmt_err(e)}", 'error')

    @staticmethod
    @contextmanager
    def _stdin_script():
        """Read a script from stdin (play -, -b -) without closing stdin."""
        source = getattr(sys.stdin, 'buffer', None)
        if source is None:
            yield sys.stdin
            return
        reader = io.TextIOWrapper(source, encoding='utf-8-sig')
        try:
            yield reader
        finally:
            reader.detach()

    # ── open / close / connect ───────────────────────────────────────────────

    def cmd_open(self, args: List[str]):
        """open [user@]host[:port] [-P port] [-l user] [-i keyfile] [-p password-or-vault-ref-or-env-ref]"""
        if not args:
            self._out("Usage: open [user@]host[:port] [-P port] [-l user] [-i keyfile] [-p password-or-vault-ref-or-env-ref]", 'error'); return

        dest         = None
        key_file     = None
        password_arg = None
        username_arg = None
        port_arg     = 22
        i = 0
        while i < len(args):
            token = args[i]
            if token in {'-i', '--identity'}:
                if i + 1 >= len(args):
                    self._out(f"open: {token} requires a keyfile path", 'error'); return
                key_file = self._lpath(args[i + 1])
                i += 2
                continue
            if token.startswith('--identity=') or token.startswith('-i='):
                key_file = self._lpath(token.split('=', 1)[1])
                i += 1
                continue
            if token in {'-p', '--password'}:
                if i + 1 >= len(args):
                    self._out(f"open: {token} requires a password, vault reference, or env reference", 'error'); return
                password_arg = args[i + 1]
                i += 2
                continue
            if token.startswith('--password=') or token.startswith('-p='):
                password_arg = token.split('=', 1)[1]
                i += 1
                continue
            if token in {'-P', '--port'}:
                if i + 1 >= len(args):
                    self._out(f"open: {token} requires a port", 'error'); return
                try:
                    port_arg = int(args[i + 1])
                except ValueError:
                    self._out("open: port must be a number", 'error'); return
                if not 1 <= port_arg <= 65535:
                    self._out("open: port must be between 1 and 65535", 'error'); return
                i += 2
                continue
            if token.startswith('--port=') or token.startswith('-P='):
                try:
                    port_arg = int(token.split('=', 1)[1])
                except ValueError:
                    self._out("open: port must be a number", 'error'); return
                if not 1 <= port_arg <= 65535:
                    self._out("open: port must be between 1 and 65535", 'error'); return
                i += 1
                continue
            if token in {'-l', '--user'}:
                if i + 1 >= len(args):
                    self._out(f"open: {token} requires a username", 'error'); return
                username_arg = args[i + 1]
                i += 2
                continue
            if token.startswith('--user=') or token.startswith('-l='):
                username_arg = token.split('=', 1)[1]
                i += 1
                continue
            if token.startswith('-'):
                self._out(f"open: unknown option: {token}", 'error'); return
            if dest is not None:
                self._out("Usage: open [user@]host[:port] [-P port] [-l user] [-i keyfile] [-p password-or-vault-ref-or-env-ref]", 'error'); return
            dest = token
            i += 1

        if dest is None:
            self._out("Usage: open [user@]host[:port] [-P port] [-l user] [-i keyfile] [-p password-or-vault-ref-or-env-ref]", 'error'); return

        username, host, port, _, valid = _parse_destination(dest, username_arg or getpass.getuser(), port_arg)
        if not valid:
            self._out(f"open: invalid destination: {dest}", 'error'); return

        password = None
        if not key_file:
            if password_arg is not None:
                try:
                    password = _resolve_vault_refs(password_arg, PasswordVault())
                except (ValueError, RuntimeError) as e:
                    self._out(f"open: {_fmt_err(e)}", 'error'); return
            else:
                if self._play_depth:
                    self._out("open: scripted connections require -p or -i; refusing to prompt for a password", 'error'); return
                try:
                    password = getpass.getpass(f"Password for {username}@{host}: ") or None
                except (EOFError, KeyboardInterrupt):
                    print()
                    self._out("open: password prompt cancelled", 'error'); return

        try:
            self.connect(host, port, username, password, key_file)
        except Exception as e:
            message = f"open: {_fmt_err(e)}"
            if self.connected and self._connected_host:
                message += f" (still connected to {self._connected_host})"
            self._out(message, 'error')

    def cmd_close(self, args: List[str]):
        if self.connected:
            self._close_connection()
            print("Connection closed.")
        else:
            print("Not connected.")

    def cmd_exit(self, args: List[str]):
        self._should_exit = True

    # ── misc ─────────────────────────────────────────────────────────────────

    def cmd_version(self, args: List[str]):
        print(f"sftp_client.py  {VERSION}")
        print(f"Log file : {self.log_file}")
        print(f"History  : {HISTORY_FILE}")
        if self.connected and self.ssh:
            try:
                t = self.ssh.get_transport()
                if t:
                    print(f"Server   : {t.remote_version}")
            except Exception:
                pass

    def cmd_help(self, args: List[str]):
        print(HELP_TEXT)

    def cmd_shell(self, args: List[str]):
        try:
            rc = subprocess.run(' '.join(args), shell=True).returncode
        except Exception as e:
            self._out(f"shell: {_fmt_err(e)}", 'error')
            return
        if rc != 0:
            self._out(f"shell: command exited with status {rc}", 'error')

    def cmd_vault(self, args: List[str]):
        """vault list | vault add <name> | vault delete <name>"""
        sub = args[0].lower() if args else 'list'
        vault = PasswordVault()
        try:
            if sub == 'list':
                names = vault.list_entries()
                if names:
                    for name in names:
                        print(f"  {name}")
                else:
                    print("Vault is empty.")
            elif sub == 'add':
                if len(args) < 2:
                    self._out("Usage: vault add <name>", 'error'); return
                name = args[1]
                try:
                    value = getpass.getpass(f"Value for '{name}': ")
                except (EOFError, KeyboardInterrupt):
                    print()
                    self._out("vault: credential prompt cancelled", 'error'); return
                vault.add(name, value)
                print(f"Stored '{name}' in vault.")
            elif sub == 'delete':
                if len(args) < 2:
                    self._out("Usage: vault delete <name>", 'error'); return
                name = args[1]
                if vault.delete(name):
                    print(f"Deleted '{name}' from vault.")
                else:
                    self._out(f"vault: '{name}' not found.", 'error')
            else:
                self._out("Usage: vault list | vault add <name> | vault delete <name>", 'error')
        except RuntimeError as e:
            self._out(f"vault: {_fmt_err(e)}", 'error')

    def cmd_atomic(self, args: List[str]):
        if not args:
            print(f"Atomic writes: {'on' if self.atomic else 'off'}")
            return
        arg = args[0].lower()
        if arg == 'on':
            self.atomic = True
            print("Atomic writes enabled.")
        elif arg == 'off':
            self.atomic = False
            print("Atomic writes disabled; failed uploads may leave partial remote files.")
        else:
            self._out("Usage: atomic [on|off]", 'error')

    # ── dispatch ─────────────────────────────────────────────────────────────

    _NO_CONNECTION_NEEDED = {'help', '?', 'version', 'open', 'connect', 'close', 'exit', 'quit', 'bye', 'lls', 'lcd', 'lpwd', 'lmkdir', 'play', 'atomic', 'vault', 'cat', 'head', 'tail'}

    def _dispatch(self, line: str):
        # Keep trailing whitespace: the scanner drops it unless it is escaped
        # ("name\ "), and stripping first would turn that into a stray "\".
        line = line.lstrip()
        if not line or line.startswith('#'):
            return

        # local shell passthrough
        if line.startswith('!'):
            self.cmd_shell([line[1:].strip()])
            return

        try:
            tokens = _split_command_line(line)
        except ValueError as e:
            self._out(f"Parse error: {_fmt_err(e)}", 'error'); return

        if not tokens:
            return
        if any('\x00' in token for token in tokens):
            # SFTP paths are C strings on the server; OpenSSH's sftp-server
            # drops the whole session when a request contains a NUL.
            self._out("Parse error: arguments cannot contain NUL characters", 'error'); return

        cmd  = tokens[0].lower()
        args = tokens[1:]

        handler = COMMANDS.get(cmd)
        if not handler:
            self._out(f"Unknown command: '{cmd}'  (type 'help' for a list)", 'error')
            return

        if not self.connected and cmd not in self._NO_CONNECTION_NEEDED:
            self._out("Not connected.  Use:  open [user@]host[:port]", 'error')
            return

        try:
            handler(self, args)
        except Exception as e:
            self._out(f"Error in '{cmd}': {_fmt_err(e)}", 'error')

        # Detect session loss: handlers catch and print their own errors, but
        # they leave self.connected=True, so the prompt stays "sftp [dir]>"
        # and every subsequent command fails silently.  Checking the transport
        # here recovers cleanly after any command that kills the socket.
        if self.connected and self._connection_is_dead():
            channel = getattr(self.sftp, 'sock', None)
            reason = ("timed out" if getattr(channel, 'sftp_timed_out', False) is True
                      else "lost")
            self._out(f"Connection {reason}.  Use 'open' to reconnect.", 'error')
            self._close_connection()

    # ── REPL ─────────────────────────────────────────────────────────────────

    def run(self,
            host:       Optional[str] = None,
            port:       int           = 22,
            username:   Optional[str] = None,
            password:   Optional[str] = None,
            key_file:   Optional[str] = None,
            batch_file: Optional[str] = None):
        self._should_exit = False
        self._batch_had_error = False

        print(f"sftp_client.py  {VERSION}   log -> {self.log_file}", flush=True)
        if not batch_file:
            print("Type 'help' or '?' for commands, 'exit' to quit.\n", flush=True)

        if host:
            self._log('debug', "DBG run(): calling connect()")
            try:
                self.connect(host, port, username, password, key_file)
            except KeyboardInterrupt:
                self._log('debug', "DBG run(): connect() interrupted")
                print("\nConnection cancelled.", flush=True)
                sys.exit(1)
            except Exception as e:
                self._log('error', f"DBG connect() raised: {e!r}")
                print(f"Connection failed: {_fmt_err(e)}", flush=True)
                sys.exit(1)
            self._log('debug', "DBG run(): connect() finished")

        if batch_file:
            try:
                self.cmd_play([batch_file])
            finally:
                # Readline was not initialised in batch mode; saving history
                # here would replace the interactive history with an empty file.
                if self.connected:
                    self._close_connection()
            if self._batch_had_error:
                sys.exit(1)
            return

        # Initialise readline here — after getpass and paramiko are done —
        # so the terminal is in its normal cooked state when readline
        # configures its key bindings.
        self._log('debug', "DBG run(): calling _setup_readline()")
        self._setup_readline()
        self._log('debug', "DBG run(): _setup_readline() done, entering REPL loop")

        try:
            while not self._should_exit:
                rdir = os.path.basename(self.remote_cwd) or '/'
                prompt = (f"sftp [{rdir}]> " if self.connected else "sftp> ")

                self._log('debug', f"DBG REPL: about to read input(prompt={prompt!r})")
                sys.stdout.flush()
                try:
                    line = input(prompt)
                except EOFError:
                    self._log('debug', "DBG REPL: got EOFError")
                    print(); break
                except KeyboardInterrupt:
                    self._log('debug', "DBG REPL: got KeyboardInterrupt")
                    print(); continue

                self._log('debug', f"DBG REPL: input() returned {_redact_command_for_log(line)!r}")
                try:
                    self._dispatch(line)
                except KeyboardInterrupt:
                    self._log('debug', "DBG REPL: got KeyboardInterrupt during dispatch")
                    print()
        finally:
            self._save_history()
            if self.connected:
                self._close_connection()
            print("Goodbye.")


# ──────────────────────────────────────────────────────────────────────────────
# Command registry
# ──────────────────────────────────────────────────────────────────────────────

COMMANDS = {
    # remote listing
    'ls':      SFTPClient.cmd_ls,
    'dir':     SFTPClient.cmd_ls,
    # local listing
    'lls':     SFTPClient.cmd_lls,
    # navigation
    'cd':      SFTPClient.cmd_cd,
    'lcd':     SFTPClient.cmd_lcd,
    'pwd':     SFTPClient.cmd_pwd,
    'lpwd':    SFTPClient.cmd_lpwd,
    # transfer
    'get':     SFTPClient.cmd_get,
    'put':     SFTPClient.cmd_put,
    'dirput':  SFTPClient.cmd_dirput,
    'mget':    SFTPClient.cmd_mget,
    'mput':    SFTPClient.cmd_mput,
    # directories
    'mkdir':   SFTPClient.cmd_mkdir,
    'lmkdir':  SFTPClient.cmd_lmkdir,
    'rmdir':   SFTPClient.cmd_rmdir,
    # file ops
    'rm':      SFTPClient.cmd_rm,
    'delete':  SFTPClient.cmd_rm,
    'rename':  SFTPClient.cmd_rename,
    # permissions
    'chmod':   SFTPClient.cmd_chmod,
    'chown':   SFTPClient.cmd_chown,
    'chgrp':   SFTPClient.cmd_chgrp,
    # info
    'stat':    SFTPClient.cmd_stat,
    # view contents
    'rcat':    SFTPClient.cmd_rcat,
    'cat':     SFTPClient.cmd_cat,
    'rhead':   SFTPClient.cmd_rhead,
    'head':    SFTPClient.cmd_head,
    'rtail':   SFTPClient.cmd_rtail,
    'tail':    SFTPClient.cmd_tail,
    # links
    'symlink': SFTPClient.cmd_symlink,
    'ln':      SFTPClient.cmd_ln,
    # extended
    'new':     SFTPClient.cmd_new,
    'play':    SFTPClient.cmd_play,
    # connection
    'open':    SFTPClient.cmd_open,
    'connect': SFTPClient.cmd_open,
    'close':   SFTPClient.cmd_close,
    'exit':    SFTPClient.cmd_exit,
    'quit':    SFTPClient.cmd_exit,
    'bye':     SFTPClient.cmd_exit,
    # settings
    'atomic':  SFTPClient.cmd_atomic,
    'vault':   SFTPClient.cmd_vault,
    # misc
    'version': SFTPClient.cmd_version,
    'help':    SFTPClient.cmd_help,
    '?':       SFTPClient.cmd_help,
}

# ──────────────────────────────────────────────────────────────────────────────
# Help text
# ──────────────────────────────────────────────────────────────────────────────

HELP_TEXT = """
sftp_client.py command reference
================================

CONNECTION
  open [user@]host[:port] [-P port] [-l user] [-i keyfile] [-p password]
                                        Connect to remote host
  close                                 Disconnect

REMOTE DIRECTORY
  ls [path]       List remote directory
  cd [path]       Change remote directory
  pwd             Print remote working directory
  mkdir path      Create remote directory
  rmdir path      Remove remote directory

LOCAL DIRECTORY
  lls [path]      List local directory
  lcd [path]      Change local directory
  lpwd            Print local working directory
  lmkdir path     Create local directory

FILE TRANSFER
  get [-f|-i] remote [local]    Download file
  put [-f|-i] local [remote]    Upload file
  dirput [-f|-i] local [remote] Upload directory tree
  mget [-f|-i] pattern          Download files matching glob
  mput [-f|-i] pattern          Upload files matching glob

  -f / --force    overwrite an existing destination without asking
  -i / --confirm  ask per destination; 'a' answers yes to the rest of
                  this command's batch, 'q' aborts the rest
  Without either flag, an existing destination is skipped.

FILE MANAGEMENT
  rm path                    Remove remote file
  rename [-f|-i] old new     Rename remote file
  chmod mode path            Change permissions (octal mode)
  chown uid path             Change owner (numeric uid)
  chgrp gid path             Change group (numeric gid)
  stat path                  Show remote file attributes
  symlink [-f|-i] src dest   Create remote symbolic link
  ln [-s] [-f|-i] src dest   Alias for symlink

VIEW FILE CONTENTS
  rcat remote-file          Print remote file to screen
  cat local-file            Print local file to screen
  rhead [-n N] remote-file  First N lines of remote file (default 10)
  head [-n N] local-file    First N lines of local file (default 10)
  rtail [-n N] remote-file  Last N lines of remote file (default 10)
  tail [-n N] local-file    Last N lines of local file (default 10)
  rtail buffers at most 16 MiB or 100000 lines of output.

CONTENT CREATION
  new [-f|-i] filename "content"    Create remote file with template content
  Existing files are skipped unless -f or -i is given.
  Generated content is limited to 16 MiB.

  Tokens: %DATE% %DATETIME% %GMTDATE% %GUID% %MD5%
          %REP% "str" n, %REP% 'str' n, %REP% c n
  Escapes: \\n newline, \\r carriage-return, \\t tab

SCRIPTING
  play localfile            Execute commands from a script file

VAULT
  vault list                List stored credential names
  vault add <name>          Prompt securely and store a credential
  vault delete <name>       Remove a stored credential
  Use vault:<name> or env:<VAR> anywhere a password is accepted.
  Vault files: ~/.sftpclient/vault.json and ~/.sftpclient/vault.key

SETTINGS
  atomic [on|off]           Toggle atomic uploads (default: on)

SHELL & MISC
  !command                  Execute a local shell command
  version                   Show version and log-file path
  help / ?                  Show this help
  exit / quit / bye         Exit the client
"""


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Interactive SFTP client",
        usage="%(prog)s [[user@]host[:port]] [-P port] [-l user] [-i keyfile] [-p password] [-b batchfile]"
    )
    p.add_argument('destination', nargs='?',
                   help="[user@]host  or  [user@]host:port")
    p.add_argument('-P', '--port',     type=int, default=22,  metavar='port')
    p.add_argument('-l', '--user',     metavar='user')
    p.add_argument('-i', '--identity', metavar='keyfile')
    p.add_argument('-p', '--password', metavar='PASS',
                   help="Password, vault reference (e.g. vault:mypassword), "
                        "or env reference (e.g. env:MY_PASS_VAR). "
                        "Omit to prompt interactively.")
    p.add_argument('-b', '--batch',    metavar='file',
                   help="Run commands from file then exit")
    atomic_group = p.add_mutually_exclusive_group()
    atomic_group.add_argument('-A', '--atomic', dest='atomic', action='store_true',
                              help="Atomic uploads: write to .tmp then rename into place (default)")
    atomic_group.add_argument('--no-atomic', dest='atomic', action='store_false',
                              help="Write uploads directly (a failed upload may leave a partial file)")
    p.set_defaults(atomic=True)
    # vault management — these run and exit without starting an SFTP session
    p.add_argument('--vault-add',    metavar='NAME',
                   help="Store a new vault credential (prompts securely for the value)")
    p.add_argument('--vault-delete', metavar='NAME',
                   help="Remove a vault credential")
    p.add_argument('--vault-list',   action='store_true',
                   help="List stored vault credential names")
    return p.parse_args()


def _log_paramiko_thread_disconnects() -> None:
    """paramiko's download prefetch thread does not catch the EOFError or
    OSError it hits when the connection drops, so Python printed its
    traceback in the middle of the session. The main thread already reports
    the lost connection; send these to the log file instead."""
    paramiko_dir = os.path.dirname(os.path.abspath(paramiko.__file__)) + os.sep
    previous = threading.excepthook

    def hook(args):
        frames = traceback.extract_tb(args.exc_traceback) if args.exc_traceback else []
        if (issubclass(args.exc_type, (EOFError, OSError))
                and any(os.path.abspath(f.filename).startswith(paramiko_dir) for f in frames)):
            logging.getLogger("sftp_client").warning(
                f"paramiko thread {getattr(args.thread, 'name', '?')} stopped: "
                f"{args.exc_type.__name__}: {args.exc_value}")
            return
        previous(args)

    threading.excepthook = hook


def main():
    _log_paramiko_thread_disconnects()
    # Local names that are not valid UTF-8 surface as surrogate escapes;
    # print them escaped rather than crash the REPL with UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors='backslashreplace')
        except (AttributeError, ValueError):
            pass
    args = _parse_args()

    # ── vault management (--vault-list / --vault-add / --vault-delete) ────────
    # These flags operate on the local credential store and exit immediately
    # without starting an SFTP session.
    if args.vault_list or args.vault_add or args.vault_delete:
        vault = PasswordVault()
        try:
            if args.vault_list:
                names = vault.list_entries()
                if names:
                    for n in names:
                        print(f"  {n}")
                else:
                    print("Vault is empty.")
            if args.vault_add:
                try:
                    value = getpass.getpass(f"Value for '{args.vault_add}': ")
                except (EOFError, KeyboardInterrupt):
                    print(file=sys.stderr); sys.exit(1)
                vault.add(args.vault_add, value)
                print(f"Stored '{args.vault_add}' in vault.")
            if args.vault_delete:
                if vault.delete(args.vault_delete):
                    print(f"Deleted '{args.vault_delete}' from vault.")
                else:
                    print(f"vault: '{args.vault_delete}' not found.", file=sys.stderr)
                    sys.exit(1)
        except RuntimeError as e:
            print(f"vault: {e}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    # ── normal connection setup ───────────────────────────────────────────────
    host     = None
    port     = args.port
    username = args.user or getpass.getuser()

    if not 1 <= port <= 65535:
        print(f"Invalid port: {port}", file=sys.stderr)
        sys.exit(2)

    if args.destination:
        username, host, parsed_port, port_explicit, valid = _parse_destination(args.destination, username, port)
        if not valid:
            print(f"Invalid destination: {args.destination}", file=sys.stderr)
            sys.exit(2)
        if port_explicit or port == 22:
            port = parsed_port

    identity = os.path.abspath(os.path.expanduser(args.identity)) if args.identity else None
    if args.batch == '-':
        batch_file = '-'  # commands on stdin, as with OpenSSH's sftp -b -
    else:
        batch_file = os.path.abspath(os.path.expanduser(args.batch)) if args.batch else None

    if identity and args.password:
        print("Warning: -p is ignored when -i is also given; using key authentication.", file=sys.stderr)

    # Any readable non-directory works: /dev/stdin, a named pipe, <(...).
    if batch_file and batch_file != '-' and (not os.path.exists(batch_file) or os.path.isdir(batch_file)):
        problem = "is a directory" if os.path.isdir(batch_file) else "not found"
        print(f"Error: batch file {problem}: {args.batch}", file=sys.stderr)
        sys.exit(2)

    password = None
    if host and not identity:
        if args.password is not None:
            try:
                password = _resolve_vault_refs(args.password, PasswordVault())
            except (ValueError, RuntimeError) as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
        elif args.batch:
            print("Error: batch mode requires -p or -i when connecting with a password.", file=sys.stderr)
            sys.exit(1)
        else:
            try:
                password = getpass.getpass(f"Password for {username}@{host}: ") or None
            except (EOFError, KeyboardInterrupt):
                print(file=sys.stderr)
                sys.exit(1)

    client = SFTPClient()
    client.atomic = args.atomic
    client.run(
        host       = host,
        port       = port,
        username   = username,
        password   = password,
        key_file   = identity,
        batch_file = batch_file,
    )


if __name__ == '__main__':
    main()
