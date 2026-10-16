# sftp_client.py

An interactive SFTP client in a single Python file, built on [paramiko](https://www.paramiko.org/).
It covers the usual OpenSSH `sftp` commands and adds tab-completion, persistent history,
remote file creation from templates, scripted playback, an encrypted credential vault,
atomic uploads and daily-rotating session logs.

Version 1.1.0.

## Requirements

- Python 3
- `paramiko` (required)
- `cryptography`: optional, needed only for the credential vault
- `pyreadline3`: optional, Windows only, for tab-completion and history

```bash
pip install paramiko
pip install cryptography      # optional: vault support
pip install pyreadline3       # optional: Windows tab-completion/history
```

If no readline module is available, the client still runs, just without completion or history.

## Quick start

```bash
# Start with no connection, then use `open` at the prompt
python3 sftp_client.py

# Connect on launch
python3 sftp_client.py user@host
python3 sftp_client.py user@host:2222
python3 sftp_client.py user@host -P 2222
python3 sftp_client.py user@[::1]:2222          # IPv6 literal
python3 sftp_client.py user@host -i ~/.ssh/id_rsa

# Run a script non-interactively, then exit
python3 sftp_client.py user@host -i ~/.ssh/id_rsa -b script.sftp
```

> **Host keys:** the client rejects servers whose host key is unknown. The server must
> already be in your system `known_hosts` file (connect once with `ssh` or `sftp` to add it).

## Command-line options

| Option | Description |
|---|---|
| `[user@]host[:port]` | Destination to connect to on launch |
| `-P`, `--port PORT` | Port (default 22) |
| `-l`, `--user USER` | Username (default: current local user) |
| `-i`, `--identity KEYFILE` | Private key for key authentication |
| `-p`, `--password PASS` | Password, `vault:<name>` or `env:<VAR>`. Leave it out to be prompted. Ignored when `-i` is given |
| `-b`, `--batch FILE` | Run commands from FILE, then exit (exit code 1 if any command fails) |
| `-A`, `--atomic` / `--no-atomic` | Turn atomic uploads on (the default) or off |
| `--vault-list` | List stored vault credential names, then exit |
| `--vault-add NAME` | Store a credential (you are prompted for the value), then exit |
| `--vault-delete NAME` | Remove a credential, then exit |

Batch mode never prompts for a password. Pass `-p` or `-i` instead.

## Authentication

- **Key:** `-i keyfile`.
- **Password:** `-p`, or an interactive prompt. If plain password authentication fails, the
  client tries keyboard-interactive authentication.
- When a password is given, the client skips the SSH agent and the `~/.ssh/id_*` key scan, so
  connections don't stall on servers that are slow to reject keys.

Wherever a password is accepted, you can give a reference instead of the literal value:

- `vault:<name>`: a credential from the encrypted vault
- `env:<VAR>`: the value of an environment variable

## Commands

Type `help` or `?` at the prompt for the full reference.

### Connection

| Command | Description |
|---|---|
| `open [user@]host[:port] [-P port] [-l user] [-i keyfile] [-p password]` | Connect (alias: `connect`) |
| `close` | Disconnect |
| `exit` / `quit` / `bye` | Leave the client |

### Navigation and directories

| Remote | Local | Description |
|---|---|---|
| `ls [path\|glob]` / `dir` | `lls [path]` | List a directory (always the long format; `-l`/`-la` are accepted) |
| `cd [path]` | `lcd [path]` | Change directory |
| `pwd` | `lpwd` | Print the working directory |
| `mkdir path` | `lmkdir path` | Create a directory |
| `rmdir path` | | Remove a remote directory |

### File transfer

| Command | Description |
|---|---|
| `get [-f\|-i] remote [local]` | Download a file |
| `put [-f\|-i] local [remote]` | Upload a file |
| `dirput [-f\|-i] local [remote]` | Upload a directory tree |
| `mget [-f\|-i] pattern` | Download the files that match a glob (directories, links to them, and broken links are skipped) |
| `mput [-f\|-i] pattern` | Upload the files that match a glob |

**Overwrite protection.** By default an existing destination is skipped.

- `-f` / `--force` overwrites without asking.
- `-i` / `--confirm` asks for each file. Answer `a` to say yes to the rest of the batch, or `q` to abort.

The same flags work with `rename`, `symlink`/`ln` and `new`.

Like OpenSSH `sftp`, overwriting a file with `put`, `dirput`, `mput` or `new` writes through a
symlink to its target, keeps the replaced file's permissions (and owner, where the server
allows it), and refuses a read-only file; `chmod` it first. A downloaded file keeps the
permissions of the local file it replaces, or gets the remote permissions filtered by your
umask.

Downloads and the `rcat`/`rhead`/`rtail` viewers accept regular files only; devices such as
`/dev/zero`, FIFOs and sockets are refused (`mget` skips them with a warning). An upload whose
local source changes size or modification time while it is being sent is not published.

**Quoting.** Quote names that contain spaces (`"my file.txt"`) or escape the space
(`my\ file.txt`). Backslashes are literal, so Windows paths work as typed, except before a
space, a quote or the end of the line: there `\\` is one literal backslash, so `put name\\ dest`
uploads `name\`.

### File management

| Command | Description |
|---|---|
| `rm path` / `delete path` | Remove a remote file |
| `rename [-f\|-i] old new` | Rename or move a remote file; like `mv`, an existing directory (or a trailing `/`) receives `old` under its own name |
| `chmod mode path` | Change permissions (octal) |
| `chown uid path` | Change owner (numeric uid) |
| `chgrp gid path` | Change group (numeric gid) |
| `stat path` | Show remote file attributes |
| `symlink [-f\|-i] src dest` | Create a remote symbolic link (alias: `ln [-s]`) |

### Viewing files

| Remote | Local | Description |
|---|---|---|
| `rcat file` | `cat file` | Print the whole file |
| `rhead [-n N] file` | `head [-n N] file` | Print the first N lines (default 10) |
| `rtail [-n N] file` | `tail [-n N] file` | Print the last N lines (default 10) |

`rhead` and `rtail` end lines at `\n` only, like Unix `head` and `tail`. `rtail` buffers at most 16 MiB or
100,000 lines.

### Local shell and miscellaneous

| Command | Description |
|---|---|
| `!command` | Run a local shell command |
| `atomic [on\|off]` | Show or toggle atomic uploads |
| `vault list \| add <name> \| delete <name>` | Manage the credential vault |
| `version` | Show the version, the log and history paths, and the server banner |
| `help` / `?` | Show the command reference |

These commands work without a connection: `help`, `version`, `open`, `close`, `exit`, `lls`,
`lcd`, `lpwd`, `lmkdir`, `cat`, `head`, `tail`, `play`, `atomic` and `vault`.

## Creating remote files from templates: `new`

```
new [-f|-i] remote-filename "content"
```

`new` writes a remote file from a content string. Before writing, it expands tokens and escapes
in the string:

| Token | Expands to |
|---|---|
| `%DATE%` | Local date, `YYYY-MM-DD` |
| `%DATETIME%` | Local date and time, `YYYY-MM-DD HH:MM:SS` |
| `%GMTDATE%` | UTC timestamp, `YYYY-MM-DDTHH:MM:SSZ` |
| `%GUID%` | A random UUID4, fresh at every occurrence |
| `%MD5%` | MD5 hex digest of a fresh UUID4, fresh at every occurrence |
| `%REP% "str" n` | `str` repeated `n` times (also `'str'`, or a single bare character) |

The escapes `\n`, `\r` and `\t` become a newline, a carriage return and a tab, and `\\`
becomes one backslash; any other backslash is kept as typed. Tokens can be used inside a
`%REP%` string, and each copy gets its own `%GUID%`/`%MD5%`. Generated content is limited to
16 MiB.

```
new report.txt "Generated %DATETIME%\nid=%GUID%\n"
new divider.txt %REP% - 80
new rows.csv %REP% "%GUID%,%DATE%\n" 1000
```

## Scripting: `play` and batch mode

A script is a plain text file with one command per line. Blank lines and lines that start with
`#` are ignored.

```
play script.sftp                                   # from the prompt
python3 sftp_client.py user@host -b script.sftp    # non-interactive
printf 'cd logs\nmget *.log\n' | python3 sftp_client.py user@host -p vault:host -b -   # stdin
```

- The script stops at the first command that fails.
- Scripts can `play` other scripts, up to 10 levels deep. Relative paths resolve against the
  directory of the calling script.
- A script that runs `open` must pass `-p` or `-i`. Scripts never prompt for passwords.
- `-b -` (or `play -`) reads the script from standard input; `/dev/stdin`, named pipes and
  `<(...)` work as script paths too.

An example template is in [`templates/push_json_files.sftp`](templates/push_json_files.sftp).
It uploads every `*.json` file from a local directory to a remote directory.

## Atomic uploads

Atomic uploads are on by default. Each upload is written to a hidden temporary file
(`.sftp-<id>.tmp`) in the destination directory and renamed into place only after it
completes, so a failed transfer never leaves a partial file. Turn this off with `--no-atomic`
or `atomic off` if the server doesn't allow renames.

If the connection drops or the server stops responding for 30 seconds, the session is closed
("Connection lost" or "Connection timed out"). A temporary file that could not be removed then
is deleted the next time you `open` the same host. During a transfer, Ctrl-C takes effect at the
next chunk so the session stays usable; press it twice to stop a stuck transfer at once.

## Credential vault

The vault stores passwords encrypted with Fernet (it needs the `cryptography` package), so they
don't have to appear on the command line or in scripts.

```bash
python3 sftp_client.py --vault-add prod          # prompts for the value
python3 sftp_client.py user@host -p vault:prod
```

Files:

- `~/.sftpclient/vault.json`: the encrypted entries
- `~/.sftpclient/vault.key`: the encryption key

Both are created with owner-only permissions (a restricted ACL on Windows). Keep them out of
version control.

## Files and logs

| Path | Purpose |
|---|---|
| `~/.sftp_logs/sftp_client.log` | Session log, rotated daily, 30 days kept. All console output is logged; passwords are redacted |
| `~/.sftp_client_history` | Command history (up to 2,000 lines) |
| `~/.sftpclient/` | Vault data and key |

## Development

Everything lives in `sftp_client.py`. The regression tests in `test_sftp_client.py` mock
paramiko, so they don't need network access.

```bash
# Syntax check
python3 -c "import py_compile; py_compile.compile('sftp_client.py', doraise=True)"

# Run the test suite
python3 -m unittest test_sftp_client -v
```

To add a command, write a `cmd_<name>` method on `SFTPClient` and register it in the
`COMMANDS` dict. If it doesn't need a connection, also add it to `_NO_CONNECTION_NEEDED`.
For changes that depend on server behaviour, also test against a live SFTP server and check
`~/.sftp_logs/`.

This project uses `ngit` for version control.
