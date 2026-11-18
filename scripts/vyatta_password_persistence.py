"""Target-only saved password updates, serialized with supported startup writers.

This module never handles plaintext or calls configd. The caller must stage
before committing runtime state and publish afterwards; publication failure
after a commit is a partial failure, not grounds for an unconditional rollback.
Advisory locking cannot serialize uncooperative administrators or provide a
transaction spanning configd and the filesystem.
"""
import errno
import os
from pathlib import Path
import re
import secrets
import stat
import time
from collections import namedtuple


class SavedPasswordError(Exception):
    """Saved configuration could not be safely prepared or published."""


_Token = namedtuple("_Token", "value start end kind")
_Node = namedtuple("_Node", "name argument children disabled")
_MAX_SIZE = 8 * 1024 * 1024
_NAME = re.compile(rb"[A-Za-z_][A-Za-z0-9_-]*\Z")
_HASH = re.compile(r"\$(?:1|2[abxy]|5|6|7|y|gy)\$[A-Za-z0-9./$,=+-]+\Z")


def _tokens(data):
    """Byte offsets for the config/parse statement grammar, without reformatting.

    Double-quoted/backslash-escaped strings and /* */ or // comments follow
    config/parse/lex.go. Colons remain ordinary argument bytes (e.g. IPv6).
    Legacy Xorp '! ' disabled prefixes are recognized separately by the parser.
    Legacy name:value syntax and other unsupported forms fail closed.
    """
    if len(data) > _MAX_SIZE:
        raise SavedPasswordError("Startup configuration is too large")
    try:
        data.decode("utf-8", "strict")
    except UnicodeError as error:
        raise SavedPasswordError("Startup configuration is not UTF-8") from error
    if any(c < 32 and c not in (9, 10, 13) for c in data):
        raise SavedPasswordError("Unsupported startup control character")
    result = []
    i = 0
    while i < len(data):
        start = i
        c = data[i]
        if c in (32, 9):
            i += 1
            continue
        if data.startswith(b"/*", i):
            end = data.find(b"*/", i + 2)
            if end < 0:
                raise SavedPasswordError("Unclosed startup comment")
            i = end + 2
            continue
        if data.startswith(b"//", i):
            end = data.find(b"\n", i + 2)
            if end < 0:
                raise SavedPasswordError("Unclosed startup line comment")
            # Keep the statement boundary; comments never become target tokens.
            i = end
            continue
        if c in (10, 13, 59, 123, 125):
            result.append(_Token(bytes([c]), i, i + 1, bytes([c])))
            i += 1
            continue
        if c == 34:
            i += 1
            value_start = i
            while i < len(data) and data[i] != 34:
                if data[i] == 92:
                    i += 1
                i += 1
            if i >= len(data):
                raise SavedPasswordError("Unclosed startup quoted string")
            value = data[value_start:i]
            i += 1
        else:
            while i < len(data) and data[i] not in b' \t\r\n;{}"':
                if data[i] == 92:
                    i += 1
                    if i == len(data):
                        raise SavedPasswordError("Unclosed startup escape")
                i += 1
            value = data[start:i]
        result.append(_Token(value, start, i, b"string"))
    return result


def _password_span(data, user):
    """Return the complete existing hash token's byte span, quotes included."""
    if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", user):
        raise SavedPasswordError("Unsupported saved account name")
    tokens = _tokens(data)
    index = 0
    separators = (b"\n", b"\r", b";")

    def statements(depth=0):
        nonlocal index
        if depth > 128:
            raise SavedPasswordError("Startup nesting is too deep")
        nodes = []
        while index < len(tokens):
            token = tokens[index]
            if token.kind in separators:
                index += 1
                continue
            if token.kind == b"}":
                if depth == 0:
                    raise SavedPasswordError("Unexpected startup closing brace")
                index += 1
                return nodes
            disabled = data[token.start:token.end] == b"!"
            if disabled:
                index += 1
                if index == len(tokens):
                    raise SavedPasswordError("Incomplete disabled startup statement")
                token = tokens[index]
            if not _NAME.fullmatch(token.value):
                raise SavedPasswordError("Unsupported startup statement name")
            name = token.value
            index += 1
            argument = None
            if index < len(tokens) and tokens[index].kind == b"string":
                argument = tokens[index]
                index += 1
            children = None
            if index < len(tokens) and tokens[index].kind == b"{":
                index += 1
                children = statements(depth + 1)
            elif index < len(tokens) and tokens[index].kind in separators:
                index += 1
            elif index < len(tokens):
                raise SavedPasswordError("Malformed startup statement")
            nodes.append(_Node(name, argument, children, disabled))
        if depth:
            raise SavedPasswordError("Unclosed startup block")
        return nodes

    def single(nodes, name, value=None, leaf=False):
        matches = [node for node in nodes if node.name == name and
                   (value is None or (node.argument is not None and node.argument.value == value))]
        if len(matches) != 1:
            raise SavedPasswordError("Saved account path is missing or ambiguous; save account configuration first")
        node = matches[0]
        if node.disabled or (node.children is None) != leaf:
            raise SavedPasswordError("Saved account path is disabled or malformed")
        if not leaf and value is None and node.argument is not None:
            raise SavedPasswordError("Malformed saved account container")
        return node

    system = single(statements(), b"system")
    login = single(system.children, b"login")
    account = single(login.children, b"user", user.encode("ascii"))
    auth = single(account.children, b"authentication")
    if any(node.name == b"plaintext-password" for node in auth.children):
        raise SavedPasswordError("Saved plaintext password is unsupported; save account configuration first")
    password = single(auth.children, b"encrypted-password", leaf=True)
    if password.argument is None or not password.argument.value:
        raise SavedPasswordError("Saved encrypted password is missing")
    return password.argument.start, password.argument.end


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class SavedPasswordUpdate:
    """Hold startup.lock across caller verification, staging, commit and publish.

    Paths are trusted caller constants, never RPC input. Owned private temporary
    paths permit unprivileged filesystem tests. Production callers execute root.
    Startup directories may be group-writable (/config is root:vyattacfg 2770);
    operations use anchored directory descriptors and never follow final links.
    Other privileged/uncooperative writers are detected when possible, not made
    atomic with this protocol.
    """
    def __init__(self, user, filename="/config/config.boot",
                 lock_dir="/run/nudanos-startup", timeout=10):
        self.user = user
        self.filename = Path(filename)
        self.lock_dir = Path(lock_dir)
        self.timeout = timeout
        self._lock_directory = self._lock = self._directory = None
        self._temp = None
        self._prepared = False
        self._published = False

    @staticmethod
    def _directory_fd(path):
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    def _acquire(self):
        import fcntl
        try:
            os.mkdir(self.lock_dir, 0o700)
        except FileExistsError:
            pass
        self._lock_directory = self._directory_fd(self.lock_dir)
        info = os.fstat(self._lock_directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise SavedPasswordError("Unsafe startup lock directory")
        self._lock = os.open("startup.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                             os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=self._lock_directory)
        info = os.fstat(self._lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise SavedPasswordError("Unsafe startup lock file")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as error:
                if error.errno not in (errno.EAGAIN, errno.EACCES):
                    raise
                if time.monotonic() >= deadline:
                    raise SavedPasswordError("Timed out waiting for startup configuration lock") from error
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))

    def _read(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=self._directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) not in (0o400, 0o440, 0o600, 0o640)):
                raise SavedPasswordError("Unsafe startup file ownership, type or permissions")
            parts = []
            size = 0
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                parts.append(block)
                size += len(block)
                if size > _MAX_SIZE:
                    raise SavedPasswordError("Startup configuration is too large")
            if _identity(info) != _identity(os.fstat(fd)):
                raise SavedPasswordError("Startup file changed while reading")
            return b"".join(parts), info
        finally:
            os.close(fd)

    def __enter__(self):
        try:
            self._acquire()
            self._directory = self._directory_fd(self.filename.parent)
            self._source, self._original = self._read(self.filename.name)
            self._span = _password_span(self._source, self.user)
            return self
        except (OSError, SavedPasswordError) as error:
            self.__exit__(type(error), error, error.__traceback__)
            if isinstance(error, SavedPasswordError):
                raise
            raise SavedPasswordError("Could not open saved configuration safely") from error

    def prepare(self, new_hash):
        if self._directory is None or self._prepared or self._published:
            raise SavedPasswordError("Saved password update is not ready for staging")
        if not isinstance(new_hash, str) or len(new_hash) > 4096 or not _HASH.fullmatch(new_hash):
            raise SavedPasswordError("Candidate encrypted password is invalid")
        start, end = self._span
        self._replacement = self._source[:start] + b'"' + new_hash.encode("ascii") + b'"' + self._source[end:]
        name = ".password-" + secrets.token_hex(16)
        fd = None
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self._directory)
            self._temp = name
            os.fchown(fd, self._original.st_uid, self._original.st_gid)
            os.fchmod(fd, stat.S_IMODE(self._original.st_mode))
            view = memoryview(self._replacement)
            while view:
                written = os.write(fd, view)
                if written == 0:
                    raise OSError("Short startup-file write")
                view = view[written:]
            os.fsync(fd)
            self._staged = os.fstat(fd)
            os.close(fd)
            fd = None
            self._prepared = True
        except OSError as error:
            raise SavedPasswordError("Could not stage saved password update") from error
        finally:
            if fd is not None:
                os.close(fd)

    def publish(self):
        if not self._prepared or self._published:
            raise SavedPasswordError("Saved password update has not been staged")
        try:
            parent = self._directory_fd(self.filename.parent)
            try:
                opened = os.fstat(self._directory)
                current_parent = os.fstat(parent)
                if (opened.st_dev, opened.st_ino) != (current_parent.st_dev, current_parent.st_ino):
                    raise SavedPasswordError("Startup directory changed before publication")
            finally:
                os.close(parent)
            current, info = self._read(self.filename.name)
            if current != self._source or _identity(info) != _identity(self._original):
                raise SavedPasswordError("Saved configuration changed before publication")
            staged, info = self._read(self._temp)
            if staged != self._replacement or _identity(info) != _identity(self._staged):
                raise SavedPasswordError("Staged configuration changed before publication")
            os.replace(self._temp, self.filename.name,
                       src_dir_fd=self._directory, dst_dir_fd=self._directory)
            self._temp = None
            self._published = True
            os.fsync(self._directory)
        except OSError as error:
            raise SavedPasswordError("Could not durably publish saved password update") from error

    def __exit__(self, exc_type, exc_value, traceback):
        failed = False
        if self._temp is not None and self._directory is not None:
            try:
                os.unlink(self._temp, dir_fd=self._directory)
            except FileNotFoundError:
                pass
            except OSError:
                failed = True
            self._temp = None
        for attr in ("_directory", "_lock", "_lock_directory"):
            fd = getattr(self, attr)
            if fd is not None:
                # Never retry close after an error: Linux may have released the
                # descriptor already. Always attempt the remaining descriptors.
                setattr(self, attr, None)
                try:
                    os.close(fd)
                except OSError:
                    failed = True
        if failed:
            message = "Saved password update cleanup failed; verify running and saved configuration"
            if exc_value is not None:
                # Preserve the primary outcome, especially a partial commit.
                exc_value.add_note(message)
            else:
                raise SavedPasswordError(message)
        return False
