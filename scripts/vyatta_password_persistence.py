"""Read-only post-commit saved-password verification.

No configuration writes, writer lock, or configd calls. A successful observation
and fsync are not a transaction with runtime state or a universal concurrency
check: privileged writers may change the file after the final check.
"""
import os
from pathlib import Path
import re
import stat
import sys
from collections import namedtuple
from hashlib import sha256
from hmac import compare_digest


class SavedPasswordError(Exception):
    """Saved password could not be safely verified and synchronized."""


_Token = namedtuple("_Token", "value start end kind")
_Node = namedtuple("_Node", "name argument children disabled")
_MAX_SIZE = 8 * 1024 * 1024
_NAME = re.compile(rb"[A-Za-z_][A-Za-z0-9_-]*\Z")
_HASH = re.compile(r"\$(?:1|2[abxy]|5|6|7|y|gy)\$[A-Za-z0-9./,=+-]+(?:\$[A-Za-z0-9./,=+-]+)+\Z")


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


def _read_file(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    parts = []
    size = 0
    while True:
        block = os.read(fd, 65536)
        if not block:
            return b"".join(parts)
        size += len(block)
        if size > _MAX_SIZE:
            raise SavedPasswordError("Startup configuration is too large")
        parts.append(block)


def verify_saved_password(user, expected, filename="/config/config.boot"):
    """Return True after matching and syncing a stable, safely opened saved file.

    The path is a trusted caller constant, never RPC input. Tests use private
    paths owned by their effective user; production executes as root. Restricted
    file permissions and existing owner/group are verified and never changed.
    The caller must already have completed Commit and checked its outcome and
    current RUNNING password. Failure can follow a runtime change: no rollback
    or compensating Save is performed here.
    """
    if not isinstance(expected, str) or len(expected) > 4096 or not _HASH.fullmatch(expected):
        raise SavedPasswordError("Expected encrypted password is invalid")
    filename = Path(filename)
    descriptors = []
    try:
        parent = os.open(filename.parent, os.O_RDONLY | os.O_DIRECTORY |
                         os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(parent)
        parent_info = os.fstat(parent)
        fd = os.open(filename.name, os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        descriptors.append(fd)
        original = os.fstat(fd)
        if (not stat.S_ISREG(original.st_mode) or original.st_nlink != 1 or
                original.st_uid != os.geteuid() or
                stat.S_IMODE(original.st_mode) not in (0o400, 0o440, 0o600, 0o640)):
            raise SavedPasswordError("Unsafe saved configuration metadata")
        data = _read_file(fd)
        if _identity(os.fstat(fd)) != _identity(original):
            raise SavedPasswordError("Saved configuration changed while reading")
        start, end = _password_span(data, user)
        token = data[start:end]
        if token.startswith(b'"') and token.endswith(b'"'):
            token = token[1:-1]
        if not compare_digest(token, expected.encode("ascii")):
            raise SavedPasswordError("Saved password does not match the committed password")
        fingerprint = sha256(data).digest()
        os.fsync(fd)
        os.fsync(parent)
        after = _read_file(fd)
        if (not compare_digest(sha256(after).digest(), fingerprint) or
                _identity(os.fstat(fd)) != _identity(original)):
            raise SavedPasswordError("Saved configuration changed during verification")
        path_info = os.stat(filename.name, dir_fd=parent, follow_symlinks=False)
        current_parent = os.stat(filename.parent, follow_symlinks=False)
        if (_identity(path_info) != _identity(original) or
                not stat.S_ISDIR(current_parent.st_mode) or
                (current_parent.st_dev, current_parent.st_ino) !=
                (parent_info.st_dev, parent_info.st_ino)):
            raise SavedPasswordError("Saved configuration path changed during verification")
        return True
    except OSError as error:
        raise SavedPasswordError("Could not verify saved password durability") from error
    finally:
        primary = sys.exc_info()[1]
        cleanup_failed = False
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            message = "Saved password verification cleanup failed"
            if primary is not None:
                primary.add_note(message)
            else:
                raise SavedPasswordError(message)
