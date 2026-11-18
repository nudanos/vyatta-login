"""Linux real-file tests for the read-only post-commit verifier."""
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
MODULE = Path(__file__).resolve().parents[1] / "scripts" / "vyatta_password_persistence.py"
HASH = "$6$fixture$abcdefgh"
CONFIG = (b'/* preserved */\nsystem { login { user tester { authentication {\n'
          b' encrypted-password "$6$fixture$abcdefgh"\n'
          b'} level admin; } user other { authentication { encrypted-password other; } } } }\n'
          b'! protocols { static { route 2001:db8::/64 { blackhole; } } }\n'
          b'description "quote \\" and brace }"\n')


@unittest.skipUnless(os.name == "posix", "requires Linux fd and fsync semantics")
class SavedPasswordVerificationTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(MODULE.is_file(), "read-only saved-password verifier is missing")
        spec = importlib.util.spec_from_file_location("saved_password_verifier", MODULE)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.filename = self.directory / "config.boot"
        self.filename.write_bytes(CONFIG)
        self.filename.chmod(0o640)

    def verify(self, expected=HASH, user="tester"):
        return self.module.verify_saved_password(user, expected, self.filename)

    def test_success_syncs_file_and_directory_without_writes_or_metadata_changes(self):
        before = self.filename.stat()
        synced = []
        fsync = os.fsync

        def sync(fd):
            synced.append(stat.S_IFMT(os.fstat(fd).st_mode))
            fsync(fd)

        with patch.object(self.module.os, "fsync", side_effect=sync):
            self.assertTrue(self.verify())
        after = self.filename.stat()
        self.assertEqual(synced, [stat.S_IFREG, stat.S_IFDIR])
        self.assertEqual(self.filename.read_bytes(), CONFIG)
        self.assertEqual((before.st_ino, before.st_uid, before.st_gid, before.st_mode,
                          before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_ino, after.st_uid, after.st_gid, after.st_mode,
                          after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        self.assertEqual(list(self.directory.iterdir()), [self.filename])

    def test_mismatched_redacted_plaintext_or_invalid_expected_never_succeeds(self):
        for expected in ("$6$different$hash", "********", "plaintext", "", None,
                         "$6$abc$def\n", "$6$" + "x" * 5000):
            with self.subTest(expected=str(expected)[:12]):
                with self.assertRaises(self.module.SavedPasswordError) as error:
                    self.verify(expected)
                self.assertNotIn(HASH, str(error.exception))
                if isinstance(expected, str) and len(expected) > 8:
                    self.assertNotIn(expected, str(error.exception))
        self.assertEqual(self.filename.read_bytes(), CONFIG)

    def test_missing_disabled_duplicate_plaintext_and_malformed_paths_fail(self):
        variants = [
            CONFIG.replace(b'user tester', b'user absent'),
            CONFIG.replace(b'user tester', b'! user tester'),
            CONFIG.replace(b'login {', b'! login {'),
            CONFIG.replace(b'authentication {', b'authentication {} authentication {', 1),
            CONFIG.replace(b'encrypted-password "', b'plaintext-password "', 1),
            CONFIG + b'system {}\n',
            CONFIG + b'/* unclosed',
            CONFIG + b'unclosed {\n',
            CONFIG + b'\0',
        ]
        for content in variants:
            with self.subTest(content=content[-25:]):
                self.filename.write_bytes(content)
                with self.assertRaises(self.module.SavedPasswordError):
                    self.verify()
                self.assertEqual(self.filename.read_bytes(), content)

    def test_unquoted_hash_and_quoted_structural_values_are_supported(self):
        data = CONFIG.replace(b'"$6$fixture$abcdefgh"', HASH.encode())
        data += b'description "{"\ncomment ";"\n'
        self.filename.write_bytes(data)
        self.assertTrue(self.verify())
        self.assertEqual(self.filename.read_bytes(), data)

    def test_matching_incomplete_crypt_setting_is_not_a_usable_saved_hash(self):
        for incomplete in ("$6$onlysalt", "$6$salt$", "$y$onlyparameters", "$2b$12$"):
            self.filename.write_bytes(CONFIG.replace(HASH.encode(), incomplete.encode()))
            with self.subTest(incomplete=incomplete):
                with self.assertRaises(self.module.SavedPasswordError):
                    self.verify(incomplete)

    def test_cleanup_failure_preserves_primary_and_closes_remaining_descriptors(self):
        real_close = os.close
        closed = []

        def close(fd):
            closed.append(fd)
            real_close(fd)
            if len(closed) == 1:
                raise OSError("sensitive close diagnostic " + HASH)

        with patch.object(self.module.os, "close", side_effect=close):
            with self.assertRaisesRegex(self.module.SavedPasswordError, "does not match") as error:
                self.verify("$6$other$different")
        self.assertEqual(len(closed), 2)
        self.assertNotIn(HASH, str(error.exception))
        self.assertTrue(self.verify())

    def test_cleanup_failure_does_not_report_success(self):
        real_close = os.close

        def close(fd):
            real_close(fd)
            raise OSError("private backend diagnostic " + HASH)

        with patch.object(self.module.os, "close", side_effect=close):
            with self.assertRaisesRegex(self.module.SavedPasswordError, "cleanup failed") as error:
                self.verify()
        self.assertNotIn(HASH, str(error.exception))

    def test_missing_file_symlink_hardlink_and_fifo_are_rejected(self):
        self.filename.unlink()
        with self.assertRaises(self.module.SavedPasswordError):
            self.verify()
        actual = self.directory / "actual"
        actual.write_bytes(CONFIG)
        actual.chmod(0o600)
        self.filename.symlink_to(actual)
        with self.assertRaises(self.module.SavedPasswordError):
            self.verify()
        self.filename.unlink()
        os.link(actual, self.filename)
        with self.assertRaises(self.module.SavedPasswordError):
            self.verify()
        self.filename.unlink()
        os.mkfifo(self.filename)
        with self.assertRaises(self.module.SavedPasswordError):
            self.verify()

    def test_unsafe_permissions_and_parent_symlink_are_rejected(self):
        for mode in (0o620, 0o606, 0o644, 0o1600):
            self.filename.chmod(mode)
            with self.assertRaises(self.module.SavedPasswordError):
                self.verify()
        self.filename.chmod(0o600)
        alias = self.directory / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        self.filename = alias / "config.boot"
        with self.assertRaises(self.module.SavedPasswordError):
            self.verify()

    def test_file_and_directory_sync_failures_are_static_errors(self):
        fsync = os.fsync
        for failure_kind in (stat.S_IFREG, stat.S_IFDIR):
            def sync(fd):
                if stat.S_IFMT(os.fstat(fd).st_mode) == failure_kind:
                    raise OSError("sensitive backend diagnostic " + HASH)
                fsync(fd)
            with self.subTest(kind=failure_kind):
                with patch.object(self.module.os, "fsync", side_effect=sync):
                    with self.assertRaises(self.module.SavedPasswordError) as error:
                        self.verify()
                self.assertNotIn(HASH, str(error.exception))
                self.assertEqual(self.filename.read_bytes(), CONFIG)

    def test_in_place_change_during_sync_is_rejected_even_for_other_saved_setting(self):
        fsync = os.fsync
        changed = CONFIG.replace(b'level admin', b'level superuser')

        def sync(fd):
            fsync(fd)
            if stat.S_ISREG(os.fstat(fd).st_mode):
                self.filename.write_bytes(changed)

        with patch.object(self.module.os, "fsync", side_effect=sync):
            with self.assertRaises(self.module.SavedPasswordError):
                self.verify()
        self.assertEqual(self.filename.read_bytes(), changed)

    def test_same_content_inode_replacement_during_sync_is_rejected(self):
        fsync = os.fsync

        def sync(fd):
            fsync(fd)
            if stat.S_ISREG(os.fstat(fd).st_mode):
                self.filename.unlink()
                self.filename.write_bytes(CONFIG)
                self.filename.chmod(0o640)

        with patch.object(self.module.os, "fsync", side_effect=sync):
            with self.assertRaises(self.module.SavedPasswordError):
                self.verify()
        self.assertEqual(self.filename.read_bytes(), CONFIG)

    def test_same_content_parent_replacement_during_sync_is_rejected(self):
        parent = self.directory / "parent"
        parent.mkdir(mode=0o700)
        self.filename.rename(parent / "config.boot")
        self.filename = parent / "config.boot"
        fsync = os.fsync

        def sync(fd):
            fsync(fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                parent.rename(self.directory / "old-parent")
                parent.mkdir(mode=0o700)
                self.filename.write_bytes(CONFIG)
                self.filename.chmod(0o640)

        with patch.object(self.module.os, "fsync", side_effect=sync):
            with self.assertRaises(self.module.SavedPasswordError):
                self.verify()

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0,
                         "root-only metadata check confined to private temporary files")
    def test_preserves_nonroot_group_but_rejects_foreign_file_owner(self):
        os.chown(self.filename, 0, 65534)
        self.assertTrue(self.verify())
        info = self.filename.stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 65534, 0o640))
        os.chown(self.filename, 65534, 65534)
        with self.assertRaises(self.module.SavedPasswordError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
