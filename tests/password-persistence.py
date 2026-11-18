"""Real startup-file tests; root-only cases use private temporary directories."""
import importlib.util
import multiprocessing
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock


sys.dont_write_bytecode = True
HELPER = Path(__file__).resolve().parents[1] / "scripts/vyatta_password_persistence.py"
OLD = b"$6$old$abcdefgh"
NEW = "$6$new$ijklmnop"
CONFIG = b'''/* saved configuration; keep every unrelated byte */
interfaces {
 ethernet dp0s1 {
  address 2001:db8::1/64
  description "quote \\" and slash \\\\ and { braces }"
 }
}
! protocols {
 static { route 192.0.2.0/24 { blackhole; } }
}
system {
 login {
  user "tester" {
   authentication {
    encrypted-password "$6$old$abcdefgh"
   }
   level admin
  }
  user other {
   authentication { encrypted-password "$6$other$unchanged"; }
  }
 }
}
// footer follows
/* === configuration version information === */
'''


def load_helper(case):
    case.assertTrue(HELPER.is_file(), "saved-password persistence helper is missing")
    spec = importlib.util.spec_from_file_location("password_persistence", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def hold_lock(path, ready, release):
    import fcntl
    with open(path, "r+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        ready.set()
        release.wait(5)


def change_other_user(filename, lockdir, started, entered):
    spec = importlib.util.spec_from_file_location("password_persistence", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    started.set()
    with module.SavedPasswordUpdate("other", filename=filename, lock_dir=lockdir) as update:
        entered.set()
        update.prepare("$6$other$replacement")
        update.publish()


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.helper = load_helper(self)

    def test_finds_only_the_saved_target_token(self):
        start, end = self.helper._password_span(CONFIG, "tester")
        self.assertEqual(CONFIG[start:end], b'"$6$old$abcdefgh"')

    def test_rejects_missing_duplicate_disabled_plaintext_or_malformed_target(self):
        invalid = [
            CONFIG.replace(b'user "tester"', b'user absent'),
            CONFIG.replace(b'user "tester"', b'! user "tester"'),
            CONFIG.replace(b' login {', b' ! login {'),
            CONFIG.replace(b'system {', b'! system {'),
            CONFIG.replace(b'   authentication {', b'   ! authentication {', 1),
            CONFIG.replace(b'    encrypted-password', b'    ! encrypted-password'),
            CONFIG.replace(b'    encrypted-password', b'    plaintext-password secret\n    encrypted-password'),
            CONFIG.replace(b'    encrypted-password', b'    encrypted-password "$6$duplicate$value"\n    encrypted-password'),
            CONFIG + b'system { login { user tester { authentication { encrypted-password x; } } } }\n',
            CONFIG.replace(b'  user other', b'  user tester'),
            CONFIG.replace(b' login {', b' login {}\n login {'),
            CONFIG.replace(b'   authentication {', b'   authentication {}\n   authentication {', 1),
            CONFIG + b'/* unterminated',
            CONFIG + b'broken "unterminated',
            CONFIG + b'broken {\n',
            CONFIG + b'}\n',
            CONFIG + b'node first second\n',
            CONFIG.replace(b'encrypted-password "', b'encrypted-password: "', 1),
            CONFIG + b'\0',
        ]
        for data in invalid:
            with self.subTest(data=data[-80:]):
                with self.assertRaises(self.helper.SavedPasswordError):
                    self.helper._password_span(data, "tester")

    def test_unquoted_hash_and_semicolon_are_supported(self):
        data = b'system { login { user tester { authentication { encrypted-password $6$old$value; } } } }\n'
        start, end = self.helper._password_span(data, "tester")
        self.assertEqual(data[start:end], b'$6$old$value')

    def test_quoted_structural_characters_are_values_not_delimiters(self):
        for value in (b'"{"', b'"}"', b'";"', b'"!"', b'""'):
            data = b'description ' + value + b'\n' + CONFIG
            with self.subTest(value=value):
                start, end = self.helper._password_span(data, "tester")
                self.assertEqual(data[start:end], b'"$6$old$abcdefgh"')


@unittest.skipUnless(os.name == "posix", "requires Linux filesystem and flock semantics")
class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.helper = load_helper(self)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.config = self.base / "config.boot"
        self.config.write_bytes(CONFIG)
        self.config.chmod(0o600)
        self.lockdir = self.base / "lock"

    def update(self, **kwargs):
        return self.helper.SavedPasswordUpdate("tester", filename=self.config,
                                               lock_dir=self.lockdir, **kwargs)

    def assert_no_staging(self):
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), ["config.boot", "lock"])

    def test_prepare_does_not_publish_then_atomic_replace_preserves_other_bytes(self):
        before = self.config.stat()
        with self.update() as update:
            update.prepare(NEW)
            self.assertEqual(self.config.read_bytes(), CONFIG)
            stage = next(self.base.glob(".password-*"))
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o600)
            if Path("/proc/self/fd").exists():
                self.assertNotIn(str(stage), [os.path.realpath(p) for p in Path("/proc/self/fd").iterdir()])
            update.publish()
        self.assertEqual(self.config.read_bytes(), CONFIG.replace(OLD, NEW.encode(), 1))
        after = self.config.stat()
        self.assertNotEqual(before.st_ino, after.st_ino)
        self.assertEqual((after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
                         (before.st_uid, before.st_gid, 0o600))
        self.assert_no_staging()

    def test_context_failure_discards_staging_and_releases_lock(self):
        with self.assertRaisesRegex(RuntimeError, "runtime commit failed"):
            with self.update() as update:
                update.prepare(NEW)
                raise RuntimeError("runtime commit failed")
        self.assertEqual(self.config.read_bytes(), CONFIG)
        self.assert_no_staging()
        with self.update(timeout=0):
            pass

    def test_cleanup_unlink_failure_preserves_primary_error_and_releases_lock(self):
        with self.assertRaisesRegex(RuntimeError, "partial password change"):
            with self.update() as update:
                update.prepare(NEW)
                with mock.patch.object(self.helper.os, "unlink", side_effect=OSError("unlink failed")):
                    # Call the actual exit under the injected filesystem error.
                    original = RuntimeError("partial password change")
                    update.__exit__(RuntimeError, original, None)
                    raise original
        with self.update(timeout=0):
            pass

    def test_cleanup_attempts_all_closes_after_one_close_reports_failure(self):
        update = self.update()
        update.__enter__()
        descriptors = [update._directory, update._lock, update._lock_directory]
        real_close = os.close
        attempted = []

        def close(fd):
            attempted.append(fd)
            real_close(fd)
            if len(attempted) == 1:
                raise OSError("close failed after release")

        with mock.patch.object(self.helper.os, "close", side_effect=close):
            with self.assertRaisesRegex(self.helper.SavedPasswordError, "cleanup failed"):
                update.__exit__(None, None, None)
        self.assertEqual(attempted, descriptors)
        self.assertTrue(all(getattr(update, name) is None for name in
                            ("_directory", "_lock", "_lock_directory")))
        with self.update(timeout=0):
            pass

    def test_successful_context_cleanup_error_is_reported_safely(self):
        update = self.update()
        update.__enter__()
        update.prepare(NEW)
        with mock.patch.object(self.helper.os, "unlink", side_effect=OSError("sensitive filesystem detail")):
            with self.assertRaisesRegex(self.helper.SavedPasswordError, "cleanup failed") as caught:
                update.__exit__(None, None, None)
        self.assertNotIn("sensitive filesystem detail", str(caught.exception))
        with self.update(timeout=0):
            pass

    def test_invalid_candidate_hash_never_changes_file(self):
        for value in ["plaintext", "$6$salt$x\nextra", "$6$salt$\"", "", None, "$6$" + "x" * 5000]:
            with self.subTest(value=str(value)[:15]):
                with self.update() as update:
                    with self.assertRaises(self.helper.SavedPasswordError):
                        update.prepare(value)
                self.assertEqual(self.config.read_bytes(), CONFIG)
                self.assert_no_staging()

    def test_refuses_symlink_multilink_nonregular_or_writable_startup(self):
        original = self.base / "original"
        self.config.rename(original)
        self.config.symlink_to(original)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass
        self.config.unlink()
        os.link(original, self.config)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass
        self.config.unlink()
        os.mkfifo(self.config)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass
        self.config.unlink()
        original.rename(self.config)
        self.config.chmod(0o620)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass

    def test_rejects_symlink_or_unsafe_lock_directory(self):
        actual = self.base / "actual"
        actual.mkdir(mode=0o700)
        self.lockdir.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass
        self.lockdir.unlink()
        self.lockdir.mkdir(mode=0o777)
        self.lockdir.chmod(0o777)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass

    def test_rejects_symlink_multilink_and_wrong_mode_lock_file(self):
        self.lockdir.mkdir(mode=0o700)
        path = self.lockdir / "startup.lock"
        path.symlink_to(self.config)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass
        path.unlink()
        os.link(self.config, path)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass
        path.unlink()
        path.touch(mode=0o644)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass

    def test_lock_contention_is_bounded_and_lock_inode_is_stable(self):
        with self.update():
            pass
        path = self.lockdir / "startup.lock"
        inode = path.stat().st_ino
        ready, release = multiprocessing.Event(), multiprocessing.Event()
        process = multiprocessing.Process(target=hold_lock, args=(path, ready, release))
        process.start()
        try:
            self.assertTrue(ready.wait(3))
            started = time.monotonic()
            with self.assertRaises(self.helper.SavedPasswordError):
                with self.update(timeout=0.12):
                    pass
            self.assertLess(time.monotonic() - started, 1)
        finally:
            release.set()
            process.join(3)
        self.assertEqual(process.exitcode, 0)
        with self.update():
            self.assertEqual(path.stat().st_ino, inode)

    def test_publication_refuses_changed_content_or_replaced_inode(self):
        for replacement in [False, True]:
            self.config.write_bytes(CONFIG)
            with self.subTest(replacement=replacement):
                with self.update() as update:
                    update.prepare(NEW)
                    # The replacement case has identical bytes: only inode
                    # validation can detect that uncooperative writer.
                    changed = CONFIG if replacement else CONFIG + b'// concurrent administrator\n'
                    if replacement:
                        self.config.unlink()
                    self.config.write_bytes(changed)
                    self.config.chmod(0o600)
                    with self.assertRaises(self.helper.SavedPasswordError):
                        update.publish()
                self.assertEqual(self.config.read_bytes(), changed)
                self.assert_no_staging()

    def test_stage_replaced_with_symlink_is_never_published(self):
        with self.update() as update:
            update.prepare(NEW)
            stage = next(self.base.glob(".password-*"))
            stage.unlink()
            stage.symlink_to(self.config)
            with self.assertRaises(self.helper.SavedPasswordError):
                update.publish()
        self.assertEqual(self.config.read_bytes(), CONFIG)
        self.assertFalse(self.config.is_symlink())
        self.assert_no_staging()

    def test_failed_stage_sync_leaves_saved_state_unchanged(self):
        with self.update() as update:
            with mock.patch.object(self.helper.os, "fsync", side_effect=OSError("disk failure")):
                with self.assertRaises(self.helper.SavedPasswordError):
                    update.prepare(NEW)
        self.assertEqual(self.config.read_bytes(), CONFIG)
        self.assert_no_staging()

    def test_short_write_is_an_error_and_discards_staging(self):
        with self.update() as update:
            with mock.patch.object(self.helper.os, "write", return_value=0):
                with self.assertRaises(self.helper.SavedPasswordError):
                    update.prepare(NEW)
        self.assertEqual(self.config.read_bytes(), CONFIG)
        self.assert_no_staging()

    def test_temporary_name_collision_does_not_delete_existing_file(self):
        collision = self.base / ".password-collision"
        collision.write_bytes(b"existing unrelated file")
        with self.update() as update:
            with mock.patch.object(self.helper.secrets, "token_hex", return_value="collision"):
                with self.assertRaises(self.helper.SavedPasswordError):
                    update.prepare(NEW)
        self.assertEqual(collision.read_bytes(), b"existing unrelated file")
        self.assertEqual(self.config.read_bytes(), CONFIG)

    def test_changed_parent_directory_is_not_reported_as_published(self):
        parent = self.base / "config"
        parent.mkdir(mode=0o700)
        self.config.rename(parent / "config.boot")
        self.config = parent / "config.boot"
        with self.update() as update:
            update.prepare(NEW)
            parent.rename(self.base / "moved")
            parent.mkdir(mode=0o700)
            self.config.write_bytes(CONFIG)
            self.config.chmod(0o600)
            with self.assertRaises(self.helper.SavedPasswordError):
                update.publish()
        self.assertEqual(self.config.read_bytes(), CONFIG)
        self.assertEqual((self.base / "moved/config.boot").read_bytes(), CONFIG)

    def test_different_users_serialize_without_losing_either_password(self):
        # Independent RPC processes must not inherit the parent's held flock fd.
        context = multiprocessing.get_context("spawn")
        started, entered = context.Event(), context.Event()
        process = context.Process(target=change_other_user,
                                  args=(self.config, self.lockdir, started, entered))
        with self.update() as update:
            update.prepare(NEW)
            process.start()
            self.assertTrue(started.wait(3))
            self.assertFalse(entered.wait(0.1))
            update.publish()
        process.join(3)
        self.assertEqual(process.exitcode, 0)
        self.assertTrue(entered.is_set())
        expected = CONFIG.replace(OLD, NEW.encode(), 1).replace(b"$6$other$unchanged", b"$6$other$replacement")
        self.assertEqual(self.config.read_bytes(), expected)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0,
                         "root-only ownership check in a private temporary directory")
    def test_refuses_foreign_owned_startup_and_lock_entries(self):
        os.chown(self.config, 65534, 65534)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass
        os.chown(self.config, 0, 0)
        path = self.lockdir / "startup.lock"
        os.chown(path, 65534, 65534)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass
        os.chown(path, 0, 0)
        os.chown(self.lockdir, 65534, 65534)
        with self.assertRaises(self.helper.SavedPasswordError):
            with self.update():
                pass

    def test_failed_rename_leaves_saved_state_unchanged(self):
        with self.update() as update:
            update.prepare(NEW)
            with mock.patch.object(self.helper.os, "replace", side_effect=OSError("disk failure")):
                with self.assertRaises(self.helper.SavedPasswordError):
                    update.publish()
        self.assertEqual(self.config.read_bytes(), CONFIG)
        self.assert_no_staging()

    def test_failed_directory_sync_reports_failure_without_blind_rollback(self):
        with self.update() as update:
            update.prepare(NEW)
            with mock.patch.object(self.helper.os, "fsync", side_effect=OSError("directory failure")):
                with self.assertRaises(self.helper.SavedPasswordError):
                    update.publish()
        self.assertEqual(self.config.read_bytes(), CONFIG.replace(OLD, NEW.encode(), 1))
        self.assert_no_staging()


if __name__ == "__main__":
    unittest.main()
