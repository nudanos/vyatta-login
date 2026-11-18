"""RPC regression with configd's actual commit-and-save behavior.

Configd may apply RUNNING yet skip Save and return a nonfatal warning. The
renewal RPC must never treat that response, or an unverified save, as success.
"""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from crypt_r import crypt

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
OLD_PASSWORD = "old autosave fixture"
NEW_PASSWORD = 'new fixture \\ "雪"'
OLD_HASH = crypt(OLD_PASSWORD, "$6$oldfixture$")
NEW_HASH = crypt(NEW_PASSWORD, "$6$newfixture$")


def saved(hash_value):
    return ('system { login { user tester { authentication { encrypted-password "' +
            hash_value + '"; } } } host-name committed; }\n').encode()


class Client:
    RUNNING = "running"
    CANDIDATE = "candidate"

    def __init__(self, directory):
        self.directory = directory
        self.startup = directory / "config.boot"
        self.startup.write_bytes(saved(OLD_HASH))
        self.startup.chmod(0o600)
        self.running = OLD_HASH
        self.events = []
        self.warning = False
        self.fail_commit = False
        self.fail_setup = False
        self.fail_teardown = False
        self.mask_candidate = False
        self.after_save = None

    def session_setup(self, sid):
        self.events.append("setup")
        if self.fail_setup:
            raise RuntimeError("lost setup response")

    def session_exists(self):
        return True

    def set(self, path):
        assert path[:6] == ["system", "login", "user", "tester", "authentication", "plaintext-password"]
        assert path[-1] == NEW_PASSWORD
        self.candidate = NEW_HASH
        self.events.append("set")

    def tree_get_dict(self, path, source):
        assert path == "system login user tester authentication encrypted-password"
        self.events.append("read-" + source)
        value = self.running if source == self.RUNNING else self.candidate
        if source == self.CANDIDATE and self.mask_candidate:
            value = "********"
        return {"encrypted-password": value}

    def commit(self, message):
        import fcntl
        self.events.append("commit")
        if self.fail_commit:
            self.running = self.candidate
            raise RuntimeError("save failed after applying password; sensitive backend detail")
        self.running = self.candidate
        if self.warning:
            return "\nCommit succeeded (non-fatal failures detected).\n"
        # The actual daemon's successful Commit invokes Save under its writer
        # lock. This catches an outer RPC lock even if simple fake peers pass.
        lock_dir = self.directory / "lock"
        lock_dir.mkdir(mode=0o700, exist_ok=True)
        with open(lock_dir / "startup.lock", "a+b") as lock:
            os.chmod(lock.name, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.startup.write_bytes(saved(self.running))
        self.events.append("automatic-save")
        if self.after_save:
            self.after_save()
        return ""

    def session_teardown(self):
        self.events.append("teardown")
        if self.fail_teardown:
            raise RuntimeError("sensitive cleanup detail")


class AutoSaveRPCTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.client = Client(self.directory)
        fake_configd = types.ModuleType("vyatta.configd")
        fake_configd.Client = Client
        fake_vyatta = types.ModuleType("vyatta")
        fake_vyatta.configd = fake_configd
        loader = importlib.machinery.SourceFileLoader("password_rpc", str(SCRIPTS / "vyatta-password-rpc"))
        self.rpc = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
        with patch.dict(sys.modules, {"vyatta": fake_vyatta, "vyatta.configd": fake_configd}):
            loader.exec_module(self.rpc)
        def verify(user, expected):
            from vyatta_password_persistence import verify_saved_password
            self.client.events.append("verify-saved")
            return verify_saved_password(user, expected, self.client.startup)

        self.rpc.verify_saved_password = verify

    def change(self, current=OLD_PASSWORD):
        return self.rpc.ChangePassword(self.client, "tester", NEW_PASSWORD, current).change_password()

    def test_automatic_save_does_not_nest_an_rpc_writer_lock(self):
        self.change()
        self.assertEqual(self.client.startup.read_bytes(), saved(NEW_HASH))
        self.assertIn("automatic-save", self.client.events)
        self.assertIn("verify-saved", self.client.events)
        self.assertEqual(self.client.events[-1], "teardown")

    def test_nonfatal_commit_warning_is_partial_failure_and_is_not_saved_again(self):
        self.client.warning = True
        with self.assertRaisesRegex(Exception, "running.*not.*saved"):
            self.change()
        self.assertEqual(self.client.running, NEW_HASH)
        self.assertEqual(self.client.startup.read_bytes(), saved(OLD_HASH))
        self.assertNotIn("automatic-save", self.client.events)
        self.assertEqual(self.client.events.count("commit"), 1)

    def test_save_failure_after_runtime_change_has_safe_partial_diagnostic(self):
        self.client.fail_commit = True
        with self.assertRaisesRegex(Exception, "running.*saved") as caught:
            self.change()
        self.assertNotIn("sensitive", str(caught.exception))
        self.assertEqual(self.client.running, NEW_HASH)
        self.assertEqual(self.client.startup.read_bytes(), saved(OLD_HASH))

    def test_saved_mismatch_is_not_success(self):
        self.client.after_save = lambda: self.client.startup.write_bytes(saved(OLD_HASH))
        with self.assertRaisesRegex(Exception, "running.*not.*saved"):
            self.change()
        self.assertEqual(self.client.events[-1], "teardown")

    def test_intervening_runtime_change_is_not_rolled_back(self):
        self.client.after_save = lambda: setattr(self.client, "running", OLD_HASH)
        with self.assertRaisesRegex(Exception, "running.*not.*saved"):
            self.change()
        self.assertEqual(self.client.running, OLD_HASH)
        self.assertEqual(self.client.events.count("commit"), 1)

    def test_current_password_is_reverified_before_candidate(self):
        with self.assertRaisesRegex(Exception, "Authentication failure"):
            self.change("wrong fixture")
        self.assertNotIn("setup", self.client.events)

    def test_masked_candidate_is_rejected_before_commit(self):
        self.client.mask_candidate = True
        with self.assertRaises(Exception):
            self.change()
        self.assertNotIn("commit", self.client.events)

    def test_interrupted_setup_is_torn_down(self):
        self.client.fail_setup = True
        with self.assertRaisesRegex(Exception, "establish"):
            self.change()
        self.assertEqual(self.client.events[-1], "teardown")

    def test_unique_private_sessions(self):
        first = self.rpc.ChangePassword(self.client, "tester", NEW_PASSWORD)
        second = self.rpc.ChangePassword(self.client, "tester", NEW_PASSWORD)
        self.assertNotEqual(first.sessid, second.sessid)

    def test_cleanup_failure_does_not_expose_backend_message(self):
        self.client.fail_teardown = True
        with self.assertRaises(Exception) as caught:
            self.change()
        self.assertNotIn("sensitive", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
