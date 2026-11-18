"""Exercise the real password RPC against real saved files and a configd peer.

The peer models configd's set-time password substitution; no system accounts,
production paths or real credentials are used by these tests.
"""
import importlib.machinery
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from crypt_r import crypt

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from vyatta_password_persistence import SavedPasswordError, SavedPasswordUpdate

OLD_PASSWORD = "old fixture password"
NEW_PASSWORD = 'new fixture \\ "雪"'
OLD_HASH = crypt(OLD_PASSWORD, "$6$oldfixture$")
NEW_HASH = crypt(NEW_PASSWORD, "$6$newfixture$")
SAVED = (b'/* preserve this file exactly */\nsystem {\n login {\n'
         b'  user tester {\n   authentication {\n'
         b'    encrypted-password "' + OLD_HASH.encode() + b'"\n'
         b'   }\n   level admin\n  }\n }\n host-name saved\n}\n'
         b'! protocols { static { route 2001:db8::/64 { blackhole; } } }\n')


class Client:
    RUNNING = "running"
    CANDIDATE = "candidate"

    def __init__(self, startup):
        self.startup = startup
        self.running = OLD_HASH
        self.candidate = None
        self.events = []
        self.fail_commit = False
        self.mask_candidate = False
        self.after_commit = None

    def session_setup(self, sid):
        self.events.append("setup")

    def session_exists(self):
        return True

    def set(self, path):
        assert path[:6] == ["system", "login", "user", "tester",
                           "authentication", "plaintext-password"]
        assert path[6] == NEW_PASSWORD
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
        self.events.append("commit")
        staged = list(self.startup.parent.glob(".password-*"))
        self.staged_before_commit = (len(staged) == 1 and NEW_HASH.encode() in staged[0].read_bytes())
        assert self.startup.read_bytes() == SAVED
        if self.fail_commit:
            raise RuntimeError("backend error containing sensitive input")
        self.running = self.candidate
        if self.after_commit:
            self.after_commit()

    def session_teardown(self):
        self.events.append("teardown")
        self.candidate = None


def load_rpc():
    fake_configd = types.ModuleType("vyatta.configd")
    fake_configd.Client = Client
    fake_vyatta = types.ModuleType("vyatta")
    fake_vyatta.configd = fake_configd
    loader = importlib.machinery.SourceFileLoader("password_rpc", str(SCRIPTS / "vyatta-password-rpc"))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    with patch.dict(sys.modules, {"vyatta": fake_vyatta, "vyatta.configd": fake_configd}):
        loader.exec_module(module)
    return module


class PasswordPersistenceRPCTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.startup = self.directory / "config.boot"
        self.startup.write_bytes(SAVED)
        self.startup.chmod(0o600)
        self.rpc = load_rpc()
        self.client = Client(self.startup)

        def saved_update(user):
            return SavedPasswordUpdate(user, self.startup, self.directory / "lock")

        self.rpc.SavedPasswordUpdate = saved_update

    def change(self, current=OLD_PASSWORD):
        change = self.rpc.ChangePassword(self.client, "tester", NEW_PASSWORD)
        change.current_password = current
        return change.change_password()

    def assert_no_staging(self):
        self.assertEqual(list(self.directory.glob(".password-*")), [])

    def test_target_only_update_is_staged_before_commit_and_published_after(self):
        self.change()
        self.assertEqual(self.startup.read_bytes(), SAVED.replace(OLD_HASH.encode(), NEW_HASH.encode()))
        self.assertTrue(self.client.staged_before_commit)
        self.assertEqual(self.startup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.client.running, NEW_HASH)
        self.assertLess(self.client.events.index("read-running"), self.client.events.index("setup"))
        self.assertEqual(self.client.events[-1], "teardown")
        self.assert_no_staging()

    def test_unsaved_account_is_rejected_before_session_or_commit(self):
        self.startup.write_bytes(b"system { host-name saved; }\n")
        with self.assertRaisesRegex(Exception, "save account configuration first"):
            self.change()
        self.assertEqual(self.client.events, [])
        self.assertEqual(self.client.running, OLD_HASH)

    def test_current_password_is_reverified_under_lock_before_candidate(self):
        with self.assertRaisesRegex(Exception, "Authentication failure"):
            self.change("wrong fixture")
        self.assertNotIn("setup", self.client.events)
        self.assertEqual(self.startup.read_bytes(), SAVED)

    def test_renewals_in_same_process_have_distinct_private_sessions(self):
        first = self.rpc.ChangePassword(self.client, "tester", NEW_PASSWORD)
        second = self.rpc.ChangePassword(self.client, "tester", NEW_PASSWORD)
        self.assertNotEqual(first.sessid, second.sessid)
        self.assertFalse(first.sessid.isdecimal())

    def test_interrupted_setup_attempt_is_torn_down_without_commit(self):
        def interrupted_setup(sid):
            self.client.events.append("setup")
            raise RuntimeError("response lost after server created session")

        self.client.session_setup = interrupted_setup
        with self.assertRaisesRegex(Exception, "establish a password change session"):
            self.change()
        self.assertEqual(self.client.events[-1], "teardown")
        self.assertNotIn("commit", self.client.events)
        self.assertEqual(self.startup.read_bytes(), SAVED)

    def test_masked_candidate_is_rejected_before_commit(self):
        self.client.mask_candidate = True
        with self.assertRaises(Exception):
            self.change()
        self.assertNotIn("commit", self.client.events)
        self.assertEqual(self.client.events[-1], "teardown")
        self.assertEqual(self.startup.read_bytes(), SAVED)
        self.assert_no_staging()

    def test_commit_failure_keeps_saved_password_and_discards_stage(self):
        self.client.fail_commit = True
        with self.assertRaises(Exception) as caught:
            self.change()
        self.assertNotIn("sensitive input", str(caught.exception))
        self.assertEqual(self.startup.read_bytes(), SAVED)
        self.assertEqual(self.client.running, OLD_HASH)
        self.assertEqual(self.client.events[-1], "teardown")
        self.assert_no_staging()

    def test_staging_failure_does_not_commit(self):
        with patch.object(SavedPasswordUpdate, "prepare", side_effect=SavedPasswordError("stage failed")):
            with self.assertRaisesRegex(Exception, "stage failed"):
                self.change()
        self.assertNotIn("commit", self.client.events)
        self.assertEqual(self.startup.read_bytes(), SAVED)
        self.assert_no_staging()

    def test_publish_failure_reports_partial_change_without_rollback(self):
        with patch.object(SavedPasswordUpdate, "publish", side_effect=SavedPasswordError("publish failed")):
            with self.assertRaisesRegex(Exception, "changed.*not.*saved"):
                self.change()
        self.assertEqual(self.client.running, NEW_HASH)
        self.assertEqual(self.startup.read_bytes(), SAVED)
        self.assertEqual(self.client.events.count("commit"), 1)
        self.assert_no_staging()

    def test_intervening_runtime_password_is_not_overwritten_or_persisted(self):
        self.client.after_commit = lambda: setattr(self.client, "running", OLD_HASH)
        with self.assertRaisesRegex(Exception, "changed.*not.*saved"):
            self.change()
        self.assertEqual(self.client.running, OLD_HASH)
        self.assertEqual(self.startup.read_bytes(), SAVED)
        self.assertEqual(self.client.events.count("commit"), 1)
        self.assert_no_staging()


if __name__ == "__main__":
    unittest.main()
