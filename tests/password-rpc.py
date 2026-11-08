import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import crypt_r

TEST_DIR = Path(__file__).resolve().parent
RPC = TEST_DIR.parent / "scripts" / "vyatta-password-rpc"
PASSWORD = 'new \\t "quotes" 雪'


class PasswordRPCTest(unittest.TestCase):
    def run_rpc(self, method, stored_hash, **fields):
        return subprocess.run(
            [sys.executable, RPC, method], text=True, input=json.dumps(fields),
            env=dict(os.environ, PYTHONPATH=str(TEST_DIR / "fixtures"),
                     TEST_HASH=stored_hash, VCI_RPC_METADATA='{"User":"tester"}'),
            capture_output=True,
        )

    def verify(self, stored_hash, password):
        return self.run_rpc("verify-password", stored_hash,
                            **{"current-password": password})

    def test_verify_sha512(self):
        result = self.verify(crypt_r.crypt(PASSWORD, "$6$test$"), PASSWORD)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_verify_long_unicode_password(self):
        password = "ä" * 250 + "\\"
        result = self.verify(crypt_r.crypt(password, "$6$test$"), password)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_verify_yescrypt(self):
        result = self.verify(crypt_r.crypt(PASSWORD, "$y$j9T$WmN1f7MkyWdZfRXXQ6CdQ1"), PASSWORD)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_locked_invalid_and_overlength_passwords_fail_cleanly(self):
        stored_hash = crypt_r.crypt(PASSWORD, "$6$test$")
        for encoded, password in (
            (stored_hash, PASSWORD + "x"), ("!" + stored_hash, PASSWORD),
            ("*", PASSWORD), ("", PASSWORD), (stored_hash, "x" * 5000),
            (stored_hash, None), (stored_hash, "nul\0byte"), (stored_hash, "\ud800"),
        ):
            with self.subTest(encoded=encoded[:3], length=len(password or "")):
                result = self.verify(encoded, password)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "Authentication failure\n")
                self.assertEqual(result.stderr, "")

    def test_expired_password_can_be_verified_and_changed(self):
        # PAM account policy triggers renewal; the running config's current hash
        # still authorizes the change. The RPC does not consult shadow age.
        stored_hash = crypt_r.crypt(PASSWORD, "$6$test$")
        replacement = '雪 \\ "replacement"' + "x" * 400
        result = self.run_rpc("change-password", stored_hash,
                              **{"current-password": PASSWORD, "new-password": replacement})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)[-1], replacement)

    def test_unsupported_new_passwords_are_rejected(self):
        stored_hash = crypt_r.crypt(PASSWORD, "$6$test$")
        for password in ("x" * 512, "雪" * 171, "line\nbreak", "line\rbreak", "\ud800"):
            with self.subTest(password=repr(password)):
                result = self.run_rpc("change-password", stored_hash,
                                      **{"current-password": PASSWORD, "new-password": password})
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
