import json
import os
from crypt_r import crypt


class Client:
    RUNNING = "running"
    CANDIDATE = "candidate"

    def tree_get_dict(self, path, source):
        assert path == "system login user tester authentication encrypted-password"
        if source == self.CANDIDATE:
            return {"encrypted-password": self.candidate}
        assert source == self.RUNNING
        return {"encrypted-password": getattr(self, "running", os.environ["TEST_HASH"])}

    def session_setup(self, session_id):
        self.path = None

    def session_exists(self):
        assert self.path is None

    def set(self, path):
        assert path[:6] == ["system", "login", "user", "tester", "authentication",
                           "plaintext-password"]
        self.path = path
        self.candidate = crypt(path[-1], "$6$replacement$")

    def commit(self, message):
        self.running = self.candidate
        self.startup.write_text('system { login { user tester { authentication { encrypted-password "' +
                                self.running + '"; } } } }\n')
        print(json.dumps(self.path))
        return ""

    def session_teardown(self):
        pass
