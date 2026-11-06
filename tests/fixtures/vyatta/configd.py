import json
import os


class Client:
    RUNNING = "running"

    def tree_get_dict(self, path, source):
        assert source == self.RUNNING
        assert path == "system login user tester authentication encrypted-password"
        return {"encrypted-password": os.environ["TEST_HASH"]}

    def session_setup(self, session_id):
        self.path = None

    def session_exists(self):
        assert self.path is None

    def set(self, path):
        assert path[:6] == ["system", "login", "user", "tester", "authentication",
                           "plaintext-password"]
        self.path = path

    def commit(self, message):
        print(json.dumps(self.path))

    def session_teardown(self):
        pass
