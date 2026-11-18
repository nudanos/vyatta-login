"""Run the real RPC with an isolated startup file and the fixture configd peer."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys
import tempfile

rpc_path = Path(sys.argv[1])
sys.path.insert(0, str(rpc_path.parent))
from vyatta_password_persistence import verify_saved_password

loader = importlib.machinery.SourceFileLoader("fixture_password_rpc", str(rpc_path))
module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(module)
sys.argv = sys.argv[1:]
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    startup = directory / "config.boot"
    startup.write_text('system { login { user tester { authentication { encrypted-password "' +
                       os.environ["TEST_HASH"] + '"; } } } }\n')
    startup.chmod(0o600)
    module.configd.Client.startup = startup
    module.verify_saved_password = lambda user, expected: verify_saved_password(user, expected, startup)
    module.main()
