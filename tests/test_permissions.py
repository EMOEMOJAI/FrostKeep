"""Linux root integration gate for mapped-container access, without Proxmox."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("fk", Path(__file__).resolve().parents[1] / "lib/frostkeep/frostkeep.py")
fk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fk)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Linux root gate runs separately in CI")
class MappedPermissions(unittest.TestCase):
    def test_inherited_acl_does_not_grant_unrelated_uid_access(self):
        self.assertIsNotNone(shutil.which("setfacl"))
        self.assertIsNotNone(shutil.which("getfacl"))
        runner = fk.Runner()
        with tempfile.TemporaryDirectory() as parent:
            base = Path(parent).resolve()
            base.chmod(0o711)
            runner(["setfacl", "-m", "d:u:165537:r-x", str(base)])
            def run(args, **kwargs):
                if args[:2] == ["pct", "config"]:
                    return "unprivileged: 1\nlxc.idmap: u 0 165536 65536\n"
                return runner(args, **kwargs)
            with patch.object(fk, "Path", side_effect=lambda value: base if value == "/var/tmp" else Path(value)):
                with fk.dump_workspace(run, "lxc", 201) as name:
                    acl = runner(["getfacl", "-cp", name])
                    self.assertNotIn("165537", acl)
                    self.assertNotIn("default:", acl)
                    self.assertIn("user:165536:--x", acl)
                    target = Path(name) / "config"
                    target.write_text("fixture")
                    target.chmod(0o644)
                    def read_as(uid):
                        return subprocess.run(["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups",
                                               "cat", str(target)], capture_output=True)
                    self.assertEqual(read_as(165536).stdout, b"fixture")
                    self.assertNotEqual(read_as(165537).returncode, 0)

    def test_only_mapped_user_can_read_vzdump_temporary_config(self):
        self.assertIsNotNone(shutil.which("setfacl"), "Install acl for the required Linux gate")
        self.assertIsNotNone(shutil.which("setpriv"))
        runner = fk.Runner()
        def run(args, **kwargs):
            if args[:2] == ["pct", "config"]:
                return "unprivileged: 1\nlxc.idmap: u 0 165536 65536\nlxc.idmap: g 0 165536 65536\n"
            return runner(args, **kwargs)
        with fk.dump_workspace(run, "lxc", 201) as name:
            # Model Proxmox mkdir + config creation under the subprocess umask.
            runner([sys.executable, "-c", "import os,sys;os.mkdir(sys.argv[1]);open(sys.argv[1]+'/config','w').write('fixture')", name + "/vzdump"], umask=0o022)
            target = name + "/vzdump/config"
            def read_as(uid):
                return subprocess.run(["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", "cat", target], capture_output=True)
            self.assertEqual(read_as(165536).stdout, b"fixture")
            self.assertNotEqual(read_as(165537).returncode, 0)
            self.assertEqual(Path(name).stat().st_mode & 0o007, 0)
        self.assertFalse(Path(name).exists())


if __name__ == "__main__":
    unittest.main()
