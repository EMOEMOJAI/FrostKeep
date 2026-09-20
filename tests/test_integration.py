"""Real local rclone crypt integration; synthetic data, no network or credentials."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid


@unittest.skipUnless(shutil.which("rclone"), "Install rclone to run local encryption integration")
class CryptIntegration(unittest.TestCase):
    def test_real_encryption_names_round_trip_and_corruption(self):
        binary = shutil.which("rclone")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "rclone.conf"
            env = {k: v for k, v in os.environ.items() if not k.startswith("RCLONE_")}
            secret = subprocess.check_output([binary, "obscure", uuid.uuid4().hex], text=True).strip()
            config.write_text(f"[archive]\ntype = crypt\nremote = {root / 'encrypted'}\npassword = {secret}\nfilename_encryption = standard\ndirectory_name_encryption = true\n")
            config.chmod(0o600)
            def run(*args):
                return subprocess.run([binary, "--config", str(config), *map(str, args)],
                                      capture_output=True, env=env, check=True, timeout=30)
            source = root / "fixture.bin"
            source.write_bytes(os.urandom(150000))
            run("copyto", source, "archive:run/fixture.bin", "--immutable")
            encoded = json.loads(run("backend", "encode", "archive:", "run/fixture.bin", "--json").stdout)[0]
            encrypted = root / "encrypted" / encoded
            self.assertTrue(encrypted.is_file())
            self.assertNotIn("fixture", encoded)
            self.assertNotEqual(encrypted.read_bytes(), source.read_bytes())
            listing = json.loads(run("lsjson", "archive:run/fixture.bin", "--stat").stdout)
            self.assertEqual(listing["Size"], source.stat().st_size)
            downloaded = root / "download.bin"
            run("copyto", "archive:run/fixture.bin", downloaded)
            self.assertEqual(hashlib.sha256(downloaded.read_bytes()).digest(), hashlib.sha256(source.read_bytes()).digest())
            damaged = bytearray(encrypted.read_bytes())
            damaged[-1] ^= 0xFF
            encrypted.write_bytes(damaged)
            with self.assertRaises(subprocess.CalledProcessError):
                run("copyto", "archive:run/fixture.bin", root / "corrupt.bin", "--retries", "1", "--low-level-retries", "1")
