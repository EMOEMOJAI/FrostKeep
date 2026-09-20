import importlib.util
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release", ROOT / "scripts/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_allowlist_excludes_private_history_and_config(self):
        files = release.public_files()
        self.assertFalse(any(p.parts[0] in ("local", "dist") for p in files))
        self.assertNotIn(Path("config.json"), files)
        self.assertEqual(release.scan(ROOT, files), [])

    def test_secret_rejected_without_echoing_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Construct synthetic detection cases; no real secret is used.
            secret = "AK" + "IA" + "A" * 16
            (root / "README.md").write_text(secret)
            findings = release.scan(root, [Path("README.md")])
            self.assertTrue(findings)
            self.assertNotIn(secret, str(findings))

    def test_image_metadata_removed_without_changing_pixels(self):
        original = (ROOT / "favicon.png").read_bytes()
        chunks = list(release.png_chunks(original))
        text = b"Author\0synthetic private author"
        kind = b"tEXt"
        block = struct.pack(">I", len(text)) + kind + text + struct.pack(">I", zlib.crc32(kind + text))
        extra = original[:8] + b"".join(b for k, b in chunks if k != b"IEND") + block + chunks[-1][1]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "icon.png"
            path.write_bytes(extra)
            release.clean_png(path)
            before = [b for k, b in chunks if k == b"IDAT"]
            after = [b for k, b in release.png_chunks(path.read_bytes()) if k == b"IDAT"]
            self.assertEqual(before, after)
            self.assertFalse(any(k == b"tEXt" for k, _ in release.png_chunks(path.read_bytes())))

    def test_export_refuses_existing_destination_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "RELEASE_FILES").write_text("README.md\n")
            (root / "README.md").write_text("safe\n")
            with self.assertRaises(ValueError):
                release.export(root, root)
            (root / "README.md").unlink()
            (root / "README.md").symlink_to(root / "RELEASE_FILES")
            with self.assertRaises(ValueError):
                release.public_files(root)

    def test_workspace_detects_ignored_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "RELEASE_FILES").write_text("RELEASE_FILES\nREADME.md\n")
            (root / "README.md").write_text("safe\n")
            (root / "local").mkdir()
            (root / "local/notes.txt").write_text("private operational notes\n")
            findings = release.scan_workspace(root)
            self.assertTrue(any("local/notes.txt" in f for f in findings))

    def test_workspace_scans_distribution_copies_for_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "RELEASE_FILES").write_text("RELEASE_FILES\nREADME.md\n")
            (root / "README.md").write_text("safe\n")
            exported = root / "dist/frostkeep-test"
            exported.mkdir(parents=True)
            (exported / "README.md").write_text("AK" + "IA" + "A" * 16)
            self.assertTrue(any("AWS access key" in f for f in release.scan_workspace(root)))

    def test_archive_excludes_owner_metadata_and_local_timestamps(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "public.zip"
            release.write_archive(archive)
            release.verify_archive(archive)
            with zipfile.ZipFile(archive) as packaged:
                self.assertEqual(len(packaged.infolist()), len(release.public_files()))
                for entry in packaged.infolist():
                    self.assertEqual(entry.date_time, (1980, 1, 1, 0, 0, 0))
                    self.assertEqual(entry.extra, b"")
                    self.assertEqual(entry.comment, b"")
                    self.assertTrue(entry.filename.startswith("frostkeep/"))
                    self.assertNotIn("__MACOSX", entry.filename)
                self.assertIsNone(packaged.testzip())

    def test_archive_verification_rejects_extra_files_and_modified_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "RELEASE_FILES").write_text("README.md\n")
            (root / "README.md").write_text("original")
            archive = root / "public.zip"
            release.write_archive(archive, root)
            (root / "README.md").write_text("changed")
            with self.assertRaises(ValueError):
                release.verify_archive(archive, root)
            (root / "README.md").write_text("original")
            with zipfile.ZipFile(archive, "a") as packaged:
                packaged.writestr("private-notes.txt", "must not ship")
            with self.assertRaises(ValueError):
                release.verify_archive(archive, root)

    def test_archive_verification_rejects_hidden_raw_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "RELEASE_FILES").write_text("README.md\n")
            (root / "README.md").write_text("safe\n")
            archive = root / "public.zip"
            release.write_archive(archive, root)
            raw = archive.read_bytes()
            # Local-header extra fields need not appear in central-directory extras.
            name_length = struct.unpack_from("<H", raw, 26)[0]
            extra = struct.pack("<HH", 0xCAFE, 7) + b"private"
            local = bytearray(raw[:30 + name_length])
            struct.pack_into("<H", local, 28, len(extra))
            amended = bytearray(local + extra + raw[30 + name_length:])
            end = amended.rfind(b"PK\x05\x06")
            central = struct.unpack_from("<I", amended, end + 16)[0]
            struct.pack_into("<I", amended, end + 16, central + len(extra))
            for malicious in (b"private" + raw, raw + b"private", amended):
                with self.subTest(kind=bytes(malicious[:8])):
                    archive.write_bytes(malicious)
                    with self.assertRaises(ValueError):
                        release.verify_archive(archive, root)

    def test_verification_never_decompresses_untrusted_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "RELEASE_FILES").write_text("README.md\n")
            (root / "README.md").write_text("tiny")
            archive = root / "oversized.zip"
            info = zipfile.ZipInfo("frostkeep/README.md")
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            with zipfile.ZipFile(archive, "w") as packaged:
                packaged.writestr(info, b"A" * (8 * 1024 * 1024), compress_type=zipfile.ZIP_DEFLATED)
            with patch.object(zipfile.ZipExtFile, "read", side_effect=AssertionError("Untrusted ZIP was decompressed")):
                with self.assertRaises(ValueError):
                    release.verify_archive(archive, root)

    def test_archive_is_canonical_and_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "first.zip", Path(directory) / "second.zip"
            release.write_archive(first)
            release.write_archive(second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertTrue(all(i.compress_type == zipfile.ZIP_STORED for i in archive.infolist()))


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.source, self.destination = self.base / "source", self.base / "destination"
        for subtree in ("scripts", "lib", "config", "deploy"):
            shutil.copytree(ROOT / subtree, self.source / subtree)
        for relative, data, mode in (
            ("usr/local/lib/frostkeep/frostkeep.py", "old library", 0o644),
            ("usr/local/bin/frostkeep", "old command", 0o755),
            ("etc/frostkeep/config.json", '{"private": "preserve"}', 0o600),
        ):
            target = self.destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(data)
            target.chmod(mode)
        self.before = self.snapshot()

    def snapshot(self):
        return {str(p.relative_to(self.destination)): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
                for p in self.destination.rglob("*") if p.is_file()}

    def install(self, fault=None):
        environment = dict(os.environ, DESTDIR=str(self.destination), PYTHONDONTWRITEBYTECODE="1")
        if fault:
            shim = self.base / "shim"
            shim.mkdir(exist_ok=True)
            launcher = shim / "python3"
            launcher.write_text(f"#!{sys.executable}\n" + """
import os, signal, sys
replace = os.replace
calls = 0
def injected(source, destination):
    global calls
    calls += 1
    replace(source, destination)
    if calls == 4:
        if os.environ['INSTALL_TEST_FAULT'].startswith('signal:'):
            os.kill(os.getpid(), getattr(signal, os.environ['INSTALL_TEST_FAULT'].split(':')[1]))
        else:
            raise OSError('Injected late commit failure')
os.replace = injected
sys.argv = ['-'] + sys.argv[2:]
exec(compile(sys.stdin.read(), '<installer>', 'exec'))
""")
            launcher.chmod(0o755)
            environment.update(PATH=str(shim) + os.pathsep + os.environ.get("PATH", ""), INSTALL_TEST_FAULT=fault)
        return subprocess.run(["bash", str(self.source / "scripts/install.sh")], env=environment,
                              capture_output=True, text=True, timeout=30)

    def test_missing_source_preserves_prior_installation(self):
        (self.source / "scripts/glacier-status").unlink()
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), self.before)
        self.assertEqual(list(self.destination.rglob(".frostkeep-install-*")), [])

    def test_live_install_lock_refuses_symlink_without_truncating_target(self):
        victim = self.base / "must-preserve"
        victim.write_text("preserved private fixture")
        lock = self.base / "install.lock"
        lock.symlink_to(victim)
        # Exercise the actual production branch with only its lock path remapped.
        # It must fail before touching any real installation directory.
        script = (self.source / "scripts/install.sh").read_text()
        program = script.split("<<'PYTHON'\n", 1)[1].rsplit("\nPYTHON", 1)[0]
        program = program.replace('"/run/lock/pve-glacier.lock"', repr(str(lock)))
        result = subprocess.run([sys.executable, "-", str(self.source), ""], input=program,
                                capture_output=True, text=True, timeout=30,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(victim.read_text(), "preserved private fixture")
        self.assertEqual(self.snapshot(), self.before)

    def test_root_equivalent_destdir_cannot_bypass_live_install_checks(self):
        alias = self.base / "root-alias"
        alias.symlink_to("/", target_is_directory=True)
        script = (self.source / "scripts/install.sh").read_text()
        # Run the argument guard alone, never a live installation in a test.
        guard = script.split("<<'PYTHON'\n", 1)[1].split("entries = [", 1)[0]
        for destination in ("/", "/./", "//", str(alias)):
            with self.subTest(destination=destination):
                result = subprocess.run([sys.executable, "-", str(self.source), destination],
                                        input=guard, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("DESTDIR", result.stderr)

    def test_late_commit_failure_rolls_back_replacements_and_new_files(self):
        result = self.install("error")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installed files restored", result.stderr)
        self.assertEqual(self.snapshot(), self.before)
        self.assertEqual(list(self.destination.rglob(".frostkeep-install-*")), [])

    def test_nested_staging_symlink_preserves_external_files(self):
        outside = self.base / "external-usr"
        shutil.move(str(self.destination / "usr"), outside)
        (self.destination / "usr").symlink_to(outside, target_is_directory=True)
        before = {str(p.relative_to(outside)): p.read_bytes() for p in outside.rglob("*") if p.is_file()}
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink components", result.stderr)
        self.assertEqual({str(p.relative_to(outside)): p.read_bytes() for p in outside.rglob("*") if p.is_file()}, before)
        self.assertEqual(list(outside.rglob(".frostkeep-install-*")), [])
        # Check an absent leaf as well: an existing symlink parent must not be
        # traversed while recursively creating new installation directories.
        shutil.rmtree(outside / "local/lib/frostkeep")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((outside / "local/lib/frostkeep").exists())

    def test_termination_rolls_back_replacements_and_new_files(self):
        for name in ("SIGINT", "SIGTERM", "SIGHUP"):
            with self.subTest(signal=name):
                result = self.install("signal:" + name)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("installed files restored", result.stderr)
                self.assertEqual(self.snapshot(), self.before)
                self.assertEqual(list(self.destination.rglob(".frostkeep-install-*")), [])

    def test_successful_install_preserves_config_and_installed_command_runs(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot()["etc/frostkeep/config.json"], self.before["etc/frostkeep/config.json"])
        command = self.destination / "usr/local/bin/frostkeep"
        result = subprocess.run([str(command), "--help"], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.destination.rglob(".frostkeep-install-*")), [])
