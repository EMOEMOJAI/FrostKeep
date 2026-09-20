"""Recovery safety regressions using synthetic objects and local subprocesses."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

import test_frostkeep as fixtures

fk = fixtures.fk


class RecoveryAuditTests(unittest.TestCase):
    setUp = fixtures.WorkflowTests.setUp
    tearDown = fixtures.WorkflowTests.tearDown
    pack = staticmethod(fixtures.WorkflowTests.pack)
    backup = fixtures.WorkflowTests.backup
    latest = fixtures.WorkflowTests.latest
    restore_fixture = fixtures.WorkflowTests.restore_fixture
    interrupted_fixture = fixtures.WorkflowTests.interrupted_fixture

    @unittest.skipUnless(hasattr(os, "fork"), "Hard-stop probe requires fork")
    def test_hard_stop_at_publication_boundaries_remains_resumable(self):
        for boundary in ("before_manifest", "after_manifest", "before_marker", "after_marker",
                         "before_latest", "before_full_state", "before_health", "before_full_attempt", "before_local_commit"):
            with self.subTest(boundary=boundary):
                snapshot = self.root / "mock-cloud.json"
                pid = os.fork()
                if pid == 0:
                    def stop():
                        snapshot.write_text(json.dumps({key: dict(value, data=value["data"].hex())
                                                       for key, value in self.run.objects.items()}))
                        os._exit(99)
                    def run(argv, **kwargs):
                        name = str(argv[5]).rsplit("/", 1)[-1] if "copyto" in argv else ""
                        phase = "manifest" if name == "MANIFEST.json" else "marker" if name == "COMPLETE.json" else ""
                        if phase and boundary == "before_" + phase:
                            stop()
                        result = self.run(argv, **kwargs)
                        if phase and boundary == "after_" + phase:
                            stop()
                        return result
                    atomic = fk.atomic_json
                    def write(path, value):
                        names = {"before_latest": "latest.json", "before_full_state": "full-latest.json",
                                 "before_health": "last-success.json", "before_full_attempt": "full-attempt.json",
                                 "before_local_commit": "MANIFEST.json"}
                        if Path(path).name == names.get(boundary) and value.get("status") == "complete":
                            stop()
                        return atomic(path, value)
                    try:
                        with patch.object(fk, "atomic_json", side_effect=write):
                            fk.Backup(self.cfg, run).execute()
                    except BaseException:
                        os._exit(98)
                    os._exit(0)
                _, status = os.waitpid(pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 99)
                self.run.objects = {key: dict(value, data=bytes.fromhex(value["data"]))
                                    for key, value in json.loads(snapshot.read_text()).items()}
                run_id = self.latest()["run_id"]
                work, local = fk.local_run(self.cfg, run_id)
                self.assertEqual(local["status"], "finalizing")
                before = (work / "MANIFEST.json").read_bytes()
                self.run.calls.clear()
                fk.resume_backup(self.cfg, run_id, run=self.run)
                self.assertEqual((work / "MANIFEST.json").read_bytes(), before)
                self.assertFalse(any("copyto" in call or call[0] == "vzdump" for call in self.run.calls))
                fk.resume_backup(self.cfg, run_id, execute=True, run=self.run)
                self.assertFalse(any(call[0] == "vzdump" for call in self.run.calls))
                fresh = self.latest()
                self.assertEqual(fresh["status"], "complete")
                self.assertEqual(fk.Restore(self.cfg, self.run).manifest(fresh["run_id"]), fresh)
                self.assertEqual(fk.health(self.cfg), 0)

    def legacy_finalization_fixture(self):
        self.cfg["keep_local_archives"] = True
        self.backup()
        data = self.latest()
        root = fk.remote_join(self.cfg["remote"], data["run_id"])
        del self.run.objects[root + "/COMPLETE.json"]
        del self.run.objects[root + "/MANIFEST.json"]
        return data, Path(self.cfg["staging_dir"]) / data["run_id"]

    def test_older_premature_completion_can_resume_without_new_dumps(self):
        data, work = self.legacy_finalization_fixture()
        before = (work / "MANIFEST.json").read_bytes()
        self.run.calls.clear()
        fk.resume_backup(self.cfg, data["run_id"], run=self.run)
        self.assertEqual((work / "MANIFEST.json").read_bytes(), before)
        fk.resume_backup(self.cfg, data["run_id"], execute=True, run=self.run)
        self.assertFalse(any(call[0] == "vzdump" for call in self.run.calls))
        self.assertEqual(fk.health(self.cfg), 0)

    def test_older_premature_completion_cleanup_requires_acknowledgment(self):
        data, work = self.legacy_finalization_fixture()
        with self.assertRaises(fk.Failure):
            fk.cleanup(self.cfg, data["run_id"], execute=True, run=self.run)
        fk.cleanup(self.cfg, data["run_id"], allow_incomplete=True, run=self.run)
        self.assertTrue(work.exists())
        fk.cleanup(self.cfg, data["run_id"], allow_incomplete=True, execute=True, run=self.run)
        self.assertFalse(work.exists())

    def test_finalization_recovery_preserves_files_on_remote_failure(self):
        data, work = self.legacy_finalization_fixture()
        for failure in ("listing", "payload", "context"):
            with self.subTest(failure=failure):
                self.run.fail = lambda a: "lsjson" in a if failure == "listing" else False
                self.run.bad_size = failure == "payload"
                original_remote = self.cfg["remote"]
                if failure == "context":
                    self.cfg["remote"] = "archive:other"
                try:
                    with self.assertRaises(fk.Failure):
                        fk.resume_backup(self.cfg, data["run_id"], execute=True, run=self.run)
                    with self.assertRaises(fk.Failure):
                        fk.cleanup(self.cfg, data["run_id"], allow_incomplete=True, execute=True, run=self.run)
                    self.assertTrue(work.exists())
                finally:
                    self.cfg["remote"] = original_remote
        self.run.fail = lambda a: False
        self.run.bad_size = False
        entry = next(e for e in data["files"] if e["role"] == "guest")
        del self.run.objects[fk.entry_remote(self.cfg, data["run_id"], entry)]
        with self.assertRaises(fk.Failure):
            fk.cleanup(self.cfg, data["run_id"], allow_incomplete=True, execute=True, run=self.run)
        self.assertTrue(work.exists())

    def test_verified_complete_run_cannot_be_reclassified_for_resume(self):
        self.backup()
        with self.assertRaises(fk.Failure):
            fk.resume_backup(self.cfg, self.latest()["run_id"], execute=True, run=self.run)

    def test_older_published_run_with_unfinished_health_state_can_recover(self):
        self.backup()
        data = self.latest()
        fk.atomic_json(Path(self.cfg["state_dir"]) / "latest.json", dict(data, status="finalizing"))
        (Path(self.cfg["state_dir"]) / "last-success.json").unlink()
        self.run.calls.clear()
        fk.resume_backup(self.cfg, data["run_id"], execute=True, run=self.run)
        self.assertFalse(any(call[0] == "vzdump" for call in self.run.calls))
        self.assertEqual(fk.health(self.cfg), 0)

    def replace_manifest(self, manifest, raw=None):
        root = fk.remote_join(self.cfg["remote"], manifest["run_id"])
        data = raw if raw is not None else json.dumps(manifest).encode()
        self.run.objects[fk.remote_join(root, "MANIFEST.json")]["data"] = data
        self.run.objects[fk.remote_join(root, "COMPLETE.json")]["data"] = json.dumps({
            "run_id": manifest["run_id"], "manifest_sha256": hashlib.sha256(data).hexdigest()
        }).encode()

    def test_cleanup_preserves_only_local_copies_when_remote_payload_missing(self):
        self.cfg["keep_local_archives"] = True
        self.backup()
        manifest = self.latest()
        work = Path(self.cfg["staging_dir"]) / manifest["run_id"]
        for role in ("guest", "host"):
            with self.subTest(role=role):
                entry = next(e for e in manifest["files"] if e["role"] == role)
                key = fk.entry_remote(self.cfg, manifest["run_id"], entry)
                saved = self.run.objects.pop(key)
                try:
                    with self.assertRaises(fk.Failure):
                        fk.cleanup(self.cfg, manifest["run_id"], execute=True, run=self.run)
                    self.assertEqual(len(list(work.glob("*/*.zst"))), 2)
                finally:
                    self.run.objects[key] = saved

    def test_cleanup_checks_reused_origin_objects(self):
        self.cfg["keep_local_archives"] = True
        old = self.interrupted_fixture()
        fk.resume_backup(self.cfg, old["run_id"], execute=True, run=self.run)
        fresh = self.latest()
        entry = next(e for e in fresh["files"] if e.get("source_run") and e["role"] == "guest")
        del self.run.objects[fk.entry_remote(self.cfg, fresh["run_id"], entry)]
        with self.assertRaises(fk.Failure):
            fk.cleanup(self.cfg, fresh["run_id"], execute=True, run=self.run)
        self.assertTrue((Path(self.cfg["staging_dir"]) / fresh["run_id"]).is_dir())

    def test_cleanup_rechecks_payloads_at_execution(self):
        self.backup()
        manifest = self.latest()
        fk.cleanup(self.cfg, manifest["run_id"], run=self.run)
        entry = next(e for e in manifest["files"] if e["role"] == "guest")
        self.run.objects[fk.entry_remote(self.cfg, manifest["run_id"], entry)]["data"] += b"changed"
        with self.assertRaises(fk.Failure):
            fk.cleanup(self.cfg, manifest["run_id"], execute=True, run=self.run)
        self.assertTrue((Path(self.cfg["staging_dir"]) / manifest["run_id"]).is_dir())

    def test_manifest_limits_bytes_depth_and_inventory(self):
        restore, run_id, _, _ = self.restore_fixture()
        manifest = self.latest()
        with patch.object(fk, "MAX_MANIFEST_BYTES", 4096):
            manifest["padding"] = "x" * 4096
            self.replace_manifest(manifest)
            with self.assertRaises(fk.Failure):
                restore.manifest(run_id)
        self.replace_manifest(manifest, b"[" * 2000 + b"]" * 2000)
        with self.assertRaises(fk.Failure):
            restore.manifest(run_id)
        with patch.object(fk, "MAX_MANIFEST_GUESTS", 1):
            with self.assertRaises(fk.Failure):
                fk.validate_manifest(manifest, run_id)

    def test_metadata_listing_is_shallow_filtered_and_bounded(self):
        restore, run_id, _, _ = self.restore_fixture()
        self.run.calls.clear()
        restore.manifest(run_id)
        listing = next(a for a in self.run.calls if "lsjson" in a)
        self.assertNotIn("--recursive", listing)
        self.assertEqual(listing[listing.index("--max-depth") + 1], "1")
        self.assertEqual(listing.count("--include"), 3)

    def test_download_rejects_remote_size_change_before_writing(self):
        restore, run_id, entry, _ = self.restore_fixture()
        self.run.objects[fk.entry_remote(self.cfg, run_id, entry)]["data"] += b"extra"
        self.run.calls.clear()
        destination = self.root / "download"
        with self.assertRaises(fk.Failure):
            restore.download(run_id, entry["path"], destination)
        self.assertFalse(any("cat" in a and entry["path"] in a[4] for a in self.run.calls))
        self.assertFalse((destination / entry["path"]).exists())

    def streamed_download(self, payload, declared_size=None, available=None):
        restore = fk.Restore(self.cfg, self.run)
        size = len(payload) if declared_size is None else declared_size
        entry = {"path": "archive.zst", "role": "guest", "size": size,
                 "sha256": hashlib.sha256(payload).hexdigest(), "tier": "DEEP_ARCHIVE"}
        self.bytes_written = None
        def stream_call(*args, **kwargs):
            self.assertEqual(args[0], "cat")
            self.assertEqual(args[args.index("--count") + 1], str(size + 1))
            try:
                return fk.Runner(timeout=5)(
                    [sys.executable, "-c", "import sys; sys.stdout.buffer.write(" + repr(payload) + ")"],
                    **kwargs)
            finally:
                self.bytes_written = kwargs["output_file"].tell()
        with patch.object(restore, "entry", return_value=entry), \
             patch.object(restore.rclone, "stat", return_value={"Size": size, "Tier": "DEEP_ARCHIVE"}), \
             patch.object(restore.rclone, "call", side_effect=stream_call), \
             patch.object(fk.shutil, "disk_usage", side_effect=available):
            return restore.download("20260101T000000Z-aaaaaaaaaaaa", entry["path"], self.root / "streamed")

    def test_streamed_download_caps_bytes_even_if_remote_stat_lies(self):
        available = lambda _: type("Usage", (), {"free": 1000000})()
        with self.assertRaises(fk.Failure):
            self.streamed_download(b"x" * 100, declared_size=21, available=available)
        self.assertLessEqual(self.bytes_written, 21)
        self.assertFalse(list((self.root / "streamed").glob(".download-*")))
        self.assertFalse((self.root / "streamed/archive.zst").exists())

    def test_streamed_download_preserves_binary_data(self):
        payload = bytes(range(256)) * 64
        available = lambda _: type("Usage", (), {"free": 1000000})()
        path = self.streamed_download(payload, available=available)
        self.assertEqual(path.read_bytes(), payload)

    def test_streamed_download_checks_free_space_before_each_write(self):
        readings = iter([1000000, 1000000])
        available = lambda _: type("Usage", (), {"free": next(readings, 0)})()
        with self.assertRaises(fk.Failure):
            self.streamed_download(b"x" * 100000, available=available)
        self.assertGreater(self.bytes_written, 0)
        self.assertLess(self.bytes_written, 100000)
        self.assertFalse((self.root / "streamed/archive.zst").exists())

    def test_unavailable_health_state_alerts_and_retries_delivery(self):
        self.cfg["notification_command"] = ["/test/notify"]
        with patch.object(fk, "private_dir", side_effect=fk.Failure("unavailable")):
            self.run.fail = lambda a: a[0] == "/test/notify"
            self.assertEqual(fk.health(self.cfg, notify=True, run=self.run), 2)
            self.run.fail = lambda a: False
            self.assertEqual(fk.health(self.cfg, notify=True, run=self.run), 1)
        self.assertEqual(self.run.notification_payload["reasons"], ["health_state_unavailable"])

    def test_encoded_keys_support_unicode_and_leading_hyphen_safely(self):
        restore, run_id, entry, _ = self.restore_fixture()
        for encoded in ("encoded/-AbCd_123", "\u4e00\u4e8c/\u4e09\u56db"):
            with self.subTest(encoded=encoded):
                def backend(*args, **kwargs):
                    if args[:2] == ("backend", "encode"):
                        return [encoded]
                    if args[:2] == ("backend", "restore"):
                        self.assertEqual(args[args.index("--include") + 1], "/" + encoded.split("/")[-1])
                        return [{"Remote": encoded.split("/")[-1], "Status": "OK"}]
                    raise AssertionError(args)
                with patch.object(restore, "entry", return_value=entry), \
                     patch.object(restore.rclone, "json", side_effect=backend):
                    restore.request(run_id, entry["path"], execute=True)
        for encoded in ("../outside", "dir/*", "dir/[ab]", "dir/a\nb"):
            with self.subTest(encoded=encoded), patch.object(restore.rclone, "json", return_value=[encoded]):
                with self.assertRaises(fk.Failure):
                    restore.rclone.raw_object(run_id + "/" + entry["path"])


class FullBackupHealthTests(unittest.TestCase):
    setUp = fixtures.WorkflowTests.setUp
    tearDown = fixtures.WorkflowTests.tearDown
    pack = staticmethod(fixtures.WorkflowTests.pack)
    backup = fixtures.WorkflowTests.backup
    latest = fixtures.WorkflowTests.latest

    def health(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = fk.health(self.cfg, notify=True, run=self.run)
        return code, json.loads(output.getvalue())

    def fail_full_preflight(self):
        self.run.bad_encryption = True
        try:
            with self.assertRaises(fk.Failure):
                fk.backup_invocation(self.cfg, self.backup, self.run, full_scope=True)
        finally:
            self.run.bad_encryption = False

    @unittest.skipUnless(hasattr(os, 'fork'), 'Hard-stop probe requires fork')
    def test_hard_stopped_full_run_survives_subset_success(self):
        self.backup()
        pid = os.fork()
        if pid == 0:
            with patch.object(fk.Backup, 'backup_guest', side_effect=lambda guest: os._exit(99)):
                fk.backup_invocation(self.cfg, self.backup, self.run, full_scope=True)
            os._exit(98)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 99)
        fk.backup_invocation(self.cfg, lambda: self.backup(requested=[101]), self.run)
        code, payload = self.health()
        self.assertEqual(code, 1)
        self.assertIn('backup_interrupted', payload['reasons'])
        self.backup()
        self.assertEqual(self.health()[0], 0)

    def test_finalizing_full_run_survives_subset_and_unrelated_lock(self):
        self.backup()
        state = Path(self.cfg['state_dir'])
        full = dict(self.latest(), status='finalizing')
        fk.atomic_json(state / 'full-latest.json', full)
        self.backup(requested=[101])
        with fk.Lock(self.cfg['lock_file']):
            code, payload = self.health()
        self.assertEqual(code, 1)
        self.assertIn('backup_interrupted', payload['reasons'])

    def test_active_full_backup_is_not_reported_as_interrupted(self):
        self.backup()
        state = Path(self.cfg['state_dir'])
        for status in ('running', 'finalizing'):
            with self.subTest(status=status):
                active = dict(self.latest(), status=status)
                for name in ('latest.json', 'full-latest.json'):
                    fk.atomic_json(state / name, active)
                with fk.Lock(self.cfg['lock_file']):
                    self.assertEqual(self.health()[0], 0)
                code, payload = self.health()
                self.assertEqual(code, 1)
                self.assertEqual(payload['reasons'].count('backup_interrupted'), 1)

    def test_full_preflight_failure_persists_and_repeats_alerts_after_subset(self):
        self.cfg['notification_command'] = ['/test/notify']
        self.backup()
        self.fail_full_preflight()
        fk.backup_invocation(self.cfg, lambda: self.backup(requested=[101]), self.run)
        for _ in range(2):
            code, payload = self.health()
            self.assertEqual(code, 1)
            self.assertIn('full_backup_invocation_failed', payload['reasons'])
            self.assertEqual(self.run.notification_payload, payload)
        self.backup(requested=[101, 201])
        self.assertEqual(self.health()[0], 0)

    def test_preflight_check_cannot_clear_full_failure(self):
        self.backup()
        self.fail_full_preflight()
        state = Path(self.cfg['state_dir'])
        before = {p.name: p.read_bytes() for p in state.iterdir()}
        self.backup(check=True)
        self.assertEqual({p.name: p.read_bytes() for p in state.iterdir()}, before)
        self.assertEqual(self.health()[0], 1)

    def test_failed_full_publication_cannot_clear_preflight_failure(self):
        self.backup()
        self.fail_full_preflight()
        self.run.fail = lambda a: 'copyto' in a and a[5].endswith('/COMPLETE.json')
        with self.assertRaises(fk.Failure):
            self.backup()
        self.assertIn('full_backup_invocation_failed', self.health()[1]['reasons'])
        self.run.fail = lambda a: False
        run_id = self.latest()['run_id']
        fk.backup_invocation(self.cfg, lambda: fk.resume_backup(self.cfg, run_id, execute=True, run=self.run), self.run)
        self.assertEqual(self.health()[0], 0)

    def test_subset_failure_does_not_create_persistent_full_failure(self):
        self.backup()
        self.run.bad_encryption = True
        with self.assertRaises(fk.Failure):
            fk.backup_invocation(self.cfg, lambda: self.backup(requested=[101]), self.run)
        self.run.bad_encryption = False
        fk.backup_invocation(self.cfg, lambda: self.backup(requested=[101]), self.run)
        self.assertEqual(self.health()[0], 0)

    def test_cli_records_full_scope_only_for_unrestricted_backup(self):
        def fail(*args):
            raise fk.Failure('synthetic preflight failure')
        for guests in ([], ['101']):
            with self.subTest(guests=guests), patch.object(fk, 'load_config', return_value=self.cfg), \
                 patch.object(fk.signal, 'signal'), patch.object(fk.os, 'umask'), \
                 patch.object(fk.Backup, 'execute', side_effect=fail), \
                 contextlib.redirect_stderr(io.StringIO()):
                marker = Path(self.cfg['state_dir']) / 'full-attempt.json'
                marker.unlink(missing_ok=True)
                self.assertEqual(fk.main(['backup', *guests]), 1)
                self.assertEqual(marker.exists(), not guests)
        with patch.object(fk, 'load_config', return_value=self.cfg), \
             patch.object(fk.signal, 'signal'), patch.object(fk.os, 'umask'), \
             patch.object(fk.Backup, 'execute', return_value=0), \
             patch.object(fk, 'backup_invocation', side_effect=AssertionError('check must not record an attempt')):
            self.assertEqual(fk.main(['backup', '--check']), 0)


class RecoveryFailureTests(unittest.TestCase):
    setUp = fixtures.WorkflowTests.setUp
    tearDown = fixtures.WorkflowTests.tearDown
    pack = staticmethod(fixtures.WorkflowTests.pack)
    backup = fixtures.WorkflowTests.backup
    latest = fixtures.WorkflowTests.latest
    restore_fixture = fixtures.WorkflowTests.restore_fixture
    interrupted_fixture = fixtures.WorkflowTests.interrupted_fixture

    def test_interrupted_download_removes_partial_and_allows_retry(self):
        restore, run_id, entry, local = self.restore_fixture()
        original = restore.rclone.call
        for error in (fk.Interrupted('test interruption'), subprocess.TimeoutExpired('fixture', 1)):
            with self.subTest(error=type(error).__name__):
                destination = self.root / type(error).__name__
                def interrupted(*args, **kwargs):
                    if kwargs.get('output_file') is not None:
                        kwargs['output_file'].write(b'partial')
                        raise error
                    return original(*args, **kwargs)
                with patch.object(restore.rclone, 'call', side_effect=interrupted):
                    with self.assertRaises(type(error)):
                        restore.download(run_id, entry['path'], destination)
                self.assertFalse((destination / entry['path']).exists())
                self.assertEqual(list(destination.glob('.download-*')), [])
                downloaded = restore.download(run_id, entry['path'], destination)
                self.assertEqual(downloaded.read_bytes(), local.read_bytes())
                self.assertEqual(destination.stat().st_mode & 0o077, 0)

    def test_download_keeps_file_created_during_transfer(self):
        restore, run_id, entry, _ = self.restore_fixture()
        destination = self.root / 'downloads'
        target = destination / entry['path']
        original = restore.rclone.call
        def racing_writer(*args, **kwargs):
            result = original(*args, **kwargs)
            if kwargs.get('output_file') is not None:
                target.write_bytes(b'created by another process')
            return result
        with patch.object(restore.rclone, 'call', side_effect=racing_writer):
            with self.assertRaises(FileExistsError):
                restore.download(run_id, entry['path'], destination)
        self.assertEqual(target.read_bytes(), b'created by another process')
        self.assertEqual(list(destination.glob('.download-*')), [])

    def test_same_size_corruption_never_publishes_download(self):
        restore, run_id, entry, _ = self.restore_fixture()
        obj = self.run.objects[fk.entry_remote(self.cfg, run_id, entry)]
        obj['data'] = bytes([obj['data'][0] ^ 1]) + obj['data'][1:]
        destination = self.root / 'downloads'
        with self.assertRaisesRegex(fk.Failure, 'SHA-256'):
            restore.download(run_id, entry['path'], destination)
        self.assertFalse((destination / entry['path']).exists())
        self.assertEqual(list(destination.glob('.download-*')), [])

    def test_insufficient_download_space_stops_before_payload_read(self):
        restore, run_id, entry, _ = self.restore_fixture()
        destination = self.root / 'downloads'
        self.run.calls.clear()
        with patch.object(fk.shutil, 'disk_usage', return_value=type('Usage', (), {'free': entry['size']})()):
            with self.assertRaisesRegex(fk.Failure, 'Insufficient space'):
                restore.download(run_id, entry['path'], destination)
        remote = fk.entry_remote(self.cfg, run_id, entry)
        self.assertFalse(any('cat' in call and remote in call for call in self.run.calls))
        self.assertEqual(list(destination.glob('.download-*')), [])

    def test_restore_failures_preserve_archive_and_restore_log_destination(self):
        _, run_id, entry, local = self.restore_fixture()
        previous_log = io.StringIO()
        backend = self.run
        class LoggedFixtureRunner(fk.Runner):
            def __call__(self, argv, **kwargs):
                if argv[0] in ('zstd', 'qmrestore'):
                    self.log.write('synthetic restore diagnostic\n')
                return backend(argv, **kwargs)
        runner = LoggedFixtureRunner(log=previous_log)
        restore = fk.Restore(self.cfg, runner)
        original = local.read_bytes()
        for failure in ('zstd', 'qmrestore'):
            with self.subTest(failure=failure):
                backend.calls.clear()
                backend.fail = lambda args: args[0] == failure
                with self.assertRaises(fk.Failure):
                    restore.guest(run_id, entry['path'], local, 901, 'local-zfs', execute=True)
                self.assertIs(runner.log, previous_log)
                self.assertFalse(previous_log.closed)
                self.assertEqual(local.read_bytes(), original)
                restores = [call for call in backend.calls if call[0] == 'qmrestore']
                self.assertEqual(len(restores), int(failure == 'qmrestore'))
                self.assertFalse(any(call[0] in ('qm', 'pct') and call[1] in ('start', 'destroy', 'set') for call in backend.calls))
                with fk.Lock(self.cfg['lock_file']):
                    pass
        logs = list((Path(self.cfg['state_dir']) / 'restore-logs').glob('*.log'))
        self.assertEqual(len(logs), 2)
        for log in logs:
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            self.assertIn('synthetic restore diagnostic', log.read_text())

    def test_restore_requires_confirmation_that_guest_is_stopped(self):
        restore, run_id, entry, local = self.restore_fixture()
        self.run.running_guest = True
        self.run.calls.clear()
        with self.assertRaisesRegex(fk.Failure, 'not confirmed stopped'):
            restore.guest(run_id, entry['path'], local, 901, 'local-zfs', execute=True)
        self.assertTrue(local.is_file())
        self.assertEqual(sum(call[0] == 'qmrestore' for call in self.run.calls), 1)
        self.assertFalse(any(call[0] in ('qm', 'pct') and call[1] in ('start', 'destroy') for call in self.run.calls))

    def test_ambiguous_retrieval_status_is_not_accepted(self):
        restore, run_id, entry, _ = self.restore_fixture()
        original = restore.rclone.json
        for response in ({}, [], [{'Remote': 'other-object'}],
                         [{'Remote': 'encrypted-object'}, {'Remote': 'encrypted-object'}]):
            with self.subTest(response=response):
                def ambiguous(*args, **kwargs):
                    if args[:2] == ('backend', 'restore-status'):
                        return response
                    return original(*args, **kwargs)
                with patch.object(restore.rclone, 'json', side_effect=ambiguous):
                    with self.assertRaisesRegex(fk.Failure, 'retrieval status|Retrieval status'):
                        restore.retrieval_status(run_id, entry['path'])

    def test_resume_without_guest_metadata_preserves_original_run(self):
        old = self.interrupted_fixture()
        work = Path(self.cfg['staging_dir']) / old['run_id']
        old['files'] = [e for e in old['files'] if e['role'] != 'guest_metadata']
        fk.atomic_json(work / 'MANIFEST.json', old)
        before = {str(p.relative_to(work)): p.read_bytes() for p in work.rglob('*') if p.is_file()}
        remote_before = {key: dict(value) for key, value in self.run.objects.items()}
        self.run.calls.clear()
        with self.assertRaisesRegex(fk.Failure, 'lacks backup metadata'):
            fk.resume_backup(self.cfg, old['run_id'], execute=True, run=self.run)
        after = {str(p.relative_to(work)): p.read_bytes() for p in work.rglob('*') if p.is_file()}
        self.assertEqual(after, before)
        self.assertEqual(self.run.objects, remote_before)
        self.assertEqual(list(Path(self.cfg['staging_dir']).iterdir()), [work])
        self.assertFalse(any(call[0] == 'vzdump' or 'copyto' in call for call in self.run.calls))


@unittest.skipUnless(shutil.which("rclone"), "Install rclone for local streaming integration")
class RecoveryCryptIntegration(unittest.TestCase):
    def test_binary_stream_count_corruption_and_encrypted_name_encodings(self):
        binary = shutil.which("rclone")
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            config = root / "rclone.conf"
            secret = subprocess.check_output([binary, "obscure", uuid.uuid4().hex], text=True).strip()
            payload = os.urandom(150000)
            source = root / "source.bin"
            source.write_bytes(payload)
            process = fk.Runner(timeout=30)
            def runner(argv, **kwargs):
                return process([binary, *argv[1:]], **kwargs)
            for encoding in ("base32", "base64", "base32768"):
                with self.subTest(encoding=encoding):
                    encrypted_root = root / encoding
                    config.write_text(f"[archive]\ntype = crypt\nremote = {encrypted_root}\npassword = {secret}\nfilename_encryption = standard\ndirectory_name_encryption = true\nfilename_encoding = {encoding}\n")
                    config.chmod(0o600)
                    cfg = dict(fk.DEFAULTS, rclone_config=str(config))
                    rclone = fk.Rclone(cfg, runner)
                    rclone.call("copyto", str(source), "archive:run/payload.bin", capture=False)
                    with patch.object(rclone, "encryption", return_value="raw:bucket"):
                        raw = rclone.raw_object("run/payload.bin")
                    encoded = raw.removeprefix("raw:bucket/")
                    encrypted = encrypted_root / encoded
                    self.assertTrue(encrypted.is_file())
                    target = root / (encoding + ".download")
                    with target.open("wb", buffering=0) as stream:
                        rclone.call("cat", "archive:run/payload.bin", "--count", str(len(payload) + 1),
                                    capture=False, output_file=stream, max_output_bytes=len(payload))
                    self.assertEqual(target.read_bytes(), payload)
                    with target.open("wb", buffering=0) as stream:
                        with self.assertRaises(fk.Failure):
                            rclone.call("cat", "archive:run/payload.bin", "--count", "1001",
                                        capture=False, output_file=stream, max_output_bytes=1000)
                    self.assertLessEqual(target.stat().st_size, 1000)
                    damaged = bytearray(encrypted.read_bytes())
                    damaged[-1] ^= 1
                    encrypted.write_bytes(damaged)
                    with target.open("wb", buffering=0) as stream:
                        with self.assertRaises(fk.Failure):
                            rclone.call("cat", "archive:run/payload.bin", "--count", str(len(payload) + 1),
                                        capture=False, output_file=stream, max_output_bytes=len(payload))


if __name__ == "__main__":
    unittest.main()
