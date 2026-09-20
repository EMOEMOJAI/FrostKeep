"""Failure-oriented tests. No network, credentials or Proxmox host required."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "lib/frostkeep/frostkeep.py"
spec = importlib.util.spec_from_file_location("frostkeep", MODULE)
fk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fk)


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.objects = {}
        self.fail = lambda args: False
        self.bad_tier = False
        self.bad_size = False
        self.hide_guest = False
        self.extra_archives = False
        self.no_archive = False
        self.running_guest = False
        self.conflict = False
        self.bad_encryption = False
        self.notification_payload = None

    def __call__(self, argv, **kwargs):
        a = [str(v) for v in argv]
        self.calls.append(a)
        if self.fail(a):
            raise fk.Failure("injected command failure")
        if a[0] == "rclone":
            a = a[3:]
            if a[:2] == ["config", "redacted"]:
                crypt_type = "s3" if self.bad_encryption else "crypt"
                return f"[archive]\ntype = {crypt_type}\nremote = raw:example-bucket/archives\n[raw]\ntype = s3\nprovider = AWS\n"
            if a[0] == "lsf":
                return ""
            if a[0] == "copyto":
                if Path(a[1]).is_file():
                    tier = a[a.index("--s3-storage-class") + 1]
                    self.objects[a[2]] = {"data": Path(a[1]).read_bytes(), "Tier": tier}
                else:
                    Path(a[2]).write_bytes(self.objects[a[1]]["data"])
                return ""
            if a[0] == "lsjson":
                if "--stat" in a:
                    if a[1] not in self.objects:
                        raise fk.Failure("Remote object is missing")
                    obj = self.objects[a[1]]
                    return json.dumps({"Size": len(obj["data"]) + int(self.bad_size), "Tier": "STANDARD" if self.bad_tier else obj["Tier"], "IsDir": False})
                prefix = a[1].rstrip("/") + "/"
                return json.dumps([{"Path": key[len(prefix):], "Size": len(obj["data"]), "Tier": obj["Tier"]}
                                   for key, obj in self.objects.items() if key.startswith(prefix) and not (self.hide_guest and key.endswith(".zst"))])
            if a[0] == "cat":
                payload = self.objects[a[1]]["data"]
                if "--count" in a:
                    payload = payload[:int(a[a.index("--count") + 1])]
                if kwargs.get("max_output_bytes") is not None and len(payload) > kwargs["max_output_bytes"]:
                    raise fk.Failure("Command output exceeds the configured limit")
                if kwargs.get("output_file") is not None:
                    if kwargs.get("output_check") is not None:
                        kwargs["output_check"](len(payload))
                    kwargs["output_file"].write(payload)
                    return ""
                return payload.decode()
            if a[:2] == ["backend", "encode"]:
                return json.dumps(["encrypted-run/encrypted-object"])
            if a[:2] == ["backend", "restore"]:
                return json.dumps([{"Remote": "encrypted-object", "Status": "OK"}])
            if a[:2] == ["backend", "restore-status"]:
                return json.dumps([{"Remote": "unselected-object", "RestoreStatus": None},
                                   {"Remote": "encrypted-object", "RestoreStatus": {"IsRestoreInProgress": True}}])
        if a[:2] == ["qm", "list"]:
            return "VMID NAME STATUS\n101 example running\n"
        if a[:2] == ["pct", "list"]:
            return "VMID Status Name\n201 running example\n"
        if a[0] == "vzdump":
            if self.no_archive:
                return ""
            ident = a[1]
            kind, ext = ("qemu", "vma") if ident == "101" else ("lxc", "tar")
            directory = Path(a[a.index("--dumpdir") + 1])
            name = f"vzdump-{kind}-{ident}-2026_01_01-00_00_00"
            (directory / (name + "." + ext + ".zst")).write_bytes(b"guest archive payload")
            (directory / (name + ".log")).write_text("completed backup\n")
            if self.extra_archives:
                (directory / (name + "_01." + ext + ".zst")).write_bytes(b"duplicate")
            return ""
        if a[0] == "perl":
            return json.dumps({"hasFeature": 1})
        if a[0] == "pvesh":
            return json.dumps([{"vmid": 901}] if self.conflict else [])
        if a[0] == "pvenode":
            return "[]"
        if a[0] in ("qm", "pct") and a[1] == "status":
            return "status: running" if self.running_guest else "status: stopped"
        if a[0] == "/test/notify":
            self.notification_payload = json.loads(kwargs["input_text"])
        return ""


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        # macOS /var is a symlink; use the physical temp path.
        self.root = Path(self.temp.name).resolve()
        self.cfg = copy.deepcopy(fk.DEFAULTS)
        self.cfg.update(staging_dir=str(self.root / "staging"), state_dir=str(self.root / "state"),
                        rclone_config=str(self.root / "rclone.conf"), lock_file=str(self.root / "run.lock"),
                        minimum_free_bytes=1, host_required_paths=[], host_optional_paths=[],
                        cluster_database=str(self.root / "cluster.db"))
        (self.root / "rclone.conf").write_text("fake")
        (self.root / "rclone.conf").chmod(0o600)
        with contextlib.closing(sqlite3.connect(self.root / "cluster.db")) as db:
            db.execute("create table config(value text)")
            db.commit()
        self.run = FakeRunner()
        self.which = patch.object(fk.shutil, "which", return_value="/usr/bin/fake")
        self.which.start()
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.host = patch.object(fk, "pack_host", side_effect=self.pack)
        self.host.start()

    def tearDown(self):
        self.host.stop()
        self.output.__exit__(None, None, None)
        self.which.stop()
        self.temp.cleanup()

    @staticmethod
    def pack(cfg, work, inventories, run):
        path = work / "hostconfig.tar.gz"
        path.write_bytes(b"host archive payload")
        return path

    def backup(self, **kwargs):
        return fk.Backup(self.cfg, self.run).execute(**kwargs)

    def latest(self):
        return json.loads((Path(self.cfg["state_dir"]) / "latest.json").read_text())

    def assert_no_complete(self):
        self.assertFalse(any(k.endswith("/COMPLETE.json") for k in self.run.objects))

    def restore_fixture(self):
        self.backup()
        manifest = self.latest()
        entry = next(e for e in manifest["files"] if e["role"] == "guest")
        local = self.root / "restore.zst"
        local.write_bytes(b"guest archive payload")
        local.chmod(0o600)
        return fk.Restore(self.cfg, self.run), manifest["run_id"], entry, local

    def test_success_isolated_coverage_and_tiers(self):
        staging = fk.private_dir(self.cfg["staging_dir"])
        unrelated = staging / "vzdump-qemu-999-older.vma.zst"
        unrelated.write_bytes(b"must not upload or delete")
        self.assertEqual(self.backup(), 0)
        manifest = self.latest()
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(len([e for e in manifest["files"] if e["role"] == "guest"]), 2)
        self.assertTrue(unrelated.exists())
        self.assertFalse(any("999" in k for k in self.run.objects))
        self.assertFalse(list((staging / manifest["run_id"]).glob("*/*.zst")))
        fk.Restore(self.cfg, self.run).manifest(manifest["run_id"])
        self.assertTrue(all("--immutable" in c for c in self.run.calls if "copyto" in c))

    def test_check_never_dumps_or_uploads(self):
        self.backup(check=True)
        self.assertFalse(any(c[0] == "vzdump" or "copyto" in c for c in self.run.calls))
        self.assertFalse(self.run.objects)

    def test_either_inventory_query_failure_stops_before_upload(self):
        for cmd in ("qm", "pct"):
            self.run.fail = lambda a, cmd=cmd: a[:2] == [cmd, "list"]
            with self.assertRaises(fk.Failure):
                self.backup()
            self.assertFalse(self.run.objects)

    def test_unknown_guest_rejected_before_upload(self):
        with self.assertRaises(fk.Failure):
            self.backup(requested=[999])
        self.assertFalse(self.run.objects)

    def test_malformed_and_empty_inventories_are_rejected(self):
        for value in ("", "not an inventory", "VMID NAME\ninvalid guest\n", "VMID NAME\n"):
            with self.subTest(value=value), self.assertRaises(fk.Failure):
                fk.discover(lambda argv: value)

    def test_duplicate_guest_inventory_is_rejected(self):
        with self.assertRaises(fk.Failure):
            fk.discover(lambda argv: "VMID NAME\n101 duplicate\n")

    def test_empty_selection_rejected(self):
        self.cfg["exclude_guests"] = [101, 201]
        with self.assertRaises(fk.Failure):
            self.backup()
        self.assertFalse(self.run.objects)

    def test_unencrypted_destination_rejected(self):
        self.run.bad_encryption = True
        with self.assertRaises(fk.Failure):
            self.backup()
        self.assertFalse(self.run.objects)

    def test_overlap_rejected(self):
        with fk.Lock(self.cfg["lock_file"]):
            with self.assertRaises(fk.Failure):
                self.backup()
        self.assertFalse(self.run.objects)

    def test_host_tar_error_is_fatal(self):
        fk.pack_host.side_effect = fk.Failure("tar failed")
        with self.assertRaises(fk.Failure):
            self.backup()
        self.assertEqual(self.latest()["status"], "failed")
        self.assert_no_complete()
        self.assertFalse(any(c[0] == "vzdump" for c in self.run.calls))

    def test_failed_dump_continues_other_guest_but_fails_run(self):
        self.run.fail = lambda a: a[:2] == ["vzdump", "101"]
        with self.assertRaises(fk.Failure):
            self.backup()
        self.assertEqual([g["status"] for g in self.latest()["guests"]], ["failed", "complete"])
        self.assert_no_complete()

    def test_failed_upload_preserves_archive(self):
        self.run.fail = lambda a: "copyto" in a and a[4].endswith(".zst")
        with self.assertRaises(fk.Failure):
            self.backup()
        self.assertEqual(len(list(Path(self.cfg["staging_dir"]).glob("*/*/*.zst"))), 2)
        self.assert_no_complete()

    def test_failed_metadata_upload_fails_guest_and_preserves_dump(self):
        self.run.fail = lambda a: "copyto" in a and a[4].endswith(".log")
        with self.assertRaises(fk.Failure):
            self.backup()
        self.assertEqual(len(list(Path(self.cfg["staging_dir"]).glob("*/*/*.zst"))), 2)
        self.assert_no_complete()

    def test_missing_or_duplicate_archive_fails(self):
        for flag in ("no_archive", "extra_archives"):
            with self.subTest(flag=flag):
                setattr(self.run, flag, True)
                with self.assertRaises(fk.Failure):
                    self.backup()
                setattr(self.run, flag, False)
                self.assert_no_complete()

    def test_corrupt_compressed_dump_is_not_uploaded(self):
        self.run.fail = lambda a: a[0] == "zstd"
        with self.assertRaises(fk.Failure):
            self.backup()
        self.assertFalse(any(k.endswith(".zst") for k in self.run.objects))

    def test_remote_coverage_failure_prevents_completion(self):
        self.run.hide_guest = True
        with self.assertRaises(fk.Failure):
            self.backup()
        self.assert_no_complete()

    def test_wrong_tier_or_size_prevents_completion(self):
        for attr in ("bad_tier", "bad_size"):
            with self.subTest(attr=attr):
                setattr(self.run, attr, True)
                with self.assertRaises(fk.Failure):
                    self.backup()
                setattr(self.run, attr, False)
                self.assert_no_complete()

    def test_manifest_or_completion_upload_failure_not_success(self):
        for name in ("MANIFEST.json", "COMPLETE.json"):
            self.run.fail = lambda a, name=name: "copyto" in a and a[5].endswith("/" + name)
            with self.assertRaises(fk.Failure):
                self.backup()
            self.assertEqual(self.latest()["status"], "failed")
            self.assert_no_complete()

    def test_signal_records_interrupted_and_retains_archive(self):
        original = self.run
        def interrupted(argv, **kwargs):
            if "copyto" in argv and str(argv[4]).endswith(".zst"):
                raise fk.Interrupted("injected termination")
            return original(argv, **kwargs)
        with self.assertRaises(fk.Interrupted):
            fk.Backup(self.cfg, interrupted).execute()
        self.assertEqual(self.latest()["status"], "interrupted")
        self.assertTrue(list(Path(self.cfg["staging_dir"]).glob("*/*/*.zst")))
        self.assert_no_complete()

    def test_repeat_runs_have_unique_destinations(self):
        self.backup()
        first = self.latest()["run_id"]
        self.backup()
        self.assertNotEqual(first, self.latest()["run_id"])
        self.assertEqual(len([k for k in self.run.objects if k.endswith("/COMPLETE.json")]), 2)

    def test_stale_status_detects_unlocked_incomplete_run(self):
        self.backup()
        data = self.latest()
        data["status"] = "running"
        fk.atomic_json(Path(self.cfg["state_dir"]) / "latest.json", data)
        self.assertEqual(fk.status(self.cfg), 1)

    def test_notification_does_not_include_guest_names_or_remote(self):
        self.cfg["notification_command"] = ["/test/notify"]
        self.backup()
        self.assertEqual(self.run.notification_payload["status"], "complete")
        self.assertNotIn("guests", self.run.notification_payload)
        self.assertNotIn("remote", self.run.notification_payload)

    def test_notification_failure_keeps_verified_backup_complete(self):
        self.cfg["notification_command"] = ["/test/notify"]
        self.run.fail = lambda argv: argv[0] == "/test/notify"
        with contextlib.redirect_stderr(io.StringIO()):
            self.backup()
        manifest = self.latest()
        self.assertEqual(manifest["status"], "complete")
        fk.Restore(self.cfg, self.run).manifest(manifest["run_id"])
        self.assertTrue((Path(self.cfg["staging_dir"]) / manifest["run_id"] / "notification.json").exists())

    def test_restore_download_checks_hash_and_refuses_overwrite(self):
        restore, run_id, entry, local = self.restore_fixture()
        directory = self.root / "downloads"
        dest = restore.download(run_id, entry["path"], directory)
        self.assertEqual(dest.read_bytes(), local.read_bytes())
        with self.assertRaises(fk.Failure):
            restore.download(run_id, entry["path"], directory)

    def test_corrupt_download_is_not_published(self):
        restore, run_id, entry, local = self.restore_fixture()
        key = fk.remote_join(self.cfg["remote"], run_id + "/" + entry["path"])
        self.run.objects[key]["data"] = b"corrupted"
        with self.assertRaises(fk.Failure):
            restore.download(run_id, entry["path"], self.root / "downloads")
        self.assertFalse((self.root / "downloads" / entry["path"]).exists())

    def test_tampered_manifest_rejected(self):
        restore, run_id, entry, local = self.restore_fixture()
        key = fk.remote_join(self.cfg["remote"], run_id + "/MANIFEST.json")
        self.run.objects[key]["data"] += b" "
        with self.assertRaises(fk.Failure):
            restore.manifest(run_id)

    def test_failed_or_incomplete_run_is_not_restorable(self):
        restore, run_id, entry, local = self.restore_fixture()
        key = fk.remote_join(self.cfg["remote"], run_id + "/COMPLETE.json")
        del self.run.objects[key]
        with self.assertRaises(fk.Failure):
            restore.manifest(run_id)

    def test_retrieval_defaults_to_plan_and_targets_one_encrypted_object(self):
        restore, run_id, entry, local = self.restore_fixture()
        restore.request(run_id, entry["path"])
        self.assertFalse(any("restore" in c for c in self.run.calls))
        restore.request(run_id, entry["path"], execute=True)
        call = next(c for c in self.run.calls if "restore" in c)
        self.assertIn("/encrypted-object", call)
        self.assertNotIn(entry["path"], call)
        self.assertIn("priority=Bulk", call)

    def test_guest_restore_plan_and_no_force_or_start(self):
        restore, run_id, entry, local = self.restore_fixture()
        restore.guest(run_id, entry["path"], local, 901, "local-zfs")
        self.assertFalse(any(c[0] == "qmrestore" for c in self.run.calls))
        restore.guest(run_id, entry["path"], local, 901, "local-zfs", execute=True)
        command = next(c for c in self.run.calls if c[0] == "qmrestore")
        self.assertNotIn("--force", command)
        self.assertEqual(command[command.index("--start") + 1], "0")

    def test_retrieval_status_selects_exact_object_from_directory(self):
        restore, run_id, entry, local = self.restore_fixture()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            restore.retrieval_status(run_id, entry["path"])
        value = json.loads(output.getvalue())
        self.assertEqual(value["Remote"], "encrypted-object")
        call = next(c for c in self.run.calls if "restore-status" in c)
        self.assertTrue(call[5].endswith("/encrypted-run"))
        self.assertNotIn("--include", call)

    def test_restore_rejects_world_readable_local_archive(self):
        restore, run_id, entry, local = self.restore_fixture()
        local.chmod(0o644)
        with self.assertRaises(fk.Failure):
            restore.guest(run_id, entry["path"], local, 901, "local-zfs", execute=True)

    def test_guest_restore_rejects_existing_id_and_original_id(self):
        restore, run_id, entry, local = self.restore_fixture()
        with self.assertRaises(fk.Failure):
            restore.guest(run_id, entry["path"], local, entry["guest_id"], "local-zfs", execute=True)
        self.run.conflict = True
        with self.assertRaises(fk.Failure):
            restore.guest(run_id, entry["path"], local, 901, "local-zfs", execute=True)
        self.assertFalse(any(c[0] == "qmrestore" for c in self.run.calls))

    def test_guest_restore_rejects_modified_local_file(self):
        restore, run_id, entry, local = self.restore_fixture()
        local.write_bytes(b"tampered")
        with self.assertRaises(fk.Failure):
            restore.guest(run_id, entry["path"], local, 901, "local-zfs", execute=True)

    def test_restore_traversal_and_options_rejected(self):
        for path in ("../secret", "/etc/shadow", "a/../../b", "--config", "a\nb", "a//b", "a\\b"):
            with self.subTest(path=path), self.assertRaises(fk.Failure):
                fk.relative_path(path)

    def test_symlink_staging_is_rejected(self):
        (self.root / "target").mkdir()
        Path(self.cfg["staging_dir"]).symlink_to(self.root / "target")
        with self.assertRaises(fk.Failure):
            self.backup()

    def test_private_config_permissions_and_unknown_keys(self):
        path = self.root / "config.json"
        path.write_text(json.dumps(self.cfg))
        path.chmod(0o644)
        with self.assertRaises(fk.Failure):
            fk.load_config(path)
        path.chmod(0o600)
        self.assertEqual(fk.load_config(path)["remote"], "archive:")
        data = dict(self.cfg, typo=True)
        path.write_text(json.dumps(data))
        with self.assertRaises(fk.Failure):
            fk.load_config(path)

    def interrupted_fixture(self):
        self.run.fail = lambda a: a[:2] == ["vzdump", "201"]
        with self.assertRaises(fk.Failure):
            self.backup()
        old = self.latest()
        self.run.fail = lambda a: False
        self.run.calls.clear()
        return old

    def test_resume_plan_does_not_dump_or_upload(self):
        old = self.interrupted_fixture()
        fk.resume_backup(self.cfg, old["run_id"], run=self.run)
        self.assertFalse(any(a[0] == "vzdump" or "copyto" in a for a in self.run.calls))

    def test_resume_reuses_completed_archive_and_restore_resolves_origin(self):
        old = self.interrupted_fixture()
        fk.resume_backup(self.cfg, old["run_id"], execute=True, run=self.run)
        fresh = self.latest()
        self.assertNotEqual(old["run_id"], fresh["run_id"])
        self.assertEqual([a[1] for a in self.run.calls if a[0] == "vzdump"], ["201"])
        archive = next(e for e in fresh["files"] if e.get("guest_id") == 101 and e["role"] == "guest")
        self.assertEqual(archive["source_run"], old["run_id"])
        self.assertIn(f"archive:{old['run_id']}/FAILED.json", self.run.objects)
        restore = fk.Restore(self.cfg, self.run)
        restore.download(fresh["run_id"], archive["path"], self.root / "download")
        self.assertEqual((self.root / "download" / archive["path"]).read_bytes(), b"guest archive payload")
        self.assertFalse(any("copyto" in a and a[3].startswith("archive:") and fresh["run_id"] in a[3] for a in self.run.calls))

    def test_resume_refuses_changed_storage_context(self):
        old = self.interrupted_fixture()
        self.cfg["remote"] = "archive:changed"
        with self.assertRaises(fk.Failure):
            fk.resume_backup(self.cfg, old["run_id"], execute=True, run=self.run)
        self.assertFalse(any(a[0] == "vzdump" for a in self.run.calls))

    def test_resume_refuses_changed_exclusions(self):
        old = self.interrupted_fixture()
        self.cfg["exclude_guests"] = [201]
        with self.assertRaises(fk.Failure):
            fk.resume_backup(self.cfg, old["run_id"], execute=True, run=self.run)
        self.assertFalse(any(a[0] == "vzdump" for a in self.run.calls))

    def test_resume_rechecks_remote_objects_before_writes(self):
        old = self.interrupted_fixture()
        self.run.bad_size = True
        with self.assertRaises(fk.Failure):
            fk.resume_backup(self.cfg, old["run_id"], execute=True, run=self.run)
        self.assertFalse(any("copyto" in a for a in self.run.calls))

    def test_resume_and_cleanup_refuse_active_lock(self):
        old = self.interrupted_fixture()
        with fk.Lock(self.cfg["lock_file"]):
            for action in (lambda: fk.resume_backup(self.cfg, old["run_id"], run=self.run),
                           lambda: fk.cleanup(self.cfg, old["run_id"], run=self.run)):
                with self.assertRaises(fk.Failure):
                    action()

    def test_proxmox_worker_outliving_client_blocks_recovery(self):
        with self.assertRaises(fk.Failure):
            fk.assert_no_active_tasks(lambda argv, **kwargs: '[{"type":"vzdump"}]')
        with self.assertRaises(fk.Failure):
            fk.assert_no_active_tasks(lambda argv, **kwargs: '[{"unexpected":true}]')

    def test_cleanup_plan_and_execution_preserve_remote_and_audit(self):
        self.cfg["keep_local_archives"] = True
        self.backup()
        data = self.latest()
        work = Path(self.cfg["staging_dir"]) / data["run_id"]
        objects = copy.deepcopy(self.run.objects)
        fk.cleanup(self.cfg, data["run_id"], run=self.run)
        self.assertTrue(work.is_dir())
        fk.cleanup(self.cfg, data["run_id"], execute=True, run=self.run)
        self.assertFalse(work.exists())
        self.assertEqual(objects, self.run.objects)
        self.assertTrue((Path(self.cfg["state_dir"]) / "cleanup" / (data["run_id"] + ".json")).is_file())

    def test_cleanup_requires_incomplete_acknowledgment_and_rejects_symlinks(self):
        old = self.interrupted_fixture()
        with self.assertRaises(fk.Failure):
            fk.cleanup(self.cfg, old["run_id"], execute=True, run=self.run)
        work = Path(self.cfg["staging_dir"]) / old["run_id"]
        (work / "outside").symlink_to(self.root / "cluster.db")
        with self.assertRaises(fk.Failure):
            fk.cleanup(self.cfg, old["run_id"], execute=True, allow_incomplete=True, run=self.run)
        self.assertTrue(work.is_dir())

    def test_partial_success_does_not_reset_freshness(self):
        self.backup(requested=[101])
        self.assertFalse((Path(self.cfg["state_dir"]) / "last-success.json").exists())
        self.assertEqual(fk.health(self.cfg), 1)

    def test_full_success_and_overdue_health(self):
        self.backup()
        self.assertEqual(fk.health(self.cfg), 0)
        future = fk.dt.datetime.now(fk.dt.timezone.utc) + fk.dt.timedelta(hours=self.cfg["maximum_backup_age_hours"] + 1)
        self.assertEqual(fk.health(self.cfg, now=future), 1)

    def test_subset_success_cannot_hide_failed_full_backup(self):
        self.backup()
        self.interrupted_fixture()
        self.backup(requested=[101])
        self.assertEqual(fk.health(self.cfg), 1)

    def test_resume_does_not_make_old_guest_snapshots_fresh(self):
        self.backup()
        path = Path(self.cfg["state_dir"]) / "last-success.json"
        data = json.loads(path.read_text())
        old = fk.dt.datetime.now(fk.dt.timezone.utc) - fk.dt.timedelta(hours=self.cfg["maximum_backup_age_hours"] + 1)
        entry = next(e for e in data["files"] if e["role"] == "guest")
        entry["source_run"] = old.strftime("%Y%m%dT%H%M%SZ-") + "a" * 12
        fk.atomic_json(path, data)
        self.assertEqual(fk.health(self.cfg), 1)

    def test_preflight_failure_records_attempt_and_notifies_without_identifiers(self):
        self.cfg["notification_command"] = ["/test/notify"]
        self.run.bad_encryption = True
        with self.assertRaises(fk.Failure):
            fk.backup_invocation(self.cfg, self.backup, self.run)
        self.assertEqual(self.run.notification_payload["event"], "backup_invocation")
        self.assertEqual(self.run.notification_payload["status"], "failed")
        self.assertNotIn("remote", self.run.notification_payload)
        self.assertEqual(fk.health(self.cfg, notify=True, run=self.run), 1)
        self.assertIn("backup_invocation_failed", self.run.notification_payload["reasons"])

    def test_health_delivery_failure_is_nonzero_and_retried(self):
        self.cfg["notification_command"] = ["/test/notify"]
        self.run.fail = lambda a: a[0] == "/test/notify"
        self.assertEqual(fk.health(self.cfg, notify=True, run=self.run), 2)
        self.run.fail = lambda a: False
        self.assertEqual(fk.health(self.cfg, notify=True, run=self.run), 1)
        self.assertEqual(self.run.notification_payload["status"], "unhealthy")

    def test_unwritable_state_does_not_prevent_failure_notification(self):
        self.cfg["notification_command"] = ["/test/notify"]
        with patch.object(fk, "private_dir", side_effect=OSError("state unavailable")):
            with self.assertRaises(OSError):
                fk.backup_invocation(self.cfg, lambda: None, self.run)
        self.assertEqual(self.run.notification_payload["status"], "failed")

    def test_corrupt_state_emits_health_alert(self):
        self.backup()
        (Path(self.cfg["state_dir"]) / "latest.json").write_text("corrupt")
        self.cfg["notification_command"] = ["/test/notify"]
        self.assertEqual(fk.health(self.cfg, notify=True, run=self.run), 1)
        self.assertIn("invalid_health_state", self.run.notification_payload["reasons"])

    def test_retained_archives_are_private(self):
        self.cfg["keep_local_archives"] = True
        self.backup()
        archives = list(Path(self.cfg["staging_dir"]).glob("*/*/*.zst"))
        self.assertEqual(len(archives), 2)
        self.assertTrue(all(a.stat().st_mode & 0o077 == 0 for a in archives))

    def test_real_host_packer_fails_closed_and_snapshots_database(self):
        self.host.stop()
        work = fk.private_dir(self.root / "host-test")
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if argv[0] == "tar":
                raise fk.Failure("tar failed")
            return "inventory\n"
        with self.assertRaises(fk.Failure):
            fk.pack_host(self.cfg, work, {"qemu": "VMID", "lxc": "VMID"}, run)
        self.assertTrue((work / "inventory/config.db").is_file())
        self.assertTrue(any(c[0] == "tar" for c in calls))


class ProcessTests(unittest.TestCase):
    def test_subprocess_umask_is_scoped_and_private_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "normal", Path(directory) / "dump"
            run = fk.Runner()
            script = "import os,sys;os.mkdir(sys.argv[1])"
            run([sys.executable, "-c", script, str(first)])
            run([sys.executable, "-c", script, str(second)], umask=0o022)
            self.assertEqual(first.stat().st_mode & 0o777, 0o700)
            self.assertEqual(second.stat().st_mode & 0o777, 0o755)

    def test_mapped_root_uid_and_invalid_custom_maps(self):
        self.assertEqual(fk.container_root_uid("unprivileged: 1\n"), 100000)
        self.assertEqual(fk.container_root_uid("unprivileged: 0\n"), 0)
        self.assertEqual(fk.container_root_uid("unprivileged: 1\nlxc.idmap: u 0 165536 65536\n"), 165536)
        for mapping in ("bad", "u 1 165536 65536", "u 0 0 65536", "u 0 165536 0"):
            with self.subTest(mapping=mapping), self.assertRaises(fk.Failure):
                fk.container_root_uid("unprivileged: 1\nlxc.idmap: " + mapping + "\n")

    def test_timeout_kills_command_group(self):
        run = fk.Runner(timeout=1)
        with self.assertRaises(subprocess.TimeoutExpired):
            run([sys.executable, "-c", "import time; time.sleep(30)"])

    def test_signal_handling_stops_child(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "signal_probe.py"
            script.write_text(
                f"import importlib.util, signal, sys\ns=importlib.util.spec_from_file_location('fk', {str(MODULE)!r})\n"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n"
                "def stop(*a): raise m.Interrupted('stop')\n"
                "signal.signal(signal.SIGTERM, stop)\n"
                "try: m.Runner()([sys.executable, '-c', 'import time;time.sleep(30)'])\n"
                "except m.Interrupted: sys.exit(42)\n")
            proc = subprocess.Popen([sys.executable, str(script)])
            try:
                import time
                time.sleep(0.3)
                proc.send_signal(signal.SIGTERM)
                self.assertEqual(proc.wait(timeout=20), 42)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    unittest.main()
