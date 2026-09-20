"""Regression probes for bounded commands and backup preflight safety."""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("fk", Path(__file__).resolve().parents[1] / "lib/frostkeep/frostkeep.py")
fk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fk)


class BackupSafetyTests(unittest.TestCase):
    def test_root_equivalent_host_paths_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            alias = Path(directory) / "root-alias"
            alias.symlink_to("/", target_is_directory=True)
            for key in ("host_required_paths", "host_optional_paths"):
                for root in ("/", "/.", "/./", "///", str(alias)):
                    with self.subTest(key=key, root=root):
                        config.write_text(json.dumps({key: [root]}))
                        config.chmod(0o600)
                        with self.assertRaises(fk.Failure):
                            fk.load_config(config)

    def test_active_backup_beyond_default_page_is_rejected(self):
        records = [{"type": "vncproxy"}] * 50 + [{"type": "vzdump"}]
        def run(argv, **kwargs):
            selected = records
            if "--typefilter" in argv:
                kind = argv[argv.index("--typefilter") + 1]
                selected = [item for item in selected if item["type"] == kind]
            limit = int(argv[argv.index("--limit") + 1]) if "--limit" in argv else 50
            return json.dumps(selected[:limit])
        with self.assertRaises(fk.Failure):
            fk.assert_no_active_tasks(run)

    def test_each_relevant_worker_type_is_checked(self):
        for kind in ("vzdump", "vzrestore", "qmrestore", "qmigrate", "vzmigrate"):
            def run(argv, **kwargs):
                return json.dumps([{"type": kind}] if argv[argv.index("--typefilter") + 1] == kind else [])
            with self.subTest(kind=kind), self.assertRaises(fk.Failure):
                fk.assert_no_active_tasks(run)

    def test_snapshot_support_requires_explicit_typed_success(self):
        for answer in (True, 1):
            fk.assert_container_snapshot(lambda *a, **kw: json.dumps({"hasFeature": answer}), 201)
        for answer in (False, 0, 1.0, "1", None, [], {}):
            with self.subTest(answer=answer), self.assertRaises(fk.Failure):
                fk.assert_container_snapshot(lambda *a, **kw: json.dumps({"hasFeature": answer}), 201)
        with self.assertRaises(fk.Failure):
            fk.assert_container_snapshot(lambda *a, **kw: "invalid", 201)

    def test_snapshot_probe_requires_perl(self):
        with patch.object(fk.shutil, "which", return_value=None):
            with self.assertRaisesRegex(fk.Failure, "unavailable: perl"):
                fk.assert_container_snapshot(Mock(), 201)

    @unittest.skipUnless(shutil.which("perl"), "Perl is required for the capability fixture")
    def test_snapshot_probe_uses_backup_only_mount_selection(self):
        # Model the PVE contract: generic snapshots include an unsupported mp0,
        # but vzdump excludes it. Guest102 additionally has an unsupported rootfs.
        with tempfile.TemporaryDirectory() as directory:
            modules = Path(directory)
            (modules / "PVE/LXC").mkdir(parents=True)
            (modules / "PVE/Cluster.pm").write_text(
                "package PVE::Cluster; our $ready=0; sub cfs_update {$ready=1;} 1;\n")
            (modules / "PVE/Storage.pm").write_text(
                "package PVE::Storage; sub config {die 'cache not initialized' unless $PVE::Cluster::ready; return {};} 1;\n")
            (modules / "PVE/LXC/Config.pm").write_text("""
package PVE::LXC::Config;
sub load_config {
    my ($class, $id) = @_;
    die 'invalid fixture guest' unless $id eq '101' || $id eq '102';
    return {rootfs => {backup => 1, snapshot => ($id eq '101')},
            mp0 => {backup => 0, snapshot => 0}};
}
sub has_feature {
    my ($class, $feature, $conf, $storage, $snap, $running, $backup_only) = @_;
    die 'wrong capability contract' unless $feature eq 'snapshot' && !defined($snap) && !defined($running);
    foreach my $mount (values %$conf) {
        next if $backup_only && !$mount->{backup};
        return 0 unless $mount->{snapshot};
    }
    return 1;
}
1;
""")
            runner = fk.Runner(timeout=5)
            def run(argv, **kwargs):
                return runner([argv[0], "-I", str(modules), *argv[1:]], **kwargs)
            generic = fk.CONTAINER_SNAPSHOT_PROBE.replace("undef, undef, 1)", "undef, undef)")
            answer = run(["perl", "-e", generic, "--", "101"])
            self.assertEqual(json.loads(answer), {"hasFeature": 0})
            fk.assert_container_snapshot(run, 101)
            with self.assertRaises(fk.Failure):
                fk.assert_container_snapshot(run, 102)

    def test_unsupported_snapshot_stops_before_any_upload(self):
        import test_frostkeep as workflow
        fixture = workflow.WorkflowTests()
        fixture.setUp()
        try:
            original = fixture.run.__call__
            def run(argv, **kwargs):
                if argv[0] == "perl":
                    return '{"hasFeature": 0}'
                return original(argv, **kwargs)
            with self.assertRaises(workflow.fk.Failure):
                workflow.fk.Backup(fixture.cfg, run).execute()
            self.assertFalse(fixture.run.objects)
            self.assertFalse(any(call[0] == "vzdump" for call in fixture.run.calls))
        finally:
            fixture.tearDown()

    def test_backup_rejects_inventory_above_consumer_limit_before_upload(self):
        import test_frostkeep as workflow
        fixture = workflow.WorkflowTests()
        fixture.setUp()
        try:
            with patch.object(workflow.fk, "MAX_MANIFEST_GUESTS", 1):
                with self.assertRaises(workflow.fk.Failure):
                    fixture.backup()
            self.assertFalse(fixture.run.objects)
            self.assertFalse(any(call[0] == "vzdump" for call in fixture.run.calls))
        finally:
            fixture.tearDown()

    def test_oversized_manifest_cannot_publish_completion(self):
        import test_frostkeep as workflow
        fixture = workflow.WorkflowTests()
        fixture.setUp()
        try:
            with patch.object(workflow.fk, "MAX_MANIFEST_BYTES", 1):
                with self.assertRaises(workflow.fk.Failure):
                    fixture.backup()
            self.assertFalse(any(name.endswith("/COMPLETE.json") for name in fixture.run.objects))
        finally:
            fixture.tearDown()


class BoundedRunnerTests(unittest.TestCase):
    def test_exiting_zombie_group_is_reaped_and_signal_retried(self):
        proc = Mock(pid=12345)
        with patch.object(fk.os, "killpg", side_effect=[PermissionError(), ProcessLookupError()]) as kill:
            fk.Runner.signal_group(proc, signal.SIGTERM)
        proc.wait.assert_called_once_with(timeout=0.2)
        self.assertEqual(kill.call_count, 2)

    def test_live_process_permission_failure_is_not_suppressed(self):
        proc = Mock(pid=12345)
        proc.wait.side_effect = subprocess.TimeoutExpired("fixture", 0.2)
        with patch.object(fk.os, "killpg", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                fk.Runner.signal_group(proc, signal.SIGTERM)
        proc.wait.side_effect = None
        with patch.object(fk.os, "killpg", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                fk.Runner.signal_group(proc, signal.SIGTERM)

    def test_capture_accepts_exact_bound_and_preserves_unicode(self):
        result = fk.Runner()([sys.executable, "-c", "import sys;sys.stdout.buffer.write('雪'.encode())"], max_output_bytes=3)
        self.assertEqual(result, "雪")

    def test_capture_overflow_terminates_producer(self):
        before = time.monotonic()
        with self.assertRaisesRegex(fk.Failure, "permitted size"):
            fk.Runner()([sys.executable, "-c", "import sys,time;sys.stdout.write('x'*100000);sys.stdout.flush();time.sleep(30)"], max_output_bytes=32)
        self.assertLess(time.monotonic() - before, 5)

    def test_binary_stream_checks_before_writes_and_rejects_overflow(self):
        target = io.BytesIO()
        observed = []
        fk.Runner()([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'\\x00\\xff')"], capture=False,
                    output_file=target, max_output_bytes=2, output_check=lambda n: observed.append((n, target.tell())))
        self.assertEqual(target.getvalue(), b"\x00\xff")
        self.assertEqual(observed, [(2, 0)])
        target = io.BytesIO()
        with self.assertRaises(fk.Failure):
            fk.Runner()([sys.executable, "-c", "print('overflow')"], capture=False, output_file=target, max_output_bytes=1)
        self.assertEqual(target.getvalue(), b"")

    def test_output_check_failure_prevents_write(self):
        target = io.BytesIO()
        def deny(_):
            raise fk.Failure("reserve exhausted")
        with self.assertRaisesRegex(fk.Failure, "reserve exhausted"):
            fk.Runner()([sys.executable, "-c", "print('data')"], capture=False, output_file=target,
                        max_output_bytes=1024, output_check=deny)
        self.assertEqual(target.getvalue(), b"")

    def test_bounded_timeout_and_nonzero_exit(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            fk.Runner(timeout=0.1)([sys.executable, "-c", "import time;time.sleep(30)"], max_output_bytes=10)
        with self.assertRaises(fk.Failure):
            fk.Runner()([sys.executable, "-c", "raise SystemExit(3)"], max_output_bytes=10)

    def test_timeout_kills_descendant_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "survived"
            pidfile = Path(directory) / "child-pid"
            child = ("import os,signal,time,pathlib;signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                     f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid()));"
                     f"time.sleep(0.7);pathlib.Path({str(marker)!r}).write_text('alive');time.sleep(30)")
            parent = f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child!r}]);time.sleep(30)"
            pid = None
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    fk.Runner(timeout=0.4)([sys.executable, "-c", parent])
                pid = int(pidfile.read_text())
                time.sleep(0.5)
                self.assertFalse(marker.exists(), "descendant survived process-group termination")
            finally:
                if pid is not None:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    unittest.main()
