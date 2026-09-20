#!/usr/bin/env python3
"""FrostKeep: encrypted, independently recoverable Proxmox cold backups."""
from __future__ import annotations

import argparse
import configparser
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shlex
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import uuid

VERSION = "0.2.1"
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DEFAULTS = {
    "remote": "archive:",
    "rclone_config": "/root/.config/rclone/rclone.conf",
    "staging_dir": "/var/lib/vz/frostkeep",
    "state_dir": "/var/lib/frostkeep",
    # Shared with the original script to prevent overlap during migration.
    "lock_file": "/run/lock/pve-glacier.lock",
    "exclude_guests": [],
    "minimum_free_bytes": 10737418240,
    "command_timeout_seconds": 86400,
    "notification_command": [],
    "maximum_backup_age_hours": 840,
    "keep_local_archives": False,
    "host_required_paths": ["/etc/pve", "/etc/network/interfaces", "/etc/hostname"],
    "host_optional_paths": [
        "/etc/network/interfaces.d", "/etc/hosts", "/etc/resolv.conf", "/etc/fstab",
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/subuid", "/etc/subgid",
        "/etc/apt/sources.list", "/etc/apt/sources.list.d", "/etc/ssh", "/root/.ssh",
        "/etc/vzdump.conf", "/etc/cron.d", "/var/spool/cron/crontabs",
        "/etc/systemd/system", "/etc/modprobe.d", "/etc/sysctl.d",
    ],
    "cluster_database": "/var/lib/pve-cluster/config.db",
}
RUN_PATTERN = r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}"
# Match VZDump::LXC::prepare's backup-only capability check. The public
# /lxc/ID/feature endpoint also checks excluded volumes and bind mounts.
CONTAINER_SNAPSHOT_PROBE = """
use strict;
use warnings;
use JSON::PP;
use PVE::Cluster;
use PVE::LXC::Config;
use PVE::Storage;
PVE::Cluster::cfs_update();
my $id = shift @ARGV;
my $conf = PVE::LXC::Config->load_config($id);
my $storage = PVE::Storage::config();
my $supported = PVE::LXC::Config->has_feature("snapshot", $conf, $storage, undef, undef, 1);
print JSON::PP::encode_json({hasFeature => $supported ? 1 : 0});
"""


class Failure(Exception):
    """An actionable operational failure with a safe summary."""


class Interrupted(Failure):
    pass


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def guest_id(value):
    if isinstance(value, bool) or not re.fullmatch(r"[1-9][0-9]{2,8}", str(value)):
        raise Failure("Guest IDs must be integers from 100 to 999999999")
    return int(value)


def relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or any(ord(c) < 32 for c in value):
        raise Failure("Invalid relative archive path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ("", ".", "..") for p in value.split("/")):
        raise Failure("Unsafe relative archive path")
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", p) or p.startswith("-") for p in path.parts):
        raise Failure("Unsupported archive path characters")
    return value


def remote_join(remote, name):
    relative_path(name)
    return remote.rstrip("/") + ("" if remote.endswith(":") else "/") + name


def private_file(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise Failure("Private configuration must be a regular file owned by the current user, mode 0600")
    return path


def private_dir(path):
    path = Path(path)
    # No symlink component may redirect writes outside the configured location.
    if not path.is_absolute() or path.resolve() != path:
        raise Failure("Private directory must be an absolute path without symlinks")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise Failure("Private directory must be owned by the current user, mode 0700")
    return path


def atomic_json(path, value):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def load_config(path):
    try:
        with private_file(path).open() as stream:
            supplied = json.load(stream)
    except (OSError, ValueError) as exc:
        raise Failure("Cannot read configuration; install a private config.json first") from exc
    if not isinstance(supplied, dict) or set(supplied) - set(DEFAULTS):
        raise Failure("Configuration has unknown keys or is not a JSON object")
    cfg = DEFAULTS | supplied
    if not isinstance(cfg["remote"], str) or not re.fullmatch(r"[A-Za-z0-9_-]+:(?:[A-Za-z0-9_./-]+)?", cfg["remote"]):
        raise Failure("remote must be a named rclone crypt remote")
    suffix = cfg["remote"].split(":", 1)[1].strip("/")
    if suffix:
        relative_path(suffix)
    for key in ("rclone_config", "staging_dir", "state_dir", "lock_file", "cluster_database"):
        if not isinstance(cfg[key], str) or not Path(cfg[key]).is_absolute() or ".." in Path(cfg[key]).parts:
            raise Failure(f"{key} must be an absolute path")
    if Path(cfg["state_dir"]) == Path(cfg["staging_dir"]):
        raise Failure("State and staging directories must be different")
    for key in ("host_required_paths", "host_optional_paths"):
        if not isinstance(cfg[key], list) or not all(isinstance(p, str) and "\0" not in p and p.startswith("/") and ".." not in Path(p).parts and Path(p).resolve() != Path("/") for p in cfg[key]):
            raise Failure(f"{key} must contain absolute paths other than root")
    if not isinstance(cfg["exclude_guests"], list):
        raise Failure("exclude_guests must be an array")
    cfg["exclude_guests"] = sorted({guest_id(g) for g in cfg["exclude_guests"]})
    for key in ("minimum_free_bytes", "command_timeout_seconds", "maximum_backup_age_hours"):
        if type(cfg[key]) is not int or cfg[key] <= 0:
            raise Failure(f"{key} must be a positive integer")
    if type(cfg["keep_local_archives"]) is not bool:
        raise Failure("keep_local_archives must be a boolean")
    hook = cfg["notification_command"]
    if not isinstance(hook, list) or not all(isinstance(v, str) and "\0" not in v for v in hook):
        raise Failure("notification_command must be an argument array")
    if hook and not Path(hook[0]).is_absolute():
        raise Failure("Notification executable must use an absolute path")
    return cfg


class Lock:
    def __init__(self, path):
        self.path = Path(path)
        self.fd = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise Failure("Unsafe lock file")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise Failure("Another backup or restore is running, or lock file is unsafe")
        return self

    def __exit__(self, *args):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class Runner:
    def __init__(self, timeout=86400, log=None):
        self.timeout = timeout
        self.log = log

    def __call__(self, argv, capture=True, timeout=None, input_text=None, umask=0o077,
                 max_output_bytes=None, output_file=None, output_check=None):
        bounded = max_output_bytes is not None or output_file is not None
        if max_output_bytes is not None and (type(max_output_bytes) is not int or max_output_bytes < 0):
            raise ValueError("max_output_bytes must be a nonnegative integer")
        if bounded and input_text is not None:
            raise ValueError("Bounded output cannot be combined with input_text")
        if max_output_bytes is not None and not capture and output_file is None:
            raise ValueError("Bounded output requires capture or output_file")
        env = dict(os.environ, PATH=SAFE_PATH, LC_ALL="C")
        # Config/environment filters must never change file selection or encryption.
        env = {k: v for k, v in env.items() if not k.startswith("RCLONE_")}
        sink = self.log if self.log is not None else subprocess.DEVNULL
        with subprocess.Popen([str(a) for a in argv], stdout=subprocess.PIPE if capture or output_file is not None else sink,
                              stderr=sink, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                              env=env, text=True, start_new_session=True, umask=umask) as proc:
            try:
                if bounded:
                    out = self.read_output(proc, timeout or self.timeout, max_output_bytes, output_file, output_check)
                else:
                    out, _ = proc.communicate(input_text, timeout=timeout or self.timeout)
            except BaseException:
                # Stop the whole command group, including compressors and rclone workers.
                self.signal_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    pass
                finally:
                    # Leader exit does not imply its descendants have stopped.
                    self.signal_group(proc, signal.SIGKILL)
                    proc.wait()
                raise
            if proc.returncode:
                raise Failure(f"{Path(str(argv[0])).name} failed (exit {proc.returncode}); inspect the private run log")
            return out or ""

    @staticmethod
    def signal_group(proc, sig):
        with contextlib.suppress(ProcessLookupError):
            try:
                os.killpg(proc.pid, sig)
            except PermissionError as exc:
                # macOS reports EPERM for an unreaped zombie-only group.
                # Reap an exited leader, then retry: a live inaccessible group
                # still raises instead of silently escaping cleanup.
                try:
                    proc.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    raise exc
                os.killpg(proc.pid, sig)

    @staticmethod
    def read_output(proc, timeout, maximum, output_file, output_check):
        deadline = time.monotonic() + timeout
        data, total = bytearray(), 0
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(proc.args, timeout)
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if maximum is not None and total > maximum:
                        raise Failure("Command output exceeded the permitted size")
                    if output_check is not None:
                        output_check(len(chunk))
                    if output_file is not None:
                        output_file.write(chunk)
                    else:
                        data.extend(chunk)
        proc.wait(timeout=max(0, deadline - time.monotonic()))
        return data.decode(proc.stdout.encoding, proc.stdout.errors) if output_file is None else ""


class Rclone:
    def __init__(self, cfg, run):
        self.cfg, self.run = cfg, run

    def call(self, *args, **kwargs):
        if kwargs.get("capture", True):
            kwargs.setdefault("max_output_bytes", 16 * 1024 * 1024)
        return self.run(["rclone", "--config", self.cfg["rclone_config"], *args], **kwargs)

    def json(self, *args, **kwargs):
        try:
            # backend encode otherwise emits plain lines, even for a single result.
            extra = ("--json",) if args and args[0] == "backend" else ()
            return json.loads(self.call(*args, *extra, **kwargs))
        except (ValueError, RecursionError) as exc:
            raise Failure("rclone returned invalid JSON") from exc

    def encryption(self):
        private_file(self.cfg["rclone_config"])
        # Read redacted config only; never print, persist or log it.
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(self.call("config", "redacted"))
        name = self.cfg["remote"].split(":", 1)[0]
        if name not in parser or parser[name].get("type") != "crypt":
            raise Failure("Backup destination must use an rclone crypt remote")
        crypt = parser[name]
        if crypt.get("filename_encryption", "standard") != "standard" or crypt.get("directory_name_encryption", "true").lower() != "true" or crypt.get("no_data_encryption", "false").lower() != "false":
            raise Failure("Content, standard filename and directory encryption must all be enabled")
        underlying = crypt.get("remote", "")
        raw_name = underlying.split(":", 1)[0]
        if ":" not in underlying or raw_name not in parser or parser[raw_name].get("type") != "s3" or parser[raw_name].get("provider") != "AWS":
            raise Failure("The crypt remote must directly wrap an AWS S3 remote with a bucket path")
        if not underlying.split(":", 1)[1].strip("/"):
            raise Failure("The S3 remote must include a bucket")
        return underlying

    def listing(self, remote):
        result = self.json("lsjson", remote, "--recursive", "--files-only")
        if not isinstance(result, list):
            raise Failure("Invalid remote listing")
        return result

    def stat(self, remote):
        result = self.json("lsjson", remote, "--stat")
        if not isinstance(result, dict) or result.get("IsDir"):
            raise Failure("Remote object is missing or is a directory")
        return result

    def upload(self, path, remote, tier):
        self.call("copyto", str(path), remote, "--immutable", "--s3-storage-class", tier,
                  "--s3-chunk-size", "64M", "--s3-upload-concurrency", "2",
                  "--transfers", "1", "--retries", "2", "--low-level-retries", "10", capture=False)
        info = self.stat(remote)
        if info.get("Size") != path.stat().st_size or info.get("Tier") != tier:
            raise Failure("Uploaded object size or storage class did not match")

    def raw_object(self, relative):
        underlying = self.encryption()
        root, prefix = self.cfg["remote"].split(":", 1)
        plaintext = "/".join(p for p in (prefix.strip("/"), relative_path(relative)) if p)
        encoded = self.json("backend", "encode", root + ":", plaintext)
        if not isinstance(encoded, list) or len(encoded) != 1:
            raise Failure("Cannot resolve encrypted S3 object name")
        key = encoded[0]
        # Crypt base64 can start with '-', and base32768 uses Unicode names.
        if (not isinstance(key, str) or len(key.encode("utf-8")) > 4096
                or any(part in ("", ".", "..") for part in key.split("/"))
                or any(c in "\\:*?[]{}" or c.isspace() or ord(c) < 32 or ord(c) == 127 for c in key)):
            raise Failure("Invalid encrypted S3 object name")
        return underlying.rstrip("/") + "/" + key


def discover(run):
    inventories, guests = {}, {}
    for kind, cmd in (("qemu", "qm"), ("lxc", "pct")):
        text = run([cmd, "list"])
        lines = text.strip().splitlines()
        if not lines or lines[0].split()[0] != "VMID":
            raise Failure("Guest discovery returned an invalid inventory")
        inventories[kind] = text
        for line in lines[1:]:
            if not line.strip():
                continue
            ident = guest_id(line.split()[0])
            if ident in guests:
                raise Failure("Guest discovery returned duplicate IDs")
            guests[ident] = kind
    if not guests:
        raise Failure("Guest discovery returned no guests")
    return guests, inventories


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_entry(path, relative, tier, role, guest=None):
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise Failure("Expected a nonempty regular backup file")
    entry = {"path": relative_path(relative), "size": path.stat().st_size,
             "sha256": sha256(path), "tier": tier, "role": role}
    if guest is not None:
        entry["guest_id"] = guest
    return entry


def check_space(cfg):
    if shutil.disk_usage(cfg["staging_dir"]).free < cfg["minimum_free_bytes"]:
        raise Failure("Staging free space is below the configured reserve")


def assert_no_active_tasks(run):
    for kind in ("vzdump", "vzrestore", "qmrestore", "qmigrate", "vzmigrate"):
        tasks = json.loads(run(["pvenode", "task", "list", "--source", "active", "--typefilter", kind,
                               "--limit", "1", "--output-format", "json"], max_output_bytes=65536))
        if not isinstance(tasks, list) or any(not isinstance(t, dict) or t.get("type") != kind for t in tasks):
            raise Failure("Cannot verify active Proxmox tasks")
        if tasks:
            raise Failure("A Proxmox backup, restore or migration worker is still active")


def assert_container_snapshot(run, ident):
    if shutil.which("perl", path=SAFE_PATH) is None:
        raise Failure("Required command unavailable: perl")
    try:
        result = json.loads(run(["perl", "-e", CONTAINER_SNAPSHOT_PROBE, "--", str(guest_id(ident))],
                                max_output_bytes=65536))
    except (ValueError, TypeError) as exc:
        raise Failure("Cannot verify container snapshot support") from exc
    if (not isinstance(result, dict) or type(result.get("hasFeature")) not in (bool, int)
            or result["hasFeature"] != 1):
        raise Failure("Container backup volumes require snapshot support; suspend fallback is not permitted")


def container_root_uid(config):
    """Resolve only the UID that Proxmox uses for container root during tar."""
    if not re.search(r"(?m)^unprivileged:\s*1\s*$", config):
        return 0
    maps = re.findall(r"(?m)^lxc\.idmap:\s*(.*?)\s*$", config)
    if not maps:
        return 100000
    roots = []
    for mapping in maps:
        match = re.fullmatch(r"([ug])\s+(\d+)\s+(\d+)\s+(\d+)", mapping)
        if not match or int(match[4]) < 1:
            raise Failure("Invalid container ID map")
        if match[1] == "u" and int(match[2]) == 0:
            roots.append(int(match[3]))
    if len(roots) != 1 or not 0 < roots[0] < 4294967295:
        raise Failure("Cannot safely resolve container root UID")
    return roots[0]


@contextlib.contextmanager
def dump_workspace(run, kind, ident):
    # The mapped tar process must traverse the temporary config directory.
    # An outer ACL grants only that UID access; other users cannot read it.
    uid = container_root_uid(run(["pct", "config", str(ident), "--current", "1"])) if kind == "lxc" else 0
    base = Path("/var/tmp").resolve()
    info = base.stat()
    if info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
        raise Failure("Unsafe system temporary directory")
    with tempfile.TemporaryDirectory(prefix="frostkeep-dump-", dir=base) as name:
        # Remove inherited entries before setfacl recalculates their access mask.
        run(["setfacl", "-b", "-k", name])
        if uid:
            run(["setfacl", "-m", f"u:{uid}:--x", name])
        yield name


def pack_host(cfg, work, inventories, run):
    info = private_dir(work / "inventory")
    for kind, value in inventories.items():
        (info / f"{kind}.txt").write_text(value)
    for name, argv in (("storage.txt", ["pvesm", "status"]),
                       ("packages.txt", ["dpkg", "--get-selections"]),
                       ("block-devices.txt", ["lsblk", "-J"]),
                       ("proxmox-version.txt", ["pveversion", "-v"])):
        (info / name).write_text(run(argv))
    for path in cfg["host_required_paths"]:
        if not Path(path).exists():
            raise Failure("A required host configuration path is missing")
    paths = list(cfg["host_required_paths"])
    absent = []
    for path in cfg["host_optional_paths"]:
        if Path(path).exists() or Path(path).is_symlink():
            paths.append(path)
        else:
            absent.append(path)
    atomic_json(info / "omitted-optional-paths.json", absent)
    dbpath = Path(cfg["cluster_database"])
    if not dbpath.is_file():
        raise Failure("The Proxmox cluster database is missing")
    deadline = time.monotonic() + 60
    def progress(*_):
        if time.monotonic() > deadline:
            raise Failure("Timed out taking a consistent cluster database snapshot")
    with contextlib.closing(sqlite3.connect(dbpath.as_uri() + "?mode=ro", uri=True)) as source:
        with contextlib.closing(sqlite3.connect(info / "config.db")) as destination:
            source.backup(destination, pages=128, progress=progress)
    archive = work / "hostconfig.tar.gz"
    # Never suppress tar exit codes; a partial host archive cannot be successful.
    run(["tar", "-czf", str(archive), "-C", "/", *[p.lstrip("/") for p in paths],
         "-C", str(work), "inventory"], capture=False)
    run(["tar", "-tzf", str(archive)], capture=False)
    return archive


class Backup:
    def __init__(self, cfg, run=None):
        self.cfg = cfg
        self.run = run or Runner(cfg["command_timeout_seconds"])
        self.rclone = Rclone(cfg, self.run)
        self.manifest = None
        self.full_scope = False

    def save(self):
        self.manifest["updated_at"] = utcnow()
        atomic_json(self.work / "MANIFEST.json", self.manifest)
        atomic_json(self.state / "latest.json", self.manifest)
        if self.full_scope:
            atomic_json(self.state / "full-latest.json", self.manifest)

    def put(self, path, relative, tier, role, guest=None):
        entry = file_entry(path, relative, tier, role, guest)
        self.rclone.upload(path, remote_join(self.remote, relative), tier)
        self.manifest["files"].append(entry)
        self.save()
        return entry

    def notify(self):
        hook = self.cfg["notification_command"]
        if not hook:
            return
        payload = {k: self.manifest[k] for k in ("run_id", "status", "started_at", "finished_at")}
        payload["completed_count"] = sum(g["status"] == "complete" for g in self.manifest["guests"])
        payload["expected_count"] = len(self.manifest["guests"])
        try:
            self.run(hook, input_text=json.dumps(payload), timeout=30, capture=False)
        except Exception:
            atomic_json(self.work / "notification.json", {"failed": True, "at": utcnow()})
            print("WARNING: notification hook failed; backup status is unchanged", file=sys.stderr)

    def execute(self, requested=None, check=False, resume=None):
        with Lock(self.cfg["lock_file"]):
            assert_no_active_tasks(self.run)
            self.state = private_dir(self.cfg["state_dir"])
            private_dir(self.cfg["staging_dir"])
            self.rclone.encryption()
            guests, inventories = discover(self.run)
            recovered = resume_plan(self.cfg, resume, self.run) if resume else None
            if recovered:
                requested = [g["id"] for g in recovered["guests"]]
            selected = sorted({guest_id(v) for v in requested} if requested else guests)
            if any(g not in guests for g in selected):
                raise Failure("A requested guest is absent from the discovered inventory")
            selected = [g for g in selected if g not in self.cfg["exclude_guests"]]
            if not selected:
                raise Failure("No guests remain after exclusions")
            if len(selected) > MAX_MANIFEST_GUESTS:
                raise Failure("Selected inventory exceeds the supported manifest guest limit")
            if recovered and (selected != sorted(g["id"] for g in recovered["guests"]) or any(guests[g["id"]] != g["kind"] for g in recovered["guests"])):
                raise Failure("Resume inventory or exclusions changed; start a fresh backup")
            self.full_scope = selected == sorted(g for g in guests if g not in self.cfg["exclude_guests"])
            for ident in selected:
                if guests[ident] == "lxc":
                    assert_container_snapshot(self.run, ident)
            self.run(["pvesm", "status"])
            self.rclone.call("lsf", self.cfg["remote"], "--dirs-only")
            for cmd in ("vzdump", "tar", "dpkg", "lsblk", "pveversion", "zstd", "setfacl", "pvesh"):
                if shutil.which(cmd, path=SAFE_PATH) is None:
                    raise Failure(f"Required command unavailable: {cmd}")
            check_space(self.cfg)
            for p in self.cfg["host_required_paths"] + [self.cfg["cluster_database"]]:
                if not Path(p).exists():
                    raise Failure("A required host path is missing")
            if check:
                print(f"CHECK OK: {len(guests)} discovered; {len(selected)} selected; encrypted remote accessible")
                return 0
            run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
            self.work = Path(self.cfg["staging_dir"]) / run_id
            self.work.mkdir(mode=0o700)
            self.remote = remote_join(self.cfg["remote"], run_id)
            self.manifest = {"schema": 2, "version": VERSION, "run_id": run_id, "status": "running",
                             "started_at": utcnow(), "finished_at": None, "files": [],
                             "excluded_guests": self.cfg["exclude_guests"],
                             "guests": [{"id": g, "kind": guests[g], "status": "pending"} for g in selected]}
            atomic_json(self.work / "context.json", backup_context(self.cfg))
            if recovered:
                self.manifest["resumed_from"] = resume
                self.manifest["files"].extend(recovered["files"])
                for guest in self.manifest["guests"]:
                    if guest["id"] in recovered["reused"]:
                        guest["status"] = "complete"
            self.save()
            # An encrypted start marker lets remote inspection distinguish incomplete runs.
            atomic_json(self.work / "STARTED.json", {"run_id": run_id, "started_at": self.manifest["started_at"]})
            log = (self.work / "run.log").open("a", buffering=1)
            if isinstance(self.run, Runner):
                self.run.log = log
            try:
                self.rclone.upload(self.work / "STARTED.json", remote_join(self.remote, "STARTED.json"), "STANDARD")
                archive = pack_host(self.cfg, self.work, inventories, self.run)
                self.put(archive, "hostconfig.tar.gz", "STANDARD", "host")
                for guest in self.manifest["guests"]:
                    if guest["status"] != "complete":
                        self.backup_guest(guest)
                if any(g["status"] != "complete" for g in self.manifest["guests"]):
                    raise Failure("One or more guests failed; local files have been retained")
                self.verify_coverage()
                log.flush()
                # Freeze the log: rclone itself may append to the live log while uploading.
                snapshot = self.work / "run-log.txt"
                shutil.copyfile(self.work / "run.log", snapshot)
                if snapshot.stat().st_size == 0:
                    snapshot.write_text("All backup commands completed successfully.\n")
                self.put(snapshot, "meta/run.log", "STANDARD", "log")
                self.manifest["status"] = "finalizing"
                self.manifest["finished_at"] = utcnow()
                self.save()
                final_manifest = dict(self.manifest, status="complete")
                validate_manifest(final_manifest, run_id)
                # Keep the authoritative local state resumable until publication
                # finishes, including when the process cannot run its handlers.
                manifest_path = self.work / "MANIFEST.complete.json"
                atomic_json(manifest_path, final_manifest)
                if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
                    raise Failure("Backup manifest exceeds the supported size limit")
                self.rclone.upload(manifest_path, remote_join(self.remote, "MANIFEST.json"), "STANDARD")
                # Read back the encrypted Standard manifest before declaring success.
                if self.rclone.json("cat", remote_join(self.remote, "MANIFEST.json")) != final_manifest:
                    raise Failure("Manifest read-back did not match")
                atomic_json(self.work / "COMPLETE.json", {"run_id": run_id, "manifest_sha256": sha256(manifest_path)})
                self.rclone.upload(self.work / "COMPLETE.json", remote_join(self.remote, "COMPLETE.json"), "STANDARD")
                if Restore(self.cfg, self.run).manifest(run_id) != final_manifest:
                    raise Failure("Published completion metadata did not match")
                self.manifest = final_manifest
            except BaseException as exc:
                self.manifest["status"] = "interrupted" if isinstance(exc, (Interrupted, KeyboardInterrupt)) else "failed"
                self.manifest["finished_at"] = utcnow()
                self.manifest["error"] = str(exc) if isinstance(exc, Failure) else type(exc).__name__
                self.save()
                # A failure marker is best-effort and can never replace the local failure.
                try:
                    self.rclone.upload(self.work / "MANIFEST.json", remote_join(self.remote, "FAILED.json"), "STANDARD")
                except Exception:
                    pass
                self.notify()
                raise
            finally:
                if isinstance(self.run, Runner):
                    self.run.log = None
                log.close()
            atomic_json(self.state / "latest.json", self.manifest)
            # Only a full-inventory success resets the scheduled-backup freshness clock.
            if self.full_scope:
                atomic_json(self.state / "full-latest.json", self.manifest)
                atomic_json(self.state / "last-success.json", self.manifest)
                atomic_json(self.state / "full-attempt.json", {"event": "backup_invocation", "status": "complete", "at": utcnow()})
            # Commit local completion last: a hard stop during state updates
            # must still leave a run that explicit resume can recover.
            atomic_json(self.work / "MANIFEST.json", self.manifest)
            self.notify()
            print(f"COMPLETE: {run_id}; {len(selected)} guests; manifest and completion marker verified")
            return 0

    def backup_guest(self, guest):
        ident, kind = guest["id"], guest["kind"]
        directory = self.work / str(ident)
        directory.mkdir(mode=0o700)
        guest["status"] = "dumping"
        self.save()
        try:
            check_space(self.cfg)
            if kind == "lxc":
                assert_container_snapshot(self.run, ident)
            with dump_workspace(self.run, kind, ident) as temporary:
                self.run(["vzdump", str(ident), "--mode", "snapshot", "--compress", "zstd",
                          "--dumpdir", str(directory), "--tmpdir", temporary, "--quiet", "1"],
                         capture=False, umask=0o022)
            suffix = ".vma.zst" if kind == "qemu" else ".tar.zst"
            archives = list(directory.glob(f"vzdump-{kind}-{ident}-*{suffix}"))
            if len(archives) != 1:
                raise Failure("vzdump did not create exactly one expected guest archive")
            archive = archives[0]
            if archive.is_symlink() or not archive.is_file():
                raise Failure("Guest archive is not a regular file")
            archive.chmod(0o600)
            self.run(["zstd", "--test", str(archive)], capture=False)
            guest["status"] = "uploading"
            self.save()
            metadata = sorted([p for p in directory.iterdir() if p.suffix in (".log", ".conf")])
            if not any(p.suffix == ".log" for p in metadata):
                raise Failure("Guest backup log is missing")
            for path in metadata:
                if path.is_symlink():
                    raise Failure("Guest metadata must not be a symlink")
                path.chmod(0o600)
                self.put(path, "meta/" + path.name, "STANDARD", "guest_metadata", ident)
            self.put(archive, archive.name, "DEEP_ARCHIVE", "guest", ident)
            guest["status"] = "complete"
            self.save()
            # Delete only this run's exact archive after successful upload/stat and state write.
            if not self.cfg["keep_local_archives"]:
                archive.unlink()
        except Exception as exc:
            if isinstance(exc, Interrupted):
                raise
            guest["status"] = "failed"
            guest["error"] = str(exc) if isinstance(exc, Failure) else type(exc).__name__
            self.save()

    def verify_coverage(self):
        remote = {f["Path"]: f for f in self.rclone.listing(self.remote)}
        for entry in self.manifest["files"]:
            found = (self.rclone.stat(entry_remote(self.cfg, self.manifest["run_id"], entry))
                     if entry.get("source_run") else remote.get(entry["path"], {}))
            if found.get("Size") != entry["size"] or found.get("Tier") != entry["tier"]:
                raise Failure("Final remote coverage, size or storage class check failed")
        expected = {g["id"] for g in self.manifest["guests"]}
        actual = [f["guest_id"] for f in self.manifest["files"] if f["role"] == "guest"]
        if len(actual) != len(expected) or set(actual) != expected:
            raise Failure("Guest archive coverage does not match the planned inventory")


MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MARKER_BYTES = 64 * 1024
MAX_MANIFEST_GUESTS = 10000
MAX_MANIFEST_FILES = 100000


def validate_manifest(manifest, run_id):
    if not isinstance(manifest, dict) or manifest.get("schema") not in (1, 2) or manifest.get("run_id") != run_id or manifest.get("status") != "complete":
        raise Failure("Unsupported or incomplete manifest")
    entries = manifest.get("files")
    guests = manifest.get("guests")
    if not isinstance(entries, list) or not isinstance(guests, list) or not guests:
        raise Failure("Manifest must include files and guests")
    if len(entries) > MAX_MANIFEST_FILES or len(guests) > MAX_MANIFEST_GUESTS:
        raise Failure("Manifest inventory exceeds supported limits")
    ids = []
    for g in guests:
        if not isinstance(g, dict) or type(g.get("id")) is not int or g.get("kind") not in ("qemu", "lxc") or g.get("status") != "complete":
            raise Failure("Manifest guest is incomplete or invalid")
        ids.append(guest_id(g.get("id")))
    if len(set(ids)) != len(ids):
        raise Failure("Duplicate manifest guest")
    kinds = {g["id"]: g["kind"] for g in guests}
    seen, archived = set(), []
    for entry in entries:
        if not isinstance(entry, dict):
            raise Failure("Invalid manifest file")
        path = relative_path(entry.get("path"))
        if len(path.encode("utf-8")) > 1024:
            raise Failure("Manifest path exceeds supported limits")
        if path in seen:
            raise Failure("Duplicate manifest path")
        seen.add(path)
        if type(entry.get("size")) is not int or entry["size"] <= 0 or not re.fullmatch(r"[a-f0-9]{64}", str(entry.get("sha256", ""))):
            raise Failure("Invalid manifest file size or checksum")
        role = entry.get("role")
        if "source_run" in entry and (manifest["schema"] != 2 or role not in ("guest", "guest_metadata") or not re.fullmatch(RUN_PATTERN, str(entry["source_run"]))):
            raise Failure("Invalid reused archive source")
        if role not in ("guest", "host", "guest_metadata", "log"):
            raise Failure("Unknown manifest file role")
        expected_tier = "DEEP_ARCHIVE" if role == "guest" else "STANDARD"
        if entry.get("tier") != expected_tier:
            raise Failure("Unexpected manifest storage class")
        if role == "guest":
            if type(entry.get("guest_id")) is not int:
                raise Failure("Archive guest ID must be an integer")
            ident = guest_id(entry.get("guest_id"))
            if ident not in kinds:
                raise Failure("Archive belongs to an unplanned guest")
            kind = kinds[ident]
            suffix = "vma" if kind == "qemu" else "tar"
            if not re.fullmatch(rf"vzdump-{kind}-{ident}-[0-9_-]+\.{suffix}\.zst", path):
                raise Failure("Archive name does not match the guest identity")
            archived.append(ident)
    if sorted(archived) != sorted(ids):
        raise Failure("Manifest does not contain exactly one archive per guest")
    if sum(e["role"] == "host" for e in entries) != 1:
        raise Failure("Manifest must include one host archive")
    return manifest


class Restore:
    def __init__(self, cfg, run=None):
        self.cfg = cfg
        self.run = run or Runner(cfg["command_timeout_seconds"])
        self.rclone = Rclone(cfg, self.run)

    def metadata(self, run_id):
        if not re.fullmatch(RUN_PATTERN, run_id):
            raise Failure("Invalid run ID; legacy date-only archives require the documented manual workflow")
        self.rclone.encryption()
        root = remote_join(self.cfg["remote"], run_id)
        rows = self.rclone.json("lsjson", root, "--files-only", "--max-depth", "1",
                                "--include", "/MANIFEST.json", "--include", "/COMPLETE.json",
                                "--include", "/FAILED.json", max_output_bytes=MAX_MARKER_BYTES)
        if not isinstance(rows, list) or len(rows) > MAX_MANIFEST_FILES or any(
                not isinstance(row, dict) or not isinstance(row.get("Path"), str) for row in rows):
            raise Failure("Invalid recovery metadata listing")
        listing = {row["Path"]: row for row in rows}
        if len(listing) != len(rows):
            raise Failure("Duplicate recovery metadata paths")
        return root, listing

    def manifest(self, run_id):
        root, listing = self.metadata(run_id)
        if "FAILED.json" in listing or "COMPLETE.json" not in listing:
            raise Failure("Run lacks a completion marker or has a failure marker")
        if any(listing.get(p, {}).get("Tier") != "STANDARD" for p in ("MANIFEST.json", "COMPLETE.json")):
            raise Failure("Recovery metadata is not in Standard storage")
        raw = self.rclone.call("cat", remote_join(root, "MANIFEST.json"),
                               "--count", str(MAX_MANIFEST_BYTES + 1), max_output_bytes=MAX_MANIFEST_BYTES)
        marker_raw = self.rclone.call("cat", remote_join(root, "COMPLETE.json"),
                                      "--count", str(MAX_MARKER_BYTES + 1), max_output_bytes=MAX_MARKER_BYTES)
        if len(raw.encode("utf-8")) > MAX_MANIFEST_BYTES or len(marker_raw.encode("utf-8")) > MAX_MARKER_BYTES:
            raise Failure("Recovery metadata exceeds supported limits")
        try:
            marker = json.loads(marker_raw)
        except (ValueError, RecursionError) as exc:
            raise Failure("Completion marker is not valid bounded JSON") from exc
        if not isinstance(marker, dict) or marker.get("run_id") != run_id or marker.get("manifest_sha256") != hashlib.sha256(raw.encode()).hexdigest():
            raise Failure("Manifest does not match the completion marker")
        try:
            return validate_manifest(json.loads(raw), run_id)
        except (ValueError, RecursionError) as exc:
            raise Failure("Manifest is not valid JSON") from exc

    def entry(self, run_id, path):
        path = relative_path(path)
        manifest = self.manifest(run_id)
        match = [e for e in manifest["files"] if e["path"] == path]
        if len(match) != 1:
            raise Failure("File is not in the verified manifest")
        return match[0]

    def request(self, run_id, path, days=3, tier="Bulk", execute=False):
        entry = self.entry(run_id, path)
        if entry["tier"] != "DEEP_ARCHIVE":
            raise Failure("This file is immediately readable and needs no archive retrieval")
        if not 1 <= days <= 30 or tier not in ("Bulk", "Standard"):
            raise Failure("Retrieval requires Bulk or Standard priority and 1–30 days")
        raw = self.rclone.raw_object(entry.get("source_run", run_id) + "/" + path)
        parent, leaf = raw.rsplit("/", 1)
        args = ["backend", "restore", parent, "--include", "/" + leaf,
                "-o", f"priority={tier}", "-o", f"lifetime={days}"]
        if not execute:
            print(f"PLAN: retrieve one encrypted object ({entry['size']} plaintext bytes), {tier}, {days} days. Charges may apply. Use --execute to submit.")
            return
        result = self.rclone.json(*args, max_output_bytes=MAX_MARKER_BYTES)
        if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict) or result[0].get("Status") != "OK" or result[0].get("Remote") != leaf:
            raise Failure("Retrieval was not confirmed for exactly one object; inspect restore status")
        print("Retrieval requested for one archive. Use restore retrieval-status before downloading.")

    def retrieval_status(self, run_id, path):
        entry = self.entry(run_id, path)
        raw = self.rclone.raw_object(entry.get("source_run", run_id) + "/" + path)
        # Some rclone versions reject a file target; restore-status ignores filters.
        # Query only the enclosing run directory and select the exact encoded name.
        parent, leaf = raw.rsplit("/", 1)
        result = self.rclone.json("backend", "restore-status", parent, "-o", "all",
                                  max_output_bytes=MAX_MANIFEST_BYTES)
        if not isinstance(result, list):
            raise Failure("Invalid retrieval status response")
        match = [item for item in result if isinstance(item, dict) and item.get("Remote") == leaf]
        if len(match) != 1:
            raise Failure("Retrieval status did not identify exactly one selected object")
        print(json.dumps(match[0], indent=2))

    def download(self, run_id, path, destination):
        entry = self.entry(run_id, path)
        directory = private_dir(Path(destination))
        with Lock(directory / ".download.lock"):
            target = directory / Path(path).name
            if target.exists() or target.is_symlink():
                raise Failure("Download destination already exists; use verify or a new directory")
            if shutil.disk_usage(directory).free < entry["size"] + self.cfg["minimum_free_bytes"]:
                raise Failure("Insufficient space for the download plus configured reserve")
            remote = entry_remote(self.cfg, run_id, entry)
            found = self.rclone.stat(remote)
            if found.get("Size") != entry["size"] or found.get("Tier") != entry["tier"]:
                raise Failure("Remote download object size or storage class changed")
            tempdir = Path(tempfile.mkdtemp(prefix=".download-", dir=directory))
            partial = tempdir / target.name
            def check_download_space(count):
                if shutil.disk_usage(directory).free < count + self.cfg["minimum_free_bytes"]:
                    raise Failure("Download would consume the configured free-space reserve")
            try:
                with partial.open("xb", buffering=0) as stream:
                    self.rclone.call("cat", remote, "--count", str(entry["size"] + 1), capture=False,
                                     output_file=stream, max_output_bytes=entry["size"],
                                     output_check=check_download_space)
                self.verify_file(partial, entry)
                # No overwrite, even if another tool created the destination while downloading.
                os.link(partial, target)
            finally:
                shutil.rmtree(tempdir)
            print(f"VERIFIED: {target.name}; size and SHA-256 match the encrypted manifest")
            return target

    @staticmethod
    def verify_file(path, entry):
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size != entry["size"] or sha256(path) != entry["sha256"]:
            raise Failure("Local archive size or SHA-256 verification failed")

    def guest(self, run_id, path, local, target_id, storage, execute=False):
        target_id = guest_id(target_id)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", storage):
            raise Failure("Invalid Proxmox storage ID")
        entry = self.entry(run_id, path)
        if entry["role"] != "guest":
            raise Failure("Only guest archives can be restored as a guest")
        if target_id == entry["guest_id"]:
            raise Failure("Restore must use a different guest ID")
        local = Path(local).absolute()
        private_dir(local.parent)
        private_file(local)
        self.verify_file(local, entry)
        kind = "qemu" if path.endswith(".vma.zst") else "lxc"
        with Lock(self.cfg["lock_file"]):
            resources = json.loads(self.run(["pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"]))
            if not isinstance(resources, list) or any(not isinstance(r, dict) or "vmid" not in r for r in resources):
                raise Failure("Invalid cluster guest inventory")
            if any(guest_id(r["vmid"]) == target_id for r in resources):
                raise Failure("Target guest ID already exists in the cluster")
            # Proxmox itself also checks occupancy atomically; never pass --force.
            if kind == "qemu":
                args = ["qmrestore", str(local), str(target_id), "--storage", storage,
                        "--unique", "1", "--start", "0", "--ha-managed", "0"]
            else:
                args = ["pct", "restore", str(target_id), str(local), "--storage", storage,
                        "--unique", "1", "--start", "0", "--onboot", "0"]
            print("RESTORE PLAN (guest remains stopped): " + shlex.join(args))
            if not execute:
                return
            logs = private_dir(Path(self.cfg["state_dir"]) / "restore-logs")
            logfile = logs / (uuid.uuid4().hex + ".log")
            with logfile.open("x") as stream:
                logfile.chmod(0o600)
                previous = self.run.log if isinstance(self.run, Runner) else None
                if isinstance(self.run, Runner):
                    self.run.log = stream
                try:
                    self.run(["zstd", "--test", str(local)], capture=False)
                    # Proxmox creates guest directories traversed by mapped root.
                    # The input archive remains under its private parent directory.
                    self.run(args, capture=False, umask=0o022)
                    if kind == "qemu":
                        self.run(["qm", "set", str(target_id), "--onboot", "0"], capture=False)
                    state = self.run(["qm" if kind == "qemu" else "pct", "status", str(target_id)])
                finally:
                    if isinstance(self.run, Runner):
                        self.run.log = previous
            if state.strip() != "status: stopped":
                raise Failure("Restored guest is not confirmed stopped; inspect it immediately")
            print("RESTORED, STOPPED: inspect network, boot settings, hooks and mounts before starting manually")


def entry_remote(cfg, run_id, entry):
    return remote_join(cfg["remote"], entry.get("source_run", run_id) + "/" + entry["path"])


def backup_context(cfg):
    return {"remote": cfg["remote"], "config_sha256": sha256(private_file(cfg["rclone_config"]))}


def local_run(cfg, run_id):
    if not re.fullmatch(RUN_PATTERN, run_id):
        raise Failure("Invalid run ID")
    work = private_dir(cfg["staging_dir"]) / run_id
    if not work.is_dir():
        raise Failure("Local run is missing")
    private_dir(work)
    data = json.loads(private_file(work / "MANIFEST.json").read_text())
    if not isinstance(data, dict) or data.get("run_id") != run_id:
        raise Failure("Local run manifest does not match its directory")
    return work, data


def recover_finalization(cfg, run_id, work, data, run):
    """Interpret an older premature local completion without changing files."""
    if data.get("status") != "complete" or data.get("schema") != 2:
        return data
    # A successful listing, not a failed remote read, establishes marker absence.
    _, listing = Restore(cfg, run).metadata(run_id)
    if "COMPLETE.json" in listing:
        # Older releases could commit the local manifest before health state.
        # Only a matching unfinished record permits recovery of that case.
        pending = False
        for name in ("latest.json", "full-latest.json"):
            path = Path(cfg["state_dir"]) / name
            if path.exists():
                record = json.loads(private_file(path).read_text())
                if isinstance(record, dict) and record.get("status") == "finalizing" and dict(record, status="complete") == data:
                    pending = True
        if not pending:
            return data
        if Restore(cfg, run).manifest(run_id) != data:
            raise Failure("Published completion metadata differs from local recovery state")
    if json.loads(private_file(work / "context.json").read_text()) != backup_context(cfg):
        raise Failure("Recovery storage configuration changed")
    validate_manifest(data, run_id)
    # Do not weaken completed-run cleanup protection if cloud data was lost.
    rclone = Rclone(cfg, run)
    for entry in data["files"]:
        found = rclone.stat(entry_remote(cfg, run_id, entry))
        if found.get("Size") != entry["size"] or found.get("Tier") != entry["tier"]:
            raise Failure("Recovery payload is missing or changed; retain local staging")
    return dict(data, status="finalizing")


def resume_plan(cfg, run_id, run):
    work, data = local_run(cfg, run_id)
    if json.loads(private_file(work / "context.json").read_text()) != backup_context(cfg):
        raise Failure("Resume storage configuration changed")
    data = recover_finalization(cfg, run_id, work, data, run)
    if data.get("schema") != 2 or data.get("status") not in ("failed", "interrupted", "running", "finalizing"):
        raise Failure("Only unfinished runs with recovery context can be resumed")
    guests = data.get("guests")
    if not isinstance(guests, list) or not guests or any(not isinstance(g, dict) or type(g.get("id")) is not int or g.get("status") not in ("pending", "dumping", "uploading", "complete", "failed") for g in guests):
        raise Failure("Invalid recovery guest inventory")
    ids = [guest_id(g.get("id")) for g in guests]
    if len(set(ids)) != len(ids) or any(g.get("kind") not in ("lxc", "qemu") for g in guests):
        raise Failure("Invalid recovery guest inventory")
    complete = [g for g in guests if g.get("status") == "complete"]
    reused = [g["id"] for g in complete]
    if not isinstance(data.get("files"), list) or any(not isinstance(e, dict) for e in data["files"]):
        raise Failure("Invalid recovery file inventory")
    files = [e for e in data["files"] if e.get("guest_id") in reused and e.get("role") in ("guest", "guest_metadata")]
    if complete:
        host = [e for e in data["files"] if e.get("role") == "host"]
        validate_manifest(dict(data, status="complete", guests=complete, files=host + files), run_id)
    rclone = Rclone(cfg, run)
    rclone.encryption()
    verified = []
    for entry in files:
        if not any(e["role"] == "guest_metadata" and e["guest_id"] == entry["guest_id"] for e in files):
            raise Failure("Reusable guest lacks backup metadata")
        item = dict(entry, source_run=entry.get("source_run", run_id))
        found = rclone.stat(entry_remote(cfg, run_id, item))
        if found.get("Size") != item["size"] or found.get("Tier") != item["tier"]:
            raise Failure("Reusable remote object is missing or changed")
        verified.append(item)
    return {"guests": guests, "reused": reused, "files": verified}


def resume_backup(cfg, run_id, execute=False, run=None):
    runner = run or Runner(cfg["command_timeout_seconds"])
    if execute:
        return Backup(cfg, runner).execute(resume=run_id)
    with Lock(cfg["lock_file"]):
        assert_no_active_tasks(runner)
        plan = resume_plan(cfg, run_id, runner)
        print(json.dumps({"source_run": run_id, "reused_guests": plan["reused"],
                          "new_dumps": [g["id"] for g in plan["guests"] if g["id"] not in plan["reused"]],
                          "note": "New run references existing objects; their original retention dates remain."}, indent=2))
    return 0


def cleanup(cfg, run_id, execute=False, allow_incomplete=False, run=None):
    run = run or Runner(cfg["command_timeout_seconds"])
    with Lock(cfg["lock_file"]):
        assert_no_active_tasks(run)
        work, data = local_run(cfg, run_id)
        data = recover_finalization(cfg, run_id, work, data, run)
        complete = data.get("status") == "complete"
        if complete:
            remote = Restore(cfg, run).manifest(run_id)
            if remote != data:
                raise Failure("Local and verified remote manifests differ")
            rclone = Rclone(cfg, run or Runner(cfg["command_timeout_seconds"]))
            for entry in remote["files"]:
                found = rclone.stat(entry_remote(cfg, run_id, entry))
                if found.get("Size") != entry["size"] or found.get("Tier") != entry["tier"]:
                    raise Failure("Remote backup payload is missing or changed; retain local staging")
        elif not allow_incomplete:
            raise Failure("Incomplete run may hold the only backup copy; use --allow-incomplete after review")
        # Refuse links, mounted filesystems, devices and unfamiliar directory layouts.
        device = work.stat().st_dev
        mountinfo = Path("/proc/self/mountinfo")
        if mountinfo.exists():
            for line in mountinfo.read_text().splitlines():
                fields = line.split()
                mounted = Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4]))
                if mounted == work or work in mounted.parents:
                    raise Failure("Mounted directory in staging; cleanup refused")
        total = 0
        for path in work.rglob("*"):
            info = path.lstat()
            if info.st_dev != device or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or info.st_uid != os.geteuid():
                raise Failure("Unsafe staging contents; cleanup refused")
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
        inventory = {"run_id": run_id, "status": data.get("status"), "bytes": total,
                     "incomplete": not complete, "remote_objects_deleted": False}
        print(json.dumps(inventory, indent=2))
        if execute:
            records = private_dir(Path(cfg["state_dir"]) / "cleanup")
            atomic_json(records / (run_id + ".json"), dict(inventory, reviewed_at=utcnow(), manifest=data))
            # All deletion stays beneath one validated directory, under the backup lock.
            shutil.rmtree(work)
            print("Removed the selected local staging directory; retained its audit record.")
    return 0


def send_event(cfg, payload, run=None):
    if not cfg["notification_command"]:
        return True
    try:
        (run or Runner())(cfg["notification_command"], input_text=json.dumps(payload), timeout=30, capture=False)
        return True
    except Exception:
        print("WARNING: notification delivery failed", file=sys.stderr)
        return False


def health(cfg, notify=False, run=None, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    reasons = []
    try:
        state = private_dir(cfg["state_dir"])
    except (OSError, Failure):
        payload = {"event": "health", "status": "unhealthy", "reasons": ["health_state_unavailable"],
                   "checked_at": now.isoformat()}
        print(json.dumps(payload, indent=2))
        if notify and not send_event(cfg, payload, run):
            return 2
        return 1
    def record(path):
        if not path.exists():
            return {}
        try:
            value = json.loads(private_file(path).read_text())
            if not isinstance(value, dict) or value.get("status") not in ("running", "finalizing", "complete", "failed", "interrupted"):
                raise ValueError("Invalid status")
            return value
        except (OSError, ValueError, RecursionError, Failure):
            if "invalid_health_state" not in reasons:
                reasons.append("invalid_health_state")
            return {}
    latest_path, success_path = state / "latest.json", state / "last-success.json"
    if not success_path.exists():
        reasons.append("no_full_backup_success")
    else:
        success = record(success_path)
        try:
            validate_manifest(success, success["run_id"])
            finished = dt.datetime.fromisoformat(success["finished_at"])
            ages = [(now - finished).total_seconds()]
            for entry in success["files"]:
                if entry["role"] == "guest":
                    origin = entry.get("source_run", success["run_id"])
                    if not re.fullmatch(RUN_PATTERN, origin):
                        raise ValueError("Invalid source timestamp")
                    captured = dt.datetime.strptime(origin.split("-")[0], "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
                    ages.append((now - captured).total_seconds())
            age = -1 if min(ages) < 0 else max(ages)
        except (KeyError, TypeError, ValueError, Failure):
            age = -1
        if success.get("status") != "complete" or age < 0 or age > cfg["maximum_backup_age_hours"] * 3600:
            reasons.append("backup_overdue")
    latest = record(latest_path)
    full = record(state / "full-latest.json")
    if latest.get("status") in ("failed", "interrupted"):
        reasons.append("latest_backup_failed")
    unfinished = ("running", "finalizing")
    if full.get("status") in unfinished and full.get("run_id") != latest.get("run_id"):
        # A later subset run cannot own the unfinished full run's lock.
        reasons.append("backup_interrupted")
    elif latest.get("status") in unfinished or full.get("status") in unfinished:
        try:
            with Lock(cfg["lock_file"]):
                reasons.append("backup_interrupted")
        except Failure:
            pass
    attempt = state / "attempt.json"
    if record(attempt).get("status") == "failed":
        reasons.append("backup_invocation_failed")
    if full.get("status") in ("failed", "interrupted"):
        reasons.append("full_backup_failed")
    if record(state / "full-attempt.json").get("status") == "failed":
        reasons.append("full_backup_invocation_failed")
    payload = {"event": "health", "status": "unhealthy" if reasons else "healthy", "reasons": reasons, "checked_at": now.isoformat()}
    print(json.dumps(payload, indent=2))
    # Repeated alerts are intentional: a failed delivery cannot silence later checks.
    if notify and reasons and not send_event(cfg, payload, run):
        return 2
    return 1 if reasons else 0


def backup_invocation(cfg, operation, run=None, full_scope=False):
    state = None
    try:
        state = private_dir(cfg["state_dir"])
        result = operation()
    except BaseException:
        payload = {"event": "backup_invocation", "status": "failed", "at": utcnow()}
        if state is not None:
            if full_scope:
                # Retain preflight failures even when no run manifest exists.
                # Only verified full-inventory completion clears this record.
                with contextlib.suppress(OSError):
                    atomic_json(state / "full-attempt.json", payload)
            with contextlib.suppress(OSError):
                atomic_json(state / "attempt.json", payload)
        send_event(cfg, payload, run)
        raise
    atomic_json(state / "attempt.json", {"event": "backup_invocation", "status": "complete", "at": utcnow()})
    return result


def status(cfg):
    path = Path(cfg["state_dir"]) / "latest.json"
    if not path.exists():
        print("No FrostKeep run recorded. Legacy script logs are not included.")
        return 0
    data = json.loads(path.read_text())
    held = False
    try:
        with Lock(cfg["lock_file"]):
            pass
    except Failure:
        held = True
    if data["status"] in ("running", "finalizing") and not held:
        data["status"] = "interrupted (no active lock; inspect retained staging files)"
    print(json.dumps({"run_id": data["run_id"], "status": data["status"],
                      "started_at": data["started_at"], "updated_at": data["updated_at"],
                      "completed": sum(g["status"] == "complete" for g in data["guests"]),
                      "expected": len(data["guests"]),
                      "guests": data["guests"]}, indent=2))
    return 0 if data["status"] == "complete" else 1


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--version", action="version", version=f"FrostKeep {VERSION}")
    p.add_argument("--config", default="/etc/frostkeep/config.json")
    sub = p.add_subparsers(dest="command", required=True)
    backup = sub.add_parser("backup", help="Back up local guests to an encrypted archive")
    backup.add_argument("--check", action="store_true", help="Preflight only; no dumps or uploads")
    backup.add_argument("guests", nargs="*", help="Optional explicit guest IDs")
    sub.add_parser("status", help="Show the latest run, not historical log totals")
    monitor = sub.add_parser("health", help="Check full-backup age, failure and interruption")
    monitor.add_argument("--notify", action="store_true")
    recovery = sub.add_parser("resume", help="Plan a new run reusing verified completed guest uploads")
    recovery.add_argument("run_id")
    recovery.add_argument("--execute", action="store_true")
    prune = sub.add_parser("cleanup", help="Review removal of one local staging directory")
    prune.add_argument("run_id")
    prune.add_argument("--execute", action="store_true")
    prune.add_argument("--allow-incomplete", action="store_true")
    restore = sub.add_parser("restore", help="Inspect, retrieve, verify and restore archives")
    actions = restore.add_subparsers(dest="action", required=True)
    actions.add_parser("list", help="List remote run directories; listing is not proof of completion")
    inspect = actions.add_parser("inspect", help="Read a checksum-verified completion manifest")
    inspect.add_argument("run_id")
    for command in ("request", "retrieval-status", "download", "verify", "guest"):
        action = actions.add_parser(command)
        action.add_argument("run_id")
        action.add_argument("path", help="Exact relative file path from the manifest")
        if command == "request":
            action.add_argument("--days", type=int, default=3)
            action.add_argument("--tier", choices=("Bulk", "Standard"), default="Bulk")
            action.add_argument("--execute", action="store_true")
        if command == "download":
            action.add_argument("--destination", required=True, help="Absolute private directory")
        if command in ("verify", "guest"):
            action.add_argument("--file", required=True)
        if command == "guest":
            action.add_argument("--target-id", required=True)
            action.add_argument("--storage", required=True)
            action.add_argument("--execute", action="store_true")
    return p


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    def interrupted(signum, _frame):
        raise Interrupted(f"Interrupted by signal {signum}")
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    try:
        cfg = load_config(args.config)
        if args.command == "backup":
            operation = lambda: Backup(cfg).execute(args.guests, args.check)
            return operation() if args.check else backup_invocation(cfg, operation, full_scope=not args.guests)
        if args.command == "status":
            return status(cfg)
        if args.command == "health":
            return health(cfg, args.notify)
        if args.command == "resume":
            operation = lambda: resume_backup(cfg, args.run_id, args.execute)
            return backup_invocation(cfg, operation) if args.execute else operation()
        if args.command == "cleanup":
            return cleanup(cfg, args.run_id, args.execute, args.allow_incomplete)
        restore = Restore(cfg)
        if args.action == "list":
            restore.rclone.encryption()
            print(restore.rclone.call("lsf", cfg["remote"], "--dirs-only"), end="")
        elif args.action == "inspect":
            print(json.dumps(restore.manifest(args.run_id), indent=2))
        elif args.action == "request":
            restore.request(args.run_id, args.path, args.days, args.tier, args.execute)
        elif args.action == "retrieval-status":
            restore.retrieval_status(args.run_id, args.path)
        elif args.action == "download":
            restore.download(args.run_id, args.path, args.destination)
        elif args.action == "verify":
            restore.verify_file(args.file, restore.entry(args.run_id, args.path))
            print("VERIFIED: size and SHA-256 match the encrypted manifest")
        elif args.action == "guest":
            restore.guest(args.run_id, args.path, args.file, args.target_id, args.storage, args.execute)
        return 0
    except (Failure, OSError, ValueError, configparser.Error, sqlite3.Error, subprocess.TimeoutExpired) as exc:
        # Unexpected dependency exceptions may embed paths or secrets. Keep console errors bounded.
        print("ERROR: " + (str(exc) if isinstance(exc, Failure) else type(exc).__name__ + "; operation failed"), file=sys.stderr)
        return 130 if isinstance(exc, Interrupted) else 1


if __name__ == "__main__":
    sys.exit(main())
