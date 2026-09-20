#!/bin/bash
# Install locally, or stage a package using DESTDIR. Does not activate a scheduler.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
umask 077
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
DESTDIR=${DESTDIR:-}
if [[ -z "$DESTDIR" && $EUID -ne 0 ]]; then
  echo "Run as root to install, or set DESTDIR to an absolute staging directory." >&2
  exit 1
fi
if [[ -n "$DESTDIR" && "$DESTDIR" != /* ]]; then
  echo "DESTDIR must be absolute." >&2
  exit 1
fi
# Hold validated locks through staging, commit, rollback and cleanup.
exec python3 - "$ROOT" "$DESTDIR" <<'PYTHON'
import contextlib
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import stat
import sys
import tempfile

root = Path(sys.argv[1])
prefix = Path(sys.argv[2] or "/").resolve()
if sys.argv[2] and prefix == Path("/"):
    sys.exit("DESTDIR must be a staging directory other than root; unset it for a live installation.")
entries = [
    ("lib/frostkeep/frostkeep.py", "usr/local/lib/frostkeep/frostkeep.py", 0o644),
    *[("scripts/" + name, "usr/local/bin/" + name, 0o755)
      for name in ("frostkeep", "pve-glacier.sh", "glacier-status")],
    ("scripts/notify-webhook.py", "usr/local/bin/frostkeep-notify-webhook", 0o755),
    ("config/frostkeep.example.json", "etc/frostkeep/config.json", 0o600),
    ("config/webhook.example.json", "etc/frostkeep/webhook.example.json", 0o600),
    *[("deploy/" + name, "etc/systemd/system/" + name, 0o644)
      for name in ("frostkeep.service", "frostkeep.timer", "frostkeep-health.service", "frostkeep-health.timer")],
    ("deploy/frostkeep.logrotate", "etc/logrotate.d/frostkeep", 0o644),
]
prepared, applied, temporary, created = [], [], [], []
old_directory_modes = []
retain_backups = False
locks = contextlib.ExitStack()


def interrupted(signum, frame):
    raise InterruptedError("Installation interrupted")


def mkdir(path, mode=0o755):
    # The staging prefix is canonicalized once; no child component may redirect
    # installation outside it, even when the final directory already exists.
    if path.resolve() != path or path.is_symlink():
        raise ValueError("Installation directory cannot contain symlink components")
    if path.exists():
        if not path.is_dir():
            raise ValueError("Installation directory is not a directory")
        return
    mkdir(path.parent)
    path.mkdir(mode=mode)
    path.chmod(mode)
    created.append(path)


for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, interrupted)
try:
    if not sys.argv[2]:
        spec = importlib.util.spec_from_file_location("frostkeep_install", root / "lib/frostkeep/frostkeep.py")
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        legacy_lock = "/run/lock/pve-glacier.lock"
        locks.enter_context(runtime.Lock(legacy_lock))
        configuration = Path("/etc/frostkeep/config.json")
        if Path("/usr/local/bin/pve-glacier.sh").exists() and not configuration.exists():
            raise ValueError("Legacy installation requires a private configuration carrying existing exclusions")
        if configuration.exists():
            configured_lock = runtime.load_config(configuration)["lock_file"]
            if configured_lock != legacy_lock:
                locks.enter_context(runtime.Lock(configured_lock))
    # Validate the entire release before changing any installed file.
    for source, relative, mode in entries:
        if not stat.S_ISREG((root / source).lstat().st_mode):
            raise ValueError("Installation source must be a regular file")
    for source, relative, mode in entries:
        target = prefix / relative
        mkdir(target.parent, 0o700 if relative.startswith("etc/frostkeep/") else 0o755)
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError("Installation target must be a regular file")
        if relative == "etc/frostkeep/config.json" and target.exists():
            continue
        stage = Path(tempfile.mkdtemp(prefix=".frostkeep-install-", dir=target.parent))
        temporary.append(stage)
        replacement = stage / "new"
        shutil.copyfile(root / source, replacement)
        replacement.chmod(mode)
        backup = stage / "original" if target.exists() else None
        if backup is not None:
            shutil.copy2(target, backup)
            os.chown(backup, target.stat().st_uid, target.stat().st_gid)
        prepared.append((target, replacement, backup))
    private = prefix / "etc/frostkeep"
    old_directory_modes.append((private, stat.S_IMODE(private.stat().st_mode)))
    private.chmod(0o700)
    for target, replacement, backup in prepared:
        # Record before replacing so a signal at either side of replace rolls back.
        applied.append((target, backup))
        os.replace(replacement, target)
except BaseException as error:
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal.SIG_IGN)
    for target, backup in reversed(applied):
        try:
            if backup is not None:
                os.replace(backup, target)
            else:
                target.unlink(missing_ok=True)
        except OSError:
            retain_backups = True
    for directory, mode in reversed(old_directory_modes):
        try:
            directory.chmod(mode)
        except OSError:
            retain_backups = True
    print("Installation failed; " + ("rollback incomplete, retain .frostkeep-install-* recovery directories." if retain_backups else "installed files restored."), file=sys.stderr)
    print(str(error), file=sys.stderr)
    sys.exit(1)
finally:
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal.SIG_IGN)
    if not retain_backups:
        for stage in temporary:
            try:
                shutil.rmtree(stage)
            except OSError:
                print("Could not remove a private .frostkeep-install-* recovery directory.", file=sys.stderr)
        if sys.exc_info()[0] is not None:
            for directory in reversed(created):
                try:
                    directory.rmdir()
                except OSError:
                    pass
    locks.close()
print("Installed. Configure /etc/frostkeep/config.json, run frostkeep backup --check, then activate ONE scheduler.")
PYTHON
