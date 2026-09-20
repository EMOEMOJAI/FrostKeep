#!/usr/bin/env python3
"""Export only reviewed public files. No Git initialization or publishing."""
import argparse
import ipaddress
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import tempfile
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
PNG_ALLOWED = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"sRGB", b"gAMA", b"cHRM"}
TEXT_SUFFIXES = {".md", ".py", ".sh", ".json", ".yml", ".service", ".timer", ".cron", ".logrotate", ".txt"}
PATTERNS = {
    "personal home path": r"/(?:Users|home)/[A-Za-z0-9_.-]+/",
    "email address": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "AWS access key": r"(?:AKIA|ASIA)[A-Z0-9]{16}",
    "private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "credential assignment": r"(?im)^\s*(?:aws_secret_access_key|secret_access_key|password2?|token)\s*=\s*(?![\"']?(?:XXX|EXAMPLE|YOUR_))\S+",
}


def png_chunks(data):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Invalid PNG signature")
    position = 8
    ended = False
    while position < len(data):
        start = position
        if len(data) - position < 12:
            raise ValueError("Truncated PNG")
        length = struct.unpack_from(">I", data, position)[0]
        kind = data[position + 4:position + 8]
        position += 12 + length
        if position > len(data):
            raise ValueError("Truncated PNG chunk")
        block = data[start:position]
        if zlib.crc32(block[4:-4]) & 0xffffffff != struct.unpack(">I", block[-4:])[0]:
            raise ValueError("Invalid PNG checksum")
        yield kind, block
        if kind == b"IEND":
            ended = True
            if position != len(data):
                raise ValueError("Trailing data in PNG")
    if not ended:
        raise ValueError("Missing PNG end")


def clean_png(path):
    path = Path(path)
    data = path.read_bytes()
    clean = data[:8] + b"".join(block for kind, block in png_chunks(data) if kind in PNG_ALLOWED)
    if clean != data:
        path.write_bytes(clean)


def public_files(root=ROOT):
    entries = (root / "RELEASE_FILES").read_text().splitlines()
    result = []
    for name in entries:
        if not name or name.startswith("#"):
            continue
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or any(p in ("local", ".git", "dist", "__pycache__") for p in relative.parts):
            raise ValueError("Unsafe release allowlist entry")
        path = root / relative
        if path.resolve() != path.absolute() or not path.is_file():
            raise ValueError("Release files must be regular files without symlink components")
        result.append(relative)
    if len(set(result)) != len(result):
        raise ValueError("Duplicate release allowlist entry")
    return result


def scan(root, files):
    findings = []
    for relative in files:
        path = root / relative
        if path.suffix == ".png":
            if any(kind not in PNG_ALLOWED for kind, _ in png_chunks(path.read_bytes())):
                findings.append(f"{relative}: PNG contains non-public metadata")
            continue
        text = path.read_text(encoding="utf-8")
        for name, pattern in PATTERNS.items():
            if re.search(pattern, text):
                findings.append(f"{relative}: possible {name}")
        for literal in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
            try:
                ip = ipaddress.ip_address(literal)
            except ValueError:
                continue
            if ip.is_private and not ip.is_loopback and not any(ip in ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
                findings.append(f"{relative}: private network address")
    return findings


def export(output, root=ROOT):
    files = public_files(root)
    findings = scan(root, files)
    if findings:
        raise ValueError("Release refused:\n" + "\n".join(findings))
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists; select a new release directory")
    output.mkdir(parents=True, mode=0o700)
    for relative in files:
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, target)
        target.chmod(0o755 if (root / relative).stat().st_mode & 0o111 else 0o644)
    return len(files)


def scan_workspace(root=ROOT):
    """Check ignored/untracked files too; Git history needs a separate review."""
    allowed = set(public_files(root))
    files, findings = [], []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts[0] == ".git":
            continue
        if path.is_symlink():
            findings.append(f"{relative}: symlinks are not permitted in the public working tree")
            continue
        if not path.is_file():
            continue
        candidate = relative
        if relative.parts[0] == "dist" and len(relative.parts) >= 3:
            candidate = Path(*relative.parts[2:])
        if candidate not in allowed:
            findings.append(f"{relative}: not in the release allowlist; move private files outside the project")
            continue
        files.append(relative)
    return findings + scan(root, files)


def write_archive(output, root=ROOT):
    """Package file contents without OS attributes, owner names or local timestamps."""
    files = public_files(root)
    findings = scan(root, files)
    if findings:
        raise ValueError("Archive refused:\n" + "\n".join(findings))
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("Archive already exists; select a new destination")
    with output.open("xb") as stream:
        write_canonical_archive(stream, root, files)
    return len(files)


def write_canonical_archive(stream, root, files):
    # Stored entries have identical bytes across Python/zlib versions. A single
    # representation lets verification reject hidden headers and trailing data.
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for relative in files:
            source = root / relative
            info = zipfile.ZipInfo("frostkeep/" + relative.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.file_size = source.stat().st_size
            with source.open("rb") as original, archive.open(info, "w") as entry:
                shutil.copyfileobj(original, entry, length=1024 * 1024)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true")
    p.add_argument("--workspace", action="store_true", help="Also scan ignored/untracked working-tree files and distribution copies")
    p.add_argument("--output", type=Path)
    p.add_argument("--archive", type=Path, help="Create a metadata-free ZIP outside the working tree")
    p.add_argument("--verify-archive", type=Path, help="Verify archive contents, allowlist and metadata against this source")
    p.add_argument("--strip-png-metadata", action="store_true", help="Remove ancillary metadata without changing image pixels")
    args = p.parse_args()
    try:
        files = public_files()
        if args.strip_png_metadata:
            for relative in files:
                if relative.suffix == ".png":
                    clean_png(ROOT / relative)
        findings = scan_workspace() if args.workspace else scan(ROOT, files)
        if findings:
            raise ValueError("\n".join(findings))
        if args.output:
            print(f"Exported {export(args.output)} reviewed public files. No publication performed.")
        else:
            print(f"Privacy checks passed for {len(files)} allowlisted files. Human review is still required.")
        if args.archive:
            print(f"Packaged {write_archive(args.archive)} public files without owner names or local filesystem metadata.")
        if args.verify_archive:
            verify_archive(args.verify_archive)
            print("Archive contents, paths, permissions and metadata verified against source.")
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


def verify_archive(path, root=ROOT):
    files = public_files(root)
    # Never parse/decompress the untrusted archive: compare its complete byte
    # representation with a canonical package of the reviewed sources instead.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as supplied, tempfile.TemporaryFile() as expected:
        if not stat.S_ISREG(os.fstat(supplied.fileno()).st_mode):
            raise ValueError("Archive must be a regular file")
        write_canonical_archive(expected, root, files)
        if os.fstat(supplied.fileno()).st_size != expected.tell():
            raise ValueError("Archive differs from canonical reviewed package")
        expected.seek(0)
        while True:
            block = expected.read(1024 * 1024)
            if supplied.read(len(block) or 1) != block:
                raise ValueError("Archive differs from canonical reviewed package")
            if not block:
                break


if __name__ == "__main__":
    sys.exit(main())
