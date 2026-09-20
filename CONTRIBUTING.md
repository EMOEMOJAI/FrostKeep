# Contributing

Use synthetic fixtures; tests must never contact production hosts or cloud storage. Keep private configuration, operational evidence and original artwork outside the project.

```sh
PYTHONDONTWRITEBYTECODE=1 bash scripts/check.sh
```

Strict checks require rclone, ShellCheck and Gitleaks. CI covers Python 3.10/3.13, local crypt round trips, failure handling and Linux mapped-user permissions (`acl` required). macOS skips only the Linux-root tests. Automated checks do not replace a real backup, cloud retrieval and isolated restore drill.

For a release, update the version, changelog and `RELEASE_FILES`, then:

```sh
python3 scripts/release.py --check --workspace
python3 scripts/release.py --output dist/frostkeep-VERSION --archive ../frostkeep-public.zip
python3 scripts/release.py --verify-archive ../frostkeep-public.zip
```

Use fresh destinations. Review exported files, image pixels and any Git history/author identity before publishing. The exporter removes filesystem metadata from the ZIP and refuses unapproved files; it does not publish anything. For new PNG artwork, run `--strip-png-metadata` before export. The root `favicon.png` is used by T3 Code; the README uses `assets/branding/banner.png`.
