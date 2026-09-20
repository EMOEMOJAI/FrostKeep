# Contributing

Use synthetic fixtures; tests must never contact production hosts or cloud storage. Keep private configuration, operational evidence and original artwork outside the project.

```sh
PYTHONDONTWRITEBYTECODE=1 bash scripts/check.sh
```

Strict checks require rclone, ShellCheck and Gitleaks. CI covers Python 3.10/3.13, local crypt round trips, failure handling and Linux mapped-user permissions (`acl` required). macOS skips only the Linux-root tests. Automated checks do not replace a real backup, cloud retrieval and isolated restore drill.

GitHub also checks workflows, internal documentation links and CodeQL security findings. Coverage reports appear in Actions summaries and expire after 14 days; they establish a baseline without a percentage gate. Subprocess-only execution is not measured. Dependabot proposes action and coverage-tool updates weekly; review them before merging. Downloaded rclone, Gitleaks and actionlint versions/checksums are maintained in the workflow.

For a release, update the version, changelog and `RELEASE_FILES`, then:

```sh
python3 scripts/release.py --check --workspace
python3 scripts/release.py --output dist/frostkeep-VERSION --archive ../frostkeep-public.zip
python3 scripts/release.py --verify-archive ../frostkeep-public.zip
```

Use fresh destinations. Review exported files, image pixels and any Git history/author identity before publishing. The exporter removes filesystem metadata from the ZIP and refuses unapproved files; it does not publish anything. For new PNG artwork, run `--strip-png-metadata` before export. The root `favicon.png` is used by T3 Code; the README uses `assets/branding/banner.png`.

For future releases, create a draft tagged `vVERSION` with `FrostKeep-VERSION-public.zip` and its `SHA256SUMS`, then publish it. **Release provenance** reruns checks, rebuilds from the tag and attests only if both uploaded files match. It never replaces release assets. Manual runs on `main` produce attested candidate packages without publishing a release. Verify a downloaded package with `gh attestation verify PACKAGE.zip --repo EMOEMOJAI/FrostKeep`. Releases predating this workflow have no build attestation.
