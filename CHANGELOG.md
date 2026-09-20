# Changelog

## 0.2.2 — 2026-09-21

- Clarify restore command help, execution flags, cleanup risks and option defaults.
- Correct stale pre-release wording.

## 0.2.1 — 2026-09-20

- First stable release.
- Keep full-backup failure and interruption alerts active after successful subset backups.
- Deterministic local crypt filename tests across supported encodings.
- GitHub-hosted Python 3.10–3.14 checks, CodeQL and verified release provenance.

## 0.2.0 — pre-release

- Configurable FrostKeep CLI with legacy command wrappers.
- Isolated staging, encrypted guest archives, checksum manifests and verified completion markers.
- Resume using verified uploads, explicit local cleanup, and stopped guest restores.
- Failure/freshness monitoring with optional private HTTPS webhooks.
- Hardened subprocess handling, mapped-container permissions, resource limits and installer rollback.
- Recoverable finalization after hard stops, including older stranded runs, with regression tests.
- Allowlisted, metadata-free releases and a shorter setup/recovery guide.

Validate a full backup, cloud retrieval and isolated restore on your installation before relying on FrostKeep.
