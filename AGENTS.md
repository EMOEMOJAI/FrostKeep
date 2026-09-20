# Working on FrostKeep

FrostKeep is a Python 3.10+ CLI for encrypted Proxmox VE guest backups to Amazon S3 Glacier Deep Archive. Runtime Python uses only the standard library. Read [README.md](README.md) for scope and [docs/guide.md](docs/guide.md) for operational behavior.

## Repository map

- `lib/frostkeep/frostkeep.py`: backup, manifests, recovery, cleanup and health checks.
- `scripts/`: CLI entry points, installer, webhooks, validation and release export.
- `config/` and `deploy/`: public examples and scheduling templates.
- `tests/`: synthetic fixtures, local crypt round trips and failure injection.
- `RELEASE_FILES`: explicit public export allowlist; update it when adding public files.

## Validate changes

Run from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 bash scripts/check.sh
```

Strict validation needs rclone, ShellCheck and Gitleaks (`FROSTKEEP_STRICT_CHECKS=1`). CI uses GitHub-hosted runners and also checks Linux mapped-user permissions. For documentation-only changes, check links and run `python3 scripts/release.py --check --workspace`; CI supplies the full gate. See [CONTRIBUTING.md](CONTRIBUTING.md) for release steps.

## Preserve these boundaries

- Keep credentials, webhook URLs, personal identifiers, host inventories and operational evidence outside this repository, including ignored files. Use synthetic examples.
- Tests must not contact live Proxmox hosts or cloud storage. Do not install, deploy, start backups or request paid retrievals as part of a code check.
- Preserve private file permissions, shared locking, isolated staging and completion verification. Test behavioral changes at failure boundaries.
- Preserve planning before execution for retrieval requests, guest restores, resume and cleanup. Never delete cloud objects or automatically start restored guests.
- Keep public docs concise. Do not claim a passing test suite proves a deployment's backup or cloud recovery succeeded.

Use the shared guidance here for coding tools that support `AGENTS.md`; otherwise attach it explicitly as project context. The [documentation index](llms.txt) provides public reference links.
