# Setup and recovery

## Storage and keys

Configure a private AWS S3 bucket and an rclone S3 remote, then wrap it directly in crypt:

```ini
[archive]
type = crypt
remote = s3-backend:YOUR_PRIVATE_BUCKET/archives
filename_encryption = standard
directory_name_encryption = true
# Set password and password2 privately with rclone config.
```

Keep the entire rclone configuration, encryption material and account recovery instructions in an independent encrypted recovery kit. Record the bucket, region and prefix holding your backups. Test that the kit decrypts a small file. rclone-obscured passwords are reversible; losing the crypt keys can make backups unreadable.

Use a backup identity with list, upload/multipart, object inspection and metadata-read permissions; keep object/version deletion denied. Recovery needs read and `s3:RestoreObject` permissions, plus relevant KMS permissions when applicable. FrostKeep does not configure IAM, retention or Object Lock. See [rclone permissions](https://rclone.org/s3/#s3-permissions).

Backups are full archives, not incremental or deduplicated. Budget for retained and failed runs, retrieval, requests, temporary restored copies and egress using [AWS pricing](https://aws.amazon.com/s3/pricing/). Review minimum storage-duration charges before choosing expiry. Keep metadata in Standard for as long as its guest archives, expire noncurrent versions deliberately, and abort abandoned multipart uploads. Lifecycle expiration can remove data despite the writer's deletion denial.

## Configuration

Install with `sudo bash scripts/install.sh`, then edit `/etc/frostkeep/config.json`. Existing configuration is preserved. Files containing configuration must be root-owned and private (`0600`); staging/state directories must be private (`0700`) without symlink components.

| Setting | Default / purpose |
| --- | --- |
| `remote` | `archive:`; named crypt remote, optionally with a subdirectory |
| `rclone_config` | `/root/.config/rclone/rclone.conf` |
| `staging_dir` | `/var/lib/vz/frostkeep`; dedicated dump space |
| `state_dir` | `/var/lib/frostkeep`; run and health records |
| `exclude_guests` | `[]`; set your exclusions explicitly |
| `minimum_free_bytes` | 10 GiB reserve; also allow space for the actual dump |
| `keep_local_archives` | `false`; enable for local restore drills |
| `maximum_backup_age_hours` | `840`; full-backup freshness threshold |
| `notification_command` | `[]`; optional executable and argument array |

Advanced defaults for host paths, database capture, command timeouts and the shared lock are in [the library](../lib/frostkeep/frostkeep.py). Configuration is JSON data; unknown keys are rejected. Use `frostkeep --config /absolute/private/config.json COMMAND` for another configuration.

An explicit rclone config file is required. `RCLONE_*` overrides, including config-password injection, are removed. Unattended operation requires a readable working config protected by root permissions and host disk security. Keep software patched and rerun preflight after Proxmox upgrades; container snapshot checks use installed Proxmox internals.

### Existing installations

Wait for active jobs to finish, verify their coverage, and save old scripts/configuration outside this project. Before installing, create the private FrostKeep configuration with your existing remote and exclusions. Retain `/run/lock/pve-glacier.lock` to prevent old/new overlap. Install, run preflight and test one guest before changing schedules. Legacy date-only archives use the manual recovery procedure below.

The installer stages files and rolls back catchable failures. After SIGKILL or power loss, inspect private `.frostkeep-install-*` recovery directories and reinstall before reactivating scheduling.

## Schedule and alerts

After a successful backup and restore drill, enable **one** scheduler:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now frostkeep.timer
systemctl list-timers frostkeep.timer
```

The timer runs at 03:00 on the first of each month in the host timezone. `Persistent=true` can trigger a missed run when enabled or after boot. Disable any old backup cron entry first; `deploy/pve-glacier.cron` is an alternative, not an additional schedule.

For optional HTTPS notifications, privately copy `/etc/frostkeep/webhook.example.json` to `/etc/frostkeep/webhook.json`, set mode `0600`, and configure the endpoint. Formats are `generic`, `discord` and `slack`; optional authorization headers stay in that file. Set:

```json
"notification_command": [
  "/usr/local/bin/frostkeep-notify-webhook",
  "--config", "/etc/frostkeep/webhook.json"
]
```

Test delivery explicitly, then enable freshness checks:

```sh
sudo systemctl enable --now frostkeep-health.timer
frostkeep health --notify
```

Events contain status, timestamps and counts/reason codes, without guest names or credentials. Delivery failures appear in the journal and local notification records without changing data-completion status. Health checks repeat unhealthy alerts; use an external dead-man monitor for host loss or failed local monitoring. Until a full-inventory backup succeeds, health reports no full backup. Subset runs do not clear that condition.

## Interrupted backups and cleanup

Each run has isolated staging and a unique remote directory. Guest uploads use Deep Archive; host configuration and metadata use Standard. Completion requires coverage, size/class checks and verified manifest/marker publication. Dump failures retain local files; guest disks or mounts excluded in Proxmox remain excluded. Do not change guest/storage configuration during a run.

```sh
frostkeep status
journalctl -u frostkeep.service
frostkeep resume RUN_ID
frostkeep resume RUN_ID --execute
```

Resume creates a new run referencing verified completed uploads, with fresh dumps for unfinished guests. Original objects keep their original expiry dates; retain them while referenced. A resumed set can contain snapshots from different times. Older runs stranded during finalization can also be recovered after checking their storage context and payloads.

Proxmox workers can outlive a killed client. Inspect active tasks and guest locks before restarting work; never blindly unlock a guest. Detailed diagnostics are in private per-run logs.

```sh
frostkeep cleanup RUN_ID
frostkeep cleanup RUN_ID --execute
```

Cleanup removes only that local staging directory, checks remote coverage for completed runs, and retains a private audit record. Unfinished runs require `--allow-incomplete` because local files may be the only copy; cleanup also removes their resume context. Remote objects are never deleted.

## Restore a guest

Keep recovery credentials separate from the backup writer. Select an exact guest archive from a verified manifest:

```sh
frostkeep restore list
frostkeep restore inspect RUN_ID
frostkeep restore request RUN_ID ARCHIVE_NAME --tier Bulk --days 3
frostkeep restore request RUN_ID ARCHIVE_NAME --tier Bulk --days 3 --execute
frostkeep restore retrieval-status RUN_ID ARCHIVE_NAME
```

Listing alone does not prove completion. Retrieval targets one encrypted object and can incur charges. Wait for AWS to finish; an absent restore status does not prove readiness. Download before the temporary copy expires. See [AWS retrieval options](https://docs.aws.amazon.com/AmazonS3/latest/userguide/restoring-objects-retrieval-options.html).

```sh
frostkeep restore download RUN_ID ARCHIVE_NAME --destination /srv/frostkeep-restore
frostkeep restore verify RUN_ID ARCHIVE_NAME --file /srv/frostkeep-restore/ARCHIVE_NAME
frostkeep restore guest RUN_ID ARCHIVE_NAME \
  --file /srv/frostkeep-restore/ARCHIVE_NAME --target-id 901 --storage local-zfs
```

Use a private `0700` destination. Downloads enforce size, SHA-256 and free-space checks, refuse overwrites and remove failed partial files. Retry failed downloads from the beginning.

Replace the target ID and storage with an unused ID and suitable storage on your installation. Review the plan, then repeat the guest command with `--execute`. FrostKeep refuses the original/existing guest ID and keeps the restored guest stopped. A failed restore can leave a partial guest; inspect it manually. Restore only trusted archives.

Before booting, inspect networking, static IPs, mounts, devices, hooks, boot settings and HA. Use disconnected networking or an isolated bridge for the first boot; a new MAC does not prevent duplicate IPs. Record the archive checksum, retrieval result, boot and application checks. Stop the test guest afterwards; delete it only after confirming it is disposable.

### Host and legacy recovery

Download and verify `hostconfig.tar.gz` the same way. It contains sensitive configuration and a consistent database snapshot at `inventory/config.db`, not a bootable image or key escrow. Review it privately, reinstall Proxmox, and recover settings selectively. Never extract it over a live host or replace a running cluster database.

The restore CLI requires new-format JSON manifests. For legacy date-only runs, manually check coverage, request the exact encrypted S3 object, download through the original crypt remote and test zstd integrity before restoring to an unused isolated guest. A newly calculated checksum cannot prove historical integrity. Old verifier scripts may destroy fixed guest IDs; do not reuse them blindly.
