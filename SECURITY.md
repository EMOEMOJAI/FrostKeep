# Security and privacy

FrostKeep is pre-release. The host and root account are trusted; a compromised host can read keys and plaintext. Crypt encryption and checksums detect corruption, but cannot protect against an attacker who controls both encryption keys and object writes. A real restore drill remains essential.

Keep credentials, encryption recovery material and webhook settings private. Deny deletion to the backup writer and manage recovery access separately. Versioning and deletion denial are not equivalent to immutable retention. Review restored guest networking and storage before booting.

Actual configuration, logs, inventories, audit reports, original artwork and backups belong **outside this project**, including ignored directories. Public examples must be synthetic. Use the allowlisted release exporter and review its output: automated privacy checks cannot guarantee anonymity. Inspect Git history and commit author identity separately before publication.

Report vulnerabilities privately through the hosting platform's private reporting feature when available. Never attach credentials, personal identifiers or unredacted operational logs to public issues. FrostKeep sends no telemetry; notifications run only through a hook you configure.
