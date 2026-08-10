# PageHold Decisions

## D001 - Explicit-URL Archiving

**Accepted:** PageHold archives only sites explicitly added by its local user. It
is not an Internet-wide crawler or general search engine.

## D002 - Single Local Account

**Accepted:** First-use setup creates one archive-owning account and atomically
closes registration. There are no separate server-management accounts.

## D003 - Local Custody

**Accepted:** SQLite metadata, captured files, profile data, manifests, and keys
remain in the installation's data directory. Backup and export preserve user
custody without introducing an external service dependency.

## D004 - Automatic Capture Selection

**Accepted:** Ordinary users do not choose a crawler. PageHold selects a bounded
lightweight or active-browser path internally and records engine provenance.

## D005 - Safe Replay

**Accepted:** Archived scripts and form submissions are disabled during replay.
Resources are served locally with restrictive browser policies.

## D006 - No Internet Archive Import

**Accepted:** Importing or repairing captures from the Internet Archive is
retired. Existing imported evidence is preserved; new UI uses only a direct,
site-specific history link opened by the user's browser.

## D007 - Signed Local Manifests

**Accepted:** Every completed capture receives a deterministic Ed25519-signed
manifest covering its pages and resources. The non-expiring local key is part of
backup integrity and has no routine rotation workflow.

## D008 - Automatic Recovery

**Accepted:** Persistent crawl jobs resume after restart. Routine recovery should
avoid human intervention; confirmation is reserved for consequential choices.

## D009 - Publication License

**Accepted:** PageHold source uses `AGPL-3.0-only`. This does not apply the source
license to archived websites, user data, or separately licensed dependencies.
No source publication is authorized until Mike gives explicit approval.
