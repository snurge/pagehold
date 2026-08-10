# PageHold Architecture

## Overview

PageHold is one self-contained service with one local account and one local data
directory. The Python HTTP process owns authentication, scheduling, crawl-job
coordination, replay, and the user interface. SQLite is the source of truth for
metadata and job state; captured bytes live in the filesystem.

## Components

| Component | Responsibility |
| --- | --- |
| `app.py` | HTTP routes, session security, UI, scheduler, crawling, replay |
| `metadata_store.py` | SQLite schema, transactions, capture runs, durable jobs and frontiers |
| `capture_engine.py` | Automatic choice between lightweight and active-browser capture |
| `capture_worker.py` | Isolated browser process contract |
| `asset_store.py` | Content-addressed asset storage and reference measurement |
| `archive_manifest.py` | Signed local manifest for every completed capture |
| `archive_portability.py` | Capture/site packages and WARC export |
| `archive_backup.py` | Consistent backup, verification, restore, and integrity inspection |
| `security.py` | Outbound URL validation and authentication rate limiting |

## Data Layout

```text
data/
  websnapshot.sqlite3
  snapshots/
  profiles/
  capture-work/
  integrity/
    identity.json
    identity.key
    manifests/
```

The database groups captured pages into a timestamped capture run. A capture run
is the user-visible snapshot of a site. Each page and asset retains its source
URL, local file, status, media type, byte count, and stable archive identifier.

## Capture Flow

1. The user adds a URL; PageHold normalizes abbreviated hostnames to HTTPS.
2. A persistent job and durable crawl frontier are created transactionally.
3. The crawler obeys host, path, robots, delay, depth, page, timeout, and size bounds.
4. Automatic engine selection may invoke an isolated Chromium worker for active pages.
5. Pages and assets are written locally and linked to one capture run.
6. A signed manifest records file digests and stable identifiers.
7. Interrupted jobs are recovered automatically after restart.

## Replay Security

Replay never executes archived scripts or submits archived forms. Content is
served with restrictive browser policies; links to pages in the same capture are
rewritten to local replay routes. Every page and asset request rechecks the
site's current private/public visibility.

## Deployment

The production profile runs one Python service bound to loopback, with Caddy (or
an equivalent reverse proxy) terminating HTTPS. Runtime data and secrets are
outside the source tree. Service management, backup scheduling, and TLS remain
deployment concerns rather than application dependencies.
