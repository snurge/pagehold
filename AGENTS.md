# PageHold Working Agreement

PageHold is a self-hosted, single-account website archiver. WebSnapshot remains
the internal compatibility name for some paths and environment variables.

## Read First

Read `README.md`, `ARCHITECTURE.md`, `DECISIONS.md`, `ROADMAP.md`, and
`CHANGELOG.md` before substantial work, then inspect the relevant implementation.

## Product Invariants

- First-use setup creates the only local archive-owning account and closes registration atomically.
- Crawl only sites explicitly added by the user. Do not add Internet-wide discovery.
- Keep crawling bounded and polite through depth, page-count, timeout, and delay limits.
- Preserve public/private access rules on every snapshot and asset request.
- Store replay resources locally. Never depend on a live site for ordinary replay.
- Do not query, crawl, import, schedule, or repair from the Internet Archive. A site-specific external history link may be opened by the user's browser.
- Keep crawler selection automatic and internal. Active-browser work runs outside the HTTP process.
- Keep archived scripts and form submission disabled during replay.
- Never delete accounts, sites, snapshots, or archive files without explicit user intent.
- Make routine recovery automatic and restart-safe. Ask for confirmation only for destructive, privacy-expanding, or exceptional security actions.
- Keep the ordinary interface simple and hide diagnostics behind advanced controls.
- Keep content-object garbage collection report-only until a destructive policy is explicitly approved.
- PageHold source is licensed under `AGPL-3.0-only`. Preserve `LICENSE` unchanged.
- Never commit runtime data, archives, credentials, keys, browser profiles, logs, or databases.
- Do not create a hosted repository, remote, release, tag, or publication without Mike's explicit approval.

## Ownership Boundaries

- `app.py`: HTTP application, authentication, views, capture, replay, jobs, and scheduling.
- `metadata_store.py`: SQLite metadata, migrations, persistent jobs, frontiers, and recovery.
- `archive_manifest.py` and `canonical_json.py`: signed local capture manifests.
- `capture_engine.py` and `capture_worker.py`: automatic isolated capture-engine boundary.
- `asset_store.py`: content-addressed local assets.
- `archive_backup.py` and `websnapshot_admin.py`: verified backup, restore, integrity, and maintenance.
- `security.py`: outbound request policy and login rate limiting.
- `deploy/` and `PRODUCTION.md`: service-manager and HTTPS templates without machine secrets.
- `data/`: runtime state; never source code.

## Change Workflow

1. State the user-visible result and inspect the relevant code and data shape.
2. Keep the edit scoped and add tests proportional to risk.
3. For storage changes, back up first and test migration on a copy.
4. For replay changes, verify static and JavaScript-rendered fixtures visually.
5. Run `./scripts/run-tests.sh`.
6. Restart the local service after runtime changes and verify `/health` and the changed workflow.
7. Update the relevant project records using ISO dates.

## Source Control

This repository is local-only until Mike explicitly approves publication. Keep
`main` as the reviewed baseline, use small commits, inspect staged files, and
never bypass `.githooks/pre-commit` or force-add ignored runtime material.
