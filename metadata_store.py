"""SQLite metadata and durable crawl-job storage for PageHold."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA_VERSION = 16
TERMINAL_JOB_STATUSES = {"complete", "error", "interrupted"}


def new_opaque_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(16)}"


class MetadataStoreError(RuntimeError):
    """Base class for metadata-store failures."""


class ActiveJobExists(MetadataStoreError):
    """Raised when a site already has a running persistent job."""

    def __init__(self, job_id: str):
        super().__init__(f"site already has a running job: {job_id}")
        self.job_id = job_id


class StorageQuotaExceeded(MetadataStoreError):
    """Raised when new archive work would exceed an owner's configured quota."""

    def __init__(self, quota_bytes: int, used_bytes: int, reserved_bytes: int, required_bytes: int):
        self.quota_bytes = quota_bytes
        self.used_bytes = used_bytes
        self.reserved_bytes = reserved_bytes
        self.required_bytes = required_bytes
        self.available_bytes = max(0, quota_bytes - used_bytes - reserved_bytes)
        available_gb = self.available_bytes / (1024 ** 3)
        required_gb = required_bytes / (1024 ** 3)
        super().__init__(
            f"Storage quota has {available_gb:.1f} GB available, but this operation's "
            f"configured safety ceiling is {required_gb:.1f} GB. Reduce the crawl size "
            "or increase the local storage allocation."
        )


class ArchiveStorageCapacityExceeded(StorageQuotaExceeded):
    """Raised when new work would exceed the installation's storage ceiling."""

    def __init__(self, quota_bytes: int, used_bytes: int, reserved_bytes: int, required_bytes: int):
        super().__init__(quota_bytes, used_bytes, reserved_bytes, required_bytes)
        available_gb = self.available_bytes / (1024 ** 3)
        required_gb = required_bytes / (1024 ** 3)
        self.args = (
            f"Archive storage capacity has {available_gb:.1f} GB available, but "
            f"this operation's configured safety ceiling is {required_gb:.1f} GB. "
            "Reduce the crawl size or increase the local storage allocation.",
        )


class JobCapacityExceeded(MetadataStoreError):
    """Raised when the installation-wide running-job limit has been reached."""

    def __init__(self, limit: int):
        self.limit = limit
        super().__init__(
            f"PageHold is already running its configured maximum of {limit} archive jobs. "
            "Try again after one finishes."
        )


class MetadataStore:
    """Own the installation's normalized SQLite metadata and job records."""

    USER_COLUMNS = {
        "id", "email", "name", "password", "role", "status", "created_at", "last_login_at",
        "email_verified_at", "session_version",
    }
    SITE_COLUMNS = {
        "id", "owner_id", "name", "url", "visibility", "interval", "custom_days",
        "crawl_depth", "max_pages", "wayback_enabled", "wayback_frequency",
        "wayback_limit", "created_at", "last_snapshot_at", "next_snapshot_at",
        "last_crawl_at", "wayback_updated_at", "archive_site_id",
        "schedule_timezone", "schedule_time", "schedule_weekday", "schedule_month_day",
        "schedule_paused", "change_policy", "last_source_digest",
    }
    SNAPSHOT_COLUMNS = {
        "id", "site_id", "kind", "source_url", "final_url", "status", "content_type",
        "bytes", "file", "rendered", "wayback_timestamp", "created_at", "created_by",
        "capture_run_id", "archive_page_id", "assets",
        "source_content_digest",
    }
    ASSET_COLUMNS = {
        "id", "source_url", "final_url", "status", "content_type", "bytes", "file",
        "fallback_from_snapshot", "resource_id", "content_digest",
    }
    EVENT_COLUMNS = {"id", "actor_id", "action", "detail", "created_at"}

    def __init__(self, database_path: str | Path, legacy_json_path: str | Path | None = None):
        self.database_path = Path(database_path)
        self.legacy_json_path = Path(legacy_json_path) if legacy_json_path else None
        self._lock = threading.RLock()
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        for path in (
            self.database_path,
            Path(f"{self.database_path}-wal"),
            Path(f"{self.database_path}-shm"),
        ):
            if path.exists():
                path.chmod(0o600)
        return connection

    def initialize(self, default_factory: Callable[[], dict[str, list[dict[str, Any]]]]) -> None:
        with self._lock:
            if self._initialized:
                return
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as connection:
                self._apply_migrations(connection)
                metadata_count = sum(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("users", "sites", "snapshots", "events")
                )
                if metadata_count == 0:
                    document = None
                    source_digest = None
                    if self.legacy_json_path and self.legacy_json_path.is_file():
                        source_bytes = self.legacy_json_path.read_bytes()
                        document = json.loads(source_bytes.decode("utf-8"))
                        source_digest = hashlib.sha256(source_bytes).hexdigest()
                    if document is None:
                        document = default_factory()
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        self._write_document(connection, document, previous=self._empty_document())
                        self._backfill_capture_runs(connection)
                        if source_digest:
                            connection.execute(
                                """
                                INSERT INTO legacy_imports(source_path, source_sha256, imported_at)
                                VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                                """,
                                (str(self.legacy_json_path), source_digest),
                            )
                        connection.commit()
                    except Exception:
                        connection.rollback()
                        raise
            self._initialized = True

    def _apply_migrations(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        applied = {
            row[0] for row in connection.execute("SELECT version FROM schema_migrations")
        }
        if applied and max(applied) > SCHEMA_VERSION:
            raise MetadataStoreError(
                f"database schema {max(applied)} is newer than supported schema {SCHEMA_VERSION}"
            )
        if 1 not in applied:
            try:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE users (
                        id TEXT PRIMARY KEY,
                        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                        name TEXT NOT NULL,
                        password TEXT NOT NULL,
                        role TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        last_login_at TEXT,
                        extra_json TEXT NOT NULL DEFAULT '{}'
                    );
                    CREATE TABLE sites (
                        id TEXT PRIMARY KEY,
                        owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        name TEXT NOT NULL,
                        url TEXT NOT NULL,
                        visibility TEXT NOT NULL,
                        interval TEXT NOT NULL,
                        custom_days TEXT,
                        crawl_depth INTEGER NOT NULL,
                        max_pages INTEGER NOT NULL,
                        wayback_enabled INTEGER NOT NULL DEFAULT 0,
                        wayback_frequency TEXT NOT NULL DEFAULT 'yearly',
                        wayback_limit INTEGER NOT NULL DEFAULT 20,
                        created_at TEXT NOT NULL,
                        last_snapshot_at TEXT,
                        next_snapshot_at TEXT,
                        last_crawl_at TEXT,
                        wayback_updated_at TEXT,
                        extra_json TEXT NOT NULL DEFAULT '{}'
                    );
                    CREATE TABLE snapshots (
                        id TEXT PRIMARY KEY,
                        site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                        kind TEXT NOT NULL,
                        source_url TEXT NOT NULL,
                        final_url TEXT NOT NULL,
                        status INTEGER NOT NULL,
                        content_type TEXT NOT NULL,
                        bytes INTEGER NOT NULL,
                        file TEXT NOT NULL,
                        rendered INTEGER NOT NULL DEFAULT 0,
                        wayback_timestamp TEXT,
                        created_at TEXT NOT NULL,
                        created_by TEXT,
                        extra_json TEXT NOT NULL DEFAULT '{}'
                    );
                    CREATE INDEX snapshots_site_created_idx
                        ON snapshots(site_id, created_at DESC);
                    CREATE UNIQUE INDEX snapshots_wayback_timestamp_idx
                        ON snapshots(site_id, wayback_timestamp)
                        WHERE wayback_timestamp IS NOT NULL;
                    CREATE TABLE snapshot_assets (
                        snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
                        id TEXT NOT NULL,
                        source_url TEXT,
                        final_url TEXT,
                        status INTEGER,
                        content_type TEXT,
                        bytes INTEGER,
                        file TEXT NOT NULL,
                        fallback_from_snapshot TEXT,
                        extra_json TEXT NOT NULL DEFAULT '{}',
                        PRIMARY KEY(snapshot_id, id)
                    );
                    CREATE TABLE events (
                        id TEXT PRIMARY KEY,
                        actor_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        detail TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        extra_json TEXT NOT NULL DEFAULT '{}'
                    );
                    CREATE INDEX events_created_idx ON events(created_at DESC);
                    CREATE TABLE crawl_jobs (
                        id TEXT PRIMARY KEY,
                        site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                        actor_id TEXT,
                        kind TEXT NOT NULL,
                        status TEXT NOT NULL CHECK(status IN ('running', 'complete', 'error', 'interrupted')),
                        message TEXT NOT NULL,
                        captured INTEGER NOT NULL DEFAULT 0,
                        failed INTEGER NOT NULL DEFAULT 0,
                        parameters_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        finished_at TEXT
                    );
                    CREATE UNIQUE INDEX one_running_job_per_site_idx
                        ON crawl_jobs(site_id) WHERE status = 'running';
                    CREATE INDEX crawl_jobs_site_created_idx
                        ON crawl_jobs(site_id, created_at DESC);
                    CREATE TABLE crawl_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        job_id TEXT NOT NULL REFERENCES crawl_jobs(id) ON DELETE CASCADE,
                        resource_url TEXT NOT NULL,
                        depth INTEGER,
                        attempt_number INTEGER NOT NULL,
                        status TEXT NOT NULL CHECK(status IN ('running', 'captured', 'failed', 'skipped')),
                        snapshot_id TEXT REFERENCES snapshots(id) ON DELETE SET NULL,
                        error TEXT,
                        started_at TEXT NOT NULL,
                        finished_at TEXT,
                        UNIQUE(job_id, resource_url, attempt_number)
                    );
                    CREATE INDEX crawl_attempts_job_idx ON crawl_attempts(job_id, id);
                    CREATE TABLE legacy_imports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source_path TEXT NOT NULL,
                        source_sha256 TEXT NOT NULL UNIQUE,
                        imported_at TEXT NOT NULL
                    );
                    INSERT INTO schema_migrations(version, name, applied_at)
                    VALUES (1, 'normalized_archive_metadata_and_jobs', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
                    COMMIT;
                    """
                )
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
        if 2 not in applied:
            self._migrate_capture_runs_and_archive_ids(connection)
        if 3 not in applied:
            self._migrate_wayback_capture_times(connection)
        if 5 not in applied:
            self._migrate_crawl_job_controls(connection)
        if 6 not in applied:
            self._migrate_content_addressed_assets(connection)
        if 8 not in applied:
            self._migrate_user_storage_quotas(connection)
        if 9 not in applied:
            self._migrate_calendar_scheduling(connection)
        if 10 not in applied:
            self._migrate_local_account_fields(connection)
        if 11 not in applied:
            self._migrate_archive_storage_capacity(connection)
        if 12 not in applied:
            self._migrate_safer_offset_capture_defaults(connection)
        if 13 not in applied:
            self._migrate_durable_crawl_frontier(connection)
        if 16 not in applied:
            self._migrate_retire_wayback_imports(connection)

    @staticmethod
    def _migrate_local_account_fields(connection: sqlite3.Connection) -> None:
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                ALTER TABLE users ADD COLUMN email_verified_at TEXT;
                ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1;
                UPDATE users
                SET email_verified_at=COALESCE(email_verified_at,created_at),
                    session_version=MAX(1,session_version);
                INSERT INTO schema_migrations(version,name,applied_at)
                VALUES (10,'local_account_session_fields',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'));
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise

    @staticmethod
    def _migrate_retire_wayback_imports(connection: sqlite3.Connection) -> None:
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                UPDATE sites SET wayback_enabled=0 WHERE wayback_enabled != 0;
                UPDATE capture_runs
                SET status='interrupted',
                    finished_at=COALESCE(
                        finished_at,
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    )
                WHERE status='running' AND id IN (
                    SELECT capture_run_id FROM crawl_jobs
                    WHERE kind='wayback' AND capture_run_id IS NOT NULL
                );
                UPDATE capture_runs
                SET status='interrupted',
                    finished_at=COALESCE(
                        finished_at,
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    )
                WHERE status='running' AND id IN (
                    SELECT capture_run_id FROM crawl_frontier
                    WHERE job_id IN (
                        SELECT id FROM crawl_jobs WHERE kind='wayback'
                    ) AND capture_run_id IS NOT NULL
                );
                UPDATE crawl_jobs
                SET status='interrupted',
                    message='Wayback import retired; existing captures preserved',
                    updated_at=strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                    finished_at=COALESCE(
                        finished_at,
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    ),
                    cancel_requested_at=COALESCE(
                        cancel_requested_at,
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    ),
                    auto_resume_pending=0
                WHERE kind='wayback' AND status IN ('running','interrupted');
                INSERT INTO schema_migrations(version, name, applied_at)
                VALUES (
                    16,
                    'retire_wayback_imports',
                    strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                );
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise



    @staticmethod
    def _migrate_durable_crawl_frontier(connection: sqlite3.Connection) -> None:
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                ALTER TABLE crawl_jobs ADD COLUMN auto_resume_pending INTEGER NOT NULL DEFAULT 0
                    CHECK(auto_resume_pending IN (0,1));
                DROP INDEX one_running_job_per_site_idx;
                CREATE UNIQUE INDEX one_active_job_per_site_idx
                    ON crawl_jobs(site_id)
                    WHERE status='running' OR auto_resume_pending=1;
                CREATE TABLE crawl_frontier (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL REFERENCES crawl_jobs(id) ON DELETE CASCADE,
                    resource_url TEXT NOT NULL,
                    depth INTEGER NOT NULL CHECK(depth >= 0),
                    state TEXT NOT NULL DEFAULT 'pending'
                        CHECK(state IN ('pending','active','done')),
                    outcome TEXT
                        CHECK(outcome IS NULL OR outcome IN ('captured','failed','skipped')),
                    capture_run_id TEXT REFERENCES capture_runs(id) ON DELETE SET NULL,
                    snapshot_id TEXT REFERENCES snapshots(id) ON DELETE SET NULL,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    claimed_at TEXT,
                    finished_at TEXT,
                    UNIQUE(job_id,resource_url)
                );
                CREATE INDEX crawl_frontier_next_idx
                    ON crawl_frontier(job_id,state,id);
                INSERT INTO schema_migrations(version,name,applied_at)
                VALUES (13,'durable_crawl_frontier_and_automatic_resume',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'));
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise

    @staticmethod
    def _migrate_safer_offset_capture_defaults(connection: sqlite3.Connection) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT id,interval,custom_days,last_snapshot_at,extra_json FROM sites"
            ).fetchall()
            frequency_days = {"daily": 1, "weekly": 7, "monthly": 30, "yearly": 365}
            for row in rows:
                extra = json.loads(row["extra_json"] or "{}")
                try:
                    current_delay = float(extra.get("request_delay_seconds", 0))
                except (TypeError, ValueError):
                    current_delay = 0
                if current_delay <= 2:
                    extra["request_delay_seconds"] = 5.0
                next_snapshot_at = None
                if row["last_snapshot_at"]:
                    try:
                        anchor = datetime.fromisoformat(
                            row["last_snapshot_at"].replace("Z", "+00:00")
                        )
                        if anchor.tzinfo is None:
                            anchor = anchor.replace(tzinfo=timezone.utc)
                        days = frequency_days.get(
                            row["interval"], max(1, int(row["custom_days"] or 30))
                        )
                        next_snapshot_at = (anchor + timedelta(days=days)).isoformat(
                            timespec="seconds"
                        )
                    except (AttributeError, TypeError, ValueError):
                        next_snapshot_at = None
                connection.execute(
                    """
                    UPDATE sites
                    SET change_policy='homepage_changed',
                        max_pages=CASE WHEN max_pages=80 THEN 25 ELSE max_pages END,
                        next_snapshot_at=COALESCE(?,next_snapshot_at),
                        extra_json=?
                    WHERE id=?
                    """,
                    (next_snapshot_at, json.dumps(extra, sort_keys=True, separators=(",", ":")), row["id"]),
                )
            connection.execute(
                """
                INSERT INTO schema_migrations(version,name,applied_at)
                VALUES (12,'safer_offset_capture_defaults',strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                """
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise

    @staticmethod
    def _migrate_archive_storage_capacity(connection: sqlite3.Connection) -> None:
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE archive_storage_capacity (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    quota_bytes INTEGER NOT NULL CHECK(quota_bytes >= 0),
                    warning_percent INTEGER NOT NULL DEFAULT 80
                        CHECK(warning_percent BETWEEN 1 AND 100),
                    updated_at TEXT NOT NULL,
                    updated_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL
                );
                INSERT INTO schema_migrations(version,name,applied_at)
                VALUES (11,'archive_storage_capacity_and_reservations',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'));
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise


    @staticmethod
    def _migrate_calendar_scheduling(connection: sqlite3.Connection) -> None:
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                ALTER TABLE sites ADD COLUMN schedule_timezone TEXT NOT NULL DEFAULT 'UTC';
                ALTER TABLE sites ADD COLUMN schedule_time TEXT NOT NULL DEFAULT '00:00';
                ALTER TABLE sites ADD COLUMN schedule_weekday INTEGER NOT NULL DEFAULT 0
                    CHECK(schedule_weekday BETWEEN 0 AND 6);
                ALTER TABLE sites ADD COLUMN schedule_month_day INTEGER NOT NULL DEFAULT 1
                    CHECK(schedule_month_day BETWEEN 1 AND 31);
                ALTER TABLE sites ADD COLUMN schedule_paused INTEGER NOT NULL DEFAULT 0
                    CHECK(schedule_paused IN (0,1));
                ALTER TABLE sites ADD COLUMN change_policy TEXT NOT NULL DEFAULT 'always'
                    CHECK(change_policy IN ('always','homepage_changed'));
                ALTER TABLE sites ADD COLUMN last_source_digest TEXT;
                ALTER TABLE snapshots ADD COLUMN source_content_digest TEXT;
                UPDATE sites
                SET schedule_time=COALESCE(substr(next_snapshot_at,12,5),'00:00'),
                    schedule_weekday=(CAST(strftime('%w',next_snapshot_at) AS INTEGER) + 6) % 7,
                    schedule_month_day=COALESCE(CAST(strftime('%d',next_snapshot_at) AS INTEGER),1)
                WHERE next_snapshot_at IS NOT NULL;
                CREATE TABLE archive_scheduler_settings (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    scheduler_timezone TEXT NOT NULL DEFAULT 'UTC',
                    capture_window_start TEXT,
                    capture_window_end TEXT,
                    max_concurrent_jobs INTEGER NOT NULL DEFAULT 2
                        CHECK(max_concurrent_jobs BETWEEN 1 AND 32),
                    scheduling_paused INTEGER NOT NULL DEFAULT 0
                        CHECK(scheduling_paused IN (0,1)),
                    updated_at TEXT,
                    updated_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL
                );
                INSERT INTO archive_scheduler_settings(singleton) VALUES(1);
                INSERT INTO schema_migrations(version,name,applied_at)
                VALUES (9,'calendar_scheduling_change_checks_and_global_limits',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'));
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise

    @staticmethod
    def _migrate_user_storage_quotas(connection: sqlite3.Connection) -> None:
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE user_storage_quotas (
                    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    quota_bytes INTEGER NOT NULL CHECK(quota_bytes >= 0),
                    warning_percent INTEGER NOT NULL DEFAULT 80
                        CHECK(warning_percent BETWEEN 1 AND 100),
                    updated_at TEXT NOT NULL,
                    updated_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL
                );
                ALTER TABLE crawl_jobs ADD COLUMN quota_owner_id TEXT
                    REFERENCES users(id) ON DELETE SET NULL;
                ALTER TABLE crawl_jobs ADD COLUMN quota_reserved_bytes INTEGER NOT NULL DEFAULT 0
                    CHECK(quota_reserved_bytes >= 0);
                CREATE INDEX crawl_jobs_quota_reservation_idx
                    ON crawl_jobs(quota_owner_id,status);
                INSERT INTO schema_migrations(version,name,applied_at)
                VALUES (8,'per_user_storage_quotas_and_job_reservations',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'));
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise


    @staticmethod
    def _migrate_content_addressed_assets(connection: sqlite3.Connection) -> None:
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                ALTER TABLE snapshot_assets ADD COLUMN content_digest TEXT;
                CREATE INDEX snapshot_assets_digest_idx ON snapshot_assets(content_digest);
                INSERT INTO schema_migrations(version,name,applied_at)
                VALUES (6,'content_addressed_asset_metadata',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'));
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise

    @staticmethod
    def _migrate_crawl_job_controls(connection: sqlite3.Connection) -> None:
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                ALTER TABLE crawl_jobs ADD COLUMN cancel_requested_at TEXT;
                ALTER TABLE crawl_jobs ADD COLUMN retry_of_job_id TEXT REFERENCES crawl_jobs(id);
                CREATE INDEX crawl_jobs_retry_idx ON crawl_jobs(retry_of_job_id);
                INSERT INTO schema_migrations(version,name,applied_at)
                VALUES (5,'durable_crawl_cancellation_and_retry_lineage',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'));
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise



    @staticmethod
    def _migrate_wayback_capture_times(connection: sqlite3.Connection) -> None:
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                UPDATE capture_runs
                SET started_at = (
                        SELECT substr(s.wayback_timestamp,1,4) || '-' ||
                               substr(s.wayback_timestamp,5,2) || '-' ||
                               substr(s.wayback_timestamp,7,2) || 'T' ||
                               substr(s.wayback_timestamp,9,2) || ':' ||
                               substr(s.wayback_timestamp,11,2) || ':' ||
                               substr(s.wayback_timestamp,13,2) || '+00:00'
                        FROM snapshots s
                        WHERE s.capture_run_id = capture_runs.id
                          AND length(s.wayback_timestamp) = 14
                        ORDER BY s.wayback_timestamp LIMIT 1
                    ),
                    finished_at = (
                        SELECT substr(s.wayback_timestamp,1,4) || '-' ||
                               substr(s.wayback_timestamp,5,2) || '-' ||
                               substr(s.wayback_timestamp,7,2) || 'T' ||
                               substr(s.wayback_timestamp,9,2) || ':' ||
                               substr(s.wayback_timestamp,11,2) || ':' ||
                               substr(s.wayback_timestamp,13,2) || '+00:00'
                        FROM snapshots s
                        WHERE s.capture_run_id = capture_runs.id
                          AND length(s.wayback_timestamp) = 14
                        ORDER BY s.wayback_timestamp LIMIT 1
                    ),
                    manifest_path = NULL,
                    manifest_digest = NULL,
                    signed_at = NULL
                WHERE kind = 'wayback' AND EXISTS (
                    SELECT 1 FROM snapshots s
                    WHERE s.capture_run_id = capture_runs.id
                      AND length(s.wayback_timestamp) = 14
                );
                INSERT INTO schema_migrations(version, name, applied_at)
                VALUES (3, 'wayback_capture_run_times', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
                COMMIT;
                """
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise

    def _migrate_capture_runs_and_archive_ids(self, connection: sqlite3.Connection) -> None:
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE archive_profile (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    archive_id TEXT NOT NULL UNIQUE,
                    installation_id TEXT NOT NULL UNIQUE,
                    setup_complete INTEGER NOT NULL DEFAULT 0 CHECK(setup_complete IN (0,1)),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE capture_runs (
                    id TEXT PRIMARY KEY,
                    manifest_id TEXT NOT NULL UNIQUE,
                    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('running','complete','partial','error','interrupted')),
                    entry_snapshot_id TEXT REFERENCES snapshots(id) ON DELETE SET NULL,
                    captured INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    manifest_path TEXT,
                    manifest_digest TEXT,
                    signed_at TEXT,
                    extra_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX capture_runs_site_started_idx
                    ON capture_runs(site_id, started_at DESC);
                ALTER TABLE sites ADD COLUMN archive_site_id TEXT;
                ALTER TABLE snapshots ADD COLUMN capture_run_id TEXT REFERENCES capture_runs(id) ON DELETE SET NULL;
                ALTER TABLE snapshots ADD COLUMN archive_page_id TEXT;
                ALTER TABLE snapshot_assets ADD COLUMN resource_id TEXT;
                ALTER TABLE crawl_jobs ADD COLUMN capture_run_id TEXT REFERENCES capture_runs(id) ON DELETE SET NULL;
                CREATE UNIQUE INDEX sites_archive_site_id_idx
                    ON sites(archive_site_id) WHERE archive_site_id IS NOT NULL;
                CREATE UNIQUE INDEX snapshots_archive_page_id_idx
                    ON snapshots(archive_page_id) WHERE archive_page_id IS NOT NULL;
                CREATE UNIQUE INDEX snapshot_assets_resource_id_idx
                    ON snapshot_assets(resource_id) WHERE resource_id IS NOT NULL;
                COMMIT;
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO archive_profile(singleton,archive_id,installation_id,setup_complete,created_at)
                VALUES (1, ?, ?, 0, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                """,
                (new_opaque_id("archive"), new_opaque_id("installation")),
            )
            for row in connection.execute("SELECT id FROM sites WHERE archive_site_id IS NULL"):
                connection.execute(
                    "UPDATE sites SET archive_site_id = ? WHERE id = ?",
                    (new_opaque_id("site"), row["id"]),
                )
            for row in connection.execute("SELECT id FROM snapshots WHERE archive_page_id IS NULL"):
                connection.execute(
                    "UPDATE snapshots SET archive_page_id = ? WHERE id = ?",
                    (new_opaque_id("page"), row["id"]),
                )
            for row in connection.execute("SELECT snapshot_id,id FROM snapshot_assets WHERE resource_id IS NULL"):
                connection.execute(
                    "UPDATE snapshot_assets SET resource_id = ? WHERE snapshot_id = ? AND id = ?",
                    (new_opaque_id("resource"), row["snapshot_id"], row["id"]),
                )
            self._backfill_capture_runs(connection)
            connection.execute(
                """
                INSERT INTO schema_migrations(version, name, applied_at)
                VALUES (2, 'capture_runs_archive_ids_and_archive_profile', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                """
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise

    def _backfill_capture_runs(self, connection: sqlite3.Connection) -> None:
        live_jobs = connection.execute(
            """
            SELECT DISTINCT j.id,j.site_id,j.kind,j.status,j.started_at,j.finished_at,j.captured,j.failed
            FROM crawl_jobs j JOIN crawl_attempts a ON a.job_id = j.id
            WHERE j.kind = 'live' AND a.snapshot_id IS NOT NULL
            ORDER BY j.created_at,j.id
            """
        ).fetchall()
        assigned: set[str] = set()
        for job in live_jobs:
            snapshot_rows = connection.execute(
                """
                SELECT s.id FROM crawl_attempts a JOIN snapshots s ON s.id = a.snapshot_id
                WHERE a.job_id = ? ORDER BY COALESCE(a.depth, 999),a.id
                """,
                (job["id"],),
            ).fetchall()
            snapshot_ids = [row["id"] for row in snapshot_rows if row["id"] not in assigned]
            if not snapshot_ids:
                continue
            run_id = new_opaque_id("capture")
            status = job["status"] if job["status"] in {"running", "complete", "error", "interrupted"} else "partial"
            connection.execute(
                """
                INSERT INTO capture_runs(id,manifest_id,site_id,kind,status,entry_snapshot_id,captured,failed,
                    started_at,finished_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run_id, new_opaque_id("manifest"), job["site_id"], job["kind"], status,
                    snapshot_ids[0], len(snapshot_ids), job["failed"], job["started_at"], job["finished_at"],
                ),
            )
            connection.executemany(
                "UPDATE snapshots SET capture_run_id = ? WHERE id = ?",
                ((run_id, snapshot_id) for snapshot_id in snapshot_ids),
            )
            connection.execute("UPDATE crawl_jobs SET capture_run_id = ? WHERE id = ?", (run_id, job["id"]))
            assigned.update(snapshot_ids)
        for snapshot in connection.execute(
            """
            SELECT id,site_id,kind,created_at,wayback_timestamp FROM snapshots
            WHERE capture_run_id IS NULL ORDER BY created_at,id
            """
        ).fetchall():
            run_id = new_opaque_id("capture")
            captured_at = snapshot["created_at"]
            timestamp = snapshot["wayback_timestamp"]
            if snapshot["kind"] == "wayback" and timestamp and len(timestamp) == 14:
                captured_at = (
                    f"{timestamp[0:4]}-{timestamp[4:6]}-{timestamp[6:8]}T"
                    f"{timestamp[8:10]}:{timestamp[10:12]}:{timestamp[12:14]}+00:00"
                )
            connection.execute(
                """
                INSERT INTO capture_runs(id,manifest_id,site_id,kind,status,entry_snapshot_id,captured,failed,
                    started_at,finished_at)
                VALUES (?,?,?,?, 'complete', ?,1,0,?,?)
                """,
                (
                    run_id, new_opaque_id("manifest"), snapshot["site_id"], snapshot["kind"],
                    snapshot["id"], captured_at, captured_at,
                ),
            )
            connection.execute(
                "UPDATE snapshots SET capture_run_id = ? WHERE id = ?",
                (run_id, snapshot["id"]),
            )

    @staticmethod
    def _empty_document() -> dict[str, list[dict[str, Any]]]:
        return {"users": [], "sites": [], "snapshots": [], "events": []}

    @staticmethod
    def _extra(record: dict[str, Any], known: set[str]) -> str:
        return json.dumps(
            {key: value for key, value in record.items() if key not in known},
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _restore(row: sqlite3.Row, excluded: set[str]) -> dict[str, Any]:
        record = {key: row[key] for key in row.keys() if key not in excluded}
        extra = json.loads(row["extra_json"] or "{}") if "extra_json" in row.keys() else {}
        record.update(extra)
        return record

    def load_document(self) -> dict[str, list[dict[str, Any]]]:
        with self._lock, self._connect() as connection:
            return self._load_document(connection)

    def _load_document(self, connection: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
        users = [
            self._restore(row, {"extra_json"})
            for row in connection.execute("SELECT * FROM users ORDER BY rowid")
        ]
        sites = []
        for row in connection.execute("SELECT * FROM sites ORDER BY rowid"):
            site = self._restore(row, {"extra_json"})
            site["wayback_enabled"] = bool(site["wayback_enabled"])
            site["schedule_paused"] = bool(site["schedule_paused"])
            sites.append(site)
        snapshots = []
        for row in connection.execute("SELECT * FROM snapshots ORDER BY rowid"):
            snapshot = self._restore(row, {"extra_json"})
            snapshot["rendered"] = bool(snapshot["rendered"])
            snapshot["assets"] = [
                self._restore(asset, {"snapshot_id", "extra_json"})
                for asset in connection.execute(
                    "SELECT * FROM snapshot_assets WHERE snapshot_id = ? ORDER BY rowid",
                    (snapshot["id"],),
                )
            ]
            snapshots.append(snapshot)
        events = [
            self._restore(row, {"extra_json"})
            for row in connection.execute("SELECT * FROM events ORDER BY rowid")
        ]
        return {"users": users, "sites": sites, "snapshots": snapshots, "events": events}

    def replace_document(self, document: dict[str, list[dict[str, Any]]]) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                previous = self._load_document(connection)
                self._write_document(connection, document, previous)
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def mutate_document(self, callback: Callable[[dict[str, list[dict[str, Any]]]], Any]) -> Any:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                document = self._load_document(connection)
                previous = json.loads(json.dumps(document))
                result = callback(document)
                self._write_document(connection, document, previous)
                connection.commit()
                return result
            except Exception:
                connection.rollback()
                raise

    @staticmethod
    def _records(document: dict[str, Any], name: str) -> dict[str, dict[str, Any]]:
        records = document.get(name)
        if not isinstance(records, list):
            raise ValueError(f"{name} must be a list")
        result = {}
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                raise ValueError(f"every {name} record must have a string id")
            if record["id"] in result:
                raise ValueError(f"duplicate {name} id: {record['id']}")
            result[record["id"]] = record
        return result

    def _write_document(
        self,
        connection: sqlite3.Connection,
        document: dict[str, list[dict[str, Any]]],
        previous: dict[str, list[dict[str, Any]]],
    ) -> None:
        current_maps = {name: self._records(document, name) for name in self._empty_document()}
        previous_maps = {name: self._records(previous, name) for name in self._empty_document()}

        for record_id, record in current_maps["users"].items():
            if record == previous_maps["users"].get(record_id):
                continue
            connection.execute(
                """
                INSERT INTO users(id,email,name,password,role,status,created_at,last_login_at,
                    email_verified_at,session_version,extra_json)
                VALUES(:id,:email,:name,:password,:role,:status,:created_at,:last_login_at,
                    :email_verified_at,:session_version,:extra_json)
                ON CONFLICT(id) DO UPDATE SET email=excluded.email,name=excluded.name,
                    password=excluded.password,role=excluded.role,status=excluded.status,
                    created_at=excluded.created_at,last_login_at=excluded.last_login_at,
                    email_verified_at=excluded.email_verified_at,
                    session_version=excluded.session_version,
                    extra_json=excluded.extra_json
                """,
                {
                    **record,
                    "email_verified_at": record.get(
                        "email_verified_at", record.get("created_at")
                    ),
                    "session_version": max(1, int(record.get("session_version", 1))),
                    "extra_json": self._extra(record, self.USER_COLUMNS),
                },
            )
        for record_id, record in current_maps["sites"].items():
            if record == previous_maps["sites"].get(record_id):
                continue
            record.setdefault("archive_site_id", new_opaque_id("site"))
            values = {
                **{key: record.get(key) for key in self.SITE_COLUMNS},
                "crawl_depth": record.get("crawl_depth", 3),
                "max_pages": record.get("max_pages", 25),
                "wayback_enabled": int(bool(record.get("wayback_enabled"))),
                "wayback_frequency": record.get("wayback_frequency", "yearly"),
                "wayback_limit": record.get("wayback_limit", 20),
                "schedule_timezone": record.get("schedule_timezone", "UTC"),
                "schedule_time": record.get("schedule_time", "00:00"),
                "schedule_weekday": int(record.get("schedule_weekday", 0)),
                "schedule_month_day": int(record.get("schedule_month_day", 1)),
                "schedule_paused": int(bool(record.get("schedule_paused"))),
                "change_policy": record.get("change_policy", "homepage_changed"),
                "extra_json": self._extra(record, self.SITE_COLUMNS),
            }
            connection.execute(
                """
                INSERT INTO sites(id,owner_id,name,url,visibility,interval,custom_days,crawl_depth,max_pages,
                    wayback_enabled,wayback_frequency,wayback_limit,created_at,last_snapshot_at,
                    next_snapshot_at,last_crawl_at,wayback_updated_at,archive_site_id,
                    schedule_timezone,schedule_time,schedule_weekday,schedule_month_day,
                    schedule_paused,change_policy,last_source_digest,extra_json)
                VALUES(:id,:owner_id,:name,:url,:visibility,:interval,:custom_days,:crawl_depth,:max_pages,
                    :wayback_enabled,:wayback_frequency,:wayback_limit,:created_at,:last_snapshot_at,
                    :next_snapshot_at,:last_crawl_at,:wayback_updated_at,:archive_site_id,
                    :schedule_timezone,:schedule_time,:schedule_weekday,:schedule_month_day,
                    :schedule_paused,:change_policy,:last_source_digest,:extra_json)
                ON CONFLICT(id) DO UPDATE SET owner_id=excluded.owner_id,name=excluded.name,url=excluded.url,
                    visibility=excluded.visibility,interval=excluded.interval,custom_days=excluded.custom_days,
                    crawl_depth=excluded.crawl_depth,max_pages=excluded.max_pages,
                    wayback_enabled=excluded.wayback_enabled,wayback_frequency=excluded.wayback_frequency,
                    wayback_limit=excluded.wayback_limit,created_at=excluded.created_at,
                    last_snapshot_at=excluded.last_snapshot_at,next_snapshot_at=excluded.next_snapshot_at,
                    last_crawl_at=excluded.last_crawl_at,wayback_updated_at=excluded.wayback_updated_at,
                    archive_site_id=excluded.archive_site_id,
                    schedule_timezone=excluded.schedule_timezone,schedule_time=excluded.schedule_time,
                    schedule_weekday=excluded.schedule_weekday,schedule_month_day=excluded.schedule_month_day,
                    schedule_paused=excluded.schedule_paused,change_policy=excluded.change_policy,
                    last_source_digest=excluded.last_source_digest,extra_json=excluded.extra_json
                """,
                values,
            )
        for record_id, record in current_maps["snapshots"].items():
            if record == previous_maps["snapshots"].get(record_id):
                continue
            record.setdefault("archive_page_id", new_opaque_id("page"))
            values = {
                **{key: record.get(key) for key in self.SNAPSHOT_COLUMNS if key != "assets"},
                "rendered": int(bool(record.get("rendered"))),
                "extra_json": self._extra(record, self.SNAPSHOT_COLUMNS),
            }
            connection.execute(
                """
                INSERT INTO snapshots(id,site_id,kind,source_url,final_url,status,content_type,bytes,file,
                    rendered,wayback_timestamp,created_at,created_by,capture_run_id,archive_page_id,
                    source_content_digest,extra_json)
                VALUES(:id,:site_id,:kind,:source_url,:final_url,:status,:content_type,:bytes,:file,
                    :rendered,:wayback_timestamp,:created_at,:created_by,:capture_run_id,:archive_page_id,
                    :source_content_digest,:extra_json)
                ON CONFLICT(id) DO UPDATE SET site_id=excluded.site_id,kind=excluded.kind,
                    source_url=excluded.source_url,final_url=excluded.final_url,status=excluded.status,
                    content_type=excluded.content_type,bytes=excluded.bytes,file=excluded.file,
                    rendered=excluded.rendered,wayback_timestamp=excluded.wayback_timestamp,
                    created_at=excluded.created_at,created_by=excluded.created_by,
                    capture_run_id=excluded.capture_run_id,archive_page_id=excluded.archive_page_id,
                    source_content_digest=excluded.source_content_digest,extra_json=excluded.extra_json
                """,
                values,
            )
            connection.execute("DELETE FROM snapshot_assets WHERE snapshot_id = ?", (record_id,))
            for asset in record.get("assets", []):
                asset.setdefault("resource_id", new_opaque_id("resource"))
                connection.execute(
                    """
                    INSERT INTO snapshot_assets(snapshot_id,id,source_url,final_url,status,content_type,
                        bytes,file,fallback_from_snapshot,resource_id,content_digest,extra_json)
                    VALUES(:snapshot_id,:id,:source_url,:final_url,:status,:content_type,
                        :bytes,:file,:fallback_from_snapshot,:resource_id,:content_digest,:extra_json)
                    """,
                    {
                        **{key: asset.get(key) for key in self.ASSET_COLUMNS},
                        "snapshot_id": record_id,
                        "extra_json": self._extra(asset, self.ASSET_COLUMNS),
                    },
                )
        for record_id, record in current_maps["events"].items():
            if record == previous_maps["events"].get(record_id):
                continue
            connection.execute(
                """
                INSERT INTO events(id,actor_id,action,detail,created_at,extra_json)
                VALUES(:id,:actor_id,:action,:detail,:created_at,:extra_json)
                ON CONFLICT(id) DO UPDATE SET actor_id=excluded.actor_id,action=excluded.action,
                    detail=excluded.detail,created_at=excluded.created_at,extra_json=excluded.extra_json
                """,
                {**record, "extra_json": self._extra(record, self.EVENT_COLUMNS)},
            )

        for name, table in (("events", "events"), ("snapshots", "snapshots"), ("sites", "sites"), ("users", "users")):
            removed = set(previous_maps[name]) - set(current_maps[name])
            connection.executemany(f"DELETE FROM {table} WHERE id = ?", ((item_id,) for item_id in removed))

    def archive_profile(self) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            row = connection.execute("SELECT * FROM archive_profile WHERE singleton = 1").fetchone()
            if not row:
                raise MetadataStoreError("archive profile is missing")
            result = dict(row)
            result.pop("singleton", None)
            result["setup_complete"] = bool(result["setup_complete"])
            return result

    def set_setup_complete(self, enabled: bool) -> None:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE archive_profile SET setup_complete = ? WHERE singleton = 1",
                (int(enabled),),
            )
            if cursor.rowcount != 1:
                raise MetadataStoreError("archive profile is missing")

    def scheduler_settings(self) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM archive_scheduler_settings WHERE singleton=1"
            ).fetchone()
            if not row:
                raise MetadataStoreError("scheduler settings are missing")
            result = dict(row)
            result.pop("singleton", None)
            result["scheduling_paused"] = bool(result["scheduling_paused"])
            return result

    def update_scheduler_settings(
        self,
        *,
        scheduler_timezone: str,
        capture_window_start: str | None,
        capture_window_end: str | None,
        max_concurrent_jobs: int,
        scheduling_paused: bool,
        updated_at: str,
        updated_by_user_id: str,
    ) -> None:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE archive_scheduler_settings
                SET scheduler_timezone=?,capture_window_start=?,capture_window_end=?,
                    max_concurrent_jobs=?,scheduling_paused=?,updated_at=?,updated_by_user_id=?
                WHERE singleton=1
                """,
                (
                    scheduler_timezone,
                    capture_window_start,
                    capture_window_end,
                    int(max_concurrent_jobs),
                    int(bool(scheduling_paused)),
                    updated_at,
                    updated_by_user_id,
                ),
            )
            if cursor.rowcount != 1:
                raise MetadataStoreError("scheduler settings are missing")

    def running_job_count(self) -> int:
        with self._lock, self._connect() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM crawl_jobs WHERE status='running'"
                ).fetchone()[0]
            )

    def create_capture_run(
        self,
        run_id: str,
        manifest_id: str,
        site_id: str,
        kind: str,
        started_at: str,
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO capture_runs(id,manifest_id,site_id,kind,status,started_at)
                VALUES (?, ?, ?, ?, 'running', ?)
                """,
                (run_id, manifest_id, site_id, kind, started_at),
            )

    def update_capture_run(self, run_id: str, updated_at: str, **changes: Any) -> None:
        allowed = {
            "status", "entry_snapshot_id", "captured", "failed", "manifest_path",
            "manifest_digest", "signed_at",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError(f"unsupported capture-run fields: {', '.join(sorted(unknown))}")
        if changes.get("status") and changes["status"] not in {
            "running", "complete", "partial", "error", "interrupted",
        }:
            raise ValueError("invalid capture-run status")
        assignments = [f"{name} = ?" for name in changes]
        values = list(changes.values())
        if changes.get("status") in {"complete", "partial", "error", "interrupted"}:
            assignments.append("finished_at = ?")
            values.append(updated_at)
        elif changes.get("status") == "running":
            assignments.append("finished_at = NULL")
        values.append(run_id)
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                f"UPDATE capture_runs SET {', '.join(assignments)} WHERE id = ?",
                values,
            )
            if cursor.rowcount != 1:
                raise MetadataStoreError(f"unknown capture run: {run_id}")

    def get_capture_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute("SELECT * FROM capture_runs WHERE id = ?", (run_id,)).fetchone()
            return self._capture_run_record(row) if row else None

    def list_capture_runs(self, site_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM capture_runs WHERE site_id = ?
                ORDER BY started_at DESC,rowid DESC LIMIT ?
                """,
                (site_id, max(0, limit)),
            )
            return [self._capture_run_record(row) for row in rows]

    def delete_capture_run(self, run_id: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM capture_runs WHERE id = ?", (run_id,))

    @staticmethod
    def _capture_run_record(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["extra"] = json.loads(result.pop("extra_json") or "{}")
        return result

    def create_job(
        self,
        job_id: str,
        site_id: str,
        actor_id: str | None,
        kind: str,
        message: str,
        created_at: str,
        parameters: dict[str, Any] | None = None,
        capture_run: dict[str, Any] | None = None,
        retry_of_job_id: str | None = None,
        quota_required_bytes: int = 0,
        max_active_jobs: int | None = None,
        frontier: list[tuple[str, int]] | None = None,
    ) -> None:
        quota_required_bytes = max(0, int(quota_required_bytes))
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    """
                    SELECT id FROM crawl_jobs
                    WHERE site_id=? AND (status='running' OR auto_resume_pending=1)
                    """,
                    (site_id,),
                ).fetchone()
                if existing:
                    raise ActiveJobExists(existing["id"])
                if max_active_jobs is not None:
                    limit = max(1, int(max_active_jobs))
                    running = int(
                        connection.execute(
                            """
                            SELECT COUNT(*) FROM crawl_jobs
                            WHERE status='running' OR auto_resume_pending=1
                            """
                        ).fetchone()[0]
                    )
                    if running >= limit:
                        raise JobCapacityExceeded(limit)
                site = connection.execute(
                    "SELECT owner_id FROM sites WHERE id=?", (site_id,)
                ).fetchone()
                if not site:
                    raise MetadataStoreError(f"unknown site: {site_id}")
                quota_owner_id = site["owner_id"]
                self._assert_storage_available(
                    connection, quota_owner_id, quota_required_bytes
                )
                if capture_run:
                    connection.execute(
                        """
                        INSERT INTO capture_runs(id,manifest_id,site_id,kind,status,started_at)
                        VALUES (?, ?, ?, ?, 'running', ?)
                        """,
                        (
                            capture_run["id"], capture_run["manifest_id"], site_id,
                            capture_run.get("kind", kind), created_at,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO crawl_jobs(id,site_id,actor_id,kind,status,message,captured,failed,
                        parameters_json,created_at,started_at,updated_at,capture_run_id,retry_of_job_id,
                        quota_owner_id,quota_reserved_bytes)
                    VALUES (?, ?, ?, ?, 'running', ?, 0, 0, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job_id, site_id, actor_id, kind, message,
                        json.dumps(parameters or {}, sort_keys=True, separators=(",", ":")),
                        created_at, created_at, created_at,
                        capture_run["id"] if capture_run else None,
                        retry_of_job_id,
                        quota_owner_id,
                        quota_required_bytes,
                    ),
                )
                for resource_url, resource_depth in frontier or []:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO crawl_frontier(
                            job_id,resource_url,depth,state,created_at
                        ) VALUES (?, ?, ?, 'pending', ?)
                        """,
                        (job_id, resource_url, max(0, int(resource_depth)), created_at),
                    )
                connection.commit()
            except ActiveJobExists:
                connection.rollback()
                raise
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                existing = connection.execute(
                    """
                    SELECT id FROM crawl_jobs
                    WHERE site_id=? AND (status='running' OR auto_resume_pending=1)
                    """,
                    (site_id,),
                ).fetchone()
                if existing:
                    raise ActiveJobExists(existing["id"]) from exc
                raise
            except Exception:
                connection.rollback()
                raise

    @staticmethod
    def _logical_usage_bytes(connection: sqlite3.Connection, user_id: str) -> int:
        row = connection.execute(
            """
            SELECT
                COALESCE((SELECT SUM(s.bytes) FROM snapshots s
                    JOIN sites site ON site.id=s.site_id WHERE site.owner_id=?),0)
                +
                COALESCE((SELECT SUM(a.bytes) FROM snapshot_assets a
                    JOIN snapshots s ON s.id=a.snapshot_id
                    JOIN sites site ON site.id=s.site_id WHERE site.owner_id=?),0)
            """,
            (user_id, user_id),
        ).fetchone()
        return int(row[0] or 0)

    @staticmethod
    def _active_reservation_bytes(connection: sqlite3.Connection, user_id: str) -> int:
        return int(
            connection.execute(
                """
                SELECT COALESCE(SUM(quota_reserved_bytes),0) FROM crawl_jobs
                WHERE quota_owner_id=?
                    AND (status='running' OR auto_resume_pending=1)
                """,
                (user_id,),
            ).fetchone()[0]
            or 0
        )

    @staticmethod
    def _logical_archive_usage_bytes(connection: sqlite3.Connection) -> int:
        row = connection.execute(
            """
            SELECT
                COALESCE((SELECT SUM(bytes) FROM snapshots),0)
                + COALESCE((SELECT SUM(bytes) FROM snapshot_assets),0)
            """
        ).fetchone()
        return int(row[0] or 0)

    @staticmethod
    def _active_archive_reservation_bytes(connection: sqlite3.Connection) -> int:
        return int(
            connection.execute(
                """
                SELECT COALESCE(SUM(quota_reserved_bytes),0) FROM crawl_jobs
                WHERE status='running' OR auto_resume_pending=1
                """
            ).fetchone()[0]
            or 0
        )

    @classmethod
    def _assert_quota_available(
        cls, connection: sqlite3.Connection, user_id: str, required_bytes: int
    ) -> None:
        quota = connection.execute(
            "SELECT quota_bytes FROM user_storage_quotas WHERE user_id=?", (user_id,)
        ).fetchone()
        if not quota:
            return
        used = cls._logical_usage_bytes(connection, user_id)
        reserved = cls._active_reservation_bytes(connection, user_id)
        if used + reserved + required_bytes > int(quota["quota_bytes"]):
            raise StorageQuotaExceeded(
                int(quota["quota_bytes"]), used, reserved, required_bytes
            )

    @classmethod
    def _assert_archive_capacity_available(
        cls, connection: sqlite3.Connection, required_bytes: int
    ) -> None:
        capacity = connection.execute(
            "SELECT quota_bytes FROM archive_storage_capacity WHERE singleton=1"
        ).fetchone()
        if not capacity:
            return
        used = cls._logical_archive_usage_bytes(connection)
        reserved = cls._active_archive_reservation_bytes(connection)
        if used + reserved + required_bytes > int(capacity["quota_bytes"]):
            raise ArchiveStorageCapacityExceeded(
                int(capacity["quota_bytes"]), used, reserved, required_bytes
            )

    @classmethod
    def _assert_storage_available(
        cls, connection: sqlite3.Connection, user_id: str, required_bytes: int
    ) -> None:
        cls._assert_quota_available(connection, user_id, required_bytes)
        cls._assert_archive_capacity_available(connection, required_bytes)

    def assert_storage_available(self, user_id: str, required_bytes: int) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._assert_storage_available(connection, user_id, max(0, int(required_bytes)))
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def storage_quota(self, user_id: str) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            user = connection.execute(
                "SELECT id,name,email FROM users WHERE id=?", (user_id,)
            ).fetchone()
            if not user:
                raise MetadataStoreError(f"unknown user: {user_id}")
            quota = connection.execute(
                "SELECT * FROM user_storage_quotas WHERE user_id=?", (user_id,)
            ).fetchone()
            return self._storage_quota_record(connection, user, quota)

    def storage_quota_summaries(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT u.id,u.name,u.email,q.quota_bytes,q.warning_percent,
                    q.updated_at,q.updated_by_user_id
                FROM users u JOIN user_storage_quotas q ON q.user_id=u.id
                ORDER BY lower(u.name),lower(u.email)
                """
            ).fetchall()
            return [self._storage_quota_record(connection, row, row) for row in rows]

    def archive_storage_capacity(self) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            capacity = connection.execute(
                "SELECT * FROM archive_storage_capacity WHERE singleton=1"
            ).fetchone()
            used = self._logical_archive_usage_bytes(connection)
            reserved = self._active_archive_reservation_bytes(connection)
            limit = int(capacity["quota_bytes"]) if capacity else None
            warning_percent = int(capacity["warning_percent"]) if capacity else 80
            committed = used + reserved
            percent = (
                committed * 100 / limit
                if limit and limit > 0
                else (100.0 if limit == 0 and committed else 0.0)
            )
            return {
                "quota_bytes": limit,
                "warning_percent": warning_percent,
                "updated_at": capacity["updated_at"] if capacity else None,
                "used_bytes": used,
                "reserved_bytes": reserved,
                "available_bytes": None if limit is None else max(0, limit - committed),
                "percent_committed": round(percent, 1),
                "warning": limit is not None and percent >= warning_percent,
                "over_capacity": limit is not None and used > limit,
            }

    def _storage_quota_record(
        self,
        connection: sqlite3.Connection,
        user: sqlite3.Row,
        quota: sqlite3.Row | None,
    ) -> dict[str, Any]:
        user_id = user["id"]
        used = self._logical_usage_bytes(connection, user_id)
        reserved = self._active_reservation_bytes(connection, user_id)
        limit = int(quota["quota_bytes"]) if quota else None
        warning_percent = int(quota["warning_percent"]) if quota else 80
        percent = (
            used * 100 / limit
            if limit and limit > 0
            else (100.0 if limit == 0 and used else 0.0)
        )
        committed_percent = (
            (used + reserved) * 100 / limit
            if limit and limit > 0
            else (100.0 if limit == 0 and used + reserved else 0.0)
        )
        return {
            "id": user_id,
            "name": user["name"],
            "email": user["email"],
            "quota_bytes": limit,
            "warning_percent": warning_percent,
            "used_bytes": used,
            "reserved_bytes": reserved,
            "available_bytes": None if limit is None else max(0, limit - used - reserved),
            "percent_used": round(percent, 1),
            "percent_committed": round(committed_percent, 1),
            "warning": limit is not None and committed_percent >= warning_percent,
            "over_quota": limit is not None and used > limit,
        }

    def update_job(self, job_id: str, updated_at: str, **changes: Any) -> None:
        allowed = {"status", "message", "captured", "failed"}
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError(f"unsupported job fields: {', '.join(sorted(unknown))}")
        if changes.get("status") and changes["status"] not in {"running", *TERMINAL_JOB_STATUSES}:
            raise ValueError("invalid job status")
        assignments = [f"{name} = ?" for name in changes]
        values = list(changes.values())
        assignments.append("updated_at = ?")
        values.append(updated_at)
        if changes.get("status") in TERMINAL_JOB_STATUSES:
            assignments.append("finished_at = ?")
            values.append(updated_at)
            assignments.append("auto_resume_pending = 0")
        values.append(job_id)
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                f"UPDATE crawl_jobs SET {', '.join(assignments)} WHERE id = ?",
                values,
            )
            if cursor.rowcount != 1:
                raise MetadataStoreError(f"unknown crawl job: {job_id}")

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute("SELECT * FROM crawl_jobs WHERE id = ?", (job_id,)).fetchone()
            return self._job_record(row) if row else None

    def list_jobs(self, site_id: str, limit: int = 5) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM crawl_jobs WHERE site_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (site_id, max(0, limit)),
            )
            return [self._job_record(row) for row in rows]

    def list_recent_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM crawl_jobs ORDER BY created_at DESC,rowid DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            )
            return [self._job_record(row) for row in rows]

    def search_jobs(
        self,
        *,
        status: str | None = None,
        kind: str | None = None,
        site_id: str | None = None,
        query: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        conditions: list[str] = []
        values: list[Any] = []
        if status:
            conditions.append("j.status = ?")
            values.append(status)
        if kind:
            conditions.append("j.kind = ?")
            values.append(kind)
        if site_id:
            conditions.append("j.site_id = ?")
            values.append(site_id)
        if query:
            escaped = (
                query.strip().lower()[:200]
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            if escaped:
                pattern = f"%{escaped}%"
                conditions.append(
                    "(LOWER(j.id) LIKE ? ESCAPE '\\' OR LOWER(j.message) LIKE ? ESCAPE '\\' "
                    "OR LOWER(s.name) LIKE ? ESCAPE '\\' OR LOWER(s.url) LIKE ? ESCAPE '\\' "
                    "OR LOWER(COALESCE(u.name,'')) LIKE ? ESCAPE '\\' "
                    "OR LOWER(COALESCE(u.email,'')) LIKE ? ESCAPE '\\')"
                )
                values.extend([pattern] * 6)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        bounded_limit = max(1, min(int(limit), 200))
        bounded_offset = max(0, int(offset))
        with self._lock, self._connect() as connection:
            total = connection.execute(
                f"""
                SELECT COUNT(*) FROM crawl_jobs j
                JOIN sites s ON s.id=j.site_id
                LEFT JOIN users u ON u.id=j.actor_id
                {where}
                """,
                values,
            ).fetchone()[0]
            rows = connection.execute(
                f"""
                SELECT j.*,s.name AS site_name,s.url AS site_url,
                    u.name AS actor_name,u.email AS actor_email,
                    (SELECT COUNT(*) FROM crawl_attempts a WHERE a.job_id=j.id) AS attempt_count
                FROM crawl_jobs j
                JOIN sites s ON s.id=j.site_id
                LEFT JOIN users u ON u.id=j.actor_id
                {where}
                ORDER BY j.created_at DESC,j.rowid DESC LIMIT ? OFFSET ?
                """,
                [*values, bounded_limit, bounded_offset],
            )
            results = []
            for row in rows:
                record = self._job_record(row)
                record.update(
                    {
                        "site_name": row["site_name"],
                        "site_url": row["site_url"],
                        "actor_name": row["actor_name"],
                        "actor_email": row["actor_email"],
                        "attempt_count": row["attempt_count"],
                    }
                )
                results.append(record)
            return {"jobs": results, "total": total}

    def repeated_capture_failure_streaks(self, threshold: int = 3) -> list[dict[str, Any]]:
        threshold = max(2, min(int(threshold), 20))
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT j.id,j.site_id,j.status,j.failed,j.created_at,
                    s.name AS site_name,s.url AS site_url
                FROM crawl_jobs j JOIN sites s ON s.id=j.site_id
                WHERE j.status != 'running' AND j.kind IN ('live','scheduled','retry')
                ORDER BY j.site_id,j.created_at DESC,j.rowid DESC
                """
            ).fetchall()
        grouped: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            grouped.setdefault(row["site_id"], []).append(row)
        alerts = []
        for site_rows in grouped.values():
            failures = []
            for row in site_rows:
                if row["status"] == "error" or int(row["failed"] or 0) > 0:
                    failures.append(row)
                else:
                    break
            if len(failures) < threshold:
                continue
            crossing = failures[len(failures) - threshold]
            latest = failures[0]
            alerts.append(
                {
                    "site_id": latest["site_id"],
                    "site_name": latest["site_name"],
                    "site_url": latest["site_url"],
                    "consecutive_failures": len(failures),
                    "alert_job_id": crossing["id"],
                    "latest_job_id": latest["id"],
                    "latest_created_at": latest["created_at"],
                }
            )
        return alerts

    def operations_summary(self) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            jobs = {
                row["status"]: row["count"]
                for row in connection.execute(
                    "SELECT status,COUNT(*) AS count FROM crawl_jobs GROUP BY status"
                )
            }
            duration = connection.execute(
                """
                SELECT AVG((julianday(finished_at)-julianday(started_at))*86400.0)
                FROM crawl_jobs WHERE finished_at IS NOT NULL
                """
            ).fetchone()[0]
            return {
                "jobs": jobs,
                "running_jobs": jobs.get("running", 0),
                "failed_attempts": connection.execute(
                    "SELECT COUNT(*) FROM crawl_attempts WHERE status='failed'"
                ).fetchone()[0],
                "average_job_seconds": round(duration or 0, 2),
                "snapshot_bytes": connection.execute(
                    "SELECT COALESCE(SUM(bytes),0) FROM snapshots"
                ).fetchone()[0],
                "asset_logical_bytes": connection.execute(
                    "SELECT COALESCE(SUM(bytes),0) FROM snapshot_assets"
                ).fetchone()[0],
                "asset_unique_bytes": connection.execute(
                    """
                    SELECT COALESCE(SUM(bytes),0) FROM snapshot_assets
                    WHERE rowid IN (
                        SELECT MIN(rowid) FROM snapshot_assets
                        GROUP BY COALESCE(content_digest,snapshot_id || ':' || id)
                    )
                    """
                ).fetchone()[0],
            }

    def event_actions(self) -> list[str]:
        with self._lock, self._connect() as connection:
            return [
                row["action"]
                for row in connection.execute(
                    "SELECT DISTINCT action FROM events ORDER BY action"
                )
            ]

    def search_events(
        self,
        *,
        action: str | None = None,
        query: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        conditions: list[str] = []
        values: list[Any] = []
        if action:
            conditions.append("e.action = ?")
            values.append(action)
        if query:
            escaped = (
                query.strip().lower()[:200]
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            if escaped:
                pattern = f"%{escaped}%"
                conditions.append(
                    "(LOWER(e.action) LIKE ? ESCAPE '\\' OR LOWER(e.detail) LIKE ? ESCAPE '\\' "
                    "OR LOWER(e.actor_id) LIKE ? ESCAPE '\\' "
                    "OR LOWER(COALESCE(u.name,'')) LIKE ? ESCAPE '\\' "
                    "OR LOWER(COALESCE(u.email,'')) LIKE ? ESCAPE '\\')"
                )
                values.extend([pattern] * 5)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        bounded_limit = max(1, min(int(limit), 200))
        bounded_offset = max(0, int(offset))
        with self._lock, self._connect() as connection:
            total = connection.execute(
                f"""
                SELECT COUNT(*) FROM events e LEFT JOIN users u ON u.id=e.actor_id
                {where}
                """,
                values,
            ).fetchone()[0]
            rows = connection.execute(
                f"""
                SELECT e.*,u.name AS actor_name,u.email AS actor_email
                FROM events e LEFT JOIN users u ON u.id=e.actor_id
                {where}
                ORDER BY e.created_at DESC,e.rowid DESC LIMIT ? OFFSET ?
                """,
                [*values, bounded_limit, bounded_offset],
            )
            return {"events": [dict(row) for row in rows], "total": total}

    @staticmethod
    def _job_record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "site_id": row["site_id"],
            "actor_id": row["actor_id"],
            "kind": row["kind"],
            "status": row["status"],
            "message": row["message"],
            "captured": row["captured"],
            "failed": row["failed"],
            "parameters": json.loads(row["parameters_json"]),
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "updated_at": row["updated_at"],
            "finished_at": row["finished_at"],
            "capture_run_id": row["capture_run_id"],
            "cancel_requested_at": row["cancel_requested_at"],
            "retry_of_job_id": row["retry_of_job_id"],
            "quota_owner_id": row["quota_owner_id"],
            "quota_reserved_bytes": row["quota_reserved_bytes"],
            "auto_resume_pending": bool(row["auto_resume_pending"]),
        }

    def request_job_cancel(self, job_id: str, requested_at: str) -> bool:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE crawl_jobs
                SET cancel_requested_at=COALESCE(cancel_requested_at,?),
                    auto_resume_pending=0,message='Cancellation requested',updated_at=?
                WHERE id=? AND status='running'
                """,
                (requested_at, requested_at, job_id),
            )
            return cursor.rowcount == 1

    def job_cancel_requested(self, job_id: str) -> bool:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT cancel_requested_at FROM crawl_jobs WHERE id=?", (job_id,)
            ).fetchone()
            return bool(row and row["cancel_requested_at"])

    def interrupt_job(
        self,
        job_id: str,
        interrupted_at: str,
        message: str,
        *,
        auto_resume: bool,
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                job = connection.execute(
                    "SELECT capture_run_id,cancel_requested_at FROM crawl_jobs WHERE id=?",
                    (job_id,),
                ).fetchone()
                if not job:
                    raise MetadataStoreError(f"unknown crawl job: {job_id}")
                should_resume = bool(auto_resume and not job["cancel_requested_at"])
                connection.execute(
                    """
                    UPDATE crawl_jobs
                    SET status='interrupted',message=?,updated_at=?,finished_at=?,
                        auto_resume_pending=?
                    WHERE id=?
                    """,
                    (
                        message,
                        interrupted_at,
                        interrupted_at,
                        int(should_resume),
                        job_id,
                    ),
                )
                connection.execute(
                    """
                    UPDATE crawl_frontier
                    SET state='pending',claimed_at=NULL
                    WHERE job_id=? AND state='active'
                    """,
                    (job_id,),
                )
                connection.execute(
                    """
                    UPDATE crawl_attempts
                    SET status='failed',error=?,finished_at=?
                    WHERE job_id=? AND status='running'
                    """,
                    (message, interrupted_at, job_id),
                )
                if job["capture_run_id"]:
                    connection.execute(
                        """
                        UPDATE capture_runs
                        SET status='interrupted',finished_at=?
                        WHERE id=? AND status='running'
                        """,
                        (interrupted_at, job["capture_run_id"]),
                    )
                connection.execute(
                    """
                    UPDATE capture_runs
                    SET status='interrupted',finished_at=?
                    WHERE status='running' AND id IN (
                        SELECT capture_run_id FROM crawl_frontier
                        WHERE job_id=? AND capture_run_id IS NOT NULL
                    )
                    """,
                    (interrupted_at, job_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def failed_attempt_urls(self, job_id: str) -> list[str]:
        with self._lock, self._connect() as connection:
            return [
                row["resource_url"]
                for row in connection.execute(
                    """
                    SELECT resource_url FROM crawl_attempts
                    WHERE job_id=? AND status='failed'
                    GROUP BY resource_url ORDER BY MIN(id)
                    """,
                    (job_id,),
                )
            ]

    def recover_interrupted_jobs(self, recovered_at: str) -> list[str]:
        resume_message = "Continuing automatically after restart."
        stopped_message = "Stopped during application restart."
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    """
                    SELECT j.*,s.url AS site_url
                    FROM crawl_jobs j JOIN sites s ON s.id=j.site_id
                    WHERE j.status='running' ORDER BY j.created_at
                    """
                ).fetchall()
                resumable: list[str] = []
                for row in rows:
                    can_resume = (
                        row["kind"]
                        in {"live", "scheduled", "retry", "asset_localization"}
                        and not row["cancel_requested_at"]
                    )
                    connection.execute(
                        """
                        UPDATE crawl_jobs
                        SET status='interrupted',message=?,updated_at=?,finished_at=?,
                            auto_resume_pending=?
                        WHERE id=?
                        """,
                        (
                            resume_message if can_resume else stopped_message,
                            recovered_at,
                            recovered_at,
                            int(can_resume),
                            row["id"],
                        ),
                    )
                    if can_resume:
                        resumable.append(row["id"])
                        if row["kind"] in {"live", "scheduled", "retry"}:
                            parameters = json.loads(row["parameters_json"] or "{}")
                            seeds = list(parameters.get("retry_urls") or [])
                            if not seeds:
                                seeds = [parameters.get("start_url") or row["site_url"]]
                            attempt_rows = connection.execute(
                                """
                                SELECT resource_url,COALESCE(depth,0) AS depth
                                FROM crawl_attempts WHERE job_id=? ORDER BY id
                                """,
                                (row["id"],),
                            ).fetchall()
                            seed_rows = [(url, 0) for url in seeds if url]
                            seed_rows.extend(
                                (attempt["resource_url"], int(attempt["depth"]))
                                for attempt in attempt_rows
                            )
                            max_pages = max(1, int(parameters.get("max_pages") or 1))
                            for resource_url, depth in seed_rows[:max_pages]:
                                connection.execute(
                                    """
                                    INSERT OR IGNORE INTO crawl_frontier(
                                        job_id,resource_url,depth,state,created_at
                                    ) VALUES (?, ?, ?, 'pending', ?)
                                    """,
                                    (row["id"], resource_url, max(0, depth), recovered_at),
                                )
                connection.execute(
                    """
                    UPDATE crawl_attempts
                    SET status = 'failed', error = ?, finished_at = ?
                    WHERE status = 'running'
                    """,
                    ("Interrupted by application restart.", recovered_at),
                )
                connection.execute(
                    """
                    UPDATE crawl_frontier
                    SET state='pending',claimed_at=NULL
                    WHERE state='active'
                    """
                )
                connection.execute(
                    """
                    UPDATE capture_runs
                    SET status = 'interrupted', finished_at = ?
                    WHERE status = 'running' AND id IN (
                        SELECT capture_run_id FROM crawl_jobs WHERE capture_run_id IS NOT NULL
                    )
                    """,
                    (recovered_at,),
                )
                connection.execute(
                    """
                    UPDATE capture_runs
                    SET status='interrupted',finished_at=?
                    WHERE status='running' AND id IN (
                        SELECT capture_run_id FROM crawl_frontier
                        WHERE capture_run_id IS NOT NULL
                    )
                    """,
                    (recovered_at,),
                )
                connection.commit()
                return resumable
            except Exception:
                connection.rollback()
                raise

    def claim_auto_resume_jobs(
        self, claimed_at: str, max_active_jobs: int
    ) -> list[dict[str, Any]]:
        limit = max(1, int(max_active_jobs))
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                running = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM crawl_jobs WHERE status='running'"
                    ).fetchone()[0]
                )
                available = max(0, limit - running)
                rows = connection.execute(
                    """
                    SELECT * FROM crawl_jobs
                    WHERE status='interrupted' AND auto_resume_pending=1
                        AND cancel_requested_at IS NULL
                    ORDER BY created_at,rowid LIMIT ?
                    """,
                    (available,),
                ).fetchall()
                claimed_ids: list[str] = []
                for row in rows:
                    cursor = connection.execute(
                        """
                        UPDATE crawl_jobs
                        SET status='running',message='Continuing crawl',updated_at=?,
                            finished_at=NULL,auto_resume_pending=0
                        WHERE id=? AND status='interrupted' AND auto_resume_pending=1
                            AND cancel_requested_at IS NULL
                        """,
                        (claimed_at, row["id"]),
                    )
                    if cursor.rowcount != 1:
                        continue
                    claimed_ids.append(row["id"])
                    if row["capture_run_id"]:
                        connection.execute(
                            """
                            UPDATE capture_runs
                            SET status='running',finished_at=NULL
                            WHERE id=?
                            """,
                            (row["capture_run_id"],),
                        )
                claimed = [
                    self._job_record(
                        connection.execute(
                            "SELECT * FROM crawl_jobs WHERE id=?", (job_id,)
                        ).fetchone()
                    )
                    for job_id in claimed_ids
                ]
                connection.commit()
                return claimed
            except Exception:
                connection.rollback()
                raise

    def claim_next_frontier(
        self, job_id: str, claimed_at: str
    ) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT * FROM crawl_frontier
                    WHERE job_id=? AND state='pending' ORDER BY id LIMIT 1
                    """,
                    (job_id,),
                ).fetchone()
                if not row:
                    connection.commit()
                    return None
                cursor = connection.execute(
                    """
                    UPDATE crawl_frontier
                    SET state='active',claimed_at=?
                    WHERE id=? AND state='pending'
                    """,
                    (claimed_at, row["id"]),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    return None
                claimed = connection.execute(
                    "SELECT * FROM crawl_frontier WHERE id=?", (row["id"],)
                ).fetchone()
                connection.commit()
                return dict(claimed)
            except Exception:
                connection.rollback()
                raise

    def enqueue_frontier(
        self,
        job_id: str,
        resources: list[tuple[str, int]],
        created_at: str,
        max_items: int,
    ) -> int:
        ceiling = max(1, int(max_items))
        inserted = 0
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                total = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM crawl_frontier WHERE job_id=?", (job_id,)
                    ).fetchone()[0]
                )
                for resource_url, depth in resources:
                    if total >= ceiling:
                        break
                    cursor = connection.execute(
                        """
                        INSERT OR IGNORE INTO crawl_frontier(
                            job_id,resource_url,depth,state,created_at
                        ) VALUES (?, ?, ?, 'pending', ?)
                        """,
                        (job_id, resource_url, max(0, int(depth)), created_at),
                    )
                    if cursor.rowcount == 1:
                        total += 1
                        inserted += 1
                connection.commit()
                return inserted
            except Exception:
                connection.rollback()
                raise

    def bind_frontier_capture_run(
        self, frontier_id: int, capture_run_id: str
    ) -> None:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE crawl_frontier SET capture_run_id=?
                WHERE id=? AND state='active'
                    AND (capture_run_id IS NULL OR capture_run_id=?)
                """,
                (capture_run_id, frontier_id, capture_run_id),
            )
            if cursor.rowcount != 1:
                raise MetadataStoreError(
                    f"crawl frontier item cannot bind capture run: {frontier_id}"
                )

    def successful_attempt_snapshot(
        self, job_id: str, resource_url: str
    ) -> str | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT snapshot_id FROM crawl_attempts
                WHERE job_id=? AND resource_url=? AND status='captured'
                    AND snapshot_id IS NOT NULL
                ORDER BY id DESC LIMIT 1
                """,
                (job_id, resource_url),
            ).fetchone()
            return row["snapshot_id"] if row else None

    def complete_frontier(
        self,
        frontier_id: int,
        finished_at: str,
        outcome: str,
        *,
        snapshot_id: str | None = None,
        error: str | None = None,
        discovered: list[tuple[str, int]] | None = None,
        max_pages: int | None = None,
    ) -> None:
        if outcome not in {"captured", "failed", "skipped"}:
            raise ValueError("invalid frontier outcome")
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT job_id FROM crawl_frontier WHERE id=? AND state='active'",
                    (frontier_id,),
                ).fetchone()
                if not row:
                    raise MetadataStoreError(
                        f"unknown or completed crawl frontier item: {frontier_id}"
                    )
                if discovered:
                    total = int(
                        connection.execute(
                            "SELECT COUNT(*) FROM crawl_frontier WHERE job_id=?",
                            (row["job_id"],),
                        ).fetchone()[0]
                    )
                    ceiling = max(1, int(max_pages or total or 1))
                    for resource_url, depth in discovered:
                        if total >= ceiling:
                            break
                        cursor = connection.execute(
                            """
                            INSERT OR IGNORE INTO crawl_frontier(
                                job_id,resource_url,depth,state,created_at
                            ) VALUES (?, ?, ?, 'pending', ?)
                            """,
                            (
                                row["job_id"],
                                resource_url,
                                max(0, int(depth)),
                                finished_at,
                            ),
                        )
                        total += int(cursor.rowcount == 1)
                connection.execute(
                    """
                    UPDATE crawl_frontier
                    SET state='done',outcome=?,snapshot_id=?,error=?,finished_at=?
                    WHERE id=?
                    """,
                    (outcome, snapshot_id, error, finished_at, frontier_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def frontier_counts(self, job_id: str) -> dict[str, int]:
        counts = {"pending": 0, "active": 0, "done": 0, "captured": 0, "failed": 0, "skipped": 0}
        with self._lock, self._connect() as connection:
            for row in connection.execute(
                """
                SELECT state,outcome,COUNT(*) AS count FROM crawl_frontier
                WHERE job_id=? GROUP BY state,outcome
                """,
                (job_id,),
            ):
                counts[row["state"]] += int(row["count"])
                if row["outcome"]:
                    counts[row["outcome"]] += int(row["count"])
        return counts

    def list_frontier(self, job_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM crawl_frontier WHERE job_id=? ORDER BY id",
                    (job_id,),
                )
            ]

    def existing_snapshot_for_frontier(
        self, job_id: str, resource_url: str
    ) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT s.id,s.source_url,s.final_url,s.content_type,s.file
                FROM crawl_jobs j JOIN snapshots s ON s.capture_run_id=j.capture_run_id
                WHERE j.id=? AND (s.source_url=? OR s.final_url=?)
                ORDER BY s.rowid DESC LIMIT 1
                """,
                (job_id, resource_url, resource_url),
            ).fetchone()
            return dict(row) if row else None

    def begin_attempt(self, job_id: str, resource_url: str, started_at: str, depth: int | None = None) -> int:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                attempt_number = connection.execute(
                    """
                    SELECT COALESCE(MAX(attempt_number), 0) + 1
                    FROM crawl_attempts WHERE job_id = ? AND resource_url = ?
                    """,
                    (job_id, resource_url),
                ).fetchone()[0]
                cursor = connection.execute(
                    """
                    INSERT INTO crawl_attempts(job_id,resource_url,depth,attempt_number,status,started_at)
                    VALUES (?, ?, ?, ?, 'running', ?)
                    """,
                    (job_id, resource_url, depth, attempt_number, started_at),
                )
                connection.commit()
                return int(cursor.lastrowid)
            except Exception:
                connection.rollback()
                raise

    def finish_attempt(
        self,
        attempt_id: int,
        status: str,
        finished_at: str,
        snapshot_id: str | None = None,
        error: str | None = None,
    ) -> None:
        if status not in {"captured", "failed", "skipped"}:
            raise ValueError("invalid attempt status")
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE crawl_attempts
                SET status = ?, snapshot_id = ?, error = ?, finished_at = ?
                WHERE id = ? AND status = 'running'
                """,
                (status, snapshot_id, error, finished_at, attempt_id),
            )
            if cursor.rowcount != 1:
                raise MetadataStoreError(f"unknown or completed crawl attempt: {attempt_id}")

    def list_attempts(
        self, job_id: str, status: str | None = None, limit: int = 500
    ) -> list[dict[str, Any]]:
        where = "job_id = ?"
        values: list[Any] = [job_id]
        if status:
            where += " AND status = ?"
            values.append(status)
        values.append(max(1, min(int(limit), 1000)))
        with self._lock, self._connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    f"SELECT * FROM crawl_attempts WHERE {where} ORDER BY id LIMIT ?", values
                )
            ]

    def storage_health(self) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
            version = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            return {
                "ok": integrity == "ok",
                "schema_version": version,
                "integrity": integrity,
                "capture_runs": connection.execute("SELECT COUNT(*) FROM capture_runs").fetchone()[0],
                "setup_complete": bool(
                    connection.execute(
                        "SELECT setup_complete FROM archive_profile WHERE singleton = 1"
                    ).fetchone()[0]
                ),
            }
