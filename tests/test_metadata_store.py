import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app
from metadata_store import (
    ActiveJobExists,
    JobCapacityExceeded,
    MetadataStore,
    ArchiveStorageCapacityExceeded,
    StorageQuotaExceeded,
)


NOW = "2026-07-17T12:00:00+00:00"


def sample_document():
    return {
        "users": [
            {
                "id": "usr_test",
                "email": "owner@example.test",
                "name": "Owner",
                "password": "salt$digest",
                "role": "user",
                "status": "active",
                "created_at": NOW,
                "last_login_at": None,
                "future_user_field": "preserved",
            }
        ],
        "sites": [
            {
                "id": "site_test",
                "owner_id": "usr_test",
                "name": "Example",
                "url": "https://example.test/",
                "visibility": "private",
                "interval": "monthly",
                "custom_days": "30",
                "crawl_depth": 3,
                "max_pages": 80,
                "wayback_enabled": False,
                "wayback_frequency": "yearly",
                "wayback_limit": 20,
                "created_at": NOW,
                "last_snapshot_at": NOW,
                "next_snapshot_at": NOW,
            }
        ],
        "snapshots": [
            {
                "id": "snap_test",
                "site_id": "site_test",
                "kind": "live",
                "source_url": "https://example.test/",
                "final_url": "https://example.test/",
                "status": 200,
                "content_type": "text/html; charset=utf-8",
                "bytes": 42,
                "file": "site_test/snap_test.html",
                "assets": [
                    {
                        "id": "asset_test",
                        "source_url": "https://example.test/style.css",
                        "final_url": "https://example.test/style.css",
                        "status": 200,
                        "content_type": "text/css",
                        "bytes": 12,
                        "file": "site_test/snap_test_assets/asset_test.css",
                    }
                ],
                "rendered": False,
                "wayback_timestamp": None,
                "created_at": NOW,
                "created_by": "usr_test",
                "capture_quality": {
                    "version": 1,
                    "asset_count": 1,
                    "failed": 1,
                    "items": [{"outcome": "failed", "stage": "html_asset"}],
                },
            }
        ],
        "events": [
            {
                "id": "evt_test",
                "actor_id": "usr_test",
                "action": "test",
                "detail": "Created fixture",
                "created_at": NOW,
            }
        ],
    }


class MetadataMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "websnapshot.sqlite3"
        self.legacy = self.root / "db.json"

    def test_imports_legacy_json_once_without_modifying_source(self):
        document = sample_document()
        source = json.dumps(document, indent=2).encode("utf-8")
        self.legacy.write_bytes(source)
        source_digest = hashlib.sha256(source).hexdigest()

        store = MetadataStore(self.database, self.legacy)
        store.initialize(lambda: self.fail("default factory should not be used"))
        loaded = store.load_document()

        self.assertEqual(hashlib.sha256(self.legacy.read_bytes()).hexdigest(), source_digest)
        self.assertEqual(loaded["users"][0]["future_user_field"], "preserved")
        self.assertEqual(loaded["snapshots"][0]["assets"][0]["id"], "asset_test")
        self.assertEqual(loaded["snapshots"][0]["capture_quality"]["failed"], 1)
        self.assertEqual(store.storage_health()["schema_version"], 16)
        self.assertEqual(loaded["users"][0]["email_verified_at"], NOW)
        self.assertEqual(loaded["users"][0]["session_version"], 1)
        self.assertEqual(store.scheduler_settings()["max_concurrent_jobs"], 2)
        self.assertEqual(loaded["sites"][0]["schedule_timezone"], "UTC")
        self.assertFalse(store.archive_profile()["setup_complete"])
        self.assertRegex(loaded["sites"][0]["archive_site_id"], r"^site_[A-Za-z0-9_-]{16,64}$")
        self.assertRegex(loaded["snapshots"][0]["archive_page_id"], r"^page_[A-Za-z0-9_-]{16,64}$")
        self.assertRegex(
            loaded["snapshots"][0]["assets"][0]["resource_id"],
            r"^resource_[A-Za-z0-9_-]{16,64}$",
        )
        runs = store.list_capture_runs("site_test")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["entry_snapshot_id"], "snap_test")
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM legacy_imports").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM snapshot_assets").fetchone()[0], 1)

        changed_legacy = sample_document()
        changed_legacy["users"][0]["name"] = "Should not replace SQLite"
        self.legacy.write_text(json.dumps(changed_legacy), encoding="utf-8")
        reopened = MetadataStore(self.database, self.legacy)
        reopened.initialize(lambda: self.fail("default factory should not be used"))
        self.assertEqual(reopened.load_document()["users"][0]["name"], "Owner")

    def test_v12_moves_existing_sites_to_safer_offset_defaults(self):
        store = MetadataStore(self.database)
        store.initialize(sample_document)
        with sqlite3.connect(self.database) as connection:
            connection.execute("DELETE FROM schema_migrations WHERE version=12")
            connection.execute(
                """
                UPDATE sites SET change_policy='always',max_pages=80,
                    next_snapshot_at='2026-08-01T00:00:00+00:00',extra_json='{}'
                WHERE id='site_test'
                """
            )
        reopened = MetadataStore(self.database)
        reopened.initialize(sample_document)
        site = reopened.load_document()["sites"][0]
        self.assertEqual(site["change_policy"], "homepage_changed")
        self.assertEqual(site["max_pages"], 25)
        self.assertEqual(site["request_delay_seconds"], 5.0)
        self.assertEqual(site["next_snapshot_at"], "2026-08-16T12:00:00+00:00")

    def test_v16_retires_wayback_jobs_without_deleting_imported_snapshots(self):
        store = MetadataStore(self.database)
        store.initialize(sample_document)
        store.create_job(
            "job_wayback_retired",
            "site_test",
            "usr_test",
            "wayback",
            "Importing",
            NOW,
            {"limit": 20, "frequency": "yearly"},
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE sites SET wayback_enabled=1 WHERE id='site_test'"
            )
            connection.execute(
                """
                UPDATE snapshots
                SET kind='wayback',wayback_timestamp='20010925123456'
                WHERE id='snap_test'
                """
            )
            connection.execute(
                "DELETE FROM schema_migrations WHERE version=16"
            )

        reopened = MetadataStore(self.database)
        reopened.initialize(sample_document)

        document = reopened.load_document()
        self.assertFalse(document["sites"][0]["wayback_enabled"])
        self.assertEqual(document["snapshots"][0]["id"], "snap_test")
        self.assertEqual(
            document["snapshots"][0]["wayback_timestamp"],
            "20010925123456",
        )
        job = reopened.get_job("job_wayback_retired")
        self.assertEqual(job["status"], "interrupted")
        self.assertFalse(job["auto_resume_pending"])
        self.assertIsNotNone(job["cancel_requested_at"])
        self.assertIn("retired", job["message"].lower())

    def test_wayback_backfill_uses_archive_time_not_import_time(self):
        document = sample_document()
        document["snapshots"][0]["kind"] = "wayback"
        document["snapshots"][0]["wayback_timestamp"] = "20010925123456"
        store = MetadataStore(self.database)
        store.initialize(lambda: document)
        run = store.list_capture_runs("site_test")[0]
        self.assertEqual(run["started_at"], "2001-09-25T12:34:56+00:00")

    def test_invalid_relationship_rolls_back_the_whole_mutation(self):
        store = MetadataStore(self.database)
        store.initialize(sample_document)

        def assign_missing_owner(document):
            document["sites"][0]["owner_id"] = "usr_missing"

        with self.assertRaises(sqlite3.IntegrityError):
            store.mutate_document(assign_missing_owner)

        loaded = store.load_document()
        self.assertEqual([user["id"] for user in loaded["users"]], ["usr_test"])
        self.assertEqual([site["owner_id"] for site in loaded["sites"]], ["usr_test"])


class PersistentJobTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "websnapshot.sqlite3"
        self.store = MetadataStore(self.database)
        self.store.initialize(sample_document)

    def test_one_running_job_per_site_is_enforced_by_sqlite(self):
        self.store.create_job("job_first", "site_test", "usr_test", "live", "Starting", NOW)
        with self.assertRaises(ActiveJobExists) as caught:
            self.store.create_job("job_second", "site_test", "usr_test", "wayback", "Starting", NOW)
        self.assertEqual(caught.exception.job_id, "job_first")

        self.store.update_job("job_first", NOW, status="complete", message="Done", captured=1)
        self.store.create_job("job_second", "site_test", "usr_test", "wayback", "Starting", NOW)
        self.assertEqual(self.store.get_job("job_second")["status"], "running")

    def test_installation_wide_job_limit_is_atomic_across_sites(self):
        document = self.store.load_document()
        second = {**document["sites"][0], "id": "site_second", "name": "Second"}
        second.pop("archive_site_id", None)
        document["sites"].append(second)
        self.store.replace_document(document)

        self.store.create_job(
            "job_first", "site_test", "usr_test", "live", "Starting", NOW,
            max_active_jobs=1,
        )
        with self.assertRaises(JobCapacityExceeded) as caught:
            self.store.create_job(
                "job_second", "site_second", "usr_test", "live", "Starting", NOW,
                max_active_jobs=1,
            )
        self.assertEqual(caught.exception.limit, 1)
        self.assertIsNone(self.store.get_job("job_second"))

    def test_scheduler_settings_are_persistent_and_validated_by_sqlite(self):
        self.store.update_scheduler_settings(
            scheduler_timezone="Europe/London",
            capture_window_start="22:00",
            capture_window_end="06:00",
            max_concurrent_jobs=4,
            scheduling_paused=True,
            updated_at=NOW,
            updated_by_user_id="usr_test",
        )
        reopened = MetadataStore(self.database)
        reopened.initialize(sample_document)
        settings = reopened.scheduler_settings()
        self.assertEqual(settings["scheduler_timezone"], "Europe/London")
        self.assertEqual(settings["capture_window_start"], "22:00")
        self.assertEqual(settings["capture_window_end"], "06:00")
        self.assertEqual(settings["max_concurrent_jobs"], 4)
        self.assertTrue(settings["scheduling_paused"])
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.update_scheduler_settings(
                scheduler_timezone="UTC",
                capture_window_start=None,
                capture_window_end=None,
                max_concurrent_jobs=33,
                scheduling_paused=False,
                updated_at=NOW,
                updated_by_user_id="usr_test",
            )

    def test_quota_defaults_unlimited_and_counts_logical_archive_bytes(self):
        quota = self.store.storage_quota("usr_test")
        self.assertIsNone(quota["quota_bytes"])
        self.assertEqual(quota["used_bytes"], 54)
        self.assertEqual(quota["reserved_bytes"], 0)
        self.assertIsNone(quota["available_bytes"])

    def test_job_reservations_prevent_overbooking_and_release_on_completion(self):
        document = self.store.load_document()
        second = {**document["sites"][0], "id": "site_second", "name": "Second"}
        second.pop("archive_site_id", None)
        document["sites"].append(second)
        self.store.replace_document(document)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO user_storage_quotas VALUES (?,?,80,?,?)",
                ("usr_test", 200, NOW, "usr_test"),
            )

        self.store.create_job(
            "job_reserved", "site_test", "usr_test", "live", "Starting", NOW,
            quota_required_bytes=100,
        )
        quota = self.store.storage_quota("usr_test")
        self.assertEqual(quota["used_bytes"], 54)
        self.assertEqual(quota["reserved_bytes"], 100)
        summaries = self.store.storage_quota_summaries()
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["id"], "usr_test")
        with self.assertRaises(StorageQuotaExceeded) as caught:
            self.store.create_job(
                "job_blocked", "site_second", "usr_test", "live", "Starting", NOW,
                quota_required_bytes=50,
            )
        self.assertEqual(caught.exception.available_bytes, 46)
        self.assertIsNone(self.store.get_job("job_blocked"))

        self.store.update_job("job_reserved", NOW, status="complete", message="Done")
        self.assertEqual(self.store.storage_quota("usr_test")["reserved_bytes"], 0)
        self.store.create_job(
            "job_after_release", "site_second", "usr_test", "live", "Starting", NOW,
            quota_required_bytes=50,
        )

    def test_archive_capacity_reserves_across_jobs_and_survives_lower_limit(self):
        document = self.store.load_document()
        second = {**document["sites"][0], "id": "site_org_second", "name": "Second"}
        second.pop("archive_site_id", None)
        document["sites"].append(second)
        self.store.replace_document(document)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO archive_storage_capacity VALUES (1,200,80,?,?)",
                (NOW, "usr_test"),
            )

        capacity = self.store.archive_storage_capacity()
        self.assertEqual(capacity["used_bytes"], 54)
        self.assertEqual(capacity["reserved_bytes"], 0)
        self.store.create_job(
            "job_org_reserved", "site_test", "usr_test", "live", "Starting", NOW,
            quota_required_bytes=100,
        )
        self.assertEqual(
            self.store.archive_storage_capacity()["reserved_bytes"], 100
        )
        with self.assertRaises(ArchiveStorageCapacityExceeded) as caught:
            self.store.create_job(
                "job_org_blocked", "site_org_second", "usr_test", "live", "Starting", NOW,
                quota_required_bytes=50,
            )
        self.assertEqual(caught.exception.available_bytes, 46)
        self.store.update_job("job_org_reserved", NOW, status="complete", message="Done")
        self.store.create_job(
            "job_org_after_release", "site_org_second", "usr_test", "live", "Starting", NOW,
            quota_required_bytes=50,
        )
        self.store.update_job(
            "job_org_after_release", NOW, status="complete", message="Done"
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE archive_storage_capacity SET quota_bytes=10 WHERE singleton=1"
            )
        before = self.store.load_document()
        with self.assertRaises(ArchiveStorageCapacityExceeded):
            self.store.assert_storage_available("usr_test", 1)
        self.assertEqual(before["snapshots"], self.store.load_document()["snapshots"])
        self.assertTrue(self.store.archive_storage_capacity()["over_capacity"])

    def test_quota_below_existing_usage_blocks_new_storage_without_deletion(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO user_storage_quotas VALUES (?,?,80,?,?)",
                ("usr_test", 10, NOW, "usr_test"),
            )
        before = self.store.load_document()
        with self.assertRaises(StorageQuotaExceeded):
            self.store.assert_storage_available("usr_test", 1)
        after = self.store.load_document()
        self.assertEqual(before["snapshots"], after["snapshots"])
        self.assertTrue(self.store.storage_quota("usr_test")["over_quota"])

    def test_progress_and_page_attempts_survive_store_reopen(self):
        self.store.create_job(
            "job_test",
            "site_test",
            "usr_test",
            "live",
            "Starting",
            NOW,
            {"depth": 3, "max_pages": 80},
        )
        attempt_id = self.store.begin_attempt("job_test", "https://example.test/", NOW, 0)
        self.store.finish_attempt(attempt_id, "captured", NOW, snapshot_id="snap_test")
        self.store.update_job(
            "job_test", NOW, message="Captured entry page", captured=1, failed=0
        )

        reopened = MetadataStore(self.database)
        reopened.initialize(sample_document)
        job = reopened.get_job("job_test")
        attempts = reopened.list_attempts("job_test")
        self.assertEqual(job["captured"], 1)
        self.assertEqual(job["parameters"], {"depth": 3, "max_pages": 80})
        self.assertEqual(attempts[0]["status"], "captured")
        self.assertEqual(attempts[0]["snapshot_id"], "snap_test")

    def test_restart_queues_running_crawl_for_automatic_resume(self):
        capture_run = {
            "id": "capture_restartabcdefgh",
            "manifest_id": "manifest_restartabcdef",
        }
        self.store.create_job(
            "job_running",
            "site_test",
            "usr_test",
            "live",
            "Capturing",
            NOW,
            {"depth": 2, "max_pages": 5, "start_url": "https://example.test/"},
            capture_run,
            frontier=[("https://example.test/", 0)],
        )
        frontier = self.store.claim_next_frontier("job_running", NOW)
        self.store.begin_attempt("job_running", "https://example.test/page", NOW, 1)

        recovered = self.store.recover_interrupted_jobs("2026-07-17T12:01:00+00:00")

        self.assertEqual(recovered, ["job_running"])
        job = self.store.get_job("job_running")
        self.assertEqual(job["status"], "interrupted")
        self.assertTrue(job["auto_resume_pending"])
        self.assertIn("automatically", job["message"])
        attempt = self.store.list_attempts("job_running")[0]
        self.assertEqual(attempt["status"], "failed")
        self.assertIn("restart", attempt["error"])
        self.assertEqual(
            self.store.list_frontier("job_running")[0]["state"], "pending"
        )
        self.assertEqual(
            self.store.get_capture_run(capture_run["id"])["status"], "interrupted"
        )
        claimed = self.store.claim_auto_resume_jobs(
            "2026-07-17T12:02:00+00:00", 1
        )
        self.assertEqual([item["id"] for item in claimed], ["job_running"])
        self.assertEqual(self.store.get_job("job_running")["status"], "running")
        self.assertEqual(
            self.store.get_capture_run(capture_run["id"])["status"], "running"
        )
        self.assertEqual(self.store.recover_interrupted_jobs(NOW), ["job_running"])
        self.assertTrue(self.store.get_job("job_running")["auto_resume_pending"])
        self.assertEqual(frontier["resource_url"], "https://example.test/")

    def test_user_cancelled_crawl_is_never_automatically_resumed(self):
        self.store.create_job(
            "job_cancelled",
            "site_test",
            "usr_test",
            "live",
            "Capturing",
            NOW,
            {"max_pages": 1},
            frontier=[("https://example.test/", 0)],
        )
        self.assertTrue(self.store.request_job_cancel("job_cancelled", NOW))

        self.assertEqual(self.store.recover_interrupted_jobs(NOW), [])
        job = self.store.get_job("job_cancelled")
        self.assertEqual(job["status"], "interrupted")
        self.assertFalse(job["auto_resume_pending"])
        self.assertEqual(self.store.claim_auto_resume_jobs(NOW, 1), [])

    def test_every_long_running_archive_job_is_eligible_for_restart_recovery(self):
        for kind in ("live", "scheduled", "retry", "asset_localization"):
            job_id = f"job_resume_{kind}"
            self.store.create_job(
                job_id,
                "site_test",
                "usr_test",
                kind,
                "Working",
                NOW,
                {"max_pages": 1},
            )
            self.assertEqual(self.store.recover_interrupted_jobs(NOW), [job_id])
            self.assertTrue(self.store.get_job(job_id)["auto_resume_pending"])
            claimed = self.store.claim_auto_resume_jobs(NOW, 1)
            self.assertEqual([item["id"] for item in claimed], [job_id])
            self.store.update_job(
                job_id, NOW, status="complete", message="Done"
            )

    def test_frontier_completion_and_discovery_are_atomic_and_bounded(self):
        self.store.create_job(
            "job_frontier",
            "site_test",
            "usr_test",
            "live",
            "Starting",
            NOW,
            frontier=[("https://example.test/", 0)],
        )
        frontier = self.store.claim_next_frontier("job_frontier", NOW)
        self.store.complete_frontier(
            frontier["id"],
            NOW,
            "captured",
            snapshot_id="snap_test",
            discovered=[
                ("https://example.test/a", 1),
                ("https://example.test/b", 1),
            ],
            max_pages=2,
        )

        items = self.store.list_frontier("job_frontier")
        self.assertEqual(
            [(item["resource_url"], item["state"]) for item in items],
            [
                ("https://example.test/", "done"),
                ("https://example.test/a", "pending"),
            ],
        )
        self.assertEqual(self.store.frontier_counts("job_frontier")["captured"], 1)

    def test_resume_reuses_snapshot_written_before_frontier_commit(self):
        capture_run = {
            "id": "capture_crashwindowabc",
            "manifest_id": "manifest_crashwindowab",
        }
        self.store.create_job(
            "job_crash_window",
            "site_test",
            "usr_test",
            "live",
            "Capturing",
            NOW,
            {"depth": 0, "max_pages": 1},
            capture_run,
            frontier=[("https://example.test/", 0)],
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE snapshots SET capture_run_id=? WHERE id='snap_test'",
                (capture_run["id"],),
            )

        existing = self.store.existing_snapshot_for_frontier(
            "job_crash_window", "https://example.test/"
        )

        self.assertEqual(existing["id"], "snap_test")
        self.assertEqual(
            self.store.list_frontier("job_crash_window")[0]["state"], "pending"
        )

    def test_application_reuses_persisted_running_job_without_second_worker(self):
        thread = mock.Mock()
        with (
            mock.patch.object(app, "METADATA_STORE", self.store),
            mock.patch.object(app.threading, "Thread", return_value=thread) as thread_factory,
        ):
            first = app.start_site_crawl("site_test", "usr_test", depth=1, max_pages=2)
            second = app.start_site_crawl("site_test", "usr_test", depth=1, max_pages=2)

        self.assertEqual(second, first)
        self.assertEqual(thread_factory.call_count, 1)
        thread.start.assert_called_once_with()
        reopened = MetadataStore(self.database)
        reopened.initialize(sample_document)
        self.assertEqual(reopened.get_job(first)["status"], "running")

    def test_resumed_worker_does_not_recapture_an_already_written_page(self):
        capture_run = {
            "id": "capture_workerresumeab",
            "manifest_id": "manifest_workerresumea",
        }
        self.store.create_job(
            "job_worker_resume",
            "site_test",
            "usr_test",
            "live",
            "Continuing crawl",
            NOW,
            {
                "depth": 0,
                "max_pages": 1,
                "policy": app.normalized_site_policy(
                    sample_document()["sites"][0], app.USER_AGENT
                ),
            },
            capture_run,
            frontier=[("https://example.test/", 0)],
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE snapshots SET capture_run_id=? WHERE id='snap_test'",
                (capture_run["id"],),
            )

        with (
            mock.patch.object(app, "METADATA_STORE", self.store),
            mock.patch.object(app, "load_robots_policy", return_value=None),
            mock.patch.object(app, "save_snapshot") as save_snapshot,
            mock.patch.object(app, "finalize_capture_run"),
            mock.patch.object(app, "structured_log"),
        ):
            app.run_site_crawl("job_worker_resume")

        save_snapshot.assert_not_called()
        job = self.store.get_job("job_worker_resume")
        self.assertEqual(job["status"], "complete")
        self.assertEqual(job["captured"], 1)
        self.assertEqual(
            self.store.list_frontier("job_worker_resume")[0]["outcome"], "captured"
        )

    def test_resume_dispatcher_starts_each_supported_worker_without_user_action(self):
        cases = (
            ("live", "crawl"),
            ("asset_localization", "assets"),
        )
        for kind, expected_worker in cases:
            job_id = f"job_dispatch_{kind}"
            self.store.create_job(
                job_id,
                "site_test",
                "usr_test",
                kind,
                "Working",
                NOW,
                {"max_pages": 1},
            )
            self.store.recover_interrupted_jobs(NOW)
            with (
                mock.patch.object(app, "METADATA_STORE", self.store),
                mock.patch.object(app, "active_job_limit", return_value=1),
                mock.patch.object(app, "structured_log"),
                mock.patch.object(app, "start_crawl_worker") as crawl_worker,
                mock.patch.object(app, "start_worker") as generic_worker,
            ):
                self.assertEqual(app.resume_pending_crawls(), [job_id])
            if expected_worker == "crawl":
                crawl_worker.assert_called_once_with(job_id)
                generic_worker.assert_not_called()
            else:
                crawl_worker.assert_not_called()
                self.assertEqual(generic_worker.call_args.args[1], f"{expected_worker}-{job_id}")
            self.store.update_job(job_id, NOW, status="complete", message="Done")

    def test_job_and_capture_run_are_created_atomically(self):
        capture_run = {"id": "capture_abcdefghijklmnop", "manifest_id": "manifest_abcdefghijklmnop"}
        self.store.create_job(
            "job_with_run",
            "site_test",
            "usr_test",
            "live",
            "Starting",
            NOW,
            capture_run=capture_run,
        )
        self.assertEqual(self.store.get_job("job_with_run")["capture_run_id"], capture_run["id"])
        self.assertEqual(self.store.get_capture_run(capture_run["id"])["status"], "running")

        with self.assertRaises(ActiveJobExists):
            self.store.create_job(
                "job_conflict",
                "site_test",
                "usr_test",
                "live",
                "Starting",
                NOW,
                capture_run={
                    "id": "capture_qrstuvwxyzABCDE",
                    "manifest_id": "manifest_qrstuvwxyzABCDE",
                },
            )
        self.assertIsNone(self.store.get_capture_run("capture_qrstuvwxyzABCDE"))

    def test_cancel_request_and_retry_lineage_survive_restart(self):
        self.store.create_job("job_original", "site_test", "usr_test", "live", "Starting", NOW)
        attempt_id = self.store.begin_attempt(
            "job_original", "https://example.test/failed", NOW, 1
        )
        self.store.finish_attempt(attempt_id, "failed", NOW, error="timeout")
        self.assertTrue(self.store.request_job_cancel("job_original", NOW))
        self.assertTrue(self.store.job_cancel_requested("job_original"))
        self.store.update_job("job_original", NOW, status="interrupted", message="Cancelled")

        self.store.create_job(
            "job_retry",
            "site_test",
            "usr_test",
            "retry",
            "Retrying",
            NOW,
            retry_of_job_id="job_original",
        )
        reopened = MetadataStore(self.database)
        reopened.initialize(sample_document)
        self.assertEqual(
            reopened.failed_attempt_urls("job_original"),
            ["https://example.test/failed"],
        )
        self.assertEqual(reopened.get_job("job_retry")["retry_of_job_id"], "job_original")

    def test_job_search_filters_and_returns_context(self):
        self.store.create_job(
            "job_complete",
            "site_test",
            "usr_test",
            "live",
            "Captured the entry page",
            NOW,
        )
        self.store.update_job(
            "job_complete", NOW, status="complete", message="Done", captured=1
        )
        self.store.create_job(
            "job_error", "site_test", "usr_test", "scheduled", "Network timeout", NOW
        )
        self.store.update_job(
            "job_error", NOW, status="error", message="Network timeout", failed=1
        )

        result = self.store.search_jobs(status="error", query="owner@example.test")

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["jobs"][0]["id"], "job_error")
        self.assertEqual(result["jobs"][0]["site_name"], "Example")
        self.assertEqual(result["jobs"][0]["actor_email"], "owner@example.test")
        self.assertEqual(self.store.search_jobs(query="100% missing")["total"], 0)

    def test_repeated_failure_alert_anchor_is_stable_until_recovery(self):
        for number in range(1, 4):
            job_id = f"job_failure_{number}"
            self.store.create_job(job_id, "site_test", "usr_test", "scheduled", "Starting", NOW)
            self.store.update_job(
                job_id, NOW, status="complete", message="Partial", captured=1, failed=1
            )

        alerts = self.store.repeated_capture_failure_streaks(3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_job_id"], "job_failure_3")
        self.assertEqual(alerts[0]["consecutive_failures"], 3)

        self.store.create_job("job_failure_4", "site_test", "usr_test", "live", "Starting", NOW)
        self.store.update_job(
            "job_failure_4", NOW, status="error", message="Failed", failed=1
        )
        alerts = self.store.repeated_capture_failure_streaks(3)
        self.assertEqual(alerts[0]["alert_job_id"], "job_failure_3")
        self.assertEqual(alerts[0]["latest_job_id"], "job_failure_4")
        self.assertEqual(alerts[0]["consecutive_failures"], 4)

        self.store.create_job("job_recovered", "site_test", "usr_test", "live", "Starting", NOW)
        self.store.update_job(
            "job_recovered", NOW, status="complete", message="Recovered", captured=1
        )
        self.assertEqual(self.store.repeated_capture_failure_streaks(3), [])

    def test_activity_events_are_searchable_by_type_actor_and_page(self):
        def add_events(document):
            for number in range(125):
                document["events"].append(
                    {
                        "id": f"evt_search_{number}",
                        "actor_id": "usr_test",
                        "action": "capture_checked" if number % 2 else "site_reviewed",
                        "detail": f"Review batch {number}",
                        "created_at": f"2026-07-17T12:{number // 60:02d}:{number % 60:02d}+00:00",
                    }
                )

        self.store.mutate_document(add_events)

        first = self.store.search_events(query="Owner", limit=100)
        filtered = self.store.search_events(action="site_reviewed", query="batch 12")
        second = self.store.search_events(limit=100, offset=100)

        self.assertEqual(first["total"], 126)
        self.assertEqual(len(first["events"]), 100)
        self.assertGreater(len(second["events"]), 0)
        self.assertTrue(all(item["action"] == "site_reviewed" for item in filtered["events"]))
        self.assertIn("capture_checked", self.store.event_actions())
        document = self.store.load_document()
        app.record_event(document, "usr_test", "retention_test", "Keep this event")
        self.assertEqual(len(document["events"]), 127)


if __name__ == "__main__":
    unittest.main()
