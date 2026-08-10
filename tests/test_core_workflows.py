import tempfile
import unittest
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import app
from archive_manifest import ArchiveManifestManager
from metadata_store import MetadataStore
from archive_lock import ArchiveDataLock


NOW = "2026-07-18T12:00:00+00:00"


class ResponseRecorder:
    def __init__(self):
        self.response = None

    def redirect(self, location):
        self.response = (303, location)
        return self.response

    def set_session(self, user_id, location):
        self.response = (303, location, user_id)
        return self.response

    def html(self, body, status=200):
        self.response = (status, body)
        return self.response


class CoreBehaviorTests(unittest.TestCase):
    def test_first_start_creates_all_runtime_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary) / "new" / "data"
            with (
                mock.patch.object(app, "DATA_DIR", data),
                mock.patch.object(app, "SNAPSHOT_DIR", data / "snapshots"),
                mock.patch.object(app, "PROFILE_DIR", data / "profiles"),
            ):
                app.ensure_dirs()
            self.assertTrue((data / "snapshots").is_dir())
            self.assertTrue((data / "profiles").is_dir())

    def test_url_normalization_and_wayback_history_link(self):
        self.assertEqual(
            app.normalize_url(" Example.COM/archive#section "),
            "https://Example.COM/archive",
        )
        self.assertEqual(
            app.normalize_url("mikehardcastle.com"),
            "https://mikehardcastle.com",
        )
        self.assertEqual(
            app.normalize_url("www.mikehardcastle.com/about"),
            "https://www.mikehardcastle.com/about",
        )
        with self.assertRaises(ValueError):
            app.normalize_url("ftp://example.com/archive")
        self.assertEqual(
            app.wayback_history_url("mikehardcastle.com"),
            "https://web.archive.org/web/*/https://mikehardcastle.com",
        )

    def test_retired_wayback_endpoint_creates_no_import_job(self):
        user = {"id": "usr_owner", "role": "user"}
        site = {
            "id": "site_example",
            "owner_id": user["id"],
            "url": "https://example.test/",
            "visibility": "private",
        }
        recorder = ResponseRecorder()
        with (
            mock.patch.object(
                app,
                "load_db",
                return_value={"users": [user], "sites": [site], "snapshots": [], "events": []},
            ),
        ):
            app.Handler.retired_wayback_import(recorder, user, site["id"])
        self.assertEqual(recorder.response[0], 303)
        self.assertIn("Wayback%20importing%20has%20been%20retired", recorder.response[1])

    def test_site_page_links_to_external_history_without_import_controls(self):
        user = {
            "id": "usr_owner",
            "email": "owner@example.test",
            "name": "Owner",
            "role": "user",
            "status": "active",
        }
        site = {
            "id": "site_example",
            "owner_id": user["id"],
            "name": "Example",
            "url": "https://example.test/",
            "visibility": "private",
            "interval": "monthly",
            "crawl_depth": 3,
            "max_pages": 25,
        }
        store = mock.Mock()
        store.list_capture_runs.return_value = []
        store.list_jobs.return_value = []
        with (
            mock.patch.object(app, "METADATA_STORE", store),
            mock.patch.object(
                app,
                "load_db",
                return_value={"users": [user], "sites": [site], "snapshots": [], "events": []},
            ),
        ):
            page = app.site_page(user, site["id"])
        self.assertIn(
            'href="https://web.archive.org/web/*/https://example.test/"',
            page,
        )
        self.assertIn('target="_blank"', page)
        self.assertIn("Browse on Wayback Machine", page)
        self.assertNotIn("Import Wayback", page)
        self.assertNotIn("Edit Wayback", page)
        self.assertNotIn("/import-wayback", page)

    def test_site_summary_shortcuts_one_capture_but_lists_multiple_captures(self):
        site = {
            "id": "site_example",
            "owner_id": "usr_owner",
            "name": "Example",
            "url": "https://example.test/",
            "visibility": "private",
            "next_snapshot_at": "2026-08-18T12:00:00+00:00",
        }
        first = {
            "id": "snap_first",
            "site_id": site["id"],
            "capture_run_id": "capture_first",
            "source_url": site["url"],
            "created_at": "2026-07-18T12:00:00+00:00",
        }
        second = {
            "id": "snap_second",
            "site_id": site["id"],
            "capture_run_id": "capture_second",
            "source_url": site["url"],
            "created_at": "2026-07-19T12:00:00+00:00",
        }
        one_capture = app.site_row(site, {"snapshots": [first]})
        self.assertIn('href="/snapshots/snap_first"', one_capture)
        self.assertIn('href="/sites/site_example/edit">Edit</a>', one_capture)
        self.assertNotIn("Wayback", one_capture)

        multiple_captures = app.site_row(site, {"snapshots": [first, second]})
        self.assertIn('href="/sites/site_example"', multiple_captures)
        self.assertNotIn('href="/snapshots/snap_second"', multiple_captures)

    def test_site_listing_and_edit_page_separate_destructive_controls(self):
        user = {
            "id": "usr_owner",
            "email": "owner@example.test",
            "name": "Owner",
            "role": "user",
            "status": "active",
        }
        site = {
            "id": "site_example",
            "owner_id": user["id"],
            "name": "Example",
            "url": "https://example.test/",
            "visibility": "private",
            "interval": "monthly",
            "crawl_depth": 3,
            "max_pages": 25,
        }
        snapshot = {
            "id": "snap_example",
            "site_id": site["id"],
            "created_at": "2026-07-18T12:00:00+00:00",
            "source_url": site["url"],
            "kind": "live",
            "status": 200,
            "bytes": 1024,
            "content_type": "text/html",
            "assets": [],
        }
        store = mock.Mock()
        store.list_capture_runs.return_value = []
        store.list_jobs.return_value = []
        with (
            mock.patch.object(app, "METADATA_STORE", store),
            mock.patch.object(
                app,
                "load_db",
                return_value={
                    "users": [user],
                    "sites": [site],
                    "snapshots": [snapshot],
                    "events": [],
                },
            ),
        ):
            listing = app.site_page(user, site["id"])
            editing = app.site_edit_page(user, site["id"])
            site["visibility"] = "public"
            denied_edit = app.site_edit_page(
                {
                    "id": "usr_viewer",
                    "email": "viewer@example.test",
                    "name": "Viewer",
                    "role": "user",
                    "status": "active",
                },
                site["id"],
            )
        self.assertIn('href="/sites/site_example/edit">Edit</a>', listing)
        self.assertNotIn("/snapshots/snap_example/delete", listing)
        self.assertNotIn("Crawl policy", listing)
        self.assertIn('href="/sites/site_example">Back to captures</a>', editing)
        self.assertIn("/snapshots/snap_example/delete", editing)
        self.assertIn("Crawl policy", editing)
        self.assertIn("Site not found", denied_edit)
        self.assertNotIn("Crawl policy", denied_edit)

    def test_snapshot_toolbar_exposes_wayback_history_button(self):
        user = {
            "id": "usr_owner",
            "email": "owner@example.test",
            "name": "Owner",
            "role": "user",
            "status": "active",
        }
        site = {
            "id": "site_example",
            "owner_id": user["id"],
            "name": "Example",
            "url": "https://example.test/",
            "visibility": "private",
        }
        snapshot = {
            "id": "snap_example",
            "site_id": site["id"],
            "created_at": "2026-07-18T12:00:00+00:00",
            "kind": "live",
            "content_type": "text/html",
            "assets": [],
        }
        with (
            mock.patch.object(
                app,
                "load_db",
                return_value={
                    "users": [user],
                    "sites": [site],
                    "snapshots": [snapshot],
                    "events": [],
                },
            ),
        ):
            page = app.snapshot_page(user, snapshot["id"])
        self.assertIn(
            'class="button secondary small" href="https://web.archive.org/web/*/https://example.test/"',
            page,
        )
        self.assertIn("Wayback history", page)
        self.assertIn('target="_blank"', page)
        self.assertNotIn(">Delete</button>", page)
        self.assertIn(
            'class="button secondary small" href="/sites/site_example">Back to site</a>',
            page,
        )

    def test_asset_repair_does_not_fetch_from_legacy_wayback_captures(self):
        snapshots = [
            {
                "id": "snap_live",
                "site_id": "site_example",
                "kind": "live",
                "content_type": "text/html",
            },
            {
                "id": "snap_wayback",
                "site_id": "site_example",
                "kind": "wayback",
                "content_type": "text/html",
            },
        ]
        store = mock.Mock()
        with (
            mock.patch.object(app, "METADATA_STORE", store),
            mock.patch.object(
                app,
                "load_db",
                return_value={"sites": [], "snapshots": snapshots},
            ),
            mock.patch.object(app, "active_job_limit", return_value=2),
            mock.patch.object(app, "start_worker"),
            mock.patch.object(app.SHUTDOWN_EVENT, "is_set", return_value=False),
        ):
            app.start_asset_localization("site_example", "usr_owner")
        self.assertEqual(
            store.create_job.call_args.kwargs["frontier"],
            [("urn:websnapshot:snapshot:snap_live", 0)],
        )

    def test_authorization_matrix_and_replay_rewriting_fail_closed(self):
        owner = {"id": "usr_owner", "role": "user"}
        other = {"id": "usr_other", "role": "user"}
        public = {"id": "site_public", "owner_id": owner["id"], "visibility": "public"}
        private = {**public, "id": "site_private", "visibility": "private"}
        self.assertTrue(app.can_view_site(None, public))
        self.assertFalse(app.can_view_site(None, private))
        self.assertFalse(app.can_manage_site(other, public))
        self.assertTrue(app.can_manage_site(owner, public))

        replay = app.prepare_html_replay(
            b'<a href="child.html#part">Child</a><a href="javascript:alert(1)">Bad</a>'
            b'<form action="/submit"></form><script>alert(1)</script>',
            "https://example.test/index.html",
            "https://archive.test",
            {"https://example.test/child.html": "snap_child"},
        ).decode()
        self.assertIn("https://archive.test/snapshots/snap_child/content#part", replay)
        self.assertIn('href="#"', replay)
        self.assertIn('action="about:blank"', replay)
        self.assertIn('type="application/x-websnapshot-disabled"', replay)

    def test_calendar_helpers_bound_invalid_custom_values(self):
        self.assertEqual(app.interval_to_days("daily"), 1)
        self.assertEqual(app.interval_to_days("weekly"), 7)
        self.assertEqual(app.interval_to_days("monthly"), 30)
        self.assertEqual(app.interval_to_days("yearly"), 365)
        self.assertEqual(app.interval_to_days("custom", "0"), 1)
        self.assertEqual(app.interval_to_days("custom", "invalid"), 30)
        self.assertEqual(
            app.next_capture_after("2026-07-18T12:00:00+00:00", "weekly"),
            "2026-07-25T12:00:00+00:00",
        )
        self.assertEqual(
            app.next_capture_after("2026-07-18T12:00:00+00:00", "yearly"),
            "2027-07-18T12:00:00+00:00",
        )

    def test_add_site_form_is_simple_and_prefilled(self):
        page = app.new_site_page(
            {"id": "usr_owner", "role": "user", "email": "owner@example.test"},
            initial_url="example.test/path",
        )
        self.assertIn('value="example.test/path"', page)
        self.assertIn('type="text" inputmode="url"', page)
        self.assertIn('placeholder="example.com"', page)
        self.assertNotIn('type="url" name="url"', page)
        self.assertIn('<option value="yearly">Yearly</option>', page)
        self.assertNotIn("Display name", page)
        self.assertNotIn("Schedule time zone", page)
        self.assertNotIn("Local capture time", page)
        self.assertNotIn("Maximum pages per crawl", page)
        self.assertNotIn("Crawl depth", page)

    def test_capture_run_collapses_its_individual_pages(self):
        run = {
            "id": "capture_test",
            "kind": "live",
            "status": "complete",
            "started_at": NOW,
            "entry_snapshot_id": "snap_entry",
            "captured": 2,
            "failed": 0,
        }
        snapshots = [
            {"id": "snap_entry", "source_url": "https://example.test", "created_at": NOW,
             "kind": "live", "status": 200, "bytes": 100},
            {"id": "snap_child", "source_url": "https://example.test/about", "created_at": NOW,
             "kind": "live", "status": 200, "bytes": 100},
        ]
        page = app.capture_run_row(run, snapshots)
        self.assertIn('<details class="capture-pages-disclosure">', page)
        self.assertNotIn('<details class="capture-pages-disclosure" open', page)
        self.assertIn('href="/snapshots/snap_entry"', page)

    def test_document_title_is_used_for_site_names(self):
        self.assertEqual(
            app.document_title(b"<html><title> Ventnor &amp; Arts\n Club </title></html>"),
            "Ventnor & Arts Club",
        )
        self.assertEqual(app.provisional_site_name("https://www.example.test/"), "example.test")

    def test_login_preserves_only_safe_local_archive_requests(self):
        requested = "/sites/new?url=https%3A%2F%2Fexample.test%2F"
        recorder = ResponseRecorder()
        recorder.path = requested
        app.Handler.require_user(recorder, None, lambda: None)
        self.assertEqual(
            recorder.response,
            (303, "/login?next=" + urllib.parse.quote(requested, safe="")),
        )
        page = app.login_page(return_to=requested)
        self.assertIn(f'name="return_to" value="{requested.replace("&", "&amp;")}"', page)
        self.assertEqual(app.safe_local_return("https://evil.example/", "/dashboard"), "/dashboard")

    def test_calendar_scheduling_handles_month_ends_dst_and_overnight_windows(self):
        self.assertEqual(
            app.next_calendar_capture(
                "2027-01-31T12:00:00+00:00", "monthly", timezone_name="UTC",
                local_time="09:00", month_day=31,
            ),
            "2027-02-28T09:00:00+00:00",
        )
        self.assertEqual(
            app.next_calendar_capture(
                "2026-03-22T10:00:00+00:00", "weekly",
                timezone_name="Europe/London", local_time="09:00", weekday=6,
            ),
            "2026-03-29T08:00:00+00:00",
        )
        settings = {
            "scheduler_timezone": "UTC",
            "capture_window_start": "22:00",
            "capture_window_end": "06:00",
        }
        self.assertTrue(
            app.capture_window_open(datetime(2026, 7, 18, 23, tzinfo=timezone.utc), settings)
        )
        self.assertTrue(
            app.capture_window_open(datetime(2026, 7, 18, 5, 59, tzinfo=timezone.utc), settings)
        )
        self.assertFalse(
            app.capture_window_open(datetime(2026, 7, 18, 12, tzinfo=timezone.utc), settings)
        )

    def test_archive_search_never_discloses_private_content_to_a_guest(self):
        owner = {"id": "usr_owner", "role": "user", "name": "Owner", "email": "owner@example.test"}
        sites = [
            {"id": "site_public", "owner_id": owner["id"], "name": "Public", "url": "https://public.test", "visibility": "public"},
            {"id": "site_private", "owner_id": owner["id"], "name": "Private", "url": "https://private.test", "visibility": "private"},
        ]
        snapshots = [
            {"id": "snap_public", "site_id": "site_public", "kind": "live", "source_url": "https://public.test", "final_url": "https://public.test", "content_type": "text/html", "file": "public.html", "created_at": NOW},
            {"id": "snap_private", "site_id": "site_private", "kind": "live", "source_url": "https://private.test", "final_url": "https://private.test", "content_type": "text/html", "file": "private.html", "created_at": NOW},
        ]
        document = {"users": [owner], "sites": sites, "snapshots": snapshots, "events": []}
        bodies = {"snap_public": b"<p>shared phrase</p>", "snap_private": b"<p>private phrase</p>"}
        with (
            mock.patch.object(app, "load_db", return_value=document),
            mock.patch.object(app, "snapshot_file_bytes", side_effect=lambda snapshot, limit=None: bodies[snapshot["id"]]),
        ):
            guest_private = app.archive_search_page(None, {"q": ["private phrase"]})
            guest_public = app.archive_search_page(None, {"q": ["shared phrase"]})
            owner_private = app.archive_search_page(owner, {"q": ["private phrase"]})
        self.assertNotIn("snap_private", guest_private)
        self.assertIn("No accessible archive records matched", guest_private)
        self.assertIn("snap_public", guest_public)
        self.assertIn("snap_private", owner_private)

    def test_capture_comparison_reports_page_and_resource_changes(self):
        owner = {"id": "usr_owner", "role": "user", "name": "Owner", "email": "owner@example.test"}
        site = {"id": "site_test", "owner_id": owner["id"], "name": "Test", "url": "https://example.test", "visibility": "private"}
        base = {"site_id": site["id"], "kind": "live", "final_url": "https://example.test", "content_type": "text/html", "created_at": NOW}
        snapshots = [
            {**base, "id": "snap_old", "capture_run_id": "capture_old", "source_url": "https://example.test", "file": "old.html", "assets": [{"id": "asset_old", "source_url": "https://example.test/a.css", "content_digest": "old"}]},
            {**base, "id": "snap_new", "capture_run_id": "capture_new", "source_url": "https://example.test", "file": "new.html", "assets": [{"id": "asset_new", "source_url": "https://example.test/a.css", "content_digest": "new"}]},
            {**base, "id": "snap_added", "capture_run_id": "capture_new", "source_url": "https://example.test/added", "file": "added.html", "assets": []},
        ]
        store = mock.Mock()
        store.list_capture_runs.return_value = [
            {"id": "capture_new", "site_id": site["id"], "started_at": NOW, "kind": "live"},
            {"id": "capture_old", "site_id": site["id"], "started_at": "2026-06-18T12:00:00+00:00", "kind": "live"},
        ]
        bodies = {"snap_old": b"old", "snap_new": b"new", "snap_added": b"added"}
        with (
            mock.patch.object(app, "METADATA_STORE", store),
            mock.patch.object(app, "load_db", return_value={"users": [owner], "sites": [site], "snapshots": snapshots, "events": []}),
            mock.patch.object(app, "snapshot_file_bytes", side_effect=lambda snapshot, limit=None: bodies[snapshot["id"]]),
        ):
            page = app.capture_comparison(owner, site["id"], {"left": ["capture_old"], "right": ["capture_new"]})
            denied = app.capture_comparison(None, site["id"], {"left": ["capture_old"], "right": ["capture_new"]})
        self.assertIn("Pages added", page)
        self.assertIn("Pages changed", page)
        self.assertIn("Changed resources", page)
        self.assertIn("https://example.test/added", page)
        self.assertIn("Site not found", denied)


class ApplicationWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.snapshots = self.root / "snapshots"
        self.snapshots.mkdir()
        self.store = MetadataStore(self.root / "websnapshot.sqlite3")
        self.store.initialize(
            lambda: {
                "users": [],
                "sites": [],
                "snapshots": [],
                "events": [],
            }
        )
        self.lock = ArchiveDataLock(self.root / ".archive.lock")
        self.manifests = ArchiveManifestManager(self.root / "integrity", self.snapshots)
        self.patches = [
            mock.patch.object(app, "DATA_DIR", self.root),
            mock.patch.object(app, "SNAPSHOT_DIR", self.snapshots),
            mock.patch.object(app, "PROFILE_DIR", self.root / "profiles"),
            mock.patch.object(app, "INTEGRITY_DIR", self.root / "integrity"),
            mock.patch.object(app, "MANIFEST_MANAGER", self.manifests),
            mock.patch.object(app, "METADATA_STORE", self.store),
            mock.patch.object(app, "DATA_LOCK", self.lock),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_signup_public_and_private_site_creation_and_snapshot_deletion(self):
        response = ResponseRecorder()
        app.Handler.signup(
            response,
            {
                "email": "owner@example.test",
                "name": "Archive Owner",
                "password": "Correct Horse Battery 2026!",
            },
        )
        user = self.store.load_document()["users"][0]
        self.assertEqual(response.response, (303, "/dashboard", user["id"]))
        self.assertIsNotNone(user["email_verified_at"])

        with mock.patch.object(app, "start_site_crawl", return_value="job_fixture"):
            app.Handler.create_site(
                response,
                user,
                {
                    "name": "Public Fixture",
                    "url": "public.example.test",
                    "visibility": "public",
                    "interval": "weekly",
                    "crawl_depth": "2",
                    "max_pages": "10",
                },
            )
            app.Handler.create_site(
                response,
                user,
                {
                    "name": "Private Fixture",
                    "url": "private.example.test",
                    "visibility": "private",
                    "interval": "monthly",
                    "crawl_depth": "1",
                    "max_pages": "5",
                },
            )

        document = self.store.load_document()
        public = next(site for site in document["sites"] if site["visibility"] == "public")
        private = next(site for site in document["sites"] if site["visibility"] == "private")
        self.assertEqual("https://public.example.test", public["url"])
        self.assertEqual("https://private.example.test", private["url"])
        self.assertTrue(app.can_view_site(None, public))
        self.assertFalse(app.can_view_site(None, private))

        page_path = self.snapshots / "fixture.html"
        page_path.write_text("<h1>Fixture</h1>", encoding="utf-8")

        def add_snapshot(current):
            current["snapshots"].append(
                {
                    "id": "snap_fixture",
                    "site_id": private["id"],
                    "capture_run_id": None,
                    "kind": "live",
                    "source_url": private["url"],
                    "final_url": private["url"],
                    "status": 200,
                    "content_type": "text/html",
                    "bytes": page_path.stat().st_size,
                    "file": page_path.name,
                    "rendered": False,
                    "wayback_timestamp": None,
                    "created_at": NOW,
                    "created_by": user["id"],
                    "assets": [],
                }
            )

        self.store.mutate_document(add_snapshot)
        app.Handler.delete_snapshot(response, user, "snap_fixture")
        self.assertFalse(page_path.exists())
        self.assertFalse(self.store.load_document()["snapshots"])
        self.assertIn("Snapshot%20deleted", response.response[1])

    def test_scheduler_starts_due_sites_and_defers_failures(self):
        password = app.hash_password("Correct Horse Battery 2026!")

        def seed(current):
            current["users"].append(
                {
                    "id": "usr_owner",
                    "email": "owner@example.test",
                    "name": "Owner",
                    "password": password,
                    "role": "user",
                    "status": "active",
                    "created_at": NOW,
                    "last_login_at": None,
                }
            )
            current["sites"].append(
                {
                    "id": "site_due",
                    "owner_id": "usr_owner",
                    "name": "Due",
                    "url": "https://due.example.test",
                    "visibility": "private",
                    "interval": "monthly",
                    "custom_days": "30",
                    "crawl_depth": 1,
                    "max_pages": 5,
                    "wayback_enabled": False,
                    "wayback_frequency": "yearly",
                    "wayback_limit": 20,
                    "created_at": NOW,
                    "next_snapshot_at": "2026-01-01T00:00:00+00:00",
                }
            )

        self.store.mutate_document(seed)
        shutdown = mock.Mock()
        shutdown.is_set.side_effect = [False, True]
        before = datetime.now(timezone.utc)
        with (
            mock.patch.object(app, "SHUTDOWN_EVENT", shutdown),
            mock.patch.object(app, "start_site_crawl", side_effect=RuntimeError("offline")) as start,
            mock.patch.object(app, "structured_log"),
        ):
            app.scheduler_loop()
        start.assert_called_once_with("site_due", "system", "scheduled", 1, 5)
        site = self.store.load_document()["sites"][0]
        deferred = app.parse_iso(site["next_snapshot_at"])
        self.assertGreaterEqual(deferred, before.replace(microsecond=0))
        self.assertLessEqual(deferred, datetime.now(timezone.utc).replace(microsecond=0) + app.timedelta(hours=6, seconds=1))
        self.assertEqual(self.store.load_document()["events"][-1]["action"], "scheduled_capture_failed")

    def test_scheduler_skips_unchanged_homepage_and_advances_by_frequency_offset(self):
        password = app.hash_password("Correct Horse Battery 2026!")
        digest = app.hashlib.sha256(b"unchanged source").hexdigest()

        def seed(current):
            current["users"].append(
                {
                    "id": "usr_owner",
                    "email": "owner@example.test",
                    "name": "Owner",
                    "password": password,
                    "role": "user",
                    "status": "active",
                    "created_at": NOW,
                    "last_login_at": None,
                }
            )
            current["sites"].append(
                {
                    "id": "site_due",
                    "owner_id": "usr_owner",
                    "name": "Due",
                    "url": "https://due.example.test",
                    "visibility": "private",
                    "interval": "weekly",
                    "custom_days": "7",
                    "crawl_depth": 1,
                    "max_pages": 5,
                    "wayback_enabled": False,
                    "wayback_frequency": "yearly",
                    "wayback_limit": 20,
                    "created_at": NOW,
                    "next_snapshot_at": "2026-01-01T00:00:00+00:00",
                    "schedule_timezone": "UTC",
                    "schedule_time": "09:00",
                    "schedule_weekday": 0,
                    "schedule_month_day": 1,
                    "change_policy": "homepage_changed",
                    "last_source_digest": digest,
                }
            )

        self.store.mutate_document(seed)
        shutdown = mock.Mock()
        shutdown.is_set.side_effect = [False, True]
        with (
            mock.patch.object(app, "SHUTDOWN_EVENT", shutdown),
            mock.patch.object(
                app,
                "fetch_bytes",
                return_value=("https://due.example.test", 200, "text/html", b"unchanged source"),
            ),
            mock.patch.object(app, "start_site_crawl") as start,
            mock.patch.object(app, "structured_log"),
        ):
            app.scheduler_loop()

        start.assert_not_called()
        document = self.store.load_document()
        self.assertEqual(document["events"][-1]["action"], "scheduled_capture_unchanged")
        self.assertGreater(app.parse_iso(document["sites"][0]["next_snapshot_at"]), datetime.now(timezone.utc))


if __name__ == "__main__":
    unittest.main()
