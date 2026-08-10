import os
import re
import unittest
from unittest import mock

import app


@unittest.skipUnless(
    os.environ.get("WEBSNAPSHOT_BROWSER_TEST") == "1",
    "real-browser release check",
)
class BrowserInterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright

        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(headless=True)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def open_markup(self, markup, viewport):
        stylesheet = (app.STATIC_DIR / "styles.css").read_text(encoding="utf-8")
        markup = re.sub(
            r'<link[^>]+href="/static/styles\.css[^>]*>',
            lambda _match: f"<style>{stylesheet}</style>",
            markup,
            count=1,
        )
        page = self.browser.new_page(viewport=viewport)
        console_errors = []
        page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: console_errors.append(str(error)))
        page.set_content(markup, wait_until="load")
        return page, console_errors


    def render_dashboard(self, viewport):
        user = {
            "id": "usr_fixture",
            "email": "owner@example.test",
            "name": "Archive Owner",
            "role": "user",
            "status": "active",
        }
        site = {
            "id": "site_fixture",
            "owner_id": user["id"],
            "name": "Representative Archive",
            "url": "https://example.test",
            "visibility": "private",
            "next_snapshot_at": "2026-08-18T12:00:00+00:00",
        }
        quota = {
            "quota_bytes": 10 * 1024 ** 3,
            "used_bytes": 2 * 1024 ** 3,
            "reserved_bytes": 0,
            "available_bytes": 8 * 1024 ** 3,
            "warning": False,
            "over_quota": False,
        }
        with (
            mock.patch.object(
                app,
                "load_db",
                return_value={"users": [user], "sites": [site], "snapshots": [], "events": []},
            ),
            mock.patch.object(app.METADATA_STORE, "storage_quota", return_value=quota),
        ):
            markup = app.dashboard(user)
        return self.open_markup(markup, viewport)

    def assert_layout(self, viewport):
        page, console_errors = self.render_dashboard(viewport)
        self.addCleanup(page.close)
        self.assertEqual(console_errors, [])
        self.assertEqual(
            page.evaluate("document.documentElement.scrollWidth"),
            page.evaluate("document.documentElement.clientWidth"),
        )
        self.assertTrue(page.get_by_text("Representative Archive").is_visible())
        self.assertTrue(page.locator("summary").get_by_text("Archive Owner", exact=True).is_visible())
        self.assertGreater(len(page.screenshot(full_page=True)), 10_000)
        self.assertEqual(page.locator("main").count(), 1)
        self.assertEqual(page.locator('nav[aria-label="Primary navigation"]').count(), 1)
        self.assertEqual(
            page.evaluate(
                """() => [...document.querySelectorAll('input, select, textarea')]
                    .filter((control) => !control.labels || control.labels.length === 0)
                    .map((control) => control.name || control.type)"""
            ),
            [],
        )
        page.keyboard.press("Tab")
        self.assertTrue(page.locator(".skip-link").evaluate("element => element === document.activeElement"))
        clipped = page.evaluate(
            """() => [...document.querySelectorAll('a, button')].filter((element) => {
                const style = getComputedStyle(element);
                return style.display !== 'none' && element.scrollWidth > element.clientWidth + 1;
            }).map((element) => element.textContent.trim()).filter(Boolean)"""
        )
        self.assertEqual(clipped, [])

    def test_dashboard_desktop_has_no_console_or_layout_failures(self):
        self.assert_layout({"width": 1440, "height": 900})

    def test_dashboard_mobile_has_no_console_or_layout_failures(self):
        self.assert_layout({"width": 390, "height": 844})

    def test_simplified_enrollment_and_collapsed_capture_fit_desktop_and_mobile(self):
        user = {
            "id": "usr_fixture",
            "email": "owner@example.test",
            "name": "Archive Owner",
            "role": "user",
            "status": "active",
        }
        run = {
            "id": "capture_fixture",
            "kind": "live",
            "status": "complete",
            "started_at": "2026-07-19T12:00:00+00:00",
            "entry_snapshot_id": "snap_entry",
            "captured": 2,
            "failed": 0,
        }
        snapshots = [
            {"id": "snap_entry", "source_url": "https://example.test/", "created_at": run["started_at"], "kind": "live", "status": 200, "bytes": 100},
            {"id": "snap_child", "source_url": "https://example.test/a/long/example/page", "created_at": run["started_at"], "kind": "live", "status": 200, "bytes": 100},
        ]
        pages = (
            app.new_site_page(user, initial_url="https://example.test/a/long/example/page"),
            app.render_shell(
                "Captures",
                '<main class="workspace"><section class="table-panel">'
                + app.capture_run_row(run, snapshots, can_manage=True)
                + "</section></main>",
                user,
            ),
        )
        for viewport in ({"width": 1440, "height": 900}, {"width": 390, "height": 844}):
            for markup in pages:
                with self.subTest(viewport=viewport):
                    page, errors = self.open_markup(markup, viewport)
                    try:
                        self.assertEqual(errors, [])
                        self.assertEqual(
                            page.evaluate("document.documentElement.scrollWidth"),
                            page.evaluate("document.documentElement.clientWidth"),
                        )
                        self.assertGreater(len(page.screenshot(full_page=True)), 10_000)
                    finally:
                        page.close()

    def test_snapshot_toolbar_wayback_button_fits_desktop_and_mobile(self):
        user = {
            "id": "usr_fixture",
            "email": "owner@example.test",
            "name": "Archive Owner",
            "role": "user",
            "status": "active",
        }
        site = {
            "id": "site_fixture",
            "owner_id": user["id"],
            "name": "Representative Archive",
            "url": "https://example.test/",
            "visibility": "private",
        }
        snapshot = {
            "id": "snap_fixture",
            "site_id": site["id"],
            "created_at": "2026-07-19T12:00:00+00:00",
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
            markup = app.snapshot_page(user, snapshot["id"])
        for viewport in ({"width": 1440, "height": 900}, {"width": 390, "height": 844}):
            with self.subTest(viewport=viewport):
                page, errors = self.open_markup(markup, viewport)
                try:
                    self.assertEqual(errors, [])
                    self.assertEqual(
                        page.evaluate("document.documentElement.scrollWidth"),
                        page.evaluate("document.documentElement.clientWidth"),
                    )
                    self.assertTrue(
                        page.get_by_role("link", name="Wayback history").is_visible()
                    )
                    self.assertEqual(
                        page.get_by_role("button", name="Delete").count(),
                        0,
                    )
                    self.assertTrue(
                        page.get_by_role("link", name="Back to site").is_visible()
                    )
                finally:
                    page.close()


    def test_search_and_comparison_fit_mobile_without_console_errors(self):
        user = {"id": "usr_fixture", "email": "owner@example.test", "name": "Archive Owner", "role": "user", "status": "active"}
        site = {"id": "site_fixture", "owner_id": user["id"], "name": "Representative Archive", "url": "https://example.test", "visibility": "private"}
        base = {"site_id": site["id"], "kind": "live", "final_url": site["url"], "content_type": "text/html", "created_at": "2026-07-18T12:00:00+00:00", "assets": []}
        snapshots = [
            {**base, "id": "snap_old", "capture_run_id": "capture_old", "source_url": site["url"], "file": "old.html"},
            {**base, "id": "snap_new", "capture_run_id": "capture_new", "source_url": site["url"], "file": "new.html"},
        ]
        document = {"users": [user], "sites": [site], "snapshots": snapshots, "events": []}
        store = mock.Mock()
        store.list_capture_runs.return_value = [
            {"id": "capture_new", "site_id": site["id"], "started_at": "2026-07-18T12:00:00+00:00", "kind": "live"},
            {"id": "capture_old", "site_id": site["id"], "started_at": "2026-06-18T12:00:00+00:00", "kind": "live"},
        ]
        with (
            mock.patch.object(app, "METADATA_STORE", store),
            mock.patch.object(app, "load_db", return_value=document),
            mock.patch.object(app, "snapshot_file_bytes", side_effect=lambda snapshot, limit=None: snapshot["id"].encode()),
        ):
            search_markup = app.archive_search_page(user, {"q": ["Representative"]})
            compare_markup = app.capture_comparison(
                user,
                site["id"],
                {"left": ["capture_old"], "right": ["capture_new"]},
            )
        for markup, heading in ((search_markup, "Find a capture"), (compare_markup, "Representative Archive")):
            page, errors = self.open_markup(markup, {"width": 390, "height": 844})
            try:
                self.assertEqual(errors, [])
                self.assertTrue(page.get_by_text(heading, exact=True).is_visible())
                self.assertEqual(
                    page.evaluate("document.documentElement.scrollWidth"),
                    page.evaluate("document.documentElement.clientWidth"),
                )
            finally:
                page.close()

    def test_checkbox_controls_remain_compact_and_clickable(self):
        user = {
            "id": "usr_fixture",
            "email": "owner@example.test",
            "name": "Archive Owner",
            "role": "user",
            "status": "active",
        }
        markup = app.render_shell(
            "Scheduling",
            '<main><section class="panel"><label class="check">'
            '<input type="checkbox" name="paused" value="1"> Pause scheduled captures'
            '</label></section></main>',
            user,
        )
        for viewport in ({"width": 1440, "height": 900}, {"width": 390, "height": 844}):
            page, errors = self.open_markup(markup, viewport)
            try:
                box = page.locator('input[type="checkbox"]')
                bounds = box.bounding_box()
                label_bounds = page.locator("label.check").bounding_box()
                self.assertEqual(errors, [])
                self.assertIsNotNone(bounds)
                self.assertLessEqual(bounds["width"], 24)
                self.assertGreaterEqual(bounds["width"], 13)
                self.assertGreaterEqual(label_bounds["height"], 18)
                self.assertEqual(
                    page.evaluate("document.documentElement.scrollWidth"),
                    page.evaluate("document.documentElement.clientWidth"),
                )
            finally:
                page.close()



    def test_sydney_replay_restores_static_hero_and_navigation(self):
        archived = b"""<!doctype html><html><head><style>
        body{margin:0}.site-header{position:fixed;inset:0 0 auto;z-index:1000}
        .site-title a,#mainnav a{color:#fff}.sydney-hero-area,.header-slider,
        .slides-container,.slide-item{height:0}.slide-item{background-color:#173b3a}
        .slide-inner{position:absolute;top:0;transform:translateY(-50%)}
        .page-content{min-height:500px;padding:40px}
        @media(max-width:1024px){.btn-menu{display:block}#mainnav{display:none}}
        </style></head><body class="home wp-theme-sydney">
        <header id="masthead" class="site-header"><h1 class="site-title"><a href="/">Mike Hardcastle</a></h1>
        <div class="btn-menu">Menu</div><nav id="mainnav"><div><ul>
        <li><a href="/">Home</a></li><li><a href="/about">About Me</a></li>
        </ul></div></nav></header>
        <div class="sydney-hero-area"><div class="header-slider"><div class="slides-container">
        <div class="slide-item"><div class="slide-inner">Archived introduction</div></div>
        </div></div></div><main class="page-content">Archived articles</main>
        <script>window.initializeSydneySlider()</script></body></html>"""
        markup = app.prepare_html_replay(
            archived,
            "https://fixture.test/",
            "https://archive.test",
        ).decode()
        for viewport in ({"width": 1440, "height": 900}, {"width": 390, "height": 844}):
            with self.subTest(viewport=viewport):
                page, errors = self.open_markup(markup, viewport)
                try:
                    self.assertEqual(errors, [])
                    self.assertGreaterEqual(
                        page.locator(".sydney-hero-area").bounding_box()["height"],
                        viewport["height"],
                    )
                    self.assertTrue(page.locator(".slide-item").is_visible())
                    self.assertTrue(page.locator("#mainnav").is_visible())
                    self.assertEqual(
                        page.evaluate("document.documentElement.scrollWidth"),
                        page.evaluate("document.documentElement.clientWidth"),
                    )
                    if viewport["width"] <= 1024:
                        self.assertFalse(page.locator(".btn-menu").is_visible())
                    self.assertGreater(len(page.screenshot(full_page=True)), 1_000)
                finally:
                    page.close()


if __name__ == "__main__":
    unittest.main()
