import mimetypes
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

import app
from asset_store import ContentAddressedAssetStore
from capture_quality import CaptureDiagnostics, diagnostic_url, replay_quality_report, safe_reason


FIXTURES = Path(__file__).parent / "fixtures" / "capture_sites"


class CaptureFidelityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.snapshot_root = Path(self.temporary.name) / "snapshots"
        self.snapshot_root.mkdir()
        self.asset_store = ContentAddressedAssetStore(self.snapshot_root)
        self.patches = [
            mock.patch.object(app, "SNAPSHOT_DIR", self.snapshot_root),
            mock.patch.object(app, "ASSET_STORE", self.asset_store),
            mock.patch.object(app, "MAX_ASSETS_PER_SNAPSHOT", 40),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def fixture_fetcher(self, fixture_name, failures=None):
        root = FIXTURES / fixture_name
        failures = set(failures or [])

        def fetch(url, _timeout=None, _user_agent=None):
            parsed = urllib.parse.urlsplit(url)
            relative = parsed.path.lstrip("/") or "index.html"
            if relative in failures:
                raise TimeoutError("fixture request timed out")
            target = root / relative
            if not target.is_file():
                raise FileNotFoundError(relative)
            content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            return url, 200, content_type, target.read_bytes()

        return fetch

    def capture_fixture(self, fixture_name, body_name="index.html", failures=None):
        diagnostics = CaptureDiagnostics()
        body = (FIXTURES / fixture_name / body_name).read_bytes()
        with mock.patch.object(
            app, "fetch_asset_bytes", side_effect=self.fixture_fetcher(fixture_name, failures)
        ):
            localized, assets = app.capture_linked_assets(
                "site_fixture",
                f"snap_{fixture_name}",
                body,
                f"https://fixture.test/{body_name}",
                diagnostics=diagnostics,
            )
        return localized, assets, diagnostics

    def test_static_fixture_localizes_nested_css_imports_fonts_images_and_srcset(self):
        body, assets, diagnostics = self.capture_fixture("static")
        text = body.decode()
        self.assertEqual(len(assets), 6)
        self.assertNotIn("https://fixture.test", text)
        self.assertGreaterEqual(text.count("/snapshots/snap_static/asset/"), 4)
        self.assertEqual(diagnostics.as_record(len(assets))["failed"], 0)

        css_bodies = [
            (self.snapshot_root / asset["file"]).read_text(errors="replace")
            for asset in assets
            if asset["content_type"] == "text/css"
        ]
        self.assertTrue(any("/snapshots/snap_static/asset/" in css for css in css_bodies))
        self.assertTrue(any("background-color" in css for css in css_bodies))

    def test_wordpress_fixture_promotes_lazy_image_and_preserves_dropdown_css(self):
        body, assets, diagnostics = self.capture_fixture("wordpress")
        text = body.decode()
        self.assertEqual(len(assets), 2)
        self.assertRegex(text, r'<img[^>]+src="/snapshots/snap_wordpress/asset/asset_002"')
        stylesheet = next(asset for asset in assets if asset["content_type"] == "text/css")
        css = (self.snapshot_root / stylesheet["file"]).read_text()
        self.assertIn("focus-within", css)
        self.assertEqual(diagnostics.as_record(len(assets))["failed"], 0)

    def test_asset_failures_and_limits_are_bounded_and_explained(self):
        body, _assets, diagnostics = self.capture_fixture(
            "static", failures={"assets/photo-large.svg"}
        )
        record = diagnostics.as_record(0)
        self.assertEqual(record["failed"], 1)
        failure = next(item for item in record["items"] if item["outcome"] == "failed")
        self.assertEqual(failure["stage"], "html_srcset")
        self.assertIn("timed out", failure["reason"])
        self.assertIn("https://fixture.test/assets/photo-large.svg", body.decode())

        with mock.patch.object(app, "MAX_ASSETS_PER_SNAPSHOT", 1):
            _body, _assets, limited = self.capture_fixture("static")
        limited_record = limited.as_record(0)
        self.assertGreater(limited_record["skipped"], 0)
        self.assertTrue(any(item["stage"] == "asset_limit" for item in limited_record["items"]))

    def test_legacy_frames_and_javascript_shell_have_repeatable_fixtures(self):
        frame_body = (FIXTURES / "frames" / "index.html").read_bytes()
        js_body = (FIXTURES / "javascript" / "index.html").read_bytes()
        self.assertEqual(app.first_frame_src(frame_body), "menu.html")
        self.assertTrue(app.needs_browser_render(js_body))
        decision = app.select_capture_engine(
            js_body, "text/html", browser_enabled=True
        )
        self.assertEqual(decision.engine_id, "playwright-browser-v1")

    def test_replay_routes_captured_links_and_disables_active_content(self):
        body = b"""<!doctype html><html><head></head><body>
        <a href="about.html">Captured</a><a href="https://outside.test/page">Outside</a>
        <form action="https://outside.test/submit"><input name="value"></form>
        <script src="/snapshots/snap_home/asset/asset_001"></script></body></html>"""
        page_map = {"https://fixture.test/about.html": "snap_about"}
        replay = app.prepare_html_replay(
            body, "https://fixture.test/index.html", "https://archive.test", page_map
        ).decode()
        self.assertIn("https://archive.test/snapshots/snap_about/content", replay)
        self.assertIn('target="_blank"', replay)
        self.assertIn('rel="noopener noreferrer external"', replay)
        self.assertIn('action="about:blank"', replay)
        self.assertRegex(replay, r"<form[^>]+\binert>")
        self.assertIn('type="application/x-websnapshot-disabled"', replay)
        self.assertIn("script-src 'none'", replay)
        self.assertIn('<base href="https://archive.test/">', replay)

    def test_replay_repairs_sydney_slider_and_navigation_without_scripts(self):
        body = b"""<!doctype html><html><head></head><body class="home wp-theme-sydney">
        <header id="masthead" class="site-header">
          <div class="btn-menu">Menu</div>
          <nav id="mainnav"><div><ul><li><a href="/">Home</a></li></ul></div></nav>
        </header>
        <div class="sydney-hero-area"><div class="header-slider"><div class="slides-container">
          <div class="slide-item" style="background-image:url('/snapshots/snap_home/asset/asset_001')">
            <img class="mobile-slide" src="/snapshots/snap_home/asset/asset_001">
            <div class="slide-inner">Archived introduction</div>
          </div>
        </div></div></div><script>window.initializeSydneySlider()</script></body></html>"""
        replay = app.prepare_html_replay(
            body, "https://fixture.test/", "https://archive.test"
        ).decode()
        self.assertIn(".sydney-hero-area:has(.header-slider .slide-item)", replay)
        self.assertIn("height:100svh!important", replay)
        self.assertIn("background-size:cover!important", replay)
        self.assertIn("#masthead .btn-menu{display:none!important}", replay)
        self.assertIn("#masthead #mainnav{display:block!important", replay)
        self.assertIn('type="application/x-websnapshot-disabled"', replay)

    def test_quality_report_detects_missing_local_and_remote_resources(self):
        body = (
            b'<link rel="stylesheet" href="https://cdn.test/site.css">'
            b'<img src="/snapshots/snap_test/asset/asset_missing">'
            b'<img alt="Application never supplied this image">'
        )
        report = replay_quality_report(body, [], self.snapshot_root)
        self.assertEqual(report["status"], "problems")
        self.assertEqual(report["missing_local_references"], ["asset_missing"])
        self.assertEqual(report["remote_dependency_count"], 1)
        self.assertEqual(report["images_without_source_count"], 1)
        self.assertEqual(
            report["images_without_source"], ["Application never supplied this image"]
        )

    def test_optional_screenshot_and_pdf_are_stored_as_capture_resources(self):
        assets = []
        diagnostics = CaptureDiagnostics()
        app.append_capture_evidence(
            assets,
            {"screenshot": b"png-fixture", "pdf": b"pdf-fixture"},
            "https://fixture.test/",
            diagnostics,
        )
        self.assertEqual(
            [(asset["id"], asset["content_type"]) for asset in assets],
            [
                ("evidence_screenshot", "image/png"),
                ("evidence_pdf", "application/pdf"),
            ],
        )
        self.assertTrue(all((self.snapshot_root / asset["file"]).is_file() for asset in assets))
        self.assertEqual(diagnostics.as_record(2)["captured"], 2)

    def test_diagnostic_urls_redact_query_values_and_credentials(self):
        self.assertEqual(
            diagnostic_url(
                "https://" + "user" + ":" + "secret" + "@example.test/image.png?token=secret&size=2"
            ),
            "https://example.test/image.png?token=redacted&size=redacted",
        )
        self.assertNotIn(
            "secret",
            safe_reason("Failed https://example.test/image.png?token=secret during fetch"),
        )


if __name__ == "__main__":
    unittest.main()
