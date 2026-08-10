import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from capture_engine import (
    AUTOMATIC_POLICY_VERSION,
    BROWSER_ENGINE_ID,
    CAPTURE_ENGINE_CONTRACT,
    NATIVE_ENGINE_ID,
    browser_render_reason,
    clear_stale_capture_work,
    run_browser_worker,
    select_capture_engine,
)
from capture_quality import CaptureDiagnostics


class CaptureEnginePolicyTests(unittest.TestCase):
    def test_static_server_rendered_page_uses_lightweight_engine(self):
        body = b"<html><head><title>Archive</title></head><body><h1>Useful page</h1></body></html>"
        decision = select_capture_engine(
            body,
            "text/html; charset=utf-8",
            browser_enabled=True,
        )
        self.assertEqual(decision.engine_id, NATIVE_ENGINE_ID)
        self.assertFalse(decision.browser_required)

    def test_client_application_shell_automatically_uses_browser(self):
        body = (
            b'<html><body><div id="root"></div>'
            b'<script type="module" src="/app.js"></script></body></html>'
        )
        self.assertEqual(browser_render_reason(body), "page contains an empty application root")
        decision = select_capture_engine(body, "text/html", browser_enabled=True)
        self.assertEqual(decision.engine_id, BROWSER_ENGINE_ID)
        self.assertTrue(decision.browser_required)
        self.assertEqual(decision.policy_version, AUTOMATIC_POLICY_VERSION)

    def test_archived_and_non_html_responses_never_start_browser(self):
        archived = select_capture_engine(
            b'<div id="root"></div>',
            "text/html",
            browser_enabled=True,
            archived_source=True,
        )
        binary = select_capture_engine(
            b"\x89PNG\r\n",
            "image/png",
            browser_enabled=True,
        )
        self.assertEqual(archived.engine_id, NATIVE_ENGINE_ID)
        self.assertEqual(binary.engine_id, NATIVE_ENGINE_ID)

    def test_disabled_browser_retains_lightweight_capture_with_reason(self):
        body = b'<html><body><main id="app"></main></body></html>'
        decision = select_capture_engine(body, "text/html", browser_enabled=False)
        self.assertEqual(decision.engine_id, NATIVE_ENGINE_ID)
        self.assertIn("unavailable", decision.reason)

    def test_unknown_policy_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Unsupported capture-engine policy"):
            select_capture_engine(
                b"<html></html>",
                "text/html",
                browser_enabled=True,
                policy_version="automatic-v99",
            )

    def test_worker_contract_is_isolated_and_validated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "worker.py"
            worker.write_text(
                textwrap.dedent(
                    f"""
                    import json
                    import os
                    import pathlib
                    import sys

                    if "WEBSNAPSHOT_SECRET" in os.environ:
                        raise SystemExit("secret environment leaked")
                    request = json.loads(pathlib.Path(sys.argv[1]).read_text())
                    output = pathlib.Path(sys.argv[2])
                    (output / "body.bin").write_bytes(b"<html>rendered</html>")
                    (output / "result.json").write_text(json.dumps({{
                        "contract": {CAPTURE_ENGINE_CONTRACT!r},
                        "engine_id": {BROWSER_ENGINE_ID!r},
                        "final_url": request["url"],
                        "status": 200,
                        "content_type": "text/html; charset=utf-8",
                        "evidence": [],
                        "diagnostics": {{
                            "browser_rendered": True,
                            "counts": {{"warning": 1, "warning_browser_wait": 1}},
                            "items": [{{
                                "outcome": "warning",
                                "stage": "browser_wait",
                                "reason": "fixture warning"
                            }}]
                        }}
                    }}))
                    """
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"WEBSNAPSHOT_SECRET": "must-not-leak"}):
                result = run_browser_worker(
                    worker_script=worker,
                    work_root=root / "work",
                    url="https://example.test/",
                    timeout_ms=5_000,
                    wait_ms=0,
                    user_agent="WebSnapshot test",
                    ignore_https_errors=False,
                    allow_private_networks=False,
                    max_capture_bytes=1024,
                )
        final_url, status, content_type, body, evidence, diagnostics = result
        self.assertEqual(final_url, "https://example.test/")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body, b"<html>rendered</html>")
        self.assertEqual(evidence, {})
        self.assertTrue(diagnostics["browser_rendered"])

    def test_stale_worker_exchanges_are_removed_only_inside_work_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "capture-work"
            stale = work / "capture-stale"
            stale.mkdir(parents=True)
            (stale / "body.bin").write_bytes(b"transient")
            outside = root / "archive.html"
            outside.write_bytes(b"preserve")
            self.assertEqual(clear_stale_capture_work(work), 1)
            self.assertTrue(work.is_dir())
            self.assertEqual(list(work.iterdir()), [])
            self.assertEqual(outside.read_bytes(), b"preserve")

    def test_worker_diagnostics_merge_without_duplicate_totals(self):
        diagnostics = CaptureDiagnostics()
        diagnostics.set_engine(
            BROWSER_ENGINE_ID,
            "client application shell",
            AUTOMATIC_POLICY_VERSION,
        )
        diagnostics.merge_record(
            {
                "browser_rendered": True,
                "counts": {"warning": 1, "warning_browser_wait": 1},
                "items": [
                    {
                        "outcome": "warning",
                        "stage": "browser_wait",
                        "reason": "fixture warning",
                    }
                ],
            }
        )
        record = diagnostics.as_record(3)
        self.assertEqual(record["engine_id"], BROWSER_ENGINE_ID)
        self.assertEqual(record["engine_policy_version"], AUTOMATIC_POLICY_VERSION)
        self.assertTrue(record["browser_rendered"])
        self.assertEqual(record["warnings"], 1)
        self.assertEqual(record["asset_count"], 3)


if __name__ == "__main__":
    unittest.main()
