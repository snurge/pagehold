import io
import gzip
import tarfile
import tempfile
import unittest
from pathlib import Path

from archive_portability import (
    export_capture,
    export_site,
    export_warc,
    read_capture,
    read_site,
    verify_capture,
    verify_site,
)


class ArchivePortabilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.snapshots = self.root / "snapshots"
        (self.snapshots / "site" / "assets").mkdir(parents=True)
        (self.snapshots / "site" / "page.html").write_bytes(
            b'<link rel="stylesheet" href="/snapshots/snap_old/asset/asset_001">'
        )
        (self.snapshots / "site" / "assets" / "style.css").write_bytes(b"body{color:black}")
        self.site = {"id": "site_old", "name": "Example", "url": "https://example.test/", "visibility": "public"}
        self.run = {
            "id": "capture_old",
            "site_id": "site_old",
            "status": "complete",
            "started_at": "2026-07-17T12:00:00+00:00",
            "entry_snapshot_id": "snap_old",
            "manifest_digest": "a" * 64,
        }
        self.pages = [
            {
                "id": "snap_old",
                "site_id": "site_old",
                "capture_run_id": "capture_old",
                "source_url": "https://example.test/",
                "final_url": "https://example.test/",
                "status": 200,
                "content_type": "text/html",
                "bytes": 1,
                "file": "site/page.html",
                "assets": [
                    {
                        "id": "asset_001",
                        "source_url": "https://example.test/style.css",
                        "final_url": "https://example.test/style.css",
                        "status": 200,
                        "content_type": "text/css",
                        "bytes": 17,
                        "file": "site/assets/style.css",
                    }
                ],
            }
        ]

    def test_export_is_self_verifying_and_contains_metadata_and_bytes(self):
        output = self.root / "capture.tar.gz"
        result = export_capture(self.snapshots, self.site, self.run, self.pages, output)
        self.assertTrue(result["ok"])
        verification = verify_capture(output)
        self.assertEqual(verification["pages"], 1)
        self.assertEqual(verification["site_url"], "https://example.test/")
        metadata, bodies = read_capture(output)
        self.assertEqual(metadata["capture_run"]["id"], "capture_old")
        self.assertIn("payload/pages/snap_old", bodies)
        with self.assertRaises(FileExistsError):
            export_capture(self.snapshots, self.site, self.run, self.pages, output)

    def test_unsafe_tar_member_is_rejected(self):
        output = self.root / "unsafe.tar.gz"
        with tarfile.open(output, "w:gz") as archive:
            info = tarfile.TarInfo("websnapshot-capture/../escape")
            body = b"bad"
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
        with self.assertRaises(ValueError):
            read_capture(output)

    def test_full_site_package_keeps_capture_groups_and_deduplicates_assets(self):
        second_page = {**self.pages[0], "id": "snap_second", "capture_run_id": "capture_second"}
        second_page["assets"] = [{**self.pages[0]["assets"][0], "id": "asset_second"}]
        second_run = {**self.run, "id": "capture_second", "entry_snapshot_id": "snap_second"}
        output = self.root / "site.tar.gz"
        result = export_site(
            self.snapshots,
            self.site,
            [self.run, second_run],
            [self.pages[0], second_page],
            output,
        )
        self.assertEqual(result["captures"], 2)
        self.assertEqual(verify_site(output)["pages"], 2)
        metadata, bodies = read_site(output)
        self.assertEqual(len(metadata["capture_runs"]), 2)
        asset_paths = {
            asset["package_path"]
            for page in metadata["snapshots"]
            for asset in page["assets"]
        }
        self.assertEqual(len(asset_paths), 1)
        self.assertEqual(len([path for path in bodies if path.startswith("payload/assets/")]), 1)

    def test_warc_export_contains_page_and_asset_response_records(self):
        output = self.root / "capture.warc.gz"
        result = export_warc(
            self.snapshots, self.site, self.run, self.pages, output
        )
        self.assertEqual(result["records"], 3)
        with gzip.open(output, "rb") as handle:
            body = handle.read()
        self.assertIn(b"WARC/1.1", body)
        self.assertIn(b"WARC-Type: warcinfo", body)
        self.assertEqual(body.count(b"WARC-Type: response"), 2)
        self.assertIn(b"WARC-Target-URI: https://example.test/", body)
        self.assertIn(b"body{color:black}", body)


if __name__ == "__main__":
    unittest.main()
