import tempfile
import sqlite3
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import app
import websnapshot_admin
from archive_manifest import ArchiveManifestManager
from archive_portability import export_capture, export_site
from asset_store import ContentAddressedAssetStore
from metadata_store import MetadataStore, StorageQuotaExceeded
from archive_lock import ArchiveDataLock
from tests.test_metadata_store import sample_document


class ArchiveImportTests(unittest.TestCase):
    def test_import_creates_private_capture_with_fresh_ids_and_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            (source_root / "site" / "assets").mkdir(parents=True)
            (source_root / "site" / "page.html").write_bytes(
                b'<img src="/snapshots/snap_source/asset/asset_001">'
            )
            (source_root / "site" / "assets" / "image.bin").write_bytes(b"image")
            package = root / "capture.tar.gz"
            export_capture(
                source_root,
                {"id": "site_source", "name": "Source", "url": "https://source.test/", "visibility": "public"},
                {
                    "id": "capture_source",
                    "site_id": "site_source",
                    "status": "complete",
                    "started_at": "2020-01-02T03:04:05+00:00",
                    "entry_snapshot_id": "snap_source",
                },
                [
                    {
                        "id": "snap_source",
                        "site_id": "site_source",
                        "capture_run_id": "capture_source",
                        "source_url": "https://source.test/",
                        "final_url": "https://source.test/",
                        "status": 200,
                        "content_type": "text/html",
                        "bytes": 1,
                        "file": "site/page.html",
                        "created_at": "2020-01-02T03:04:05+00:00",
                        "assets": [
                            {
                                "id": "asset_001",
                                "source_url": "https://source.test/image.bin",
                                "final_url": "https://source.test/image.bin",
                                "status": 200,
                                "content_type": "application/octet-stream",
                                "bytes": 5,
                                "file": "site/assets/image.bin",
                            }
                        ],
                    }
                ],
                package,
            )
            site_package = root / "site.tar.gz"
            source_site = {
                "id": "site_source",
                "name": "Source",
                "url": "https://source.test/",
                "visibility": "public",
            }
            source_page = {
                "id": "snap_source",
                "site_id": "site_source",
                "capture_run_id": "capture_source",
                "source_url": "https://source.test/",
                "final_url": "https://source.test/",
                "status": 200,
                "content_type": "text/html",
                "bytes": 1,
                "file": "site/page.html",
                "created_at": "2020-01-02T03:04:05+00:00",
                "assets": [
                    {
                        "id": "asset_001",
                        "source_url": "https://source.test/image.bin",
                        "final_url": "https://source.test/image.bin",
                        "status": 200,
                        "content_type": "application/octet-stream",
                        "bytes": 5,
                        "file": "site/assets/image.bin",
                    }
                ],
            }
            second_page = {
                **source_page,
                "id": "snap_source_second",
                "capture_run_id": "capture_source_second",
                "created_at": "2021-01-02T03:04:05+00:00",
            }
            export_site(
                source_root,
                source_site,
                [
                    {
                        "id": "capture_source",
                        "site_id": "site_source",
                        "status": "complete",
                        "started_at": "2020-01-02T03:04:05+00:00",
                        "entry_snapshot_id": "snap_source",
                    },
                    {
                        "id": "capture_source_second",
                        "site_id": "site_source",
                        "status": "complete",
                        "started_at": "2021-01-02T03:04:05+00:00",
                        "entry_snapshot_id": "snap_source_second",
                    },
                ],
                [source_page, second_page],
                site_package,
            )

            data = root / "target"
            snapshots = data / "snapshots"
            snapshots.mkdir(parents=True)
            database = data / "websnapshot.sqlite3"
            store = MetadataStore(database)
            store.initialize(sample_document)
            patches = {
                "DATA_DIR": data,
                "SNAPSHOT_DIR": snapshots,
                "DB_PATH": database,
                "METADATA_STORE": store,
                "DATA_LOCK": ArchiveDataLock(data / ".archive.lock"),
                "ASSET_STORE": ContentAddressedAssetStore(snapshots),
                "MANIFEST_MANAGER": ArchiveManifestManager(data / "integrity", snapshots),
            }
            with ExitStack() as stack:
                for name, value in patches.items():
                    stack.enter_context(mock.patch.object(app, name, value))
                result = websnapshot_admin.import_capture_package(
                    package, "owner@example.test"
                )
                site_result = websnapshot_admin.import_site_package(
                    site_package, "owner@example.test"
                )
                used = store.storage_quota("usr_test")["used_bytes"]
                with sqlite3.connect(database) as connection:
                    connection.execute(
                        "INSERT INTO user_storage_quotas VALUES (?,?,80,datetime('now'),?)",
                        ("usr_test", used, "usr_test"),
                    )
                site_count = len(store.load_document()["sites"])
                with self.assertRaises(StorageQuotaExceeded):
                    websnapshot_admin.import_capture_package(
                        package, "owner@example.test"
                    )
                self.assertEqual(len(store.load_document()["sites"]), site_count)

            document = store.load_document()
            imported_site = next(site for site in document["sites"] if site["id"] == result["site_id"])
            imported_page = next(
                page for page in document["snapshots"]
                if page.get("capture_run_id") == result["capture_id"]
            )
            run = store.get_capture_run(result["capture_id"])
            imported_site_runs = store.list_capture_runs(site_result["site_id"], 10)
            self.assertEqual(imported_site["visibility"], "private")
            self.assertNotEqual(imported_page["id"], "snap_source")
            body = (snapshots / imported_page["file"]).read_bytes()
            self.assertIn(f"/snapshots/{imported_page['id']}/asset/".encode(), body)
            self.assertTrue(run["manifest_digest"])
            self.assertEqual(run["started_at"], "2020-01-02T03:04:05+00:00")
            self.assertEqual(site_result["captures"], 2)
            self.assertEqual(len(imported_site_runs), 2)
            self.assertEqual(
                {item["started_at"] for item in imported_site_runs},
                {"2020-01-02T03:04:05+00:00", "2021-01-02T03:04:05+00:00"},
            )
            self.assertEqual(
                len([site for site in document["sites"] if site["id"] == site_result["site_id"]]),
                1,
            )


if __name__ == "__main__":
    unittest.main()
