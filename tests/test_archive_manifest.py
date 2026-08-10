import json
import tempfile
import unittest
from pathlib import Path

from archive_manifest import ArchiveManifestManager, ManifestError
from metadata_store import MetadataStore
from tests.test_metadata_store import sample_document


class ArchiveManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.snapshot_root = self.root / "snapshots"
        self.snapshot_root.mkdir()
        self.store = MetadataStore(self.root / "websnapshot.sqlite3")
        self.store.initialize(sample_document)
        document = self.store.load_document()
        self.site = document["sites"][0]
        self.snapshot = document["snapshots"][0]
        page_path = self.snapshot_root / self.snapshot["file"]
        page_path.parent.mkdir(parents=True)
        page_path.write_bytes(b"<html><link href='style.css'></html>")
        asset_path = self.snapshot_root / self.snapshot["assets"][0]["file"]
        asset_path.parent.mkdir(parents=True)
        asset_path.write_bytes(b"body { color: black; }")
        self.run = self.store.list_capture_runs("site_test")[0]
        self.manager = ArchiveManifestManager(self.root / "integrity", self.snapshot_root)

    def create_manifest(self):
        return self.manager.create(
            self.store.archive_profile(), self.run, self.site, [self.snapshot]
        )

    def test_manifest_is_signed_with_stable_local_archive_ids(self):
        relative, digest, _ = self.create_manifest()
        payload = self.manager.verify(relative)
        self.assertEqual(payload["capture_id"], self.run["id"])
        self.assertEqual(payload["site_id"], self.site["archive_site_id"])
        self.assertEqual(payload["entry_page_id"], self.snapshot["archive_page_id"])
        self.assertEqual(
            payload["resources"][0]["id"],
            self.snapshot["assets"][0]["resource_id"],
        )
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(
            (self.root / "integrity" / "identity.key").stat().st_mode & 0o777,
            0o600,
        )

    def test_manifest_tampering_is_rejected(self):
        relative, _, _ = self.create_manifest()
        path = self.root / "integrity" / relative
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["payload"]["pages"][0]["bytes"] += 1
        path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(ManifestError):
            self.manager.verify(relative)

    def test_archive_identity_is_stable_and_cannot_be_rebound(self):
        profile = self.store.archive_profile()
        first = self.manager.identity.ensure(profile["archive_id"])
        private_key = (self.root / "integrity" / "identity.key").read_bytes()
        self.assertEqual(self.manager.identity.ensure(profile["archive_id"]), first)
        self.assertEqual(
            (self.root / "integrity" / "identity.key").read_bytes(), private_key
        )
        with self.assertRaises(ManifestError):
            self.manager.identity.ensure("archive_abcdefghijklmnop")


if __name__ == "__main__":
    unittest.main()
