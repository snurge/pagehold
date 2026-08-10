import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from archive_manifest import ArchiveManifestManager
from metadata_store import MetadataStore
from archive_backup import create_backup, inspect_data_dir, restore_backup, verify_backup
from tests.test_metadata_store import sample_document


class ArchiveBackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.store = MetadataStore(self.data / "websnapshot.sqlite3")
        self.store.initialize(sample_document)
        snapshot = self.data / "snapshots/site_test/snap_test.html"
        snapshot.parent.mkdir(parents=True)
        snapshot.write_text("<html>fixture</html>", encoding="utf-8")
        asset = self.data / "snapshots/site_test/snap_test_assets/asset_test.css"
        asset.parent.mkdir(parents=True)
        asset.write_text("body{}", encoding="utf-8")
        profile = self.data / "profiles/usr_test/avatar.png"
        profile.parent.mkdir(parents=True)
        profile.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
        document = self.store.load_document()
        run = self.store.list_capture_runs("site_test")[0]
        manager = ArchiveManifestManager(self.data / "integrity", self.data / "snapshots")
        manifest_path, manifest_digest, signed_at = manager.create(
            self.store.archive_profile(), run, document["sites"][0], document["snapshots"]
        )
        self.store.update_capture_run(
            run["id"],
            signed_at,
            manifest_path=manifest_path,
            manifest_digest=manifest_digest,
            signed_at=signed_at,
        )
        (self.data / "db.json").write_text("{}", encoding="utf-8")

    def test_create_verify_restore_and_integrity(self):
        archive = self.root / "archive-backup.tar.gz"
        source_identity = (self.data / "integrity/identity.json").read_bytes()
        source_key = (self.data / "integrity/identity.key").read_bytes()
        created = create_backup(self.data, archive)
        verified = verify_backup(archive)
        restored = restore_backup(archive, self.root / "restored")

        self.assertEqual(created["format"], "pagehold-backup-v1")
        self.assertEqual(verified["format"], created["format"])
        self.assertEqual(verified["identity"], created["identity"])
        self.assertTrue(verified["identity"]["non_expiring"])
        self.assertTrue(restored["integrity"]["ok"])
        self.assertEqual(restored["integrity"]["signed_manifests"], 1)
        self.assertEqual(restored["integrity"]["identity"], created["identity"])
        self.assertEqual(
            (self.root / "restored/integrity/identity.json").read_bytes(),
            source_identity,
        )
        self.assertEqual(
            (self.root / "restored/integrity/identity.key").read_bytes(),
            source_key,
        )
        self.assertEqual(
            (self.root / "restored/profiles/usr_test/avatar.png").read_bytes(),
            b"\x89PNG\r\n\x1a\nfixture",
        )
        self.assertTrue((self.root / "restored/db.json").is_file())
        self.assertEqual(os.stat(archive).st_mode & 0o777, 0o600)


    def test_restore_refuses_nonempty_target(self):
        archive = self.root / "archive-backup.tar.gz"
        create_backup(self.data, archive)
        target = self.root / "occupied"
        target.mkdir()
        (target / "keep.txt").write_text("do not overwrite", encoding="utf-8")
        with self.assertRaises(ValueError):
            restore_backup(archive, target)

    def test_backup_refuses_to_overwrite_existing_archive(self):
        archive = self.root / "existing.tar.gz"
        archive.write_text("keep", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            create_backup(self.data, archive)
        self.assertEqual(archive.read_text(encoding="utf-8"), "keep")

    def test_backup_refuses_symlink(self):
        target = self.root / "outside.txt"
        target.write_text("outside", encoding="utf-8")
        (self.data / "snapshots/link.txt").symlink_to(target)
        with self.assertRaises(ValueError):
            create_backup(self.data, self.root / "bad.tar.gz")

    def test_integrity_reports_missing_archive_file(self):
        (self.data / "snapshots/site_test/snap_test.html").unlink()
        result = inspect_data_dir(self.data)
        self.assertFalse(result["ok"])
        self.assertIn("site_test/snap_test.html", result["missing"])

    def test_integrity_rejects_metadata_path_escape(self):
        with sqlite3.connect(self.data / "websnapshot.sqlite3") as connection:
            connection.execute("UPDATE snapshots SET file = '../outside.html' WHERE id = 'snap_test'")
        result = inspect_data_dir(self.data)
        self.assertFalse(result["ok"])
        self.assertEqual(result["unsafe_metadata_paths"], ["../outside.html"])

    def test_backup_and_integrity_reject_mismatched_identity_key(self):
        other = ArchiveManifestManager(
            self.root / "other-integrity", self.data / "snapshots"
        )
        other.identity.ensure("archive_other123456789")
        (self.data / "integrity/identity.key").write_bytes(
            (self.root / "other-integrity/identity.key").read_bytes()
        )

        result = inspect_data_dir(self.data)

        self.assertFalse(result["ok"])
        self.assertFalse(result["identity"]["ok"])
        self.assertIn("does not match", result["identity"]["error"])
        with self.assertRaisesRegex(ValueError, "identity failed backup validation"):
            create_backup(self.data, self.root / "bad-identity.tar.gz")


if __name__ == "__main__":
    unittest.main()
