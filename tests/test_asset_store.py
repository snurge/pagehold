import os
import tempfile
import unittest
from pathlib import Path

from asset_store import ContentAddressedAssetStore


class ContentAddressedAssetStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = ContentAddressedAssetStore(self.root)

    def test_put_reuses_verified_immutable_object(self):
        first_path, digest, first_created = self.store.put(b"shared bytes")
        second_path, second_digest, second_created = self.store.put(b"shared bytes")
        self.assertTrue(first_created)
        self.assertFalse(second_created)
        self.assertEqual((first_path, digest), (second_path, second_digest))
        self.assertEqual((self.root / first_path).read_bytes(), b"shared bytes")

    def test_existing_asset_is_hard_linked_without_removing_legacy_path(self):
        legacy = self.root / "site" / "asset.css"
        legacy.parent.mkdir()
        legacy.write_bytes(b"body { color: black; }")
        relative, digest, created = self.store.link_existing(legacy)
        self.assertTrue(created)
        self.assertTrue(legacy.is_file())
        self.assertEqual((self.root / relative).read_bytes(), legacy.read_bytes())
        if os.name != "nt":
            self.assertEqual((self.root / relative).stat().st_ino, legacy.stat().st_ino)
        self.assertEqual(digest, self.store.digest_file(legacy))

    def test_measure_reports_real_duplicate_saving(self):
        one = self.root / "one.bin"
        two = self.root / "two.bin"
        three = self.root / "three.bin"
        one.write_bytes(b"duplicate")
        two.write_bytes(b"duplicate")
        three.write_bytes(b"unique")
        report = self.store.measure(
            [{"file": "one.bin"}, {"file": "two.bin"}, {"file": "three.bin"}]
        )
        self.assertEqual(report["references"], 3)
        self.assertEqual(report["unique_objects"], 2)
        self.assertEqual(report["duplicate_references"], 1)
        self.assertEqual(report["potential_saved_bytes"], len(b"duplicate"))

    def test_invalid_or_missing_source_fails_closed(self):
        with self.assertRaises(ValueError):
            self.store.link_existing(self.root.parent / "outside")

    def test_symbolic_link_source_is_rejected(self):
        source = self.root / "source"
        source.write_bytes(b"body")
        link = self.root / "link"
        link.symlink_to(source)
        with self.assertRaises(ValueError):
            self.store.link_existing(link)

    def test_gc_report_protects_references_and_lists_verified_candidates(self):
        referenced_path, referenced_digest, _ = self.store.put(b"referenced")
        orphan_path, orphan_digest, _ = self.store.put(b"orphan")

        report = self.store.garbage_collection_report(
            [{"file": referenced_path, "content_digest": referenced_digest}]
        )

        self.assertTrue(report["ok"])
        self.assertTrue(report["dry_run"])
        self.assertFalse(report["deletion_supported"])
        self.assertEqual(report["scanned_objects"], 2)
        self.assertEqual(report["protected_objects"], 1)
        self.assertEqual(report["candidate_objects"], 1)
        self.assertEqual(report["candidates"][0]["digest"], orphan_digest)
        self.assertEqual(
            (self.root / orphan_path).read_bytes(), b"orphan"
        )

    def test_gc_report_protects_signed_manifest_digests(self):
        _, digest, _ = self.store.put(b"manifest-only")

        report = self.store.garbage_collection_report([], {digest})

        self.assertTrue(report["ok"])
        self.assertEqual(report["protected_objects"], 1)
        self.assertEqual(report["candidate_objects"], 0)

    def test_gc_report_does_not_claim_hard_link_bytes_are_reclaimable(self):
        object_path, digest, _ = self.store.put(b"shared-link")
        legacy = self.root / "legacy.bin"
        os.link(self.root / object_path, legacy)

        report = self.store.garbage_collection_report([])

        self.assertEqual(report["candidate_objects"], 1)
        self.assertEqual(report["candidates"][0]["digest"], digest)
        self.assertEqual(report["shared_link_candidates"], 1)
        self.assertEqual(report["potential_reclaimable_bytes"], 0)

    def test_gc_report_fails_closed_for_corrupt_or_unsafe_objects(self):
        object_path, _, _ = self.store.put(b"original")
        (self.root / object_path).write_bytes(b"tampered")
        unsafe = self.store.object_root / "unsafe"
        unsafe.symlink_to(self.root)

        report = self.store.garbage_collection_report([])

        self.assertFalse(report["ok"])
        self.assertEqual(report["candidate_objects"], 0)
        self.assertEqual(report["invalid_objects"][0]["reason"], "content digest mismatch")
        self.assertIn("_objects/sha256/unsafe", report["unsafe_entries"])


if __name__ == "__main__":
    unittest.main()
