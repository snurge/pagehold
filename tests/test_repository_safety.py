import hashlib
import importlib.util
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts" / "check-staged.py"
SPEC = importlib.util.spec_from_file_location("check_staged", CHECKER_PATH)
CHECK_STAGED = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(CHECK_STAGED)


class RepositorySafetyTests(unittest.TestCase):
    def test_release_dependencies_are_pinned_and_documented(self):
        required = {}
        for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                package, version = line.split("==", 1)
                required[package] = version
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        for package in required:
            self.assertIn(package, notices)

    def test_agpl_license_text_is_unmodified(self):
        license_bytes = (ROOT / "LICENSE").read_bytes()
        self.assertEqual(
            hashlib.sha256(license_bytes).hexdigest(),
            "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0",
        )
        self.assertIn(b"GNU AFFERO GENERAL PUBLIC LICENSE", license_bytes)
        for name in ("README.md", "ROADMAP.md", "DECISIONS.md"):
            self.assertIn(
                "AGPL-3.0-only",
                (ROOT / name).read_text(encoding="utf-8"),
            )

    def test_private_runtime_paths_are_rejected_by_staged_guard(self):
        forbidden = (
            "data/db.json",
            "data/websnapshot.sqlite3",
            "data/snapshots/example.html",
            "nested/credentials/account.json",
            "browser-data/profile/Cookies",
            ".env",
            "archive.warc.gz",
            "state.sqlite-wal",
            "signing.pem",
        )
        for path in forbidden:
            with self.subTest(path=path):
                self.assertIsNotNone(CHECK_STAGED.forbidden_path_reason(path))

    def test_high_confidence_secret_patterns_are_detected(self):
        samples = (
            b"-----BEGIN " + b"PRIVATE KEY-----\nnot-a-real-key",
            b"ghp_" + (b"A" * 36),
            b"https://archive-user" + b":archive-pass@example.invalid/",
        )
        for sample in samples:
            self.assertTrue(
                any(pattern.search(sample) for pattern in CHECK_STAGED.SECRET_PATTERNS.values())
            )

    def test_gitignore_covers_private_storage(self):
        for path in (
            "data/websnapshot.sqlite3",
            "data/run/pagehold.log",
            ".venv/bin/python",
            ".env",
            "archive.warc",
            "signing.pem",
            "browser-data/profile/Cookies",
        ):
            result = subprocess.run(
                ("git", "check-ignore", "--quiet", "--no-index", path),
                cwd=ROOT,
                check=False,
            )
            self.assertEqual(0, result.returncode, path)

    def test_source_tree_contains_only_local_product_terms(self):
        forbidden_fragments = ("feder" + "ation", "coord" + "inator")
        for path in ROOT.rglob("*"):
            if not path.is_file() or any(part in {".git", ".venv", "data", "__pycache__"} for part in path.parts):
                continue
            if path.suffix.lower() in {".png", ".ico", ".woff", ".woff2"}:
                continue
            body = path.read_text(encoding="utf-8", errors="ignore").lower()
            for fragment in forbidden_fragments:
                self.assertNotIn(fragment, body, str(path.relative_to(ROOT)))


if __name__ == "__main__":
    unittest.main()
