"""Immutable content-addressed asset storage and migration reporting."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Iterable


class ContentAddressedAssetStore:
    def __init__(self, snapshot_root: str | Path):
        self.snapshot_root = Path(snapshot_root).resolve()
        self.object_root = self.snapshot_root / "_objects" / "sha256"

    @staticmethod
    def digest_bytes(body: bytes) -> str:
        return hashlib.sha256(body).hexdigest()

    @staticmethod
    def digest_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def relative_path(self, digest: str) -> str:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("invalid SHA-256 digest")
        return f"_objects/sha256/{digest[:2]}/{digest}"

    def absolute_path(self, digest: str) -> Path:
        return self.snapshot_root / self.relative_path(digest)

    def put(self, body: bytes) -> tuple[str, str, bool]:
        digest = self.digest_bytes(body)
        target = self.absolute_path(digest)
        if target.is_symlink():
            raise ValueError("content-addressed object path must not be a symbolic link")
        if target.is_file():
            if target.stat().st_size != len(body) or self.digest_file(target) != digest:
                raise ValueError("content-addressed object does not match its digest")
            return self.relative_path(digest), digest, False
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{digest}.", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                pass
        finally:
            temporary.unlink(missing_ok=True)
        if self.digest_file(target) != digest:
            raise ValueError("content-addressed object failed verification")
        return self.relative_path(digest), digest, True

    def link_existing(self, source: str | Path) -> tuple[str, str, bool]:
        source = Path(source)
        if source.is_symlink():
            raise ValueError("asset source must not be a symbolic link")
        source = source.resolve()
        if self.snapshot_root not in source.parents or not source.is_file():
            raise ValueError("asset source must be a regular file beneath the snapshot root")
        digest = self.digest_file(source)
        target = self.absolute_path(digest)
        if target.is_symlink():
            raise ValueError("content-addressed object path must not be a symbolic link")
        if target.is_file():
            if self.digest_file(target) != digest:
                raise ValueError("content-addressed object does not match its digest")
            return self.relative_path(digest), digest, False
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(source, target)
        except FileExistsError:
            pass
        except OSError:
            return self.put(source.read_bytes())
        return self.relative_path(digest), digest, True

    def measure(self, assets: list[dict]) -> dict:
        logical_bytes = 0
        digest_sizes = {}
        references = Counter()
        missing = []
        for asset in assets:
            relative = asset.get("file") or ""
            path = (self.snapshot_root / relative).resolve()
            if self.snapshot_root not in path.parents or not path.is_file():
                missing.append(relative)
                continue
            size = path.stat().st_size
            digest = asset.get("content_digest") or self.digest_file(path)
            logical_bytes += size
            references[digest] += 1
            digest_sizes.setdefault(digest, size)
        unique_bytes = sum(digest_sizes.values())
        return {
            "references": sum(references.values()),
            "unique_objects": len(references),
            "logical_bytes": logical_bytes,
            "unique_bytes": unique_bytes,
            "potential_saved_bytes": logical_bytes - unique_bytes,
            "duplicate_references": sum(count - 1 for count in references.values()),
            "missing": sorted(missing),
        }

    def garbage_collection_report(
        self,
        assets: list[dict],
        protected_digests: Iterable[str] = (),
    ) -> dict:
        """Report unreferenced verified objects without changing storage."""

        references = Counter()
        expected_paths = set()
        metadata_mismatches = []
        for asset in assets:
            relative = str(asset.get("file") or "")
            digest = str(asset.get("content_digest") or "")
            if len(digest) == 64 and all(
                character in "0123456789abcdef" for character in digest
            ):
                references[digest] += 1
            if relative.startswith("_objects/sha256/"):
                parts = Path(relative).parts
                path_digest = parts[-1] if len(parts) == 4 else ""
                try:
                    expected = self.relative_path(path_digest)
                except ValueError:
                    metadata_mismatches.append(
                        {"file": relative, "reason": "invalid object path"}
                    )
                    continue
                if relative != expected:
                    metadata_mismatches.append(
                        {"file": relative, "reason": "non-canonical object path"}
                    )
                    continue
                expected_paths.add(relative)
                references[path_digest] += int(not digest)
                if digest and digest != path_digest:
                    metadata_mismatches.append(
                        {
                            "file": relative,
                            "reason": "metadata digest does not match object path",
                        }
                    )

        for digest in protected_digests:
            cleaned = str(digest)
            if len(cleaned) == 64 and all(
                character in "0123456789abcdef" for character in cleaned
            ):
                references[cleaned] += 1

        unsafe_entries = []
        invalid_objects = []
        verified_objects = {}
        if self.object_root.is_symlink():
            unsafe_entries.append(
                self.object_root.relative_to(self.snapshot_root).as_posix()
            )
        elif self.object_root.exists():
            for directory, directories, filenames in os.walk(
                self.object_root, topdown=True, followlinks=False
            ):
                directory_path = Path(directory)
                safe_directories = []
                for name in sorted(directories):
                    candidate = directory_path / name
                    if candidate.is_symlink():
                        unsafe_entries.append(
                            candidate.relative_to(self.snapshot_root).as_posix()
                        )
                    else:
                        safe_directories.append(name)
                directories[:] = safe_directories
                for name in sorted(filenames):
                    candidate = directory_path / name
                    relative = candidate.relative_to(self.snapshot_root).as_posix()
                    if candidate.is_symlink() or not candidate.is_file():
                        unsafe_entries.append(relative)
                        continue
                    object_parts = candidate.relative_to(self.object_root).parts
                    digest = object_parts[-1] if len(object_parts) == 2 else ""
                    if (
                        len(object_parts) != 2
                        or object_parts[0] != digest[:2]
                    ):
                        invalid_objects.append(
                            {"file": relative, "reason": "invalid object path"}
                        )
                        continue
                    try:
                        canonical = self.relative_path(digest)
                    except ValueError:
                        invalid_objects.append(
                            {"file": relative, "reason": "invalid object digest"}
                        )
                        continue
                    if relative != canonical:
                        invalid_objects.append(
                            {"file": relative, "reason": "non-canonical object path"}
                        )
                        continue
                    size = candidate.stat().st_size
                    if self.digest_file(candidate) != digest:
                        invalid_objects.append(
                            {"file": relative, "reason": "content digest mismatch"}
                        )
                        continue
                    verified_objects[digest] = {
                        "file": relative,
                        "digest": digest,
                        "bytes": size,
                        "link_count": candidate.stat().st_nlink,
                    }

        missing_referenced = sorted(
            relative
            for relative in expected_paths
            if not (self.snapshot_root / relative).is_file()
        )
        candidates = [
            value
            for digest, value in verified_objects.items()
            if digest not in references
        ]
        candidates.sort(key=lambda item: item["file"])
        shared_link_candidates = [
            item for item in candidates if item["link_count"] > 1
        ]
        reclaimable = [
            item for item in candidates if item["link_count"] == 1
        ]
        protected = [
            value
            for digest, value in verified_objects.items()
            if digest in references
        ]
        return {
            "ok": not (
                unsafe_entries
                or invalid_objects
                or metadata_mismatches
                or missing_referenced
            ),
            "dry_run": True,
            "deletion_supported": False,
            "scanned_objects": len(verified_objects),
            "protected_objects": len(protected),
            "protected_references": sum(references.values()),
            "candidate_objects": len(candidates),
            "candidate_logical_bytes": sum(item["bytes"] for item in candidates),
            "potential_reclaimable_bytes": sum(
                item["bytes"] for item in reclaimable
            ),
            "shared_link_candidates": len(shared_link_candidates),
            "shared_link_bytes": sum(
                item["bytes"] for item in shared_link_candidates
            ),
            "candidates": candidates,
            "invalid_objects": sorted(
                invalid_objects, key=lambda item: item["file"]
            ),
            "unsafe_entries": sorted(unsafe_entries),
            "metadata_mismatches": sorted(
                metadata_mismatches, key=lambda item: item["file"]
            ),
            "missing_referenced_objects": missing_referenced,
        }
