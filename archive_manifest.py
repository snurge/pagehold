"""Signed local manifests for reproducible PageHold capture records."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from canonical_json import canonical_digest, canonicalize
from metadata_store import new_opaque_id


MANIFEST_SCHEMA = "pagehold.archive-manifest.v1"
ENVELOPE_SCHEMA = "pagehold.archive-manifest-envelope.v1"
IDENTITY_SCHEMA = "pagehold.archive-identity.v1"
SIGNING_CONTEXT = b"PAGEHOLD-ARCHIVE-MANIFEST-V1\x00"
MANIFEST_SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "archive-manifest.schema.json"


class ManifestError(RuntimeError):
    """Raised when an archive manifest is invalid or cannot be verified."""


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_b64url(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ManifestError("invalid base64url value") from exc


def _wire_time(value: str | None = None) -> str:
    if value:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        parsed = datetime.now(timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + _b64url(digest.digest())


def _safe_file(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ManifestError("archive path escapes its storage root") from exc
    if not candidate.is_file() or candidate.is_symlink():
        raise ManifestError(f"archive file is unavailable: {relative}")
    return candidate


def _schema() -> dict[str, Any]:
    return json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_manifest_payload(payload: Mapping[str, Any]) -> None:
    validator = Draft202012Validator(_schema(), format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(dict(payload)), key=lambda error: list(error.path))
    if errors:
        raise ManifestError(errors[0].message)


def verify_manifest_envelope(
    envelope: Mapping[str, Any], expected_key_id: str, public_key: bytes
) -> dict[str, Any]:
    if set(envelope) != {"schema", "algorithm", "key_id", "payload", "signature"}:
        raise ManifestError("manifest envelope fields are invalid")
    if envelope.get("schema") != ENVELOPE_SCHEMA or envelope.get("algorithm") != "Ed25519":
        raise ManifestError("manifest envelope version is unsupported")
    if envelope.get("key_id") != expected_key_id:
        raise ManifestError("manifest signing key does not match the archive identity")
    payload = envelope.get("payload")
    if not isinstance(payload, Mapping):
        raise ManifestError("manifest payload is invalid")
    validate_manifest_payload(payload)
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _decode_b64url(str(envelope.get("signature", ""))),
            SIGNING_CONTEXT + canonicalize(unsigned),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ManifestError("manifest signature verification failed") from exc
    return dict(payload)


class ArchiveIdentity:
    """Own the private Ed25519 key used only for local capture manifests."""

    def __init__(self, integrity_dir: str | Path):
        self.root = Path(integrity_dir)
        self.identity_path = self.root / "identity.json"
        self.private_key_path = self.root / "identity.key"

    def ensure(self, archive_id: str) -> dict[str, str]:
        if self.identity_path.exists() or self.private_key_path.exists():
            if not self.identity_path.is_file() or not self.private_key_path.is_file():
                raise ManifestError("archive identity is incomplete")
            identity = json.loads(self.identity_path.read_text(encoding="utf-8"))
            if identity.get("schema") != IDENTITY_SCHEMA or identity.get("archive_id") != archive_id:
                raise ManifestError("archive identity does not match this installation")
            private_key = self.private_key()
            derived = private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            if _b64url(derived) != identity.get("public_key"):
                raise ManifestError("archive identity key does not match its public record")
            return identity
        self.root.mkdir(parents=True, exist_ok=True)
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        identity = {
            "schema": IDENTITY_SCHEMA,
            "archive_id": archive_id,
            "key_id": new_opaque_id("key"),
            "algorithm": "Ed25519",
            "public_key": _b64url(public_bytes),
            "created_at": _wire_time(),
        }
        self._atomic_write(self.private_key_path, private_bytes, 0o600)
        self._atomic_write(
            self.identity_path,
            (json.dumps(identity, sort_keys=True, indent=2) + "\n").encode("utf-8"),
            0o600,
        )
        return identity

    def private_key(self) -> Ed25519PrivateKey:
        if self.private_key_path.is_symlink():
            raise ManifestError("archive identity key cannot be a symbolic link")
        body = self.private_key_path.read_bytes()
        if len(body) != 32:
            raise ManifestError("archive identity key has an invalid length")
        return Ed25519PrivateKey.from_private_bytes(body)

    @staticmethod
    def _atomic_write(path: Path, body: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            path.chmod(mode)
        finally:
            temporary.unlink(missing_ok=True)


class ArchiveManifestManager:
    def __init__(self, integrity_dir: str | Path, snapshot_dir: str | Path):
        self.root = Path(integrity_dir)
        self.snapshot_dir = Path(snapshot_dir)
        self.manifest_dir = self.root / "manifests"
        self.identity = ArchiveIdentity(self.root)

    def create(
        self,
        profile: dict[str, Any],
        run: dict[str, Any],
        site: dict[str, Any],
        snapshots: list[dict[str, Any]],
    ) -> tuple[str, str, str]:
        if not snapshots:
            raise ManifestError("a completed capture manifest requires an archived page")
        identity = self.identity.ensure(profile["archive_id"])
        pages = []
        resources = []
        for snapshot in sorted(snapshots, key=lambda item: item["archive_page_id"]):
            page_path = _safe_file(self.snapshot_dir, snapshot["file"])
            asset_ids = []
            for asset in sorted(snapshot.get("assets", []), key=lambda item: item["resource_id"]):
                asset_path = _safe_file(self.snapshot_dir, asset["file"])
                asset_ids.append(asset["resource_id"])
                resources.append(
                    {
                        "id": asset["resource_id"],
                        "source_url": asset.get("source_url") or "",
                        "final_url": asset.get("final_url") or "",
                        "status": int(asset.get("status") or 0),
                        "content_type": asset.get("content_type") or "application/octet-stream",
                        "bytes": asset_path.stat().st_size,
                        "digest": _file_digest(asset_path),
                    }
                )
            pages.append(
                {
                    "id": snapshot["archive_page_id"],
                    "source_url": snapshot["source_url"],
                    "final_url": snapshot["final_url"],
                    "status": int(snapshot["status"]),
                    "content_type": snapshot["content_type"],
                    "bytes": page_path.stat().st_size,
                    "digest": _file_digest(page_path),
                    "resource_ids": asset_ids,
                }
            )
        entry_id = run.get("entry_snapshot_id") or snapshots[0]["id"]
        entry = next((item for item in snapshots if item["id"] == entry_id), snapshots[0])
        payload = {
            "schema": MANIFEST_SCHEMA,
            "format_version": "1.0",
            "manifest_id": run["manifest_id"],
            "archive_id": profile["archive_id"],
            "site_id": site["archive_site_id"],
            "capture_id": run["id"],
            "captured_at": _wire_time(run["started_at"]),
            "entry_page_id": entry["archive_page_id"],
            "pages": pages,
            "resources": sorted(resources, key=lambda item: item["id"]),
        }
        validate_manifest_payload(payload)
        unsigned = {
            "schema": ENVELOPE_SCHEMA,
            "algorithm": "Ed25519",
            "key_id": identity["key_id"],
            "payload": payload,
        }
        envelope = {
            **unsigned,
            "signature": _b64url(
                self.identity.private_key().sign(SIGNING_CONTEXT + canonicalize(unsigned))
            ),
        }
        relative = f"manifests/{run['id']}.json"
        ArchiveIdentity._atomic_write(
            self.root / relative,
            (json.dumps(envelope, sort_keys=True, indent=2) + "\n").encode("utf-8"),
            0o600,
        )
        return relative, canonical_digest(payload), _wire_time()

    def verify(self, relative_path: str) -> dict[str, Any]:
        path = _safe_file(self.root, relative_path)
        envelope = json.loads(path.read_text(encoding="utf-8"))
        identity = json.loads(self.identity.identity_path.read_text(encoding="utf-8"))
        return verify_manifest_envelope(
            envelope,
            identity["key_id"],
            _decode_b64url(identity["public_key"]),
        )
