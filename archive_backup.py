"""Consistent PageHold backup, verification, restore, and integrity tools."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from archive_manifest import ArchiveManifestManager, ManifestError
from canonical_json import canonical_digest
from archive_lock import ArchiveDataLock


BACKUP_FORMAT = "pagehold-backup-v1"
BACKUP_ROOT = PurePosixPath("pagehold-backup")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _validate_identity_bodies(
    identity_body: bytes | None,
    key_body: bytes | None,
    expected_archive_id: str | None = None,
    required: bool = False,
) -> dict[str, Any]:
    if identity_body is None and key_body is None:
        if required:
            return {"ok": False, "present": False, "error": "archive identity is missing"}
        return {"ok": True, "present": False}
    if identity_body is None or key_body is None:
        return {"ok": False, "present": True, "error": "archive identity is incomplete"}
    try:
        identity = json.loads(identity_body.decode("utf-8"))
        if (
            identity.get("schema") != "pagehold.archive-identity.v1"
            or identity.get("algorithm") != "Ed25519"
        ):
            raise ValueError("archive identity format is invalid")
        if "expires_at" in identity or "rotate_at" in identity:
            raise ValueError("archive identity unexpectedly contains expiry metadata")
        if expected_archive_id and identity.get("archive_id") != expected_archive_id:
            raise ValueError("archive identity does not match SQLite metadata")
        private = Ed25519PrivateKey.from_private_bytes(
            key_body
        )
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if _decode_b64url(identity["public_key"]) != public:
            raise ValueError("archive private key does not match its public identity")
        if not identity.get("archive_id") or not identity.get("key_id"):
            raise ValueError("archive identity is missing a required identifier")
    except Exception as exc:
        return {"ok": False, "present": True, "error": str(exc)}
    return {
        "ok": True,
        "present": True,
        "archive_id": identity["archive_id"],
        "key_id": identity["key_id"],
        "public_key_sha256": hashlib.sha256(public).hexdigest(),
        "non_expiring": True,
    }


def _inspect_archive_identity(
    data_dir: Path,
    expected_archive_id: str | None = None,
    required: bool = False,
) -> dict[str, Any]:
    identity_path = data_dir / "integrity" / "identity.json"
    key_path = data_dir / "integrity" / "identity.key"
    if identity_path.is_symlink() or key_path.is_symlink():
        return {"ok": False, "present": True, "error": "archive identity file is a symbolic link"}
    identity_body = identity_path.read_bytes() if identity_path.is_file() else None
    key_body = key_path.read_bytes() if key_path.is_file() else None
    return _validate_identity_bodies(
        identity_body,
        key_body,
        expected_archive_id,
        required,
    )


def _copy_tree(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    destination.mkdir(parents=True, exist_ok=True)
    for item in sorted(source.rglob("*")):
        if item.is_symlink():
            raise ValueError(f"backup refuses symbolic link: {item}")
        relative = item.relative_to(source)
        target = destination / relative
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)
        else:
            raise ValueError(f"backup refuses special file: {item}")


def create_backup(data_dir: str | Path, output: str | Path) -> dict[str, Any]:
    data_dir = Path(data_dir).resolve()
    output = Path(output).expanduser().resolve()
    database = data_dir / "websnapshot.sqlite3"
    if not database.is_file():
        raise FileNotFoundError(f"SQLite metadata not found: {database}")
    if output == data_dir or data_dir in output.parents:
        raise ValueError("backup output must be outside the live data directory")
    if output.exists():
        raise FileExistsError(f"backup output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    lock = ArchiveDataLock(data_dir / ".archive.lock")
    with tempfile.TemporaryDirectory(prefix="websnapshot-backup-") as temporary:
        staging = Path(temporary) / str(BACKUP_ROOT)
        staging.mkdir(mode=0o700)
        with lock.exclusive():
            source = sqlite3.connect(database)
            target = sqlite3.connect(staging / "metadata.sqlite3")
            try:
                source.backup(target)
                try:
                    profile = target.execute(
                        """
                        SELECT archive_id,setup_complete
                        FROM archive_profile WHERE singleton=1
                        """
                    ).fetchone()
                except sqlite3.OperationalError:
                    profile = None
            finally:
                target.close()
                source.close()
            identity = _inspect_archive_identity(
                data_dir,
                profile[0] if profile else None,
                required=bool(profile and profile[1]),
            )
            if not identity["ok"]:
                raise ValueError(f"archive identity failed backup validation: {identity['error']}")
            _copy_tree(data_dir / "snapshots", staging / "snapshots")
            _copy_tree(data_dir / "integrity", staging / "integrity")
            _copy_tree(data_dir / "profiles", staging / "profiles")
            legacy = data_dir / "db.json"
            if legacy.is_file() and not legacy.is_symlink():
                shutil.copy2(legacy, staging / "legacy-db.json")

        files = []
        for path in sorted(item for item in staging.rglob("*") if item.is_file()):
            relative = path.relative_to(staging).as_posix()
            files.append({"path": relative, "bytes": path.stat().st_size, "sha256": _sha256(path)})
        manifest = {
            "format": BACKUP_FORMAT,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "identity": identity,
            "files": files,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
        temporary_output = output.with_name(f".{output.name}.tmp")
        try:
            with tarfile.open(temporary_output, "w:gz") as archive:
                archive.add(staging, arcname=str(BACKUP_ROOT), recursive=True)
            os.chmod(temporary_output, 0o600)
            temporary_output.replace(output)
        finally:
            temporary_output.unlink(missing_ok=True)
    return {**manifest, "archive": str(output), "archive_bytes": output.stat().st_size}


def _validated_members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    members = {}
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != str(BACKUP_ROOT):
            raise ValueError(f"unsafe backup member: {member.name}")
        if member.issym() or member.islnk() or member.isdev():
            raise ValueError(f"unsupported backup member: {member.name}")
        members[member.name] = member
    return members


def verify_backup(path: str | Path) -> dict[str, Any]:
    path = Path(path).expanduser().resolve()
    with tarfile.open(path, "r:gz") as archive:
        members = _validated_members(archive)
        manifest_name = str(BACKUP_ROOT / "manifest.json")
        manifest_member = members.get(manifest_name)
        if not manifest_member or not manifest_member.isfile():
            raise ValueError("backup manifest is missing")
        manifest_handle = archive.extractfile(manifest_member)
        if manifest_handle is None:
            raise ValueError("backup manifest is unreadable")
        manifest = json.load(manifest_handle)
        if manifest.get("format") != BACKUP_FORMAT:
            raise ValueError("unsupported backup format")
        expected_names = {str(BACKUP_ROOT / item["path"]) for item in manifest.get("files", [])}
        actual_names = {
            name for name, member in members.items()
            if member.isfile() and name != manifest_name
        }
        if actual_names != expected_names:
            raise ValueError("backup file list does not match its manifest")
        for item in manifest["files"]:
            member = members[str(BACKUP_ROOT / item["path"])]
            handle = archive.extractfile(member)
            if handle is None:
                raise ValueError(f"backup file is unreadable: {item['path']}")
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
            if size != item["bytes"] or digest.hexdigest() != item["sha256"]:
                raise ValueError(f"backup checksum mismatch: {item['path']}")
        identity_name = str(BACKUP_ROOT / "integrity" / "identity.json")
        key_name = str(BACKUP_ROOT / "integrity" / "identity.key")
        identity_handle = archive.extractfile(members[identity_name]) if identity_name in members else None
        key_handle = archive.extractfile(members[key_name]) if key_name in members else None
        identity = _validate_identity_bodies(
            identity_handle.read() if identity_handle else None,
            key_handle.read() if key_handle else None,
            required=bool(manifest.get("identity", {}).get("present")),
        )
        if not identity["ok"]:
            raise ValueError(f"backup archive identity is invalid: {identity['error']}")
        recorded_identity = manifest.get("identity")
        if recorded_identity is not None and identity != recorded_identity:
            raise ValueError("backup archive identity does not match its manifest")
    return {
        **manifest,
        "identity": identity,
        "archive": str(path),
        "archive_bytes": path.stat().st_size,
    }


def restore_backup(path: str | Path, target_data_dir: str | Path) -> dict[str, Any]:
    manifest = verify_backup(path)
    target = Path(target_data_dir).expanduser().resolve()
    if target.exists() and any(target.iterdir()):
        raise ValueError("restore target must be absent or empty")
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tarfile.open(Path(path).expanduser().resolve(), "r:gz") as archive:
        members = _validated_members(archive)
        for item in manifest["files"]:
            source_name = str(BACKUP_ROOT / item["path"])
            member = members[source_name]
            relative = PurePosixPath(item["path"])
            if relative == PurePosixPath("metadata.sqlite3"):
                relative = PurePosixPath("websnapshot.sqlite3")
            elif relative == PurePosixPath("legacy-db.json"):
                relative = PurePosixPath("db.json")
            destination = target.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            handle = archive.extractfile(member)
            if handle is None:
                raise ValueError(f"backup file is unreadable: {item['path']}")
            with destination.open("wb") as output:
                shutil.copyfileobj(handle, output)
            os.chmod(destination, 0o600)
    result = inspect_data_dir(target)
    if not result["ok"]:
        raise ValueError(f"restored data failed integrity checks: {result}")
    return {"target": str(target), "manifest": manifest, "integrity": result}


def inspect_data_dir(data_dir: str | Path) -> dict[str, Any]:
    data_dir = Path(data_dir).expanduser().resolve()
    database = data_dir / "websnapshot.sqlite3"
    if not database.is_file():
        return {"ok": False, "error": "metadata database is missing"}
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        profile = connection.execute(
            """
            SELECT archive_id,setup_complete
            FROM archive_profile WHERE singleton=1
            """
        ).fetchone()
        snapshot_rows = connection.execute("SELECT id, file FROM snapshots").fetchall()
        asset_rows = connection.execute("SELECT snapshot_id, id, file FROM snapshot_assets").fetchall()
        capture_rows = connection.execute(
            "SELECT id,manifest_path,manifest_digest FROM capture_runs"
        ).fetchall()
    finally:
        connection.close()
    identity = (
        _inspect_archive_identity(
            data_dir,
            profile[0],
            required=bool(profile[1]),
        )
        if profile
        else {"ok": False, "present": False, "error": "archive profile is missing"}
    )
    snapshot_root = data_dir / "snapshots"
    expected = set()
    unsafe = []
    for relative in [row[1] for row in snapshot_rows] + [row[2] for row in asset_rows]:
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            unsafe.append(str(relative))
        else:
            expected.add(candidate.as_posix())
    missing = sorted(relative for relative in expected if not (snapshot_root / relative).is_file())
    actual = {
        path.relative_to(snapshot_root).as_posix()
        for path in snapshot_root.rglob("*")
        if path.is_file() and not path.is_symlink()
    } if snapshot_root.exists() else set()
    orphaned = sorted(actual - expected)
    manifest_errors = []
    signed_manifests = 0
    manifest_manager = ArchiveManifestManager(data_dir / "integrity", snapshot_root)
    for run_id, manifest_path, expected_digest in capture_rows:
        if not manifest_path:
            continue
        try:
            payload = manifest_manager.verify(manifest_path)
            if canonical_digest(payload) != expected_digest:
                raise ManifestError("manifest payload digest does not match SQLite metadata")
        except Exception as exc:
            manifest_errors.append(f"{run_id}: {exc}")
        else:
            signed_manifests += 1
    return {
        "ok": (
            quick_check == "ok"
            and identity["ok"]
            and not missing
            and not unsafe
            and not manifest_errors
        ),
        "sqlite": quick_check,
        "identity": identity,
        "snapshots": len(snapshot_rows),
        "assets": len(asset_rows),
        "capture_runs": len(capture_rows),
        "signed_manifests": signed_manifests,
        "manifest_errors": manifest_errors,
        "missing": missing,
        "orphaned": orphaned,
        "unsafe_metadata_paths": sorted(unsafe),
    }
