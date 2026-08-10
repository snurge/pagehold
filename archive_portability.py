"""Self-verifying capture export packages."""

from __future__ import annotations

import hashlib
import gzip
import json
import os
import shutil
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from product import NAME as PRODUCT_NAME


FORMAT = "websnapshot-capture-v1"
ROOT = PurePosixPath("websnapshot-capture")
SITE_FORMAT = "websnapshot-site-v1"
SITE_ROOT = PurePosixPath("websnapshot-site")


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("unsafe package path")
    return path


def export_capture(
    snapshot_root: str | Path,
    site: dict,
    run: dict,
    snapshots: list[dict],
    output: str | Path,
) -> dict:
    snapshot_root = Path(snapshot_root).resolve()
    output = Path(output).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"capture export already exists: {output}")
    if not snapshots:
        raise ValueError("capture export requires at least one page")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="websnapshot-export-") as temporary:
        staging = Path(temporary) / str(ROOT)
        payload = staging / "payload"
        payload.mkdir(parents=True)
        exported_snapshots = []
        copied_assets = {}
        for snapshot in snapshots:
            source = (snapshot_root / snapshot["file"]).resolve()
            if snapshot_root not in source.parents or not source.is_file() or source.is_symlink():
                raise ValueError("snapshot page is unavailable or unsafe")
            page_path = f"payload/pages/{snapshot['id']}"
            page_target = staging / page_path
            page_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, page_target)
            exported_assets = []
            for asset in snapshot.get("assets", []):
                asset_source = (snapshot_root / asset["file"]).resolve()
                if snapshot_root not in asset_source.parents or not asset_source.is_file() or asset_source.is_symlink():
                    raise ValueError("snapshot asset is unavailable or unsafe")
                digest = asset.get("content_digest") or _digest(asset_source.read_bytes())
                asset_path = f"payload/assets/{digest}"
                if digest not in copied_assets:
                    target = staging / asset_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(asset_source, target)
                    copied_assets[digest] = asset_path
                exported_assets.append(
                    {
                        **{key: value for key, value in asset.items() if key != "file"},
                        "package_path": asset_path,
                        "content_digest": digest,
                    }
                )
            exported_snapshots.append(
                {
                    **{key: value for key, value in snapshot.items() if key not in {"file", "assets"}},
                    "package_path": page_path,
                    "assets": exported_assets,
                }
            )
        metadata = {
            "format": FORMAT,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "site": site,
            "capture_run": run,
            "snapshots": exported_snapshots,
        }
        (staging / "archive.json").write_text(
            json.dumps(metadata, sort_keys=True, indent=2), encoding="utf-8"
        )
        files = []
        for path in sorted(item for item in staging.rglob("*") if item.is_file()):
            relative = path.relative_to(staging).as_posix()
            body = path.read_bytes()
            files.append({"path": relative, "bytes": len(body), "sha256": _digest(body)})
        manifest = {"format": FORMAT, "files": files}
        (staging / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8"
        )
        temporary_output = output.with_name(f".{output.name}.tmp")
        try:
            with tarfile.open(temporary_output, "w:gz") as archive:
                archive.add(staging, arcname=str(ROOT), recursive=True)
            os.chmod(temporary_output, 0o600)
            temporary_output.replace(output)
        finally:
            temporary_output.unlink(missing_ok=True)
    return {"ok": True, "archive": str(output), "files": len(files), "bytes": output.stat().st_size}


def read_capture(path: str | Path) -> tuple[dict, dict[str, bytes]]:
    path = Path(path).expanduser().resolve()
    with tarfile.open(path, "r:gz") as archive:
        members = {}
        for member in archive.getmembers():
            member_path = PurePosixPath(member.name)
            if (
                member_path.is_absolute()
                or ".." in member_path.parts
                or not member_path.parts
                or member_path.parts[0] != str(ROOT)
                or member.issym()
                or member.islnk()
                or member.isdev()
            ):
                raise ValueError(f"unsafe capture package member: {member.name}")
            members[member.name] = member
        manifest_name = str(ROOT / "manifest.json")
        manifest_member = members.get(manifest_name)
        if not manifest_member or not manifest_member.isfile():
            raise ValueError("capture package manifest is missing")
        manifest = json.load(archive.extractfile(manifest_member))
        if manifest.get("format") != FORMAT:
            raise ValueError("unsupported capture package")
        expected = {str(ROOT / _safe_relative(item["path"])) for item in manifest["files"]}
        actual = {
            name for name, member in members.items()
            if member.isfile() and name != manifest_name
        }
        if actual != expected:
            raise ValueError("capture package file inventory mismatch")
        bodies = {}
        for item in manifest["files"]:
            relative = _safe_relative(item["path"]).as_posix()
            handle = archive.extractfile(members[str(ROOT / relative)])
            if handle is None:
                raise ValueError("capture package file is unreadable")
            body = handle.read()
            if len(body) != item["bytes"] or _digest(body) != item["sha256"]:
                raise ValueError(f"capture package checksum mismatch: {relative}")
            bodies[relative] = body
    metadata = json.loads(bodies["archive.json"])
    if metadata.get("format") != FORMAT:
        raise ValueError("capture metadata format mismatch")
    referenced = {
        snapshot["package_path"] for snapshot in metadata.get("snapshots", [])
    } | {
        asset["package_path"]
        for snapshot in metadata.get("snapshots", [])
        for asset in snapshot.get("assets", [])
    }
    if not referenced or not referenced.issubset(bodies):
        raise ValueError("capture metadata references missing payload files")
    return metadata, bodies


def verify_capture(path: str | Path) -> dict:
    metadata, bodies = read_capture(path)
    return {
        "ok": True,
        "archive": str(Path(path).expanduser().resolve()),
        "site_url": metadata["site"]["url"],
        "capture_started_at": metadata["capture_run"]["started_at"],
        "pages": len(metadata["snapshots"]),
        "files": len(bodies),
    }


def export_site(
    snapshot_root: str | Path,
    site: dict,
    runs: list[dict],
    snapshots: list[dict],
    output: str | Path,
) -> dict:
    snapshot_root = Path(snapshot_root).resolve()
    output = Path(output).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"site export already exists: {output}")
    completed_runs = [run for run in runs if run.get("status") != "running"]
    run_ids = {run["id"] for run in completed_runs}
    exported_pages = [
        snapshot for snapshot in snapshots
        if snapshot.get("capture_run_id") in run_ids
    ]
    if not completed_runs or not exported_pages:
        raise ValueError("site export requires at least one completed capture")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="websnapshot-site-export-") as temporary:
        staging = Path(temporary) / str(SITE_ROOT)
        (staging / "payload" / "pages").mkdir(parents=True)
        copied_assets: dict[str, str] = {}
        metadata_pages = []
        for snapshot in exported_pages:
            source = (snapshot_root / snapshot["file"]).resolve()
            if snapshot_root not in source.parents or not source.is_file() or source.is_symlink():
                raise ValueError("snapshot page is unavailable or unsafe")
            page_path = f"payload/pages/{snapshot['id']}"
            shutil.copyfile(source, staging / page_path)
            assets = []
            for asset in snapshot.get("assets", []):
                asset_source = (snapshot_root / asset["file"]).resolve()
                if snapshot_root not in asset_source.parents or not asset_source.is_file() or asset_source.is_symlink():
                    raise ValueError("snapshot asset is unavailable or unsafe")
                digest = asset.get("content_digest") or _digest(asset_source.read_bytes())
                asset_path = f"payload/assets/{digest}"
                if digest not in copied_assets:
                    target = staging / asset_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(asset_source, target)
                    copied_assets[digest] = asset_path
                assets.append(
                    {
                        **{key: value for key, value in asset.items() if key != "file"},
                        "package_path": asset_path,
                        "content_digest": digest,
                    }
                )
            metadata_pages.append(
                {
                    **{key: value for key, value in snapshot.items() if key not in {"file", "assets"}},
                    "package_path": page_path,
                    "assets": assets,
                }
            )
        metadata = {
            "format": SITE_FORMAT,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "site": site,
            "capture_runs": completed_runs,
            "snapshots": metadata_pages,
        }
        (staging / "archive.json").write_text(
            json.dumps(metadata, sort_keys=True, indent=2), encoding="utf-8"
        )
        files = []
        for path in sorted(item for item in staging.rglob("*") if item.is_file()):
            relative = path.relative_to(staging).as_posix()
            body = path.read_bytes()
            files.append({"path": relative, "bytes": len(body), "sha256": _digest(body)})
        (staging / "manifest.json").write_text(
            json.dumps({"format": SITE_FORMAT, "files": files}, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        temporary_output = output.with_name(f".{output.name}.tmp")
        try:
            with tarfile.open(temporary_output, "w:gz") as archive:
                archive.add(staging, arcname=str(SITE_ROOT), recursive=True)
            os.chmod(temporary_output, 0o600)
            temporary_output.replace(output)
        finally:
            temporary_output.unlink(missing_ok=True)
    return {
        "ok": True,
        "archive": str(output),
        "captures": len(completed_runs),
        "pages": len(metadata_pages),
        "files": len(files),
        "bytes": output.stat().st_size,
    }


def read_site(path: str | Path) -> tuple[dict, dict[str, bytes]]:
    path = Path(path).expanduser().resolve()
    with tarfile.open(path, "r:gz") as archive:
        members = {}
        for member in archive.getmembers():
            member_path = PurePosixPath(member.name)
            if (
                member_path.is_absolute()
                or ".." in member_path.parts
                or not member_path.parts
                or member_path.parts[0] != str(SITE_ROOT)
                or member.issym()
                or member.islnk()
                or member.isdev()
            ):
                raise ValueError(f"unsafe site package member: {member.name}")
            members[member.name] = member
        manifest_name = str(SITE_ROOT / "manifest.json")
        manifest_member = members.get(manifest_name)
        if not manifest_member or not manifest_member.isfile():
            raise ValueError("site package manifest is missing")
        manifest = json.load(archive.extractfile(manifest_member))
        if manifest.get("format") != SITE_FORMAT:
            raise ValueError("unsupported site package")
        expected = {str(SITE_ROOT / _safe_relative(item["path"])) for item in manifest["files"]}
        actual = {
            name for name, member in members.items()
            if member.isfile() and name != manifest_name
        }
        if actual != expected:
            raise ValueError("site package file inventory mismatch")
        bodies = {}
        for item in manifest["files"]:
            relative = _safe_relative(item["path"]).as_posix()
            handle = archive.extractfile(members[str(SITE_ROOT / relative)])
            if handle is None:
                raise ValueError("site package file is unreadable")
            body = handle.read()
            if len(body) != item["bytes"] or _digest(body) != item["sha256"]:
                raise ValueError(f"site package checksum mismatch: {relative}")
            bodies[relative] = body
    metadata = json.loads(bodies["archive.json"])
    if metadata.get("format") != SITE_FORMAT:
        raise ValueError("site metadata format mismatch")
    run_ids = {run["id"] for run in metadata.get("capture_runs", [])}
    snapshots = metadata.get("snapshots", [])
    if not run_ids or not snapshots or any(
        snapshot.get("capture_run_id") not in run_ids for snapshot in snapshots
    ):
        raise ValueError("site package capture relationships are invalid")
    referenced = {
        snapshot["package_path"] for snapshot in snapshots
    } | {
        asset["package_path"]
        for snapshot in snapshots
        for asset in snapshot.get("assets", [])
    }
    if not referenced.issubset(bodies):
        raise ValueError("site metadata references missing payload files")
    return metadata, bodies


def verify_site(path: str | Path) -> dict:
    metadata, bodies = read_site(path)
    return {
        "ok": True,
        "archive": str(Path(path).expanduser().resolve()),
        "site_url": metadata["site"]["url"],
        "captures": len(metadata["capture_runs"]),
        "pages": len(metadata["snapshots"]),
        "files": len(bodies),
    }


def _warc_record(record_type: str, target: str, date: str, content_type: str, body: bytes) -> bytes:
    record_id = f"<urn:uuid:{uuid.uuid4()}>"
    headers = [
        "WARC/1.1",
        f"WARC-Type: {record_type}",
        f"WARC-Record-ID: {record_id}",
        f"WARC-Date: {date}",
        f"WARC-Target-URI: {target}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "",
        "",
    ]
    return "\r\n".join(headers).encode("utf-8") + body + b"\r\n\r\n"


def export_warc(
    snapshot_root: str | Path,
    site: dict,
    run: dict,
    snapshots: list[dict],
    output: str | Path,
) -> dict:
    snapshot_root = Path(snapshot_root).resolve()
    output = Path(output).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"WARC export already exists: {output}")
    if not snapshots:
        raise ValueError("WARC export requires at least one page")
    output.parent.mkdir(parents=True, exist_ok=True)
    created = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    warcinfo = json.dumps(
        {"software": PRODUCT_NAME, "format": FORMAT, "site": site.get("url"), "capture": run.get("id")},
        sort_keys=True,
    ).encode("utf-8")
    records = [_warc_record("warcinfo", "urn:websnapshot:export", created, "application/json", warcinfo)]
    seen_assets: set[tuple[str, str]] = set()
    for snapshot in snapshots:
        source = (snapshot_root / snapshot["file"]).resolve()
        if snapshot_root not in source.parents or not source.is_file() or source.is_symlink():
            raise ValueError("snapshot page is unavailable or unsafe")
        body = source.read_bytes()
        http_body = (
            f"HTTP/1.1 {int(snapshot.get('status') or 200)} Archived\r\n"
            f"Content-Type: {snapshot.get('content_type') or 'application/octet-stream'}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii", "replace") + body
        date = str(snapshot.get("created_at") or run.get("started_at") or created).replace("+00:00", "Z")
        records.append(_warc_record("response", snapshot.get("final_url") or snapshot["source_url"], date, "application/http; msgtype=response", http_body))
        for asset in snapshot.get("assets", []):
            asset_source = (snapshot_root / asset["file"]).resolve()
            if snapshot_root not in asset_source.parents or not asset_source.is_file() or asset_source.is_symlink():
                raise ValueError("snapshot asset is unavailable or unsafe")
            asset_body = asset_source.read_bytes()
            identity = (asset.get("final_url") or asset.get("source_url") or "urn:websnapshot:asset", _digest(asset_body))
            if identity in seen_assets:
                continue
            seen_assets.add(identity)
            http_asset = (
                f"HTTP/1.1 {int(asset.get('status') or 200)} Archived\r\n"
                f"Content-Type: {asset.get('content_type') or 'application/octet-stream'}\r\n"
                f"Content-Length: {len(asset_body)}\r\n\r\n"
            ).encode("ascii", "replace") + asset_body
            records.append(_warc_record("response", identity[0], date, "application/http; msgtype=response", http_asset))
    temporary_output = output.with_name(f".{output.name}.tmp")
    try:
        with temporary_output.open("wb") as handle:
            for record in records:
                handle.write(gzip.compress(record, mtime=0))
        os.chmod(temporary_output, 0o600)
        temporary_output.replace(output)
    finally:
        temporary_output.unlink(missing_ok=True)
    return {"ok": True, "archive": str(output), "records": len(records), "bytes": output.stat().st_size}
