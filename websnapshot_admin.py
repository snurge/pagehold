#!/usr/bin/env python3
"""Local CLI for backups, integrity checks, exports, and account recovery."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import app
from archive_portability import (
    export_capture,
    export_site,
    export_warc,
    read_capture,
    read_site,
    verify_capture,
    verify_site,
)
from asset_store import ContentAddressedAssetStore
from archive_manifest import ArchiveIdentity, ArchiveManifestManager
from archive_backup import create_backup, inspect_data_dir, restore_backup, verify_backup
from product import NAME as PRODUCT_NAME


def require_strong_password(password: str) -> None:
    if len(password) < 12 or len(password) > 256:
        raise ValueError("password must be between 12 and 256 characters")
    if password.lower() in {"admin123", "password", "password123", "websnapshot"}:
        raise ValueError("password is too common")


def set_password(email: str, password: str | None) -> dict:
    password = password or getpass.getpass("New password: ")
    require_strong_password(password)

    def update(document):
        user = app.find_user_by_email(document, email.strip().lower())
        if not user:
            raise ValueError("user not found")
        user["password"] = app.hash_password(password)
        app.record_event(document, "system", "password_reset_cli", f"Password reset for {user['email']}")
        return {"user_id": user["id"], "email": user["email"]}

    return app.mutate_db(update)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=f"{PRODUCT_NAME} local maintenance")
    commands = result.add_subparsers(dest="command", required=True)
    backup = commands.add_parser("backup", help="Create a verified online backup")
    backup.add_argument("output", type=Path)
    backup.add_argument("--keep-days", type=int, default=0)
    verify = commands.add_parser("verify-backup", help="Verify every file in a backup")
    verify.add_argument("archive", type=Path)
    restore = commands.add_parser("restore", help="Restore into an absent or empty data directory")
    restore.add_argument("archive", type=Path)
    restore.add_argument("target_data_dir", type=Path)
    integrity = commands.add_parser("integrity", help="Check live metadata and archive files")
    integrity.add_argument("--data-dir", type=Path, default=app.DATA_DIR)
    password = commands.add_parser("set-password", help="Reset an existing account password")
    password.add_argument("email")
    password.add_argument("--password", help=argparse.SUPPRESS)
    commands.add_parser(
        "archive-status",
        help="Show the local archive identity and integrity key",
    )
    commands.add_parser(
        "asset-dedup-report",
        help="Measure logical and unique asset storage without changing data",
    )
    commands.add_parser(
        "asset-gc-report",
        help="Dry-run a verified reference-aware object scan without deleting data",
    )
    commands.add_parser(
        "index-assets",
        help="Add verified content-addressed references while preserving legacy paths",
    )
    export = commands.add_parser("export-capture", help="Export one capture as a verified package")
    export.add_argument("capture_id")
    export.add_argument("output", type=Path)
    verify_capture_command = commands.add_parser(
        "verify-capture", help="Verify a portable capture package"
    )
    verify_capture_command.add_argument("archive", type=Path)
    import_capture_command = commands.add_parser(
        "import-capture", help="Import a verified package as a new private site"
    )
    import_capture_command.add_argument("archive", type=Path)
    import_capture_command.add_argument("owner_email")
    export_site_command = commands.add_parser(
        "export-site", help="Export all completed captures for one site"
    )
    export_site_command.add_argument("site_id")
    export_site_command.add_argument("output", type=Path)
    verify_site_command = commands.add_parser(
        "verify-site", help="Verify a portable full-site package"
    )
    verify_site_command.add_argument("archive", type=Path)
    import_site_command = commands.add_parser(
        "import-site", help="Import a verified full-site package as one private site"
    )
    import_site_command.add_argument("archive", type=Path)
    import_site_command.add_argument("owner_email")
    export_warc_command = commands.add_parser(
        "export-warc", help="Export one completed capture as WARC 1.1"
    )
    export_warc_command.add_argument("capture_id")
    export_warc_command.add_argument("output", type=Path)
    return result


def all_assets(document: dict) -> list[dict]:
    return [asset for snapshot in document["snapshots"] for asset in snapshot.get("assets", [])]


def index_assets() -> dict:
    store = ContentAddressedAssetStore(app.SNAPSHOT_DIR)
    linked = 0
    reused = 0
    with app.DATA_LOCK.exclusive():
        def update(document):
            nonlocal linked, reused
            for asset in all_assets(document):
                source = app.SNAPSHOT_DIR / (asset.get("file") or "")
                relative, digest, created = store.link_existing(source)
                asset["file"] = relative
                asset["content_digest"] = digest
                linked += int(created)
                reused += int(not created)

        app.mutate_db(update)
    report = store.measure(all_assets(app.load_db()))
    return {"ok": not report["missing"], "linked_objects": linked, "reused_objects": reused, **report}


def _manifest_digest_hex(value: str) -> str:
    if not value.startswith("sha256:"):
        raise ValueError("manifest resource digest is not SHA-256")
    encoded = value.removeprefix("sha256:")
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if len(raw) != 32:
        raise ValueError("manifest resource digest is not 32 bytes")
    return raw.hex()


def asset_gc_report() -> dict:
    store = ContentAddressedAssetStore(app.SNAPSHOT_DIR)
    with app.DATA_LOCK.exclusive():
        document = app.load_db()
        protected_digests = set()
        manifest_errors = []
        verified_manifests = 0
        manager = ArchiveManifestManager(
            app.INTEGRITY_DIR, app.SNAPSHOT_DIR
        )
        for site in document["sites"]:
            for run in app.METADATA_STORE.list_capture_runs(site["id"], 1_000_000):
                if not run.get("manifest_path"):
                    continue
                try:
                    manifest = manager.verify(run["manifest_path"])
                    for resource in manifest["resources"]:
                        protected_digests.add(
                            _manifest_digest_hex(resource["digest"])
                        )
                except Exception as exc:
                    manifest_errors.append(f"{run['id']}: {exc}")
                else:
                    verified_manifests += 1
        report = store.garbage_collection_report(
            all_assets(document), protected_digests
        )
    report["verified_manifests"] = verified_manifests
    report["manifest_protected_digests"] = len(protected_digests)
    report["manifest_errors"] = manifest_errors
    report["ok"] = bool(report["ok"] and not manifest_errors)
    return report


def export_capture_by_id(capture_id: str, output: Path) -> dict:
    document = app.load_db()
    run = app.METADATA_STORE.get_capture_run(capture_id)
    if not run or run["status"] == "running":
        raise ValueError("completed capture run not found")
    site = app.find_by_id(document["sites"], run["site_id"])
    snapshots = [
        snapshot for snapshot in document["snapshots"]
        if snapshot.get("capture_run_id") == capture_id
    ]
    return export_capture(app.SNAPSHOT_DIR, site, run, snapshots, output)


def export_site_by_id(site_id: str, output: Path) -> dict:
    document = app.load_db()
    site = app.find_by_id(document["sites"], site_id)
    if not site:
        raise ValueError("site not found")
    runs = [
        run for run in app.METADATA_STORE.list_capture_runs(site_id, 100000)
        if run["status"] != "running"
    ]
    run_ids = {run["id"] for run in runs}
    snapshots = [
        snapshot for snapshot in document["snapshots"]
        if snapshot.get("capture_run_id") in run_ids
    ]
    return export_site(app.SNAPSHOT_DIR, site, runs, snapshots, output)


def export_warc_by_id(capture_id: str, output: Path) -> dict:
    document = app.load_db()
    run = app.METADATA_STORE.get_capture_run(capture_id)
    if not run or run["status"] == "running":
        raise ValueError("completed capture run not found")
    site = app.find_by_id(document["sites"], run["site_id"])
    snapshots = [
        snapshot for snapshot in document["snapshots"]
        if snapshot.get("capture_run_id") == capture_id
    ]
    return export_warc(app.SNAPSHOT_DIR, site, run, snapshots, output)


def _import_capture_data(
    metadata: dict,
    bodies: dict[str, bytes],
    owner: dict,
    archive_name: str,
    existing_site: dict | None = None,
    check_quota: bool = True,
) -> dict:
    source_site = metadata["site"]
    source_run = metadata["capture_run"]
    site_id = existing_site["id"] if existing_site else app.new_id("site")
    capture_id = app.new_id("capture")
    snapshot_ids = {
        snapshot["id"]: app.new_id("snap") for snapshot in metadata["snapshots"]
    }
    required_bytes = sum(
        len(bodies[snapshot["package_path"]])
        + sum(len(bodies[asset["package_path"]]) for asset in snapshot.get("assets", []))
        for snapshot in metadata["snapshots"]
    )
    if check_quota:
        app.METADATA_STORE.assert_storage_available(owner["id"], required_bytes)
    site = existing_site or {
        "id": site_id,
        "owner_id": owner["id"],
        "name": f"Imported {source_site.get('name') or source_site['url']}",
        "url": app.normalize_url(source_site["url"]),
        "visibility": "private",
        "interval": "monthly",
        "custom_days": "30",
        "crawl_depth": 1,
        "max_pages": 20,
        "wayback_enabled": False,
        "wayback_frequency": "yearly",
        "wayback_limit": 20,
        "created_at": app.now_iso(),
        "last_snapshot_at": source_run["started_at"],
        "next_snapshot_at": app.next_capture_after(app.now_iso(), "monthly", 30),
    }
    imported_snapshots = []
    with app.DATA_LOCK.exclusive():
        for source_snapshot in metadata["snapshots"]:
            old_id = source_snapshot["id"]
            snap_id = snapshot_ids[old_id]
            page_body = bodies[source_snapshot["package_path"]]
            for source_id, imported_id in snapshot_ids.items():
                page_body = page_body.replace(
                    f"/snapshots/{source_id}/".encode(),
                    f"/snapshots/{imported_id}/".encode(),
                )
            suffix = ".html" if "text/html" in source_snapshot.get("content_type", "").lower() else ".bin"
            page_relative = f"{site_id}/{snap_id}{suffix}"
            page_path = app.SNAPSHOT_DIR / page_relative
            page_path.parent.mkdir(parents=True, exist_ok=True)
            page_path.write_bytes(page_body)
            assets = []
            for source_asset in source_snapshot.get("assets", []):
                asset_body = bodies[source_asset["package_path"]]
                if "text/css" in source_asset.get("content_type", "").lower():
                    asset_body = asset_body.replace(
                        f"/snapshots/{old_id}/asset/".encode(),
                        f"/snapshots/{snap_id}/asset/".encode(),
                    )
                relative, digest, _created = app.ASSET_STORE.put(asset_body)
                assets.append(
                    {
                        **{
                            key: value for key, value in source_asset.items()
                            if key not in {"package_path", "file", "resource_id", "content_digest"}
                        },
                        "file": relative,
                        "bytes": len(asset_body),
                        "content_digest": digest,
                    }
                )
            imported_snapshots.append(
                {
                    **{
                        key: value for key, value in source_snapshot.items()
                        if key not in {
                            "id", "site_id", "capture_run_id", "archive_page_id",
                            "package_path", "assets", "file",
                        }
                    },
                    "id": snap_id,
                    "site_id": site_id,
                    "capture_run_id": capture_id,
                    "kind": "imported",
                    "file": page_relative,
                    "bytes": len(page_body),
                    "assets": assets,
                    "created_by": owner["id"],
                }
            )

        def add_site(current):
            if not existing_site:
                current["sites"].append(site)
            app.record_event(
                current, owner["id"], "capture_import_started",
                f"Importing {source_site['url']} from {archive_name}",
            )

        app.mutate_db(add_site)
        app.METADATA_STORE.create_capture_run(
            capture_id,
            app.new_id("manifest"),
            site_id,
            "imported",
            source_run["started_at"],
        )

        def add_snapshots(current):
            current["snapshots"].extend(imported_snapshots)

        app.mutate_db(add_snapshots)
        entry_id = snapshot_ids.get(source_run.get("entry_snapshot_id"))
        if entry_id:
            app.METADATA_STORE.update_capture_run(
                capture_id, app.now_iso(), entry_snapshot_id=entry_id
            )
        app.finalize_capture_run(capture_id, len(imported_snapshots), 0)
    return {
        "ok": True,
        "site_id": site_id,
        "capture_id": capture_id,
        "pages": len(imported_snapshots),
        "visibility": "private",
    }


def import_capture_package(archive: Path, owner_email: str) -> dict:
    metadata, bodies = read_capture(archive)
    document = app.load_db()
    owner = app.find_user_by_email(document, owner_email.strip().lower())
    if not owner or owner.get("status") != "active":
        raise ValueError("active owner account not found")
    return _import_capture_data(metadata, bodies, owner, archive.name)


def import_site_package(archive: Path, owner_email: str) -> dict:
    metadata, bodies = read_site(archive)
    document = app.load_db()
    owner = app.find_user_by_email(document, owner_email.strip().lower())
    if not owner or owner.get("status") != "active":
        raise ValueError("active owner account not found")
    required_bytes = sum(
        len(bodies[snapshot["package_path"]])
        + sum(len(bodies[asset["package_path"]]) for asset in snapshot.get("assets", []))
        for snapshot in metadata["snapshots"]
    )
    app.METADATA_STORE.assert_storage_available(owner["id"], required_bytes)
    results = []
    imported_site = None
    snapshots_by_run = {}
    for snapshot in metadata["snapshots"]:
        snapshots_by_run.setdefault(snapshot["capture_run_id"], []).append(snapshot)
    for run in sorted(metadata["capture_runs"], key=lambda item: (item["started_at"], item["id"])):
        run_metadata = {
            "format": metadata["format"],
            "site": metadata["site"],
            "capture_run": run,
            "snapshots": snapshots_by_run.get(run["id"], []),
        }
        if not run_metadata["snapshots"]:
            continue
        result = _import_capture_data(
            run_metadata,
            bodies,
            owner,
            archive.name,
            existing_site=imported_site,
            check_quota=False,
        )
        results.append(result)
        if imported_site is None:
            imported_site = app.find_by_id(app.load_db()["sites"], result["site_id"])
    if not results:
        raise ValueError("site package has no importable captures")
    latest = max(run["started_at"] for run in metadata["capture_runs"])
    def finish_site(current):
        site = app.find_by_id(current["sites"], results[0]["site_id"])
        if site:
            site["last_snapshot_at"] = latest
        app.record_event(
            current,
            owner["id"],
            "site_import_complete",
            f"Imported {len(results)} captures from {archive.name}",
        )
    app.mutate_db(finish_site)
    return {
        "ok": True,
        "site_id": results[0]["site_id"],
        "captures": len(results),
        "pages": sum(result["pages"] for result in results),
        "visibility": "private",
    }








def main() -> int:
    args = parser().parse_args()
    if args.command == "backup":
        destination = args.output.expanduser()
        if destination.exists() and destination.is_dir() or not destination.suffix:
            destination.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            destination = destination / f"websnapshot-{stamp}.tar.gz"
        output = create_backup(app.DATA_DIR, destination)
        if args.keep_days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=args.keep_days)
            removed = []
            for candidate in destination.parent.glob("websnapshot-*.tar.gz"):
                modified = datetime.fromtimestamp(candidate.stat().st_mtime, timezone.utc)
                if candidate != destination and modified < cutoff:
                    candidate.unlink()
                    removed.append(str(candidate))
            output["pruned"] = removed
    elif args.command == "verify-backup":
        output = verify_backup(args.archive)
    elif args.command == "restore":
        output = restore_backup(args.archive, args.target_data_dir)
    elif args.command == "integrity":
        output = inspect_data_dir(args.data_dir)
    elif args.command == "set-password":
        output = set_password(args.email, args.password or os.environ.get("WEBSNAPSHOT_NEW_PASSWORD"))
    elif args.command == "archive-status":
        app.load_db()
        profile = app.METADATA_STORE.archive_profile()
        identity = ArchiveIdentity(app.INTEGRITY_DIR).ensure(profile["archive_id"])
        output = {
            "ok": True,
            "archive_id": profile["archive_id"],
            "installation_id": profile["installation_id"],
            "setup_complete": profile["setup_complete"],
            "key_id": identity["key_id"],
            "algorithm": identity["algorithm"],
            "public_key": identity["public_key"],
        }
    elif args.command == "asset-dedup-report":
        app.load_db()
        output = ContentAddressedAssetStore(app.SNAPSHOT_DIR).measure(all_assets(app.load_db()))
        output["ok"] = not output["missing"]
    elif args.command == "asset-gc-report":
        output = asset_gc_report()
    elif args.command == "index-assets":
        app.load_db()
        output = index_assets()
    elif args.command == "export-capture":
        output = export_capture_by_id(args.capture_id, args.output)
    elif args.command == "verify-capture":
        output = verify_capture(args.archive)
    elif args.command == "import-capture":
        output = import_capture_package(args.archive, args.owner_email)
    elif args.command == "export-site":
        output = export_site_by_id(args.site_id, args.output)
    elif args.command == "verify-site":
        output = verify_site(args.archive)
    elif args.command == "import-site":
        output = import_site_package(args.archive, args.owner_email)
    elif args.command == "export-warc":
        output = export_warc_by_id(args.capture_id, args.output)
    else:
        raise AssertionError(args.command)
    display = dict(output)
    if isinstance(display.get("files"), list):
        display["file_count"] = len(display.pop("files"))
    if isinstance(display.get("manifest"), dict) and "files" in display["manifest"]:
        display["manifest"] = dict(display["manifest"])
        display["manifest"]["file_count"] = len(display["manifest"].pop("files"))
    print(json.dumps(display, indent=2, sort_keys=True))
    return 0 if output.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
