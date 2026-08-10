#!/usr/bin/env python3
import pathlib
import re
from collections import Counter

import app


ROOT = pathlib.Path(__file__).resolve().parent
SNAPSHOT_ROOT = ROOT / "data" / "snapshots"


def asset_number(asset_id):
    match = re.match(r"asset_(\d+)$", str(asset_id))
    return int(match.group(1)) if match else 0


def kind_for_asset(asset):
    content_type = (asset.get("content_type") or "").lower()
    if "css" in content_type:
        return "css"
    if "javascript" in content_type or "ecmascript" in content_type:
        return "script"
    if content_type.startswith("image/"):
        return "image"
    if "font" in content_type or "opentype" in content_type or "ms-fontobject" in content_type:
        return "font"
    return "other"


def next_asset_id(used):
    next_number = max((asset_number(item) for item in used), default=0) + 1
    while True:
        candidate = f"asset_{next_number:03d}"
        next_number += 1
        if candidate not in used:
            used.add(candidate)
            return candidate


def rewrite_html_refs(text, snap_id, preferred):
    local_ref = re.compile(
        rf"(<(?P<tag>\w+)\b[^>]*?/snapshots/{re.escape(snap_id)}/asset/(?P<asset>asset_\d+)[^>]*>)",
        flags=re.IGNORECASE | re.DOTALL,
    )

    def replace(match):
        tag = match.group(0)
        lower = tag.lower()
        old_id = match.group("asset")
        replacement = None
        if "<link" in lower and "stylesheet" in lower:
            replacement = preferred.get((old_id, "css"))
        elif "<script" in lower:
            replacement = preferred.get((old_id, "script"))
        elif any(f"<{name}" in lower for name in ("img", "source", "video", "audio")):
            replacement = preferred.get((old_id, "image"))
        if not replacement:
            return tag
        return tag.replace(f"/snapshots/{snap_id}/asset/{old_id}", f"/snapshots/{snap_id}/asset/{replacement}")

    return local_ref.sub(replace, text)


def main():
    changed = []

    def dedupe(db):
        for snapshot in db["snapshots"]:
            assets = snapshot.get("assets", [])
            counts = Counter(asset.get("id") for asset in assets)
            duplicate_ids = {asset_id for asset_id, count in counts.items() if count > 1}
            if not duplicate_ids:
                continue

            used = {asset.get("id") for asset in assets if asset.get("id")}
            seen = set()
            preferred = {}

            for asset in assets:
                old_id = asset.get("id")
                if old_id not in duplicate_ids:
                    continue
                kind = kind_for_asset(asset)
                if old_id not in seen:
                    seen.add(old_id)
                    preferred.setdefault((old_id, kind), old_id)
                    continue
                new_id = next_asset_id(used)
                asset["id"] = new_id
                preferred[(old_id, kind)] = new_id

            path = SNAPSHOT_ROOT / snapshot["file"]
            if path.exists() and "text/html" in snapshot.get("content_type", "").lower():
                text = path.read_text(encoding="utf-8", errors="ignore")
                rewritten = rewrite_html_refs(text, snapshot["id"], preferred)
                if rewritten != text:
                    path.write_text(rewritten, encoding="utf-8")
                    snapshot["bytes"] = len(rewritten.encode("utf-8"))

            changed.append((snapshot.get("wayback_timestamp") or "live", snapshot["id"], sorted(duplicate_ids)))

    app.mutate_db(dedupe)
    print(f"deduped {len(changed)} snapshots")
    for row in changed:
        print(row)


if __name__ == "__main__":
    main()
