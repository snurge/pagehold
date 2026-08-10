"""Bounded capture diagnostics and replay-quality inspection."""

from __future__ import annotations

import html
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MAX_DIAGNOSTIC_ITEMS = 120
MAX_REASON_LENGTH = 240


def diagnostic_url(value: str | None) -> str | None:
    """Retain a useful URL without persisting query values or credentials."""

    if not value:
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return str(value)[:500]
    if parsed.scheme not in {"http", "https"}:
        return str(value)[:500]
    host = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port:
        host = f"{host}:{port}"
    query_keys = [key for key, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]
    query = urllib.parse.urlencode([(key, "redacted") for key in query_keys])
    return urllib.parse.urlunsplit((parsed.scheme, host, parsed.path, query, ""))[:1000]


def safe_reason(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "Unknown error")).strip()
    text = re.sub(
        r"https?://[^\s<>\"']+",
        lambda match: diagnostic_url(match.group(0)) or "redacted URL",
        text,
        flags=re.IGNORECASE,
    )
    return text[:MAX_REASON_LENGTH]


@dataclass
class CaptureDiagnostics:
    """Collect useful capture evidence without allowing unbounded metadata growth."""

    items: list[dict[str, Any]] = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)
    truncated: int = 0
    browser_rendered: bool = False
    engine_id: str | None = None
    engine_reason: str | None = None
    engine_policy_version: str | None = None

    def set_engine(self, engine_id: str, reason: str, policy_version: str) -> None:
        self.engine_id = str(engine_id)[:80]
        self.engine_reason = safe_reason(reason)
        self.engine_policy_version = str(policy_version)[:80]

    def merge_record(self, record: dict[str, Any] | None) -> None:
        """Merge diagnostics returned by a separately isolated capture worker."""

        record = record or {}
        self.browser_rendered = self.browser_rendered or bool(
            record.get("browser_rendered")
        )
        for name, count in dict(record.get("counts") or {}).items():
            try:
                self.counts[str(name)] += max(0, int(count))
            except (TypeError, ValueError):
                continue
        for item in list(record.get("items") or []):
            if len(self.items) >= MAX_DIAGNOSTIC_ITEMS:
                self.truncated += 1
                continue
            if not isinstance(item, dict):
                continue
            clean = {
                key: value
                for key, value in item.items()
                if key in {
                    "outcome",
                    "stage",
                    "url",
                    "reason",
                    "status",
                    "content_type",
                    "bytes",
                }
            }
            if "reason" in clean:
                clean["reason"] = safe_reason(clean["reason"])
            self.items.append(clean)
        try:
            self.truncated += max(0, int(record.get("truncated", 0)))
        except (TypeError, ValueError):
            pass

    def record(
        self,
        outcome: str,
        stage: str,
        *,
        url: str | None = None,
        reason: Any = None,
        status: int | None = None,
        content_type: str | None = None,
        byte_count: int | None = None,
    ) -> None:
        key = f"{outcome}_{stage}"
        self.counts[key] += 1
        self.counts[outcome] += 1
        if outcome == "captured":
            return
        item = {"outcome": outcome, "stage": stage}
        if url:
            item["url"] = diagnostic_url(url)
        if reason is not None:
            item["reason"] = safe_reason(reason)
        if status is not None:
            item["status"] = int(status)
        if content_type:
            item["content_type"] = str(content_type)[:120]
        if byte_count is not None:
            item["bytes"] = max(0, int(byte_count))
        if len(self.items) < MAX_DIAGNOSTIC_ITEMS:
            self.items.append(item)
        else:
            self.truncated += 1

    def as_record(self, asset_count: int) -> dict[str, Any]:
        return {
            "version": 2,
            "browser_rendered": self.browser_rendered,
            "engine_id": self.engine_id,
            "engine_reason": self.engine_reason,
            "engine_policy_version": self.engine_policy_version,
            "asset_count": max(0, int(asset_count)),
            "captured": int(self.counts["captured"]),
            "failed": int(self.counts["failed"]),
            "skipped": int(self.counts["skipped"]),
            "warnings": int(self.counts["warning"]),
            "truncated": self.truncated,
            "counts": dict(sorted(self.counts.items())),
            "items": list(self.items),
        }


_LOAD_ATTR_RE = re.compile(
    r"(?<![\w-])(?:src|srcset|poster)\s*=\s*([\"'])(?P<url>.*?)(?:\1)",
    flags=re.IGNORECASE | re.DOTALL,
)
_STYLESHEET_RE = re.compile(
    r"<link\b(?=[^>]*\brel\s*=\s*([\"'])[^\"']*stylesheet[^\"']*\1)[^>]*"
    r"\bhref\s*=\s*([\"'])(?P<url>.*?)(?:\2)[^>]*>",
    flags=re.IGNORECASE | re.DOTALL,
)
_CSS_URL_RE = re.compile(r"url\(\s*([\"']?)(?P<url>.*?)(?:\1)\s*\)", re.IGNORECASE)


def replay_quality_report(
    body: bytes,
    assets: list[dict[str, Any]],
    snapshot_root: Path | None = None,
    persisted: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Describe stored replay completeness without making network requests."""

    text = body.decode("utf-8", errors="replace")
    asset_by_id = {str(asset.get("id")): asset for asset in assets}
    local_ids = set(
        re.findall(
            r"/snapshots/[A-Za-z0-9_-]+/asset/([A-Za-z0-9._~-]+)",
            text,
            flags=re.IGNORECASE,
        )
    )
    missing_local = sorted(local_ids - set(asset_by_id))
    missing_files = []
    if snapshot_root is not None:
        for asset_id, asset in asset_by_id.items():
            relative = str(asset.get("file") or "")
            if not relative or not (snapshot_root / relative).is_file():
                missing_files.append(asset_id)

    remote_dependencies = []
    images_without_source = []
    for tag in re.findall(r"<img\b[^>]*>", text, flags=re.IGNORECASE | re.DOTALL):
        if re.search(
            r"(?<![\w-])(?:src|srcset)\s*=\s*([\"']).+?\1",
            tag,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            continue
        alt_match = re.search(
            r"\balt\s*=\s*([\"'])(?P<alt>.*?)(?:\1)",
            tag,
            flags=re.IGNORECASE | re.DOTALL,
        )
        images_without_source.append(
            safe_reason(html.unescape(alt_match.group("alt"))) if alt_match else "Unlabelled image"
        )
    candidates = [match.group("url") for match in _LOAD_ATTR_RE.finditer(text)]
    candidates.extend(match.group("url") for match in _STYLESHEET_RE.finditer(text))
    candidates.extend(match.group("url") for match in _CSS_URL_RE.finditer(text))
    for raw in candidates:
        for candidate in raw.split(",") if "," in raw else [raw]:
            url = html.unescape(candidate.strip().split()[0] if candidate.strip() else "")
            if urllib.parse.urlsplit(url).scheme in {"http", "https"}:
                clean = diagnostic_url(url)
                if clean and clean not in remote_dependencies:
                    remote_dependencies.append(clean)

    persisted = persisted or {}
    failed = int(persisted.get("failed", 0))
    skipped = int(persisted.get("skipped", 0))
    warning_count = int(persisted.get("warnings", 0))
    problem_count = len(missing_local) + len(missing_files)
    if problem_count:
        status = "problems"
    elif failed or skipped or warning_count or remote_dependencies or images_without_source:
        status = "warnings"
    else:
        status = "complete"
    return {
        "status": status,
        "asset_count": len(assets),
        "missing_local_references": missing_local,
        "missing_asset_files": missing_files,
        "remote_dependencies": remote_dependencies[:MAX_DIAGNOSTIC_ITEMS],
        "remote_dependency_count": len(remote_dependencies),
        "images_without_source": images_without_source[:MAX_DIAGNOSTIC_ITEMS],
        "images_without_source_count": len(images_without_source),
        "active_script_count": len(re.findall(r"<script\b", text, flags=re.IGNORECASE)),
        "form_count": len(re.findall(r"<form\b", text, flags=re.IGNORECASE)),
        "frame_count": len(re.findall(r"<(?:iframe|frame)\b", text, flags=re.IGNORECASE)),
        "failed": failed,
        "skipped": skipped,
        "warnings": warning_count,
        "items": list(persisted.get("items", []))[:MAX_DIAGNOSTIC_ITEMS],
        "truncated": int(persisted.get("truncated", 0)),
        "browser_rendered": bool(persisted.get("browser_rendered")),
    }
