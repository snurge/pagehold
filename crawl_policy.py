"""Deterministic per-site crawl policy helpers."""

from __future__ import annotations

import fnmatch
import urllib.parse


TRACKING_QUERY_KEYS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "msclkid",
}


def split_patterns(value: str | None) -> tuple[str, ...]:
    return tuple(
        pattern.strip()
        for line in (value or "").splitlines()
        for pattern in line.split(",")
        if pattern.strip()
    )


def normalize_candidate(url: str, query_mode: str = "normalize") -> str:
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    query = parsed.query
    if query_mode == "drop":
        query = ""
    elif query_mode == "normalize" and query:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        pairs = [
            (key, value)
            for key, value in pairs
            if key.lower() not in TRACKING_QUERY_KEYS and not key.lower().startswith("utm_")
        ]
        query = urllib.parse.urlencode(sorted(pairs))
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc.lower(), path, query, "")
    )


def url_matches_policy(
    url: str,
    include_patterns: str | None = None,
    exclude_patterns: str | None = None,
) -> bool:
    parsed = urllib.parse.urlsplit(url)
    target = parsed.path or "/"
    if parsed.query:
        target += f"?{parsed.query}"
    includes = split_patterns(include_patterns)
    excludes = split_patterns(exclude_patterns)
    if includes and not any(fnmatch.fnmatchcase(target, pattern) for pattern in includes):
        return False
    return not any(fnmatch.fnmatchcase(target, pattern) for pattern in excludes)


def normalized_site_policy(site: dict, default_user_agent: str) -> dict:
    robots_policy = str(site.get("robots_policy", "respect")).lower()
    if robots_policy not in {"respect", "owner_override"}:
        robots_policy = "respect"
    query_mode = str(site.get("query_mode", "normalize")).lower()
    if query_mode not in {"preserve", "normalize", "drop"}:
        query_mode = "normalize"
    return {
        "request_delay_seconds": max(
            1.0, min(120.0, float(site.get("request_delay_seconds", 5.0)))
        ),
        "request_timeout_seconds": max(
            5.0, min(120.0, float(site.get("request_timeout_seconds", 25.0)))
        ),
        "user_agent": str(site.get("crawl_user_agent") or default_user_agent)[:240],
        "robots_policy": robots_policy,
        "include_patterns": str(site.get("include_patterns") or "")[:4000],
        "exclude_patterns": str(site.get("exclude_patterns") or "")[:4000],
        "query_mode": query_mode,
    }


def estimated_upper_bound_bytes(max_pages: int, page_bytes: int, asset_bytes: int, assets: int) -> int:
    return max(1, int(max_pages)) * (
        max(0, int(page_bytes)) + max(0, int(asset_bytes)) * max(0, int(assets))
    )
