#!/usr/bin/env python3
"""Reject staged private runtime data and high-confidence credential patterns."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import PurePosixPath


FORBIDDEN_DIRECTORIES = {
    "archives",
    "browser-data",
    "captures",
    "credentials",
    "data",
    "logs",
    "secrets",
    "snapshots",
    "user-data-dir",
}

FORBIDDEN_SUFFIXES = {
    ".cdx",
    ".cdxj",
    ".db",
    ".har",
    ".jks",
    ".key",
    ".keystore",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".pid",
    ".sqlite",
    ".sqlite3",
    ".warc",
}

SECRET_PATTERNS = {
    "private key": re.compile(
        b"-----BEGIN " + b"(?:[A-Z0-9]+ )?PRIVATE KEY-----"
    ),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    "Google API key": re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "OpenAI-style key": re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "Slack token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "Stripe secret": re.compile(rb"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    "credential-bearing URL": re.compile(
        rb"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", re.IGNORECASE
    ),
}


def git(*args: str) -> bytes:
    return subprocess.check_output(("git", *args), stderr=subprocess.STDOUT)


def staged_paths() -> list[str]:
    output = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return [item.decode("utf-8", "surrogateescape") for item in output.split(b"\0") if item]


def forbidden_path_reason(path_text: str) -> str | None:
    path = PurePosixPath(path_text)
    lowered_parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    if FORBIDDEN_DIRECTORIES & lowered_parts:
        return "private runtime-data directory"
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return "environment file"
    if name.endswith(".credentials.json") or name.startswith("service-account"):
        return "credential file"
    if name.endswith(".warc.gz"):
        return "archive capture"
    if re.search(r"\.(?:db|sqlite|sqlite3)(?:-.+)?$", name):
        return "database or database sidecar"
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        return f"forbidden {path.suffix.lower()} file"
    return None


def main() -> int:
    failures: list[tuple[str, str]] = []
    for path in staged_paths():
        reason = forbidden_path_reason(path)
        if reason:
            failures.append((path, reason))
            continue
        try:
            content = git("show", f":{path}")
        except subprocess.CalledProcessError:
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                failures.append((path, label))
                break

    if failures:
        print("Commit blocked: sensitive or private material is staged.", file=sys.stderr)
        for path, reason in failures:
            print(f"  {path}: {reason}", file=sys.stderr)
        print("Unstage the file and keep it outside source control.", file=sys.stderr)
        return 1

    subprocess.run(("git", "diff", "--cached", "--check"), check=True)
    print("Staged-file safety check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
