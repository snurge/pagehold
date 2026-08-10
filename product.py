"""Stable PageHold product identity."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
NAME = "PageHold"
VERSION = (ROOT / "VERSION").read_text(encoding="ascii").strip()
SOURCE_URL = os.environ.get(
    "PAGEHOLD_SOURCE_URL", "https://github.com/snurge/pagehold"
).strip()

if SOURCE_URL:
    parsed_source = urlsplit(SOURCE_URL)
    if parsed_source.scheme not in {"http", "https"} or not parsed_source.netloc:
        raise RuntimeError("PAGEHOLD_SOURCE_URL must be an absolute HTTP(S) URL")
