"""Deterministic JSON encoding used by local archive integrity records."""

from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
from typing import Any


SAFE_INTEGER_MAX = 9_007_199_254_740_991


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented by the canonical subset."""


def _validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -SAFE_INTEGER_MAX <= value <= SAFE_INTEGER_MAX:
            raise CanonicalizationError(f"integer outside interoperable range at {path}")
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"floating-point values are not allowed at {path}")
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise CanonicalizationError(f"string contains an invalid surrogate at {path}")
        if unicodedata.normalize("NFC", value) != value:
            raise CanonicalizationError(f"string is not NFC-normalized at {path}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise CanonicalizationError(f"object key is not ASCII text at {path}")
            _validate(key, f"{path}.<key>")
            _validate(item, f"{path}.{key}")
        return
    raise CanonicalizationError(f"unsupported JSON value at {path}: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    _validate(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    digest = hashlib.sha256(canonicalize(value)).digest()
    return "sha256:" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
