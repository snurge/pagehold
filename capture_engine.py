"""Automatic capture-engine selection and isolated browser-worker execution."""

from __future__ import annotations

import html
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CAPTURE_ENGINE_CONTRACT = "websnapshot-capture-engine-v1"
AUTOMATIC_POLICY_VERSION = "automatic-v1"
NATIVE_ENGINE_ID = "native-http-v1"
BROWSER_ENGINE_ID = "playwright-browser-v1"


class BrowserWorkerError(RuntimeError):
    """Raised when the isolated browser worker cannot return a trusted result."""


@dataclass(frozen=True)
class EngineDecision:
    engine_id: str
    reason: str
    policy_version: str = AUTOMATIC_POLICY_VERSION

    @property
    def browser_required(self) -> bool:
        return self.engine_id == BROWSER_ENGINE_ID


def _visible_text(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace")
    without_code = re.sub(
        r"<(?:script|style|template)\b[^>]*>.*?</(?:script|style|template)>",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    visible = html.unescape(re.sub(r"<[^>]+>", " ", without_code))
    return re.sub(r"\s+", " ", visible).strip()


def browser_render_reason(body: bytes) -> str | None:
    """Return the first bounded, deterministic reason a page needs a browser."""

    text = body.decode("utf-8", errors="replace")
    lower = text.lower()
    if 'data-ssr="false"' in lower or "data-ssr='false'" in lower:
        return "page explicitly reports that server-side rendering is disabled"

    empty_app_root = re.search(
        r"<(?:div|main)\b[^>]*\bid\s*=\s*['\"]"
        r"(?:__nuxt|__next|root|app|application)['\"][^>]*>\s*</(?:div|main)>",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if empty_app_root:
        return "page contains an empty application root"

    visible = _visible_text(body)
    app_markers = (
        "__nuxt",
        "__next",
        "data-reactroot",
        "ng-version",
        "data-v-app",
        'type="module"',
        "type='module'",
    )
    if any(marker in lower for marker in app_markers) and len(visible) < 240:
        return "client-application markers are present with little rendered text"

    noscript_markers = (
        "enable javascript",
        "javascript is required",
        "you need to enable javascript",
        "please enable javascript",
    )
    noscript_text = " ".join(
        re.findall(r"<noscript\b[^>]*>(.*?)</noscript>", lower, re.DOTALL)
    )
    if any(marker in noscript_text for marker in noscript_markers) and len(visible) < 240:
        return "the page says JavaScript is required"
    return None


def select_capture_engine(
    body: bytes,
    content_type: str,
    *,
    browser_enabled: bool,
    archived_source: bool = False,
    evidence_requested: bool = False,
    policy_version: str = AUTOMATIC_POLICY_VERSION,
) -> EngineDecision:
    """Choose an engine without exposing crawler technology to the user."""

    if policy_version != AUTOMATIC_POLICY_VERSION:
        raise ValueError(f"Unsupported capture-engine policy: {policy_version}")
    if archived_source:
        return EngineDecision(NATIVE_ENGINE_ID, "historical replay is captured as supplied")
    if "text/html" not in (content_type or "").lower():
        return EngineDecision(NATIVE_ENGINE_ID, "response is not an HTML document")

    reason = browser_render_reason(body)
    if browser_enabled and reason:
        return EngineDecision(BROWSER_ENGINE_ID, reason)
    if browser_enabled and evidence_requested:
        return EngineDecision(
            BROWSER_ENGINE_ID,
            "configured visual capture evidence requires a browser",
        )
    if reason:
        return EngineDecision(
            NATIVE_ENGINE_ID,
            f"browser capture is unavailable; lightweight capture retained ({reason})",
        )
    return EngineDecision(NATIVE_ENGINE_ID, "server response contains usable page content")


def _minimal_worker_environment() -> dict[str, str]:
    allowed = {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PLAYWRIGHT_BROWSERS_PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TMPDIR",
    }
    return {name: value for name, value in os.environ.items() if name in allowed}


def clear_stale_capture_work(work_root: str | Path) -> int:
    """Remove transient exchanges left by a previous stopped server process."""

    root = Path(work_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    removed = 0
    for path in root.iterdir():
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)
        else:
            continue
        removed += 1
    return removed


def run_browser_worker(
    *,
    worker_script: str | Path,
    work_root: str | Path,
    url: str,
    timeout_ms: int,
    wait_ms: int,
    user_agent: str,
    ignore_https_errors: bool,
    allow_private_networks: bool,
    max_capture_bytes: int,
    screenshot: bool = False,
    pdf: bool = False,
) -> tuple[str, int, str, bytes, dict[str, bytes], dict[str, Any]]:
    """Run one high-fidelity page capture outside the WebSnapshot server process."""

    worker_script = Path(worker_script).resolve()
    work_root = Path(work_root).resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    os.chmod(work_root, 0o700)
    request = {
        "contract": CAPTURE_ENGINE_CONTRACT,
        "url": url,
        "timeout_ms": max(5_000, int(timeout_ms)),
        "wait_ms": max(0, int(wait_ms)),
        "user_agent": user_agent,
        "ignore_https_errors": bool(ignore_https_errors),
        "allow_private_networks": bool(allow_private_networks),
        "max_capture_bytes": max(1, int(max_capture_bytes)),
        "screenshot": bool(screenshot),
        "pdf": bool(pdf),
    }
    with tempfile.TemporaryDirectory(prefix="capture-", dir=work_root) as temporary:
        temporary_path = Path(temporary)
        request_path = temporary_path / "request.json"
        output_path = temporary_path / "output"
        output_path.mkdir(mode=0o700)
        request_path.write_text(
            json.dumps(request, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        os.chmod(request_path, 0o600)
        command = [
            sys.executable,
            str(worker_script),
            str(request_path),
            str(output_path),
        ]
        process_timeout = max(20, int(timeout_ms / 1000) + int(wait_ms / 1000) + 20)
        process = subprocess.Popen(
            command,
            cwd=worker_script.parent,
            env=_minimal_worker_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=process_timeout)
        except subprocess.TimeoutExpired as exc:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
            raise BrowserWorkerError("The high-fidelity capture worker timed out.") from exc
        if process.returncode != 0:
            detail = (stderr or stdout or "").strip().splitlines()
            message = detail[-1][:240] if detail else "unknown worker error"
            raise BrowserWorkerError(f"The high-fidelity capture worker failed: {message}")

        result_path = output_path / "result.json"
        body_path = output_path / "body.bin"
        if not result_path.is_file() or result_path.is_symlink():
            raise BrowserWorkerError("The high-fidelity worker returned no result.")
        if result_path.stat().st_size > 1024 * 1024:
            raise BrowserWorkerError("The high-fidelity worker result is too large.")
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise BrowserWorkerError("The high-fidelity worker result is invalid.") from exc
        if payload.get("contract") != CAPTURE_ENGINE_CONTRACT:
            raise BrowserWorkerError("The high-fidelity worker contract does not match.")
        if payload.get("engine_id") != BROWSER_ENGINE_ID:
            raise BrowserWorkerError("The high-fidelity worker identity does not match.")
        if not body_path.is_file() or body_path.is_symlink():
            raise BrowserWorkerError("The high-fidelity worker returned no page body.")
        body = body_path.read_bytes()
        if len(body) > max_capture_bytes:
            raise BrowserWorkerError("Rendered capture exceeded configured size limit.")

        evidence: dict[str, bytes] = {}
        for kind, filename in (("screenshot", "screenshot.png"), ("pdf", "page.pdf")):
            if kind not in payload.get("evidence", []):
                continue
            path = output_path / filename
            if not path.is_file() or path.is_symlink():
                raise BrowserWorkerError(f"The worker's {kind} evidence is missing.")
            content = path.read_bytes()
            if len(content) > max_capture_bytes:
                raise BrowserWorkerError(f"The worker's {kind} evidence is too large.")
            evidence[kind] = content
        return (
            str(payload["final_url"]),
            int(payload["status"]),
            str(payload["content_type"]),
            body,
            evidence,
            dict(payload.get("diagnostics") or {}),
        )
