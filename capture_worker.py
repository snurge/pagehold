#!/usr/bin/env python3
"""Isolated Playwright capture worker for WebSnapshot."""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
from pathlib import Path

from capture_engine import CAPTURE_ENGINE_CONTRACT
from capture_quality import CaptureDiagnostics
from security import validate_outbound_url


def _load_request(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise ValueError("capture request is unavailable")
    request = json.loads(path.read_text(encoding="utf-8"))
    if request.get("contract") != CAPTURE_ENGINE_CONTRACT:
        raise ValueError("unsupported capture-engine contract")
    return request


def capture(request: dict, output: Path) -> dict:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright

    diagnostics = CaptureDiagnostics()
    diagnostics.browser_rendered = True
    url = str(request["url"])
    allow_private = bool(request.get("allow_private_networks"))
    validate_outbound_url(url, allow_private)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                user_agent=str(request["user_agent"]),
                ignore_https_errors=bool(request.get("ignore_https_errors")),
                viewport={"width": 1440, "height": 1000},
            )
            page = context.new_page()

            def failed_request(browser_request):
                failure = browser_request.failure
                diagnostics.record(
                    "failed",
                    "browser_request",
                    url=browser_request.url,
                    reason=(
                        failure.get("errorText")
                        if isinstance(failure, dict)
                        else failure
                    ),
                )

            def failed_response(response):
                if response.status >= 400:
                    diagnostics.record(
                        "failed",
                        "browser_response",
                        url=response.url,
                        reason=f"HTTP {response.status}",
                        status=response.status,
                    )

            def route_request(route):
                request_url = route.request.url
                if urllib.parse.urlsplit(request_url).scheme not in {"http", "https"}:
                    route.continue_()
                    return
                try:
                    validate_outbound_url(request_url, allow_private)
                except ValueError as exc:
                    diagnostics.record(
                        "skipped",
                        "browser_policy",
                        url=request_url,
                        reason=exc,
                    )
                    route.abort()
                else:
                    route.continue_()

            page.on("requestfailed", failed_request)
            page.on("response", failed_response)
            page.on(
                "pageerror",
                lambda error: diagnostics.record(
                    "warning", "browser_script", url=page.url, reason=error
                ),
            )
            page.route("**/*", route_request)
            timeout_ms = max(5_000, int(request["timeout_ms"]))
            response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            try:
                page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 12_000))
            except PlaywrightTimeoutError:
                diagnostics.record(
                    "warning",
                    "browser_wait",
                    url=page.url,
                    reason="Network activity did not become idle before the capture deadline.",
                )
            page.wait_for_timeout(max(0, int(request.get("wait_ms", 0))))
            page.evaluate(
                """() => {
                    for (const image of document.images) {
                        if (image.currentSrc) image.setAttribute('src', image.currentSrc);
                        image.removeAttribute('srcset');
                        image.removeAttribute('loading');
                    }
                    document.querySelectorAll('script').forEach((node) => node.remove());
                    document.querySelectorAll(
                        'link[rel="modulepreload"], link[rel="prefetch"], '
                        + 'link[rel="preload"][as="script"]'
                    ).forEach((node) => node.remove());
                    document.querySelectorAll(
                        '.cky-consent-container, .cky-modal, .cky-btn-revisit-wrapper, '
                        + '#cookieyes-banner, [id^="cky-"], #userwayAccessibilityIcon, .uwy'
                    ).forEach((node) => node.remove());
                    document.querySelectorAll(
                        'iframe[src*="cookieyes"], iframe[src*="userway"], '
                        + 'iframe[src*="freshworks"], iframe[src*="googletagmanager"]'
                    ).forEach((node) => node.remove());
                    document.querySelectorAll(
                        'link[rel="stylesheet"][href*="userway"], '
                        + 'link[rel="stylesheet"][href*="cookieyes"]'
                    ).forEach((node) => node.remove());
                    document.documentElement.setAttribute(
                        'data-websnapshot-rendered', 'true'
                    );
                }"""
            )

            evidence = []
            max_bytes = max(1, int(request["max_capture_bytes"]))
            if request.get("screenshot"):
                screenshot = page.screenshot(full_page=True, type="png")
                if len(screenshot) <= max_bytes:
                    (output / "screenshot.png").write_bytes(screenshot)
                    evidence.append("screenshot")
                else:
                    diagnostics.record(
                        "skipped",
                        "screenshot_evidence",
                        url=page.url,
                        reason="Screenshot evidence exceeded the configured capture size limit.",
                    )
            if request.get("pdf"):
                pdf = page.pdf(format="A4", print_background=True)
                if len(pdf) <= max_bytes:
                    (output / "page.pdf").write_bytes(pdf)
                    evidence.append("pdf")
                else:
                    diagnostics.record(
                        "skipped",
                        "pdf_evidence",
                        url=page.url,
                        reason="PDF evidence exceeded the configured capture size limit.",
                    )
            body = page.content().encode("utf-8")
            if len(body) > max_bytes:
                raise ValueError("rendered capture exceeded configured size limit")
            (output / "body.bin").write_bytes(body)
            return {
                "contract": CAPTURE_ENGINE_CONTRACT,
                "engine_id": "playwright-browser-v1",
                "final_url": page.url,
                "status": response.status if response else 200,
                "content_type": "text/html; charset=utf-8",
                "evidence": evidence,
                "diagnostics": diagnostics.as_record(0),
            }
        finally:
            browser.close()


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        raise SystemExit("usage: capture_worker.py REQUEST_JSON OUTPUT_DIRECTORY")
    request_path = Path(argv[1]).resolve()
    output = Path(argv[2]).resolve()
    request = _load_request(request_path)
    result = capture(request, output)
    result_path = output / "result.json"
    result_path.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.chmod(result_path, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
