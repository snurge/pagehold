#!/usr/bin/env python3
import base64
import calendar
import hashlib
import hmac
import html
import json
import mimetypes
import os
import re
import secrets
import shutil
import signal
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from datetime import datetime, timedelta, timezone
from email import policy as email_policy
from email.parser import BytesParser
from html.parser import HTMLParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from archive_manifest import ArchiveManifestManager, ManifestError
from asset_store import ContentAddressedAssetStore
from capture_quality import CaptureDiagnostics, diagnostic_url, replay_quality_report, safe_reason
from capture_engine import (
    AUTOMATIC_POLICY_VERSION,
    NATIVE_ENGINE_ID,
    browser_render_reason,
    clear_stale_capture_work,
    run_browser_worker,
    select_capture_engine,
)
from crawl_policy import (
    estimated_upper_bound_bytes,
    normalize_candidate,
    normalized_site_policy,
    url_matches_policy,
)
from metadata_store import (
    ActiveJobExists,
    JobCapacityExceeded,
    MetadataStore,
    MetadataStoreError,
)
from archive_lock import ArchiveDataLock
from product import NAME as PRODUCT_NAME, SOURCE_URL, VERSION as PRODUCT_VERSION
from security import RateLimiter, ValidatingRedirectHandler, validate_outbound_url


ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("WEBSNAPSHOT_DATA_DIR", ROOT / "data")).expanduser().resolve()
SNAPSHOT_DIR = DATA_DIR / "snapshots"
PROFILE_DIR = DATA_DIR / "profiles"
INTEGRITY_DIR = DATA_DIR / "integrity"
CAPTURE_WORK_DIR = DATA_DIR / "capture-work"
STATIC_DIR = ROOT / "static"
STATIC_VERSION = "20260730-pagehold-brand-1"
LEGACY_DB_PATH = DATA_DIR / "db.json"
DB_PATH = DATA_DIR / "websnapshot.sqlite3"
METADATA_STORE = MetadataStore(DB_PATH, LEGACY_DB_PATH)
DATA_LOCK = ArchiveDataLock(DATA_DIR / ".archive.lock")
MANIFEST_MANAGER = ArchiveManifestManager(INTEGRITY_DIR, SNAPSHOT_DIR)
ASSET_STORE = ContentAddressedAssetStore(SNAPSHOT_DIR)

SECRET = os.environ.get("WEBSNAPSHOT_SECRET", "change-me-before-production")
PORT = int(os.environ.get("PORT", "18765"))
BIND = os.environ.get("WEBSNAPSHOT_BIND", "0.0.0.0")
ENVIRONMENT = os.environ.get("WEBSNAPSHOT_ENV", "development").strip().lower()
PRODUCTION = ENVIRONMENT == "production"
CONTAINER_NETWORK = os.environ.get("WEBSNAPSHOT_CONTAINER_NETWORK", "0").strip().lower() in {"1", "true", "yes"}
TRUST_PROXY = os.environ.get("WEBSNAPSHOT_TRUST_PROXY", "0").strip().lower() in {"1", "true", "yes"}
SECURE_COOKIES = PRODUCTION or os.environ.get("WEBSNAPSHOT_SECURE_COOKIES", "0").strip().lower() in {"1", "true", "yes"}
ALLOW_PRIVATE_NETWORKS = os.environ.get("WEBSNAPSHOT_ALLOW_PRIVATE_NETWORKS", "0").strip().lower() in {"1", "true", "yes"}
IGNORE_HTTPS_ERRORS = os.environ.get("WEBSNAPSHOT_IGNORE_HTTPS_ERRORS", "0").strip().lower() in {"1", "true", "yes"}
MAX_REQUEST_BODY_BYTES = int(os.environ.get("WEBSNAPSHOT_MAX_REQUEST_BODY_BYTES", str(64 * 1024)))
MAX_AVATAR_BYTES = int(os.environ.get("WEBSNAPSHOT_MAX_AVATAR_BYTES", str(2 * 1024 * 1024)))
ALLOWED_HOSTS = {
    host.strip().lower()
    for host in os.environ.get("WEBSNAPSHOT_ALLOWED_HOSTS", "").split(",")
    if host.strip()
}
MAX_CAPTURE_BYTES = int(os.environ.get("WEBSNAPSHOT_MAX_CAPTURE_BYTES", str(8 * 1024 * 1024)))
MAX_ASSET_BYTES = int(os.environ.get("WEBSNAPSHOT_MAX_ASSET_BYTES", str(4 * 1024 * 1024)))
MAX_ASSETS_PER_SNAPSHOT = int(os.environ.get("WEBSNAPSHOT_MAX_ASSETS_PER_SNAPSHOT", "120"))
ASSET_FETCH_TIMEOUT = float(os.environ.get("WEBSNAPSHOT_ASSET_FETCH_TIMEOUT", "6"))
ASSET_FETCH_DELAY_SECONDS = float(os.environ.get("WEBSNAPSHOT_ASSET_FETCH_DELAY_SECONDS", "0.25"))
BROWSER_RENDERING_ENABLED = os.environ.get("WEBSNAPSHOT_BROWSER_RENDERING", "1").strip().lower() not in {
    "0",
    "false",
    "no",
}
BROWSER_RENDER_TIMEOUT_MS = int(os.environ.get("WEBSNAPSHOT_BROWSER_RENDER_TIMEOUT_MS", "35000"))
BROWSER_RENDER_WAIT_MS = int(os.environ.get("WEBSNAPSHOT_BROWSER_RENDER_WAIT_MS", "3000"))
CAPTURE_SCREENSHOT_EVIDENCE = os.environ.get(
    "WEBSNAPSHOT_CAPTURE_SCREENSHOT_EVIDENCE", "0"
).strip().lower() in {"1", "true", "yes"}
CAPTURE_PDF_EVIDENCE = os.environ.get(
    "WEBSNAPSHOT_CAPTURE_PDF_EVIDENCE", "0"
).strip().lower() in {"1", "true", "yes"}
CRAWL_DEPTH = int(os.environ.get("WEBSNAPSHOT_CRAWL_DEPTH", "3"))
CRAWL_DELAY_SECONDS = float(os.environ.get("WEBSNAPSHOT_CRAWL_DELAY_SECONDS", "5.0"))
CRAWL_MAX_PAGES = int(os.environ.get("WEBSNAPSHOT_CRAWL_MAX_PAGES", "25"))
SNAPSHOT_DEEPER_CRAWL_MAX_PAGES = int(os.environ.get("WEBSNAPSHOT_SNAPSHOT_DEEPER_CRAWL_MAX_PAGES", "40"))
USER_AGENT = os.environ.get(
    "WEBSNAPSHOT_USER_AGENT",
    f"{PRODUCT_NAME}/{PRODUCT_VERSION} private archival service",
)
MIN_FREE_DISK_BYTES = int(
    os.environ.get("WEBSNAPSHOT_MIN_FREE_DISK_BYTES", str(5 * 1024 * 1024 * 1024))
)
REPEATED_FAILURE_THRESHOLD = max(
    2, int(os.environ.get("WEBSNAPSHOT_REPEATED_FAILURE_THRESHOLD", "3"))
)

LOGIN_LIMITER = RateLimiter(10, 15 * 60)
SIGNUP_LIMITER = RateLimiter(5, 60 * 60)
SHUTDOWN_EVENT = threading.Event()
WORKER_LOCK = threading.Lock()
WORKER_THREADS = set()

class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag not in {"a", "area"}:
            return
        attrs = dict(attrs)
        href = attrs.get("href")
        if href:
            self.links.append(href)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def structured_log(event, level="info", **fields):
    print(
        json.dumps(
            {"time": now_iso(), "level": level, "event": event, **fields},
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )


def parse_iso(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)


def avatar_type(body):
    if body.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "png"
    if body.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", "jpg"
    if body.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif", "gif"
    if len(body) >= 12 and body[:4] == b"RIFF" and body[8:12] == b"WEBP":
        return "image/webp", "webp"
    raise ValueError("Profile picture must be a PNG, JPEG, GIF, or WebP image.")












def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 160_000)
    return f"{salt}${base64.b64encode(digest).decode()}"


def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt).split("$", 1)[1], digest)


def validate_new_password(password):
    if not isinstance(password, str) or len(password) < 12 or len(password) > 256:
        raise ValueError("Password must be between 12 and 256 characters.")
    if password.lower() in {"pagehold", "password", "password123", "websnapshot"}:
        raise ValueError("Choose a less common password.")


def validate_production_configuration(db):
    if len(db["users"]) > 1:
        raise RuntimeError("PageHold supports exactly one local account.")
    if any(user.get("role") != "user" for user in db["users"]):
        raise RuntimeError(
            "The local account must own its archives directly."
        )
    if not PRODUCTION:
        return
    if SECRET == "change-me-before-production" or len(SECRET) < 32:
        raise RuntimeError("Production requires WEBSNAPSHOT_SECRET with at least 32 characters.")
    if not ALLOWED_HOSTS:
        raise RuntimeError("Production requires WEBSNAPSHOT_ALLOWED_HOSTS.")
    loopback_bind = BIND in {"127.0.0.1", "::1", "localhost"}
    isolated_container_bind = CONTAINER_NETWORK and BIND in {"0.0.0.0", "::"}
    if not loopback_bind and not isolated_container_bind:
        raise RuntimeError(
            "Production must bind to loopback, or explicitly use the isolated container profile."
        )


def start_worker(target, name):
    def run():
        try:
            target()
        finally:
            with WORKER_LOCK:
                WORKER_THREADS.discard(threading.current_thread())

    thread = threading.Thread(target=run, name=name, daemon=True)
    with WORKER_LOCK:
        WORKER_THREADS.add(thread)
    thread.start()
    return thread


def new_id(prefix):
    return f"{prefix}_{secrets.token_urlsafe(12)}"


def default_db():
    return {"users": [], "sites": [], "snapshots": [], "events": []}


def load_db():
    ensure_dirs()
    METADATA_STORE.initialize(default_db)
    return METADATA_STORE.load_document()


def mutate_db(callback):
    ensure_dirs()
    METADATA_STORE.initialize(default_db)
    with DATA_LOCK.shared():
        return METADATA_STORE.mutate_document(callback)


def record_event(db, actor_id, action, detail):
    db["events"].append(
        {
            "id": new_id("evt"),
            "actor_id": actor_id,
            "action": action,
            "detail": detail,
            "created_at": now_iso(),
        }
    )


def sign(value):
    sig = hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}.{sig}"


def unsign(value):
    if not value or "." not in value:
        return None
    raw, sig = value.rsplit(".", 1)
    expected = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return raw
    return None


def normalize_url(url):
    url = (url or "").strip()
    if not url:
        raise ValueError("URL is required.")
    if "://" not in url:
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Use a valid http or https URL.")
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def wayback_history_url(url):
    return f"https://web.archive.org/web/*/{normalize_url(url)}"


def provisional_site_name(url):
    host = urllib.parse.urlsplit(url).hostname or url
    return host.removeprefix("www.")[:160]


def safe_local_return(value, fallback="/dashboard"):
    value = str(value or "").strip()
    parsed = urllib.parse.urlsplit(value)
    if (
        not value.startswith("/")
        or value.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or len(value) > 4096
    ):
        return fallback
    return value


def host_key(url):
    host = urllib.parse.urlparse(url).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def canonical_crawl_url(url, query_mode="preserve"):
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    return normalize_candidate(
        urllib.parse.urlunparse(parsed._replace(fragment="", path=path)), query_mode
    )


def looks_like_page(url):
    path = urllib.parse.urlparse(url).path.lower()
    blocked = (
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp",
        ".svg",
        ".ico",
        ".pdf",
        ".zip",
        ".mp4",
        ".mp3",
        ".mov",
        ".avi",
        ".css",
        ".js",
        ".xml",
        ".json",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
    )
    return not path.endswith(blocked)


def internal_links(html_body, page_url, site_url, policy=None):
    parser = LinkExtractor()
    try:
        parser.feed(html_body.decode("utf-8", errors="replace"))
    except Exception:
        return []
    found = []
    site_host = host_key(site_url)
    for href in parser.links:
        href = href.strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute = urllib.parse.urljoin(page_url, href)
        parsed = urllib.parse.urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        if host_key(absolute) != site_host:
            continue
        policy = policy or {}
        absolute = canonical_crawl_url(absolute, policy.get("query_mode", "preserve"))
        if looks_like_page(absolute) and url_matches_policy(
            absolute,
            policy.get("include_patterns"),
            policy.get("exclude_patterns"),
        ):
            found.append(absolute)
    return found


def wayback_display_date(timestamp):
    if not timestamp or len(timestamp) < 8:
        return None
    return f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}"


def snapshot_sort_time(snapshot):
    timestamp = snapshot.get("wayback_timestamp")
    if timestamp and len(timestamp) >= 14:
        try:
            return datetime.strptime(timestamp[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return parse_iso(snapshot.get("created_at")) or datetime.min.replace(tzinfo=timezone.utc)


def checked(value, expected):
    return "selected" if value == expected else ""


def interval_to_days(interval, custom_days=None):
    if interval == "daily":
        return 1
    if interval == "weekly":
        return 7
    if interval == "monthly":
        return 30
    if interval == "yearly":
        return 365
    try:
        return max(1, int(custom_days or 30))
    except ValueError:
        return 30


def next_capture_after(start_iso, interval, custom_days=None):
    days = interval_to_days(interval, custom_days)
    anchor = parse_iso(start_iso)
    if anchor is None:
        raise ValueError("A schedule anchor is required.")
    return (anchor + timedelta(days=days)).isoformat(timespec="seconds")


def validated_timezone(value):
    name = str(value or "UTC").strip()[:100] or "UTC"
    try:
        ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError("Use a valid IANA time zone such as Europe/London or UTC.") from exc
    return name


def validated_clock_time(value, allow_empty=False):
    text = str(value or "").strip()
    if allow_empty and not text:
        return None
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", text):
        raise ValueError("Use a valid 24-hour time such as 02:30.")
    return text


def next_calendar_capture(
    start_iso,
    interval,
    custom_days=None,
    timezone_name="UTC",
    local_time="00:00",
    weekday=0,
    month_day=1,
):
    anchor = parse_iso(start_iso)
    if anchor is None:
        raise ValueError("A schedule anchor is required.")
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    zone = ZoneInfo(validated_timezone(timezone_name))
    local_anchor = anchor.astimezone(zone)
    hour, minute = map(int, validated_clock_time(local_time).split(":"))

    def at_local(day):
        return datetime(day.year, day.month, day.day, hour, minute, tzinfo=zone)

    if interval == "daily":
        candidate = at_local(local_anchor.date())
        if candidate <= local_anchor:
            candidate = at_local(local_anchor.date() + timedelta(days=1))
    elif interval == "weekly":
        target = max(0, min(6, int(weekday)))
        days_ahead = (target - local_anchor.weekday()) % 7
        candidate = at_local(local_anchor.date() + timedelta(days=days_ahead))
        if candidate <= local_anchor:
            candidate = at_local(candidate.date() + timedelta(days=7))
    elif interval == "monthly":
        target_day = max(1, min(31, int(month_day)))

        def in_month(year, month):
            day = min(target_day, calendar.monthrange(year, month)[1])
            return datetime(year, month, day, hour, minute, tzinfo=zone)

        candidate = in_month(local_anchor.year, local_anchor.month)
        if candidate <= local_anchor:
            year = local_anchor.year + (1 if local_anchor.month == 12 else 0)
            month = 1 if local_anchor.month == 12 else local_anchor.month + 1
            candidate = in_month(year, month)
    else:
        candidate = at_local(
            local_anchor.date() + timedelta(days=interval_to_days("custom", custom_days))
        )
    return candidate.astimezone(timezone.utc).isoformat(timespec="seconds")


def capture_window_open(current, settings):
    start = settings.get("capture_window_start")
    end = settings.get("capture_window_end")
    if not start and not end:
        return True
    if not start or not end:
        return False
    zone = ZoneInfo(validated_timezone(settings.get("scheduler_timezone", "UTC")))
    local_clock = current.astimezone(zone).strftime("%H:%M")
    if start == end:
        return True
    if start < end:
        return start <= local_clock < end
    return local_clock >= start or local_clock < end


def active_job_limit():
    return max(1, min(32, int(METADATA_STORE.scheduler_settings()["max_concurrent_jobs"])))


def outbound_opener():
    return urllib.request.build_opener(ValidatingRedirectHandler(ALLOW_PRIVATE_NETWORKS))


def fetch_bytes(url, timeout=25, user_agent=None):
    validate_outbound_url(url, ALLOW_PRIVATE_NETWORKS)
    request = urllib.request.Request(url, headers={"User-Agent": user_agent or USER_AGENT})
    with outbound_opener().open(request, timeout=timeout) as response:
        content_type = response.headers.get("Content-Type", "application/octet-stream")
        body = response.read(MAX_CAPTURE_BYTES + 1)
        if len(body) > MAX_CAPTURE_BYTES:
            raise ValueError("Capture exceeded configured size limit.")
        return response.geturl(), response.status, content_type, body


def needs_browser_render(body):
    return browser_render_reason(body) is not None


def fetch_rendered_html(
    url, timeout=25, user_agent=None, diagnostics=None, evidence=None
):
    diagnostics = diagnostics or CaptureDiagnostics()
    final_url, status, content_type, body, worker_evidence, worker_diagnostics = (
        run_browser_worker(
            worker_script=ROOT / "capture_worker.py",
            work_root=CAPTURE_WORK_DIR,
            url=url,
            timeout_ms=min(
                BROWSER_RENDER_TIMEOUT_MS, max(5000, int(timeout * 1000))
            ),
            wait_ms=BROWSER_RENDER_WAIT_MS,
            user_agent=user_agent or USER_AGENT,
            ignore_https_errors=IGNORE_HTTPS_ERRORS,
            allow_private_networks=ALLOW_PRIVATE_NETWORKS,
            max_capture_bytes=MAX_CAPTURE_BYTES,
            screenshot=CAPTURE_SCREENSHOT_EVIDENCE,
            pdf=CAPTURE_PDF_EVIDENCE,
        )
    )
    diagnostics.merge_record(worker_diagnostics)
    if evidence is not None:
        evidence.update(worker_evidence)
    return final_url, status, content_type, body


def fetch_asset_bytes(url, timeout=None, user_agent=None):
    if ASSET_FETCH_DELAY_SECONDS > 0:
        time.sleep(ASSET_FETCH_DELAY_SECONDS)
    validate_outbound_url(url, ALLOW_PRIVATE_NETWORKS)
    request = urllib.request.Request(url, headers={"User-Agent": user_agent or USER_AGENT})
    with outbound_opener().open(request, timeout=timeout or ASSET_FETCH_TIMEOUT) as response:
        content_type = response.headers.get("Content-Type", "application/octet-stream")
        body = response.read(MAX_ASSET_BYTES + 1)
        if len(body) > MAX_ASSET_BYTES:
            raise ValueError("Asset exceeded configured size limit.")
        return response.geturl(), response.status, content_type, body


def first_frame_src(body):
    text = body.decode("utf-8", errors="replace")
    match = re.search(
        r"<frame\b[^>]*\bsrc\s*=\s*([\"'])(?P<src>.*?)(?:\1)",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return None
    return html.unescape(match.group("src").strip())


def document_title(body):
    text = body.decode("utf-8", errors="replace")
    match = re.search(r"<title\b[^>]*>(.*?)</title\s*>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()
    return title[:160] or None


def wayback_capture_url(timestamp, url):
    return f"https://web.archive.org/web/{timestamp}id_/{url}"


def flatten_single_frame_capture(body, final_url, wayback_timestamp=None):
    frame_src = first_frame_src(body)
    if not frame_src:
        return final_url, body
    frame_url = urllib.parse.urljoin(final_url, frame_src)
    if not safe_asset_url(frame_url):
        return final_url, body
    capture_url = wayback_capture_url(wayback_timestamp, frame_url) if wayback_timestamp else frame_url
    try:
        frame_final_url, frame_status, frame_content_type, frame_body = fetch_bytes(capture_url)
    except Exception:
        return final_url, body
    if frame_status == 200 and "text/html" in frame_content_type.lower() and len(frame_body) > len(body):
        return frame_final_url, frame_body
    return final_url, body


def asset_extension(content_type, url):
    path_ext = Path(urllib.parse.urlparse(url).path).suffix
    if path_ext and len(path_ext) <= 8:
        return path_ext
    return mimetypes.guess_extension(content_type.split(";")[0].strip()) or ".bin"


def local_asset_url(snap_id, asset_id):
    return f"/snapshots/{snap_id}/asset/{asset_id}"


def normalize_existing_local_asset_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.path.startswith("/snapshots/"):
        local = parsed.path
        if parsed.query:
            local += f"?{parsed.query}"
        return local
    return None


def safe_asset_url(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme in {"http", "https"} and parsed.netloc


def wayback_original_parts(base_url):
    parsed = urllib.parse.urlparse(base_url)
    if parsed.netloc != "web.archive.org":
        return None
    match = re.match(r"^/web/(?P<timestamp>\d+)(?:[a-z_]+)?/(?P<original>https?://.+)$", parsed.path)
    if not match:
        return None
    return match.group("timestamp"), urllib.parse.urlparse(match.group("original"))


def resolve_replay_reference(raw_url, base_url):
    raw_url = html.unescape((raw_url or "").strip())
    existing_local = normalize_existing_local_asset_url(raw_url)
    if existing_local:
        return existing_local
    parsed = urllib.parse.urlparse(raw_url)
    parts = wayback_original_parts(base_url)
    if parsed.netloc == "web.archive.org" and "/http:/" in parsed.path and "/http://" not in parsed.path:
        return urllib.parse.urlunparse(parsed._replace(path=parsed.path.replace("/http:/", "/http://", 1)))
    if parsed.netloc == "web.archive.org" and "/https:/" in parsed.path and "/https://" not in parsed.path:
        return urllib.parse.urlunparse(parsed._replace(path=parsed.path.replace("/https:/", "/https://", 1)))
    if parsed.scheme in {"http", "https"} and parsed.netloc == "web.archive.org" and not parsed.path.startswith("/web/") and parts:
        timestamp, original = parts
        original_url = urllib.parse.urlunparse((original.scheme, original.netloc, parsed.path, "", parsed.query, ""))
        return wayback_capture_url(timestamp, original_url)
    if parsed.scheme in {"http", "https"} and parsed.netloc != "web.archive.org" and parts:
        timestamp, _original = parts
        return wayback_capture_url(timestamp, raw_url)
    if parsed.scheme in {"http", "https"}:
        return raw_url
    if parts and raw_url.startswith("/"):
        timestamp, original = parts
        original_url = urllib.parse.urlunparse((original.scheme, original.netloc, raw_url, "", "", ""))
        return wayback_capture_url(timestamp, original_url)
    return urllib.parse.urljoin(base_url, raw_url)


def rewrite_css_urls(css_text, base_url, asset_rewriter, quote_urls=True):
    def css_url(local):
        if not quote_urls:
            return f"url({local})"
        quote = '"' if '"' not in local else "'"
        return f"url({quote}{local}{quote})"

    def replace(match):
        raw = match.group("url").strip().strip("\"'")
        if not raw or raw.startswith(("data:", "#", "mailto:", "tel:")):
            return match.group(0)
        existing_local = normalize_existing_local_asset_url(raw)
        if existing_local:
            return css_url(existing_local)
        local = asset_rewriter(resolve_replay_reference(raw, base_url))
        return css_url(local)

    return re.sub(r"url\(\s*(?P<url>[^)]+?)\s*\)", replace, css_text, flags=re.IGNORECASE)


def rewrite_srcset(value, base_url, asset_rewriter):
    parts = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        bits = item.split()
        if not bits:
            continue
        bits[0] = asset_rewriter(resolve_replay_reference(bits[0], base_url))
        parts.append(" ".join(bits))
    return ", ".join(parts)


def document_base_url(text, fallback_url):
    match = re.search(
        r"<base\b[^>]*\bhref\s*=\s*([\"'])(?P<url>.*?)(?:\1)",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return urllib.parse.urljoin(fallback_url, html.unescape(match.group("url"))) if match else fallback_url


def promote_lazy_image_sources(text):
    """Promote common lazy-image attributes because archived scripts do not run."""

    def promote(tag_match):
        tag = tag_match.group(0)
        lazy_src = re.search(
            r"\b(?:data-src|data-lazy-src|data-original)\s*=\s*([\"'])(?P<url>.*?)(?:\1)",
            tag,
            flags=re.IGNORECASE | re.DOTALL,
        )
        current_src = re.search(
            r"(?<![\w-])src\s*=\s*([\"'])(?P<url>.*?)(?:\1)",
            tag,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if lazy_src and (
            not current_src
            or current_src.group("url").strip().lower().startswith("data:image")
        ):
            replacement = f'src="{html.escape(lazy_src.group("url"), quote=True)}"'
            if current_src:
                tag = tag[: current_src.start()] + replacement + tag[current_src.end() :]
            else:
                tag = tag[:-1] + " " + replacement + ">"
        lazy_srcset = re.search(
            r"\bdata-srcset\s*=\s*([\"'])(?P<url>.*?)(?:\1)",
            tag,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if lazy_srcset and not re.search(
            r"(?<![\w-])srcset\s*=", tag, flags=re.IGNORECASE
        ):
            tag = tag[:-1] + f' srcset="{html.escape(lazy_srcset.group("url"), quote=True)}">'
        return tag

    return re.sub(r"<img\b[^>]*>", promote, text, flags=re.IGNORECASE | re.DOTALL)


def rewrite_css_imports(css_text, base_url, asset_rewriter):
    def replace(match):
        raw = match.group("url").strip()
        local = asset_rewriter(resolve_replay_reference(raw, base_url))
        quote = '"' if '"' not in local else "'"
        media = match.group("media") or ""
        return f"@import {quote}{local}{quote}{media};"

    return re.sub(
        r"@import\s+(?P<quote>[\"'])(?P<url>.*?)(?P=quote)(?P<media>[^;]*);",
        replace,
        css_text,
        flags=re.IGNORECASE | re.DOTALL,
    )


def capture_linked_assets(
    site_id,
    snap_id,
    body,
    base_url,
    existing_assets=None,
    request_timeout=None,
    user_agent=None,
    diagnostics=None,
):
    diagnostics = diagnostics or CaptureDiagnostics()
    if not safe_asset_url(base_url):
        diagnostics.record(
            "skipped", "document", url=base_url, reason="The document base URL is not HTTP or HTTPS."
        )
        return body, existing_assets or []

    text = body.decode("utf-8", errors="replace")
    text = promote_lazy_image_sources(text)
    base_url = document_base_url(text, base_url)
    assets = list(existing_assets or [])
    cache = {
        asset.get("source_url"): local_asset_url(snap_id, asset["id"])
        for asset in assets
        if asset.get("source_url") and asset.get("id") and not asset.get("evidence_kind")
    }
    cache.update(
        {
            asset.get("final_url"): local_asset_url(snap_id, asset["id"])
            for asset in assets
            if asset.get("final_url") and asset.get("id") and not asset.get("evidence_kind")
        }
    )
    next_asset_number = 0
    for asset in assets:
        match = re.match(r"asset_(\d+)$", str(asset.get("id", "")))
        if match:
            next_asset_number = max(next_asset_number, int(match.group(1)))

    def next_asset_id():
        nonlocal next_asset_number
        next_asset_number += 1
        return f"asset_{next_asset_number:03d}"

    def store_asset(asset_url, stage="html_asset"):
        asset_url = urllib.parse.urldefrag(asset_url)[0]
        existing_local = normalize_existing_local_asset_url(asset_url)
        if existing_local:
            return existing_local
        if not safe_asset_url(asset_url):
            return asset_url
        if asset_url in cache:
            return cache[asset_url]
        if len(assets) >= MAX_ASSETS_PER_SNAPSHOT:
            diagnostics.record(
                "skipped",
                "asset_limit",
                url=asset_url,
                reason=f"The per-page limit of {MAX_ASSETS_PER_SNAPSHOT} assets was reached.",
            )
            return asset_url
        try:
            final_url, status, content_type, asset_body = fetch_asset_bytes(
                asset_url, request_timeout, user_agent
            )
            asset_id = next_asset_id()
            rel_path, content_digest, _created = ASSET_STORE.put(asset_body)
            assets.append(
                {
                    "id": asset_id,
                    "source_url": asset_url,
                    "final_url": final_url,
                    "status": status,
                    "content_type": content_type,
                    "bytes": len(asset_body),
                    "file": rel_path,
                    "content_digest": content_digest,
                }
            )
            cache[asset_url] = local_asset_url(snap_id, asset_id)
            cache[final_url] = cache[asset_url]
            diagnostics.record(
                "captured",
                stage,
                url=asset_url,
                status=status,
                content_type=content_type,
                byte_count=len(asset_body),
            )
            return cache[asset_url]
        except Exception as exc:
            diagnostics.record("failed", stage, url=asset_url, reason=exc)
            return asset_url

    def rewrite_attr(match, stage="html_asset"):
        attr = match.group("attr")
        quote = match.group("quote")
        raw = match.group("url")
        if not raw or raw.startswith(("data:", "#", "mailto:", "tel:", "javascript:")):
            return match.group(0)
        existing_local = normalize_existing_local_asset_url(raw)
        if existing_local:
            return f"{attr}{quote}{esc(existing_local)}{quote}"
        local = store_asset(resolve_replay_reference(raw, base_url), stage)
        return f"{attr}{quote}{esc(local)}{quote}"

    def rewrite_srcset_attr(match, stage="html_srcset"):
        attr = match.group("attr")
        quote = match.group("quote")
        raw = match.group("url")
        local = rewrite_srcset(
            raw, base_url, lambda url: store_asset(url, stage)
        )
        return f"{attr}{quote}{esc(local)}{quote}"

    def rewrite_link_tag(match):
        tag = match.group(0)
        tag_lower = tag.lower()
        rel_match = re.search(r"\brel\s*=\s*([\"'])(?P<rel>.*?)(?:\1)", tag_lower, flags=re.IGNORECASE | re.DOTALL)
        rel_values = set((rel_match.group("rel") if rel_match else "").split())
        asset_link = bool(
            rel_values
            & {
                "stylesheet",
                "icon",
                "apple-touch-icon",
                "manifest",
                "preload",
                "modulepreload",
            }
        )
        if not asset_link:
            return tag
        return re.sub(
            r"(?P<attr>\bhref\s*=\s*)(?P<quote>[\"'])(?P<url>.*?)(?P=quote)",
            lambda attr_match: rewrite_attr(attr_match, "html_link"),
            tag,
            count=1,
            flags=re.IGNORECASE | re.DOTALL,
        )

    # Store direct stylesheets before images and before following CSS url(...)
    # references. This prevents a large icon or flag stylesheet from consuming
    # the whole asset allowance before the page's primary stylesheet is saved.
    text = re.sub(r"<link\b[^>]*>", rewrite_link_tag, text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(
        r"(?P<attr>(?<![\w-])(?:src|poster)\s*=\s*)(?P<quote>[\"'])(?P<url>.*?)(?P=quote)",
        lambda attr_match: rewrite_attr(attr_match, "html_asset"),
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(
        r"(?P<attr>(?<![\w-])srcset\s*=\s*)(?P<quote>[\"'])(?P<url>.*?)(?P=quote)",
        lambda attr_match: rewrite_srcset_attr(attr_match, "html_srcset"),
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    # HTML style attributes already have their own quotes, so keep CSS url()
    # values unquoted to avoid producing invalid nested attributes.
    text = rewrite_css_urls(
        text,
        base_url,
        lambda url: store_asset(url, "inline_css"),
        quote_urls=False,
    )

    # Direct page assets now have their places. Use only the remaining allowance
    # for fonts, backgrounds and other nested CSS references.
    def css_dependency_count(asset):
        path = SNAPSHOT_DIR / asset.get("file", "")
        if not path.is_file():
            return 10**9
        return len(re.findall(r"url\(", path.read_text(encoding="utf-8", errors="replace"), flags=re.I))

    # Small, page-specific stylesheets usually contain the fonts and backgrounds
    # needed for faithful rendering. Process large optional icon catalogues last.
    processed_css = set()
    while True:
        css_assets = [
            asset
            for asset in assets
            if "text/css" in asset.get("content_type", "").lower()
            and asset.get("id") not in processed_css
        ]
        if not css_assets:
            break
        existing_asset = min(css_assets, key=css_dependency_count)
        processed_css.add(existing_asset.get("id"))
        css_path = SNAPSHOT_DIR / existing_asset.get("file", "")
        if not css_path.is_file():
            diagnostics.record(
                "failed",
                "css_file",
                url=existing_asset.get("source_url"),
                reason="The localized stylesheet file is missing.",
            )
            continue
        css_body = css_path.read_bytes()
        css_text = css_body.decode("utf-8", errors="replace")
        css_base = existing_asset.get("final_url") or existing_asset.get("source_url") or base_url
        css_rewriter = lambda url: store_asset(url, "css_dependency")
        rewritten_text = rewrite_css_imports(css_text, css_base, css_rewriter)
        rewritten_css = rewrite_css_urls(
            rewritten_text, css_base, css_rewriter
        ).encode("utf-8")
        if rewritten_css != css_body:
            rel_path, content_digest, _created = ASSET_STORE.put(rewritten_css)
            existing_asset["file"] = rel_path
            existing_asset["content_digest"] = content_digest
            existing_asset["bytes"] = len(rewritten_css)
    return text.encode("utf-8"), assets


def append_capture_evidence(assets, evidence, final_url, diagnostics):
    for evidence_kind, evidence_body in evidence.items():
        evidence_id = f"evidence_{evidence_kind}"
        evidence_type = "image/png" if evidence_kind == "screenshot" else "application/pdf"
        rel_path, content_digest, _created = ASSET_STORE.put(evidence_body)
        assets.append(
            {
                "id": evidence_id,
                "source_url": final_url,
                "final_url": final_url,
                "status": 200,
                "content_type": evidence_type,
                "bytes": len(evidence_body),
                "file": rel_path,
                "content_digest": content_digest,
                "evidence_kind": evidence_kind,
            }
        )
        diagnostics.record(
            "captured",
            f"{evidence_kind}_evidence",
            url=final_url,
            status=200,
            content_type=evidence_type,
            byte_count=len(evidence_body),
        )
    return assets


def save_snapshot(
    site_id,
    source_url,
    capture_url,
    kind,
    actor_id=None,
    wayback_timestamp=None,
    capture_run_id=None,
    request_timeout=25,
    user_agent=None,
    capture_engine_policy=AUTOMATIC_POLICY_VERSION,
):
    db = load_db()
    site = find_by_id(db["sites"], site_id)
    if not site:
        raise ValueError("Site not found.")

    diagnostics = CaptureDiagnostics()
    evidence = {}
    final_url, status, content_type, body = fetch_bytes(
        capture_url, request_timeout, user_agent
    )
    source_content_digest = hashlib.sha256(body).hexdigest()
    snap_id = new_id("snap")
    rendered = False
    if "text/html" in content_type.lower():
        final_url, body = flatten_single_frame_capture(body, final_url, wayback_timestamp)
        engine_decision = select_capture_engine(
            body,
            content_type,
            browser_enabled=BROWSER_RENDERING_ENABLED,
            archived_source=bool(wayback_timestamp),
            evidence_requested=(
                CAPTURE_SCREENSHOT_EVIDENCE or CAPTURE_PDF_EVIDENCE
            ),
            policy_version=capture_engine_policy,
        )
        diagnostics.set_engine(
            engine_decision.engine_id,
            engine_decision.reason,
            engine_decision.policy_version,
        )
        if engine_decision.browser_required:
            try:
                final_url, status, content_type, body = fetch_rendered_html(
                    capture_url, request_timeout, user_agent, diagnostics, evidence
                )
            except Exception as exc:
                diagnostics.record(
                    "warning",
                    "browser_engine_fallback",
                    url=capture_url,
                    reason=exc,
                )
                diagnostics.set_engine(
                    NATIVE_ENGINE_ID,
                    "high-fidelity capture failed; lightweight capture was retained",
                    engine_decision.policy_version,
                )
            else:
                rendered = True
    else:
        diagnostics.set_engine(
            NATIVE_ENGINE_ID,
            "response is not an HTML document",
            capture_engine_policy,
        )
    page_title = document_title(body) if "text/html" in content_type.lower() else None
    with DATA_LOCK.shared():
        assets = []
        if "text/html" in content_type.lower():
            body, assets = capture_linked_assets(
                site_id,
                snap_id,
                body,
                final_url,
                request_timeout=request_timeout,
                user_agent=user_agent,
                diagnostics=diagnostics,
            )
        append_capture_evidence(assets, evidence, final_url, diagnostics)
        suffix = ".html" if "text/html" in content_type else mimetypes.guess_extension(content_type.split(";")[0]) or ".bin"
        rel_path = f"{site_id}/{snap_id}{suffix}"
        abs_dir = SNAPSHOT_DIR / site_id
        abs_dir.mkdir(parents=True, exist_ok=True)
        abs_path = SNAPSHOT_DIR / rel_path
        abs_path.write_bytes(body)

        snap = {
            "id": snap_id,
            "site_id": site_id,
            "kind": kind,
            "source_url": source_url,
            "final_url": final_url,
            "status": status,
            "content_type": content_type,
            "bytes": len(body),
            "file": rel_path,
            "assets": assets,
            "rendered": rendered,
            "wayback_timestamp": wayback_timestamp,
            "created_at": now_iso(),
            "created_by": actor_id,
            "capture_run_id": capture_run_id,
            "source_content_digest": source_content_digest,
            "capture_quality": diagnostics.as_record(len(assets)),
        }

        def persist_snapshot(db):
            site = find_by_id(db["sites"], site_id)
            if not site:
                raise ValueError("Site not found.")
            db["snapshots"].append(snap)
            is_entry_page = replay_link_key(source_url) == replay_link_key(site["url"])
            if not wayback_timestamp and kind in {"live", "scheduled"} and is_entry_page:
                if page_title:
                    site["name"] = page_title
                site["last_snapshot_at"] = snap["created_at"]
                site["last_source_digest"] = source_content_digest
                site["next_snapshot_at"] = next_capture_after(
                    site["last_snapshot_at"],
                    site["interval"],
                    site.get("custom_days"),
                )
            record_event(db, actor_id or "system", f"{kind}_snapshot", f"Captured {source_url}")
        mutate_db(persist_snapshot)
    return snap


def finalize_capture_run(capture_run_id, captured, failed, status=None):
    completed_at = now_iso()
    run = METADATA_STORE.get_capture_run(capture_run_id)
    if not run:
        raise ValueError("Capture run not found.")
    db = load_db()
    site = find_by_id(db["sites"], run["site_id"])
    snapshots = [item for item in db["snapshots"] if item.get("capture_run_id") == capture_run_id]
    entry_snapshot_id = run.get("entry_snapshot_id") or (snapshots[0]["id"] if snapshots else None)
    final_status = status or ("complete" if captured and not failed else "partial" if captured else "error")
    changes = {
        "status": final_status,
        "entry_snapshot_id": entry_snapshot_id,
        "captured": captured,
        "failed": failed,
    }
    if snapshots and site:
        pending_run = {**run, **changes}
        try:
            manifest_path, manifest_digest, signed_at = MANIFEST_MANAGER.create(
                METADATA_STORE.archive_profile(), pending_run, site, snapshots
            )
        except ManifestError as exc:
            failed += 1
            changes.update(status="partial", failed=failed)
            mutate_db(
                lambda document: record_event(
                    document,
                    "system",
                    "capture_manifest_failed",
                    f"{capture_run_id}: {exc}",
                )
            )
        else:
            changes.update(
                manifest_path=manifest_path,
                manifest_digest=manifest_digest,
                signed_at=signed_at,
            )
    METADATA_STORE.update_capture_run(capture_run_id, completed_at, **changes)
    return METADATA_STORE.get_capture_run(capture_run_id)


def refresh_capture_manifest(capture_run_id):
    if not capture_run_id:
        return None
    run = METADATA_STORE.get_capture_run(capture_run_id)
    if not run or run["status"] == "running":
        return None
    db = load_db()
    site = find_by_id(db["sites"], run["site_id"])
    snapshots = [item for item in db["snapshots"] if item.get("capture_run_id") == capture_run_id]
    if not site or not snapshots:
        return None
    manifest_path, manifest_digest, signed_at = MANIFEST_MANAGER.create(
        METADATA_STORE.archive_profile(), run, site, snapshots
    )
    METADATA_STORE.update_capture_run(
        capture_run_id,
        now_iso(),
        manifest_path=manifest_path,
        manifest_digest=manifest_digest,
        signed_at=signed_at,
    )
    return manifest_digest


def backfill_capture_manifests():
    db = load_db()
    created = 0
    failed = 0
    for site in db["sites"]:
        for run in METADATA_STORE.list_capture_runs(site["id"], 100000):
            if run.get("manifest_digest") or run.get("status") == "running":
                continue
            try:
                if refresh_capture_manifest(run["id"]):
                    created += 1
            except Exception as exc:
                failed += 1
                mutate_db(
                    lambda document, run_id=run["id"], error=str(exc): record_event(
                        document,
                        "system",
                        "capture_manifest_backfill_failed",
                        f"{run_id}: {error}",
                    )
                )
    return {"created": created, "failed": failed}


def load_robots_policy(site_url, policy):
    if policy["robots_policy"] == "owner_override":
        return None
    parsed = urllib.parse.urlsplit(site_url)
    robots_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/robots.txt", "", ""))
    parser = urllib.robotparser.RobotFileParser()
    parser.set_url(robots_url)
    try:
        _final, status, _content_type, body = fetch_bytes(
            robots_url, policy["request_timeout_seconds"], policy["user_agent"]
        )
        if status >= 400:
            return None
        parser.parse(body.decode("utf-8", errors="replace").splitlines())
    except urllib.error.HTTPError as exc:
        if exc.code not in {401, 403}:
            return None
        parser.parse(["User-agent: *", "Disallow: /"])
    except Exception:
        return None
    return parser


def capture_storage_reservation(page_count):
    evidence_bytes = MAX_CAPTURE_BYTES * (
        int(CAPTURE_SCREENSHOT_EVIDENCE) + int(CAPTURE_PDF_EVIDENCE)
    )
    return estimated_upper_bound_bytes(
        page_count,
        MAX_CAPTURE_BYTES + evidence_bytes,
        MAX_ASSET_BYTES,
        MAX_ASSETS_PER_SNAPSHOT,
    )


def start_site_crawl(
    site_id,
    actor_id,
    kind="live",
    depth=None,
    max_pages=None,
    start_url=None,
    retry_urls=None,
    retry_of_job_id=None,
):
    if SHUTDOWN_EVENT.is_set():
        raise RuntimeError("PageHold is shutting down and is not accepting new jobs.")
    depth = CRAWL_DEPTH if depth is None else max(0, int(depth))
    max_pages = CRAWL_MAX_PAGES if max_pages is None else max(1, int(max_pages))
    db = load_db()
    initial_site = find_by_id(db["sites"], site_id)
    if not initial_site:
        raise ValueError("Site not found.")
    policy = normalized_site_policy(initial_site, USER_AGENT)
    retry_urls = list(dict.fromkeys(retry_urls or []))
    if retry_urls:
        initial_urls = [
            canonical_crawl_url(url, policy["query_mode"]) for url in retry_urls
        ][:max_pages]
    else:
        initial_urls = [
            canonical_crawl_url(start_url or initial_site["url"], policy["query_mode"])
        ]
    initial_urls = [
        url
        for url in initial_urls
        if host_key(url) == host_key(initial_site["url"])
        and looks_like_page(url)
        and url_matches_policy(
            url, policy["include_patterns"], policy["exclude_patterns"]
        )
    ]
    if not initial_urls:
        raise ValueError("No starting URL is permitted by the current crawl policy.")
    reservation_bytes = capture_storage_reservation(max_pages)
    job_id = new_id("job")
    capture_run_id = new_id("capture")
    try:
        METADATA_STORE.create_job(
            job_id,
            site_id,
            actor_id,
            kind,
            "Starting site crawl",
            now_iso(),
            {
                "depth": depth,
                "max_pages": max_pages,
                "start_url": start_url,
                "retry_urls": retry_urls,
                "policy": policy,
                "capture_engine_policy": AUTOMATIC_POLICY_VERSION,
            },
            {"id": capture_run_id, "manifest_id": new_id("manifest"), "kind": kind},
            retry_of_job_id=retry_of_job_id,
            quota_required_bytes=reservation_bytes,
            max_active_jobs=active_job_limit(),
            frontier=[(url, 0) for url in initial_urls],
        )
    except ActiveJobExists as exc:
        return exc.job_id
    structured_log(
        "crawl_job_started",
        job_id=job_id,
        capture_run_id=capture_run_id,
        site_id=site_id,
        actor_id=actor_id,
        kind=kind,
    )
    start_crawl_worker(job_id)
    return job_id


def run_site_crawl(job_id):
    job = METADATA_STORE.get_job(job_id)
    if not job or job["status"] != "running":
        return
    site_id = job["site_id"]
    actor_id = job["actor_id"]
    kind = job["kind"]
    capture_run_id = job["capture_run_id"]
    parameters = job["parameters"]
    depth = max(0, int(parameters.get("depth", CRAWL_DEPTH)))
    max_pages = max(1, int(parameters.get("max_pages", CRAWL_MAX_PAGES)))
    policy = parameters.get("policy")
    capture_engine_policy = parameters.get(
        "capture_engine_policy", AUTOMATIC_POLICY_VERSION
    )
    counts = METADATA_STORE.frontier_counts(job_id)
    captured = counts["captured"]
    failed = counts["failed"]
    try:
        db = load_db()
        site = find_by_id(db["sites"], site_id)
        if not site:
            raise ValueError("Site not found.")
        if not capture_run_id:
            raise ValueError("Crawl capture run is missing.")
        policy = policy or normalized_site_policy(site, USER_AGENT)
        robots = load_robots_policy(site["url"], policy)

        while True:
            user_cancelled = METADATA_STORE.job_cancel_requested(job_id)
            shutting_down = SHUTDOWN_EVENT.is_set()
            if user_cancelled or shutting_down:
                message = (
                    f"Stopped by user after {captured} pages; {failed} failed"
                    if user_cancelled
                    else f"Paused safely after {captured} pages; continuing automatically"
                )
                METADATA_STORE.interrupt_job(
                    job_id,
                    now_iso(),
                    message,
                    auto_resume=shutting_down and not user_cancelled,
                )
                if user_cancelled:
                    finalize_capture_run(
                        capture_run_id, captured, failed, "interrupted"
                    )
                structured_log(
                    "crawl_job_interrupted",
                    "warning",
                    job_id=job_id,
                    capture_run_id=capture_run_id,
                    site_id=site_id,
                    captured=captured,
                    failed=failed,
                    automatic_resume=shutting_down and not user_cancelled,
                )
                return

            frontier = METADATA_STORE.claim_next_frontier(job_id, now_iso())
            if frontier is None:
                break
            page_url = frontier["resource_url"]
            current_depth = int(frontier["depth"])
            METADATA_STORE.update_job(
                job_id,
                now_iso(),
                message=f"Capturing {page_url}",
                captured=captured,
                failed=failed,
            )
            existing = METADATA_STORE.existing_snapshot_for_frontier(job_id, page_url)
            attempt_id = METADATA_STORE.begin_attempt(
                job_id, page_url, now_iso(), current_depth
            )
            if existing is None and robots is not None and not robots.can_fetch(
                policy["user_agent"], page_url
            ):
                finished_at = now_iso()
                METADATA_STORE.finish_attempt(
                    attempt_id,
                    "skipped",
                    finished_at,
                    error="Blocked by robots.txt",
                )
                METADATA_STORE.complete_frontier(
                    frontier["id"],
                    finished_at,
                    "skipped",
                    error="Blocked by robots.txt",
                )
                continue

            try:
                snap = existing or save_snapshot(
                    site_id,
                    page_url,
                    page_url,
                    kind,
                    actor_id,
                    capture_run_id=capture_run_id,
                    request_timeout=policy["request_timeout_seconds"],
                    user_agent=policy["user_agent"],
                    capture_engine_policy=capture_engine_policy,
                )
            except Exception as exc:
                if SHUTDOWN_EVENT.is_set():
                    METADATA_STORE.interrupt_job(
                        job_id,
                        now_iso(),
                        "Paused safely; continuing automatically",
                        auto_resume=True,
                    )
                    return
                finished_at = now_iso()
                METADATA_STORE.finish_attempt(
                    attempt_id, "failed", finished_at, error=str(exc)
                )
                METADATA_STORE.complete_frontier(
                    frontier["id"], finished_at, "failed", error=str(exc)
                )
                mutate_db(
                    lambda current_db: record_event(
                        current_db,
                        actor_id or "system",
                        "crawl_page_failed",
                        f"{page_url}: {exc}",
                    )
                )
            else:
                discovered = []
                if current_depth < depth and "text/html" in snap["content_type"].lower():
                    try:
                        body = (SNAPSHOT_DIR / snap["file"]).read_bytes()
                        discovered = [
                            (link, current_depth + 1)
                            for link in internal_links(
                                body, snap["final_url"], site["url"], policy
                            )
                        ]
                    except Exception as exc:
                        mutate_db(
                            lambda current_db: record_event(
                                current_db,
                                actor_id or "system",
                                "crawl_discovery_failed",
                                f"{page_url}: {exc}",
                            )
                        )
                finished_at = now_iso()
                METADATA_STORE.finish_attempt(
                    attempt_id, "captured", finished_at, snapshot_id=snap["id"]
                )
                METADATA_STORE.complete_frontier(
                    frontier["id"],
                    finished_at,
                    "captured",
                    snapshot_id=snap["id"],
                    discovered=discovered,
                    max_pages=max_pages,
                )

            counts = METADATA_STORE.frontier_counts(job_id)
            captured = counts["captured"]
            failed = counts["failed"]
            METADATA_STORE.update_job(
                job_id,
                now_iso(),
                captured=captured,
                failed=failed,
            )
            if counts["pending"]:
                SHUTDOWN_EVENT.wait(policy["request_delay_seconds"])

        counts = METADATA_STORE.frontier_counts(job_id)
        captured = counts["captured"]
        failed = counts["failed"]

        def finish_crawl(current_db):
            current_site = find_by_id(current_db["sites"], site_id)
            if not current_site:
                return
            current_site["last_crawl_at"] = now_iso()
            if captured == 0:
                current_site["next_snapshot_at"] = (
                    datetime.now(timezone.utc) + timedelta(hours=6)
                ).isoformat(timespec="seconds")
            record_event(
                current_db,
                actor_id or "system",
                "site_crawl_complete",
                f"{current_site['url']}: {captured} captured, {failed} failed",
            )

        mutate_db(finish_crawl)
        METADATA_STORE.update_job(
            job_id,
            now_iso(),
            status="complete",
            message=f"Captured {captured} pages, {failed} failed",
            captured=captured,
            failed=failed,
        )
        finalize_capture_run(capture_run_id, captured, failed)
        structured_log(
            "crawl_job_completed",
            job_id=job_id,
            capture_run_id=capture_run_id,
            site_id=site_id,
            captured=captured,
            failed=failed,
        )
    except Exception as exc:
        if SHUTDOWN_EVENT.is_set():
            METADATA_STORE.interrupt_job(
                job_id,
                now_iso(),
                "Paused safely; continuing automatically",
                auto_resume=True,
            )
            return
        METADATA_STORE.update_job(
            job_id,
            now_iso(),
            status="error",
            message=str(exc),
            captured=captured,
            failed=failed,
        )
        try:
            finalize_capture_run(capture_run_id, captured, failed, "error")
        except Exception:
            pass
        structured_log(
            "crawl_job_failed",
            "error",
            job_id=job_id,
            capture_run_id=capture_run_id,
            site_id=site_id,
            captured=captured,
            failed=failed,
            error=str(exc),
        )


def start_crawl_worker(job_id):
    return start_worker(lambda: run_site_crawl(job_id), f"crawl-{job_id}")


def resume_pending_crawls():
    claimed = METADATA_STORE.claim_auto_resume_jobs(now_iso(), active_job_limit())
    started = []
    for job in claimed:
        structured_log(
            "crawl_job_resumed",
            job_id=job["id"],
            capture_run_id=job["capture_run_id"],
            site_id=job["site_id"],
        )
        try:
            if job["kind"] in {"live", "scheduled", "retry"}:
                start_crawl_worker(job["id"])
            elif job["kind"] == "asset_localization":
                start_worker(
                    lambda job_id=job["id"]: run_asset_localization_job(job_id),
                    f"assets-{job['id']}",
                )
            else:
                raise ValueError(f"Unsupported resumable job kind: {job['kind']}")
        except Exception as exc:
            METADATA_STORE.interrupt_job(
                job["id"],
                now_iso(),
                "Waiting to continue automatically",
                auto_resume=True,
            )
            structured_log(
                "crawl_resume_worker_failed",
                "error",
                job_id=job["id"],
                error=str(exc),
            )
        else:
            started.append(job["id"])
    return started


def crawl_recovery_loop():
    while not SHUTDOWN_EVENT.is_set():
        try:
            resume_pending_crawls()
        except Exception as exc:
            structured_log("crawl_resume_failed", "error", error=str(exc))
        SHUTDOWN_EVENT.wait(5)


def start_asset_localization(site_id, actor_id):
    if SHUTDOWN_EVENT.is_set():
        raise RuntimeError("PageHold is shutting down and is not accepting new jobs.")
    job_id = new_id("job")
    db = load_db()
    html_snapshot_count = len(
        [
            item
            for item in db["snapshots"]
            if item["site_id"] == site_id
            and item.get("kind") != "wayback"
            and "text/html" in item.get("content_type", "").lower()
        ]
    )
    target_ids = [
        item["id"]
        for item in db["snapshots"]
        if item["site_id"] == site_id
        and item.get("kind") != "wayback"
        and "text/html" in item.get("content_type", "").lower()
    ]
    try:
        METADATA_STORE.create_job(
            job_id,
            site_id,
            actor_id,
            "asset_localization",
            "Preparing asset localization",
            now_iso(),
            quota_required_bytes=max(1, html_snapshot_count)
            * MAX_ASSET_BYTES
            * MAX_ASSETS_PER_SNAPSHOT,
            max_active_jobs=active_job_limit(),
            frontier=[
                (f"urn:websnapshot:snapshot:{snapshot_id}", 0)
                for snapshot_id in target_ids
            ],
        )
    except ActiveJobExists as exc:
        return exc.job_id
    start_worker(
        lambda: run_asset_localization_job(job_id), f"assets-{job_id}"
    )
    return job_id


def run_asset_localization_job(job_id):
    job = METADATA_STORE.get_job(job_id)
    if not job or job["status"] != "running":
        return
    site_id = job["site_id"]
    actor_id = job["actor_id"]
    localized = int(job["captured"])
    failed = int(job["failed"])
    try:
        db = load_db()
        site = find_by_id(db["sites"], site_id)
        if not site:
            raise ValueError("Site not found.")
        targets = [
            snap
            for snap in db["snapshots"]
            if snap["site_id"] == site_id
            and snap.get("kind") != "wayback"
            and "text/html" in snap.get("content_type", "").lower()
        ]
        if not METADATA_STORE.list_frontier(job_id):
            METADATA_STORE.enqueue_frontier(
                job_id,
                [
                    (f"urn:websnapshot:snapshot:{snap['id']}", 0)
                    for snap in targets
                ],
                now_iso(),
                max(1, len(targets)),
            )
        target_by_id = {snap["id"]: snap for snap in targets}
        while True:
            user_cancelled = METADATA_STORE.job_cancel_requested(job_id)
            shutting_down = SHUTDOWN_EVENT.is_set()
            if user_cancelled or shutting_down:
                METADATA_STORE.interrupt_job(
                    job_id,
                    now_iso(),
                    "Stopped by user"
                    if user_cancelled
                    else "Paused safely; continuing automatically",
                    auto_resume=shutting_down and not user_cancelled,
                )
                return
            frontier = METADATA_STORE.claim_next_frontier(job_id, now_iso())
            if frontier is None:
                break
            resource_key = frontier["resource_url"]
            snapshot_id = resource_key.rsplit(":", 1)[-1]
            snap = target_by_id.get(snapshot_id)
            if not snap:
                METADATA_STORE.complete_frontier(
                    frontier["id"],
                    now_iso(),
                    "skipped",
                    error="Snapshot is no longer available",
                )
                continue
            previous_success = METADATA_STORE.successful_attempt_snapshot(
                job_id, resource_key
            )
            if previous_success:
                METADATA_STORE.complete_frontier(
                    frontier["id"],
                    now_iso(),
                    "captured",
                    snapshot_id=previous_success,
                )
                continue
            METADATA_STORE.update_job(
                job_id,
                now_iso(),
                message=f"Repairing assets for {snap.get('source_url')}",
                captured=localized,
                failed=failed,
            )
            attempt_id = METADATA_STORE.begin_attempt(
                job_id, resource_key, now_iso()
            )
            try:
                with DATA_LOCK.shared():
                    path = SNAPSHOT_DIR / snap["file"]
                    before = len(snap.get("assets", []))
                    diagnostics = CaptureDiagnostics()
                    diagnostics.browser_rendered = bool(snap.get("rendered"))
                    body, assets = capture_linked_assets(
                        site_id,
                        snap["id"],
                        path.read_bytes(),
                        snap["final_url"],
                        snap.get("assets", []),
                        diagnostics=diagnostics,
                    )
                    path.write_bytes(body)

                    def persist_assets(current_db):
                        current = find_by_id(
                            current_db["snapshots"], snap["id"]
                        )
                        if not current:
                            raise ValueError(
                                "Snapshot was deleted during asset localization."
                            )
                        current["assets"] = assets
                        current["bytes"] = len(body)
                        current["capture_quality"] = diagnostics.as_record(
                            len(assets)
                        )

                    mutate_db(persist_assets)
                    refresh_capture_manifest(snap.get("capture_run_id"))
                localized += max(0, len(assets) - before)
                finished_at = now_iso()
                METADATA_STORE.finish_attempt(
                    attempt_id,
                    "captured",
                    finished_at,
                    snapshot_id=snap["id"],
                )
                METADATA_STORE.complete_frontier(
                    frontier["id"],
                    finished_at,
                    "captured",
                    snapshot_id=snap["id"],
                )
            except Exception as exc:
                if SHUTDOWN_EVENT.is_set():
                    METADATA_STORE.interrupt_job(
                        job_id,
                        now_iso(),
                        "Paused safely; continuing automatically",
                        auto_resume=True,
                    )
                    return
                failed += 1
                finished_at = now_iso()
                METADATA_STORE.finish_attempt(
                    attempt_id, "failed", finished_at, error=str(exc)
                )
                METADATA_STORE.complete_frontier(
                    frontier["id"], finished_at, "failed", error=str(exc)
                )
                mutate_db(
                    lambda current_db: record_event(
                        current_db,
                        actor_id or "system",
                        "asset_localize_failed",
                        f"{snap.get('id')}: {exc}",
                    )
                )
            METADATA_STORE.update_job(
                job_id,
                now_iso(),
                captured=localized,
                failed=failed,
            )
            SHUTDOWN_EVENT.wait(1)
        mutate_db(
            lambda current_db: record_event(
                current_db,
                actor_id or "system",
                "asset_localize_complete",
                f"{site['url']}: {localized} new assets localized, {failed} failed",
            )
        )
        METADATA_STORE.update_job(
            job_id,
            now_iso(),
            status="complete",
            message=f"Localized {localized} new assets, {failed} snapshots failed",
            captured=localized,
            failed=failed,
        )
    except Exception as exc:
        if SHUTDOWN_EVENT.is_set():
            METADATA_STORE.interrupt_job(
                job_id,
                now_iso(),
                "Paused safely; continuing automatically",
                auto_resume=True,
            )
        else:
            METADATA_STORE.update_job(
                job_id,
                now_iso(),
                status="error",
                message=str(exc),
                captured=localized,
                failed=failed,
            )


def find_by_id(items, item_id):
    return next((item for item in items if item.get("id") == item_id), None)


def esc(value):
    return html.escape(str(value or ""), quote=True)


def human_size(value):
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024


def storage_quota_view(summary):
    limit = summary.get("quota_bytes")
    used = int(summary.get("used_bytes") or 0)
    reserved = int(summary.get("reserved_bytes") or 0)
    available = summary.get("available_bytes")
    if limit is None:
        limit_label = "Unlimited"
        available_label = "No limit"
    else:
        limit_label = human_size(limit)
        available_label = human_size(available)
    warning = ""
    if summary.get("over_quota"):
        warning = '<p class="quota-warning">This account is over its allocation. Existing archives remain available, but new storage is blocked.</p>'
    elif summary.get("warning"):
        warning = '<p class="quota-warning">Storage usage and active job reservations have reached the configured warning level.</p>'
    return f"""
<section class="stats quota-stats">
  <div><span>Archive storage used</span><strong>{human_size(used)}</strong></div>
  <div><span>Storage allocation</span><strong>{limit_label}</strong></div>
  <div><span>Available for new work</span><strong>{available_label}</strong></div>
  <div><span>Reserved by running jobs</span><strong>{human_size(reserved)}</strong></div>
</section>{warning}"""


def user_role_label(user):
    return "Archive owner"


def home_for_user(user):
    return "/dashboard"


def registration_available(document=None):
    document = document if document is not None else load_db()
    return len(document["users"]) == 0




def user_initials(user):
    parts = [part for part in re.split(r"\s+", user.get("name", "").strip()) if part]
    if not parts:
        return "?"
    return "".join(part[0].upper() for part in parts[:2])


def avatar_html(user, large=False):
    size_class = " avatar-large" if large else ""
    if user.get("avatar_filename"):
        version = urllib.parse.quote(user.get("avatar_updated_at", ""))
        return (
            f'<img class="avatar{size_class}" src="/users/{esc(user["id"])}/avatar?v={version}" '
            f'alt="{esc(user.get("name") or "Account")} profile picture">'
        )
    return f'<span class="avatar avatar-fallback{size_class}" aria-hidden="true">{esc(user_initials(user))}</span>'


def render_shell(title, body, user=None, notice=None):
    if user:
        primary_navigation = (
            '<a href="/dashboard">My sites</a>'
            '<a href="/search">Search</a><a href="/archive">Public archive</a>'
        )
        auth = (
            primary_navigation
            + '<details class="account-menu">'
            f'<summary>{avatar_html(user)}<span>{esc(user.get("name") or user["email"])}</span></summary>'
            '<div class="account-popover">'
            f'<div class="account-identity"><strong>{esc(user.get("name") or user["email"])}</strong>'
            f'<span>{esc(user["email"])}</span><span>{esc(user_role_label(user))}</span></div>'
            '<a href="/account">Manage account</a>'
            '<form method="post" action="/logout"><button class="ghost">Sign out</button></form>'
            '</div></details>'
        )
    else:
        setup_action = (
            '<a class="button small" href="/signup">Set up PageHold</a>'
            if registration_available()
            else ""
        )
        auth = (
            '<a href="/search">Search</a><a href="/archive">Public archive</a>'
            f'<a href="/login">Log in</a>{setup_action}'
        )
    body = re.sub(r"<main(?=[\s>])", '<main id="main-content" tabindex="-1"', body, count=1)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} · {PRODUCT_NAME}</title>
  <link rel="icon" type="image/png" href="/static/pagehold-icon.png?v={STATIC_VERSION}">
  <link rel="stylesheet" href="/static/styles.css?v={STATIC_VERSION}">
</head>
<body>
  <a class="skip-link" href="#main-content">Skip to content</a>
  <header class="topbar">
    <a class="brand" href="/" aria-label="{PRODUCT_NAME} home"><img src="/static/pagehold-logo.png?v={STATIC_VERSION}" alt="{PRODUCT_NAME}"></a>
    <nav aria-label="Primary navigation">{auth}</nav>
  </header>
  {f'<div class="notice">{esc(notice)}</div>' if notice else ''}
  {body}
  <footer class="product-footer"><span>{PRODUCT_NAME} {PRODUCT_VERSION}</span><span>AGPL-3.0-only</span>{f'<a href="{esc(SOURCE_URL)}" rel="external">Source code</a>' if SOURCE_URL else ''}</footer>
</body>
</html>"""


def landing(user=None):
    if user:
        actions = (
            '<a class="button" href="/dashboard">Open your archive</a>'
            '<a class="button secondary" href="/account">Manage account</a>'
        )
    else:
        actions = (
            '<a class="button" href="/signup">Set up PageHold</a>'
            '<a class="button secondary" href="/login">Log in</a>'
            if registration_available()
            else '<a class="button" href="/login">Log in</a>'
        )
    heading = "Archive the websites that matter to you."
    third_feature = (
        "<article><h2>Simple ownership</h2><p>One local account controls the archive "
        "and its visibility settings.</p></article>"
    )
    return render_shell(
        "Private website archiving",
        f"""
<main>
  <section class="hero">
    <div>
      <p class="eyebrow">Private, scheduled, locally stored web archives</p>
      <h1>{heading}</h1>
      <p class="lede">Add specific sites, capture live snapshots on a schedule, browse independent historical records, and decide what stays private or public.</p>
      <div class="actions">{actions}</div>
    </div>
    <div class="hero-panel">
      <div class="metric"><span>Monthly</span><strong>scheduled captures</strong></div>
      <div class="metric"><span>Private/public</span><strong>per-site visibility</strong></div>
      <div class="metric"><span>Independent</span><strong>History links</strong></div>
    </div>
  </section>
  <section class="feature-grid">
    <article><h2>Curated scope</h2><p>Users manually add the domains and pages they are responsible for. No open Internet crawling.</p></article>
    <article><h2>Local evidence</h2><p>Snapshots are written to local storage with source URL, final URL, status, size, and timestamp metadata.</p></article>
    {third_feature}
  </section>
</main>
""",
        user,
    )


def login_page(user=None, notice=None, return_to=""):
    destination = safe_local_return(return_to, "") if return_to else ""
    hidden_return = (
        f'<input type="hidden" name="return_to" value="{esc(destination)}">'
        if destination else ""
    )
    setup = (
        '<p><a href="/signup">Set up the local account</a></p>'
        if registration_available()
        else ""
    )
    return render_shell(
        "Log in",
        f"""
<main class="narrow">
  <form class="panel" method="post" action="/login">
    <h1>Log in</h1>
    {hidden_return}
    <label>Email<input name="email" autocomplete="username" required></label>
    <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
    <button class="button">Log in</button>
    {setup}
  </form>
</main>
""",
        user,
        notice,
    )


def signup_page(user=None, notice=None):
    setup_intro = (
        "<p>Create the only local account for this archive. Registration closes "
        "automatically when setup is complete.</p>"
    )
    return render_shell(
        "Set up PageHold",
        f"""
<main class="narrow">
  <form class="panel" method="post" action="/signup">
    <h1>Set up PageHold</h1>
    {setup_intro}
    <label>Name<input name="name" autocomplete="name" required></label>
    <label>Email<input type="email" name="email" autocomplete="email" required></label>
    <label>Password<input type="password" name="password" minlength="12" maxlength="256" autocomplete="new-password" required></label>
    <button class="button">Create account</button>
  </form>
</main>
""",
        user,
        notice,
    )










def account_page(user, notice=None):
    return render_shell(
        "Account",
        f"""
<main class="workspace account-workspace">
  <section class="section-head">
    <div><p class="eyebrow">Account</p><h1>Your profile</h1></div>
    <a class="button secondary" href="/dashboard">My sites</a>
  </section>
  <section class="account-grid">
    <form class="panel profile-form" method="post" action="/account/profile" enctype="multipart/form-data">
      <div class="profile-heading">{avatar_html(user, large=True)}<div><h2>{esc(user.get('name') or user['email'])}</h2><p>{esc(user_role_label(user))}</p></div></div>
      <label>Display name<input name="name" maxlength="100" value="{esc(user.get('name') or '')}" required></label>
      <label>Email<input type="email" value="{esc(user['email'])}" readonly></label>
      <label>Profile picture<input type="file" name="avatar" accept="image/png,image/jpeg,image/gif,image/webp"></label>
      {('<label class="check"><input type="checkbox" name="remove_avatar" value="1"> Remove current profile picture</label>' if user.get('avatar_filename') else '')}
      <button class="button">Save profile</button>
    </form>
    <form class="panel" method="post" action="/account/password">
      <h2>Change password</h2>
      <label>Current password<input type="password" name="current_password" autocomplete="current-password" required></label>
      <label>New password<input type="password" name="new_password" minlength="12" maxlength="256" autocomplete="new-password" required></label>
      <label>Confirm new password<input type="password" name="confirm_password" minlength="12" maxlength="256" autocomplete="new-password" required></label>
      <button class="button">Change password</button>
    </form>
  </section>
</main>
""",
        user,
        notice,
    )






def dashboard(user, notice=None):
    db = load_db()
    quota = METADATA_STORE.storage_quota(user["id"])
    sites = [s for s in db["sites"] if s["owner_id"] == user["id"]]
    rows = "".join(site_row(s, db) for s in sites) or '<p class="empty">No sites yet. Add one to take the first live snapshot.</p>'
    add_site = '<a class="button" href="/sites/new">Add site</a>'
    return render_shell(
        "Dashboard",
        f"""
<main class="workspace">
  <section class="section-head">
    <div><p class="eyebrow">Snapshot console</p><h1>Your archived sites</h1></div>
    {add_site}
  </section>
  {storage_quota_view(quota)}
  <form class="archive-search-compact" method="get" action="/search" role="search">
    <label>Search your archive<input type="search" name="q" maxlength="200" placeholder="Site, URL, date, or captured text"></label>
    <button class="button secondary">Search</button>
  </form>
  <section class="table-panel">{rows}</section>
</main>
""",
        user,
        notice,
    )


def site_row(site, db):
    snaps = [s for s in db["snapshots"] if s["site_id"] == site["id"]]
    run_count = len({snap.get("capture_run_id") or snap["id"] for snap in snaps})
    entry_pages = [
        snap
        for snap in snaps
        if replay_link_key(snap.get("source_url", "")) == replay_link_key(site["url"])
    ]
    latest_entry_id = max(entry_pages or snaps, key=snapshot_sort_time)["id"] if snaps else None
    destination = (
        f"/snapshots/{esc(latest_entry_id)}"
        if latest_entry_id and run_count == 1
        else f"/sites/{esc(site['id'])}"
    )
    return f"""
<article class="site-row site-summary-row">
  <div>
    <h2><a href="{destination}">{esc(site['name'])}</a></h2>
    <p>{esc(site['url'])}</p>
  </div>
  <span class="pill">{esc(site['visibility'])}</span>
  <span>{run_count} captures</span>
  <span>{esc(site.get('next_snapshot_at', ''))[:10]}</span>
  <a class="button secondary small" href="/sites/{esc(site['id'])}/edit">Edit</a>
</article>
"""


def new_site_page(user, notice=None, initial_url=""):
    return render_shell(
        "Add site",
        f"""
<main class="narrow wide">
  <form class="panel" method="post" action="/sites">
    <h1>Add a website</h1>
    <label>Website address<input type="text" inputmode="url" autocapitalize="none" spellcheck="false" name="url" value="{esc(initial_url)}" placeholder="example.com" maxlength="2048" required></label>
    <div class="split">
      <label>Visibility<select name="visibility"><option value="private">Private</option><option value="public">Public</option></select></label>
      <label>Capture frequency<select name="interval"><option value="monthly">Monthly</option><option value="weekly">Weekly</option><option value="daily">Daily</option><option value="yearly">Yearly</option></select></label>
    </div>
    <button class="button">Add and start crawl</button>
  </form>
</main>
""",
        user,
        notice,
    )


def site_page(user, site_id, notice=None, edit=False):
    db = load_db()
    site = find_by_id(db["sites"], site_id)
    if not site or not can_view_site(user, site):
        return error_page(user, HTTPStatus.NOT_FOUND, "Site not found.")
    snaps = [s for s in db["snapshots"] if s["site_id"] == site_id]
    snaps.sort(key=snapshot_sort_time, reverse=True)
    can_manage = can_manage_site(user, site)
    if edit and not can_manage:
        return error_page(user, HTTPStatus.NOT_FOUND, "Site not found.")
    show_management = can_manage and edit
    runs = METADATA_STORE.list_capture_runs(site_id, 200)
    snaps_by_run = {}
    for snap in snaps:
        snaps_by_run.setdefault(snap.get("capture_run_id"), []).append(snap)
    run_rows = "".join(
        capture_run_row(run, snaps_by_run.get(run["id"], []), show_management)
        for run in runs
    )
    legacy_rows = "".join(
        snapshot_row(s, show_management) for s in snaps_by_run.get(None, [])
    )
    snap_rows = run_rows + legacy_rows or '<p class="empty">No captures yet.</p>'
    recent_jobs = METADATA_STORE.list_jobs(site_id, 5)
    job_rows = "".join(
        job_row(job["id"], job, show_management) for job in recent_jobs
    )
    job_panel = f'<section class="table-panel job-panel"><h2>Crawl jobs</h2>{job_rows}</section>' if job_rows else ""
    history_url = wayback_history_url(site["url"])
    policy = normalized_site_policy(site, USER_AGENT)
    upper_bound = estimated_upper_bound_bytes(
        site.get("max_pages", CRAWL_MAX_PAGES),
        MAX_CAPTURE_BYTES,
        MAX_ASSET_BYTES,
        MAX_ASSETS_PER_SNAPSHOT,
    )
    upper_bound_gb = upper_bound / (1024 ** 3)
    compare_panel = capture_compare_form(site_id, runs) if len(runs) >= 2 else ""
    policy_panel = ""
    if show_management:
        policy_panel = f"""
  <details class="panel advanced-settings">
    <summary><span>Advanced settings</span><span class="muted">Frequency and crawl limits</span></summary>
    <div class="advanced-settings-body">
    <form method="post" action="/sites/{esc(site_id)}/schedule">
      <h2>Capture frequency</h2>
      <div class="split">
        <label>Frequency<select name="interval"><option value="daily" {checked(site.get('interval'), 'daily')}>Daily</option><option value="weekly" {checked(site.get('interval'), 'weekly')}>Weekly</option><option value="monthly" {checked(site.get('interval'), 'monthly')}>Monthly</option><option value="yearly" {checked(site.get('interval'), 'yearly')}>Yearly</option></select></label>
        <label class="check"><input type="checkbox" name="schedule_paused" value="1" {"checked" if site.get('schedule_paused') else ""}> Pause scheduled captures</label>
      </div>
      <p class="muted">The next check is offset from the time of the latest capture. A new archive is stored only when the homepage source has changed.</p>
      <button class="button secondary">Save frequency</button>
    </form>
    <form method="post" action="/sites/{esc(site_id)}/policy">
      <h2>Crawl policy</h2>
      <p class="muted">Configured safety ceiling: {upper_bound_gb:.1f} GB per run; typical captures are substantially smaller.</p>
      <div class="split">
        <label>Crawl depth<input type="number" name="crawl_depth" min="0" max="5" value="{esc(site.get('crawl_depth', CRAWL_DEPTH))}"></label>
        <label>Maximum pages<input type="number" name="max_pages" min="1" max="500" value="{esc(site.get('max_pages', CRAWL_MAX_PAGES))}"></label>
      </div>
      <div class="split">
        <label>Delay between pages (seconds)<input type="number" name="request_delay_seconds" min="1" max="120" step="0.5" value="{esc(policy['request_delay_seconds'])}"></label>
        <label>Page timeout (seconds)<input type="number" name="request_timeout_seconds" min="5" max="120" step="1" value="{esc(policy['request_timeout_seconds'])}"></label>
      </div>
      <label>User agent<input name="crawl_user_agent" maxlength="240" value="{esc(policy['user_agent'])}"></label>
      <div class="split">
        <label>robots.txt<select name="robots_policy"><option value="respect" {checked(policy['robots_policy'], 'respect')}>Respect</option><option value="owner_override" {checked(policy['robots_policy'], 'owner_override')}>Owner-authorized override</option></select></label>
        <label>Query strings<select name="query_mode"><option value="normalize" {checked(policy['query_mode'], 'normalize')}>Normalize tracking parameters</option><option value="preserve" {checked(policy['query_mode'], 'preserve')}>Preserve</option><option value="drop" {checked(policy['query_mode'], 'drop')}>Drop</option></select></label>
      </div>
      <div class="split">
        <label>Include path patterns<textarea name="include_patterns" rows="3" placeholder="/news/*">{esc(policy['include_patterns'])}</textarea></label>
        <label>Exclude path patterns<textarea name="exclude_patterns" rows="3" placeholder="/logout/*, /cart/*">{esc(policy['exclude_patterns'])}</textarea></label>
      </div>
      <label class="check"><input type="checkbox" name="owner_override_confirmed" value="1"> I confirm I am authorized to archive this site when overriding robots.txt.</label>
      <button class="button secondary">Save crawl policy</button>
    </form>
    </div>
  </details>"""
    edit_action = (
        f'<a class="button" href="/sites/{esc(site_id)}/edit">Edit</a>'
        if can_manage
        else ""
    )
    header_actions = (
        f"""
      <a class="button secondary" href="/sites/{esc(site_id)}">Back to captures</a>
      <form method="post" action="/sites/{esc(site_id)}/snapshot"><button class="button">Crawl now</button></form>
"""
        if show_management
        else f"""
      <a class="button secondary" href="/dashboard">All sites</a>
      {edit_action}
"""
    )
    repair_action = (
        f"""
    <form method="post" action="/sites/{esc(site_id)}/localize-assets">
      <button class="ghost" title="Repairs images, stylesheets, and other assets in captures made directly by PageHold.">Repair captured assets</button>
    </form>
"""
        if show_management
        else ""
    )
    return render_shell(
        site["name"],
        f"""
<main class="workspace">
  <section class="section-head">
    <div><p class="eyebrow">{esc(site['visibility'])} archive</p><h1>{esc(site['name'])}</h1><p>{esc(site['url'])}</p></div>
    <div class="actions compact">
      {header_actions}
    </div>
  </section>
  <section class="stats">
    <div><span>Last capture</span><strong>{esc(site.get('last_snapshot_at') or 'Not yet')[:16]}</strong></div>
    <div><span>Next scheduled</span><strong>{esc(site.get('next_snapshot_at') or '')[:16]}</strong></div>
    <div><span>Capture frequency</span><strong>{esc(site.get('interval', 'monthly')).title()}</strong></div>
  </section>
  <section class="panel settings-panel">
    <div>
      <h2>Earlier history</h2>
      <p class="muted">Browse captures held independently by the Internet Archive.</p>
    </div>
    <a class="button secondary" href="{esc(history_url)}" target="_blank" rel="noopener noreferrer external">Browse on Wayback Machine</a>
    {repair_action}
  </section>
  {policy_panel}
  {job_panel}
  {compare_panel}
  <section class="table-panel">{snap_rows}</section>
</main>
""",
        user,
        notice,
    )


def site_edit_page(user, site_id, notice=None):
    return site_page(user, site_id, notice, edit=True)


def snapshot_row(snap, can_manage=False):
    archived_date = wayback_display_date(snap.get("wayback_timestamp"))
    title = archived_date or esc(snap["created_at"])[:19]
    imported = f"Imported {esc(snap['created_at'])[:19]}" if archived_date else esc(snap["source_url"])
    actions = ""
    if can_manage:
        actions = f"""
  <div class="row-actions">
    <form method="post" action="/snapshots/{esc(snap['id'])}/crawl-deeper">
      <button class="ghost" title="Starts a limited depth-1 crawl from this snapshot source URL. Max {SNAPSHOT_DEEPER_CRAWL_MAX_PAGES} pages.">Crawl deeper</button>
    </form>
    <form method="post" action="/snapshots/{esc(snap['id'])}/delete">
      <button class="danger" title="Deletes this snapshot metadata and stored file.">Delete</button>
    </form>
  </div>
"""
    return f"""
<article class="site-row{' has-actions' if can_manage else ''}">
  <div>
    <h2><a href="/snapshots/{esc(snap['id'])}">{esc(title)}</a></h2>
    <p>{imported}</p>
  </div>
  <span class="pill">{esc(snap['kind'])}</span>
  <span>{esc(snap['status'])}</span>
  <span>{round(int(snap['bytes']) / 1024, 1)} KB</span>
  {actions}
</article>
"""


def capture_run_row(run, snapshots, can_manage=False):
    snapshots = sorted(snapshots, key=lambda item: item["source_url"])
    entry = next(
        (item for item in snapshots if item["id"] == run.get("entry_snapshot_id")),
        snapshots[0] if snapshots else None,
    )
    title = esc(run["started_at"])[:19]
    entry_link = f'<a href="/snapshots/{esc(entry["id"])}">{title}</a>' if entry else title
    manifest_status = "Signed" if run.get("manifest_digest") else "Manifest pending"
    page_label = "page" if len(snapshots) == 1 else "pages"
    failed = int(run.get("failed") or 0)
    captured = int(run.get("captured") or len(snapshots))
    outcome = (
        f"{captured} captured, {failed} failed"
        if failed
        else f"{captured} captured with no recorded failures"
    )
    pages = "".join(snapshot_row(snapshot, can_manage) for snapshot in snapshots)
    return f"""
<section class="capture-run">
  <header class="capture-run-head">
    <div><p class="eyebrow">{esc(run['kind'])} capture</p><h2>{entry_link}</h2></div>
    <span class="pill">{esc(run['status'])}</span>
    <span title="{esc(outcome)}">{len(snapshots)} {page_label}</span>
    <span>{esc(manifest_status)}</span>
  </header>
  <details class="capture-pages-disclosure">
    <summary>Show {len(snapshots)} archived {page_label}</summary>
    <div class="capture-pages">{pages or '<p class="empty">No archived pages remain in this capture.</p>'}</div>
  </details>
</section>
"""


def capture_compare_form(site_id, runs):
    options = "".join(
        f'<option value="{esc(run["id"])}">{esc(run["started_at"])[:19]} · {esc(run["kind"])}</option>'
        for run in runs
    )
    reversed_options = "".join(
        f'<option value="{esc(run["id"])}" {"selected" if index == 1 else ""}>'
        f'{esc(run["started_at"])[:19]} · {esc(run["kind"])}</option>'
        for index, run in enumerate(runs)
    )
    return f"""
  <section class="panel compare-picker">
    <div><h2>Compare captures</h2><p class="muted">See which archived pages and resources changed between two site captures.</p></div>
    <form method="get" action="/sites/{esc(site_id)}/compare">
      <label>Newer capture<select name="right">{options}</select></label>
      <label>Older capture<select name="left">{reversed_options}</select></label>
      <button class="button secondary">Compare</button>
    </form>
  </section>"""


def snapshot_file_bytes(snapshot, limit=None):
    try:
        path = (SNAPSHOT_DIR / snapshot.get("file", "")).resolve()
        root = SNAPSHOT_DIR.resolve()
        path.relative_to(root)
        if not path.is_file() or path.is_symlink():
            return b""
        with path.open("rb") as handle:
            return handle.read(limit + 1 if limit is not None else -1)[:limit]
    except (OSError, ValueError):
        return b""


def searchable_snapshot_text(snapshot, limit=2 * 1024 * 1024):
    content_type = str(snapshot.get("content_type") or "").lower()
    if not any(kind in content_type for kind in ("text/", "json", "xml")):
        return ""
    text = snapshot_file_bytes(snapshot, limit).decode("utf-8", errors="replace")
    if "html" in content_type:
        text = re.sub(r"<(script|style)\b.*?</\1\s*>", " ", text, flags=re.I | re.S)
        text = re.sub(r"<[^>]+>", " ", text)
        text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def search_excerpt(text, query, radius=90):
    if not text or not query:
        return ""
    index = text.casefold().find(query.casefold())
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(text), index + len(query) + radius)
    return ("…" if start else "") + text[start:end].strip() + ("…" if end < len(text) else "")


def archive_search_page(user, parameters):
    query = str(parameters.get("q", [""])[-1]).strip()[:200]
    date_from = str(parameters.get("from", [""])[-1]).strip()[:10]
    date_to = str(parameters.get("to", [""])[-1]).strip()[:10]
    try:
        start = datetime.strptime(date_from, "%Y-%m-%d").replace(tzinfo=timezone.utc) if date_from else None
        end = datetime.strptime(date_to, "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(days=1) if date_to else None
    except ValueError:
        return error_page(user, HTTPStatus.BAD_REQUEST, "Use valid search dates.")
    db = load_db()
    sites_by_id = {site["id"]: site for site in db["sites"]}
    visible_sites = {
        site["id"]: site for site in db["sites"] if can_view_site(user, site)
    }
    results = []
    if query:
        for site in visible_sites.values():
            if query.casefold() in f"{site.get('name', '')} {site.get('url', '')}".casefold():
                results.append(
                    {
                        "kind": "site",
                        "title": site["name"],
                        "url": site["url"],
                        "href": f"/sites/{site['id']}",
                        "date": "Site",
                        "excerpt": "Archive site match",
                    }
                )
                if len(results) >= 100:
                    break
    snapshots = sorted(db["snapshots"], key=snapshot_sort_time, reverse=True)[:500]
    for snapshot in snapshots:
        if len(results) >= 100:
            break
        site = sites_by_id.get(snapshot["site_id"])
        if not site or not can_view_snapshot(user, snapshot, site):
            continue
        captured = snapshot_sort_time(snapshot)
        if start and captured < start:
            continue
        if end and captured >= end:
            continue
        metadata = " ".join(
            str(value or "")
            for value in (
                site.get("name"), site.get("url"), snapshot.get("source_url"),
                snapshot.get("final_url"), wayback_display_date(snapshot.get("wayback_timestamp")),
                snapshot.get("created_at"),
            )
        )
        metadata_match = bool(query and query.casefold() in metadata.casefold())
        content = searchable_snapshot_text(snapshot) if query and not metadata_match else ""
        excerpt = search_excerpt(content, query)
        if query and not metadata_match and not excerpt:
            continue
        if not query and not (start or end):
            continue
        results.append(
            {
                "kind": "content" if excerpt else "page",
                "title": site["name"],
                "url": snapshot.get("source_url") or site["url"],
                "href": f"/snapshots/{snapshot['id']}",
                "date": wayback_display_date(snapshot.get("wayback_timestamp")) or snapshot.get("created_at", "")[:10],
                "excerpt": excerpt or "Archived page metadata match",
            }
        )
    result_rows = "".join(
        f"""<article class="search-result">
  <div><span class="pill">{esc(item['kind'])}</span><span class="search-date">{esc(item['date'])}</span></div>
  <h2><a href="{esc(item['href'])}">{esc(item['title'])}</a></h2>
  <p class="search-url">{esc(item['url'])}</p><p>{esc(item['excerpt'])}</p>
</article>"""
        for item in results
    )
    searched = bool(query or date_from or date_to)
    empty = '<p class="empty">No accessible archive records matched.</p>' if searched else '<p class="empty">Enter a site, URL, date, or phrase from a captured page.</p>'
    return render_shell(
        "Search archives",
        f"""
<main class="workspace search-workspace">
  <section class="section-head"><div><p class="eyebrow">Local archive search</p><h1>Find a capture</h1><p>Results include only archives you are permitted to view.</p></div></section>
  <form class="panel archive-search-form" method="get" action="/search" role="search">
    <label>Site, URL, or captured text<input type="search" name="q" maxlength="200" value="{esc(query)}" placeholder="example.com or a phrase"></label>
    <label>From date<input type="date" name="from" value="{esc(date_from)}"></label>
    <label>To date<input type="date" name="to" value="{esc(date_to)}"></label>
    <button class="button">Search</button>
  </form>
  <section class="search-results" aria-live="polite"><h2>{len(results)} results</h2>{result_rows or empty}</section>
</main>""",
        user,
    )


def snapshot_digest(snapshot):
    body = snapshot_file_bytes(snapshot)
    return hashlib.sha256(body).hexdigest() if body else "missing"


def capture_comparison(user, site_id, parameters):
    db = load_db()
    site = find_by_id(db["sites"], site_id)
    if not site or not can_view_site(user, site):
        return error_page(user, HTTPStatus.NOT_FOUND, "Site not found.")
    runs = {run["id"]: run for run in METADATA_STORE.list_capture_runs(site_id, 500)}
    left = runs.get(str(parameters.get("left", [""])[-1]))
    right = runs.get(str(parameters.get("right", [""])[-1]))
    if not left or not right or left["id"] == right["id"]:
        return error_page(user, HTTPStatus.BAD_REQUEST, "Choose two different captures from this site.")
    snapshots = [item for item in db["snapshots"] if item["site_id"] == site_id]
    left_pages = {replay_link_key(item["source_url"]): item for item in snapshots if item.get("capture_run_id") == left["id"]}
    right_pages = {replay_link_key(item["source_url"]): item for item in snapshots if item.get("capture_run_id") == right["id"]}
    left_keys, right_keys = set(left_pages), set(right_pages)
    added = sorted(right_keys - left_keys)
    removed = sorted(left_keys - right_keys)
    changed = sorted(key for key in left_keys & right_keys if snapshot_digest(left_pages[key]) != snapshot_digest(right_pages[key]))
    unchanged = len(left_keys & right_keys) - len(changed)

    def resources(pages):
        mapped = {}
        for page_key, snapshot in pages.items():
            for asset in snapshot.get("assets", []):
                resource_key = f"{page_key} :: {asset.get('source_url') or asset.get('final_url') or asset.get('id')}"
                body = b"" if asset.get("content_digest") else snapshot_file_bytes(asset)
                mapped[resource_key] = asset.get("content_digest") or (
                    hashlib.sha256(body).hexdigest() if body else f"missing:{asset.get('bytes')}"
                )
        return mapped

    left_assets, right_assets = resources(left_pages), resources(right_pages)
    left_asset_keys, right_asset_keys = set(left_assets), set(right_assets)
    asset_added = sorted(right_asset_keys - left_asset_keys)
    asset_removed = sorted(left_asset_keys - right_asset_keys)
    asset_changed = sorted(key for key in left_asset_keys & right_asset_keys if left_assets[key] != right_assets[key])

    def changes(title, items):
        rows = "".join(f"<li>{esc(item)}</li>" for item in items[:100]) or "<li>None</li>"
        return f"<section class=\"compare-list\"><h2>{esc(title)} <span>{len(items)}</span></h2><ul>{rows}</ul></section>"

    return render_shell(
        f"Compare {site['name']}",
        f"""
<main class="workspace compare-workspace">
  <section class="section-head"><div><p class="eyebrow">Capture comparison</p><h1>{esc(site['name'])}</h1><p>{esc(left['started_at'])[:19]} to {esc(right['started_at'])[:19]}</p></div><a class="button secondary" href="/sites/{esc(site_id)}">Back to site</a></section>
  <section class="stats compare-stats">
    <div><span>Pages added</span><strong>{len(added)}</strong></div><div><span>Pages removed</span><strong>{len(removed)}</strong></div>
    <div><span>Pages changed</span><strong>{len(changed)}</strong></div><div><span>Pages unchanged</span><strong>{unchanged}</strong></div>
  </section>
  <div class="compare-grid">{changes('Added pages', added)}{changes('Removed pages', removed)}{changes('Changed pages', changed)}{changes('Added resources', asset_added)}{changes('Removed resources', asset_removed)}{changes('Changed resources', asset_changed)}</div>
</main>""",
        user,
    )


def job_row(job_id, job, can_manage=False):
    actions = ""
    if can_manage and job.get("status") == "running":
        actions = f'<form method="post" action="/jobs/{esc(job_id)}/cancel"><button class="danger">Cancel</button></form>'
    elif can_manage and job.get("failed", 0) and job.get("kind") in {"live", "scheduled", "retry"}:
        actions = f'<form method="post" action="/jobs/{esc(job_id)}/retry"><button class="ghost">Retry failed</button></form>'
    return f"""
<article class="site-row">
  <div>
    <h2>{esc(job['status']).title()}</h2>
    <p>{esc(job.get('message', ''))}</p>
  </div>
  <span class="pill">{esc(job_id)}</span>
  <span>{esc(job.get('captured', 0))} captured</span>
  <span>{esc(job.get('failed', 0))} failed</span>
  {actions}
</article>
"""


def absolutize_replay_asset_urls(text, replay_origin):
    if not replay_origin:
        return text
    origin = replay_origin.rstrip("/")
    pattern = re.compile(
        r"(?P<prefix>^|[\"'\(=\s])"
        r"(?P<path>/snapshots/[A-Za-z0-9_-]+/asset/[A-Za-z0-9._~-]+)",
        flags=re.MULTILINE,
    )
    return pattern.sub(lambda match: f"{match.group('prefix')}{origin}{match.group('path')}", text)


def replay_link_key(url):
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, "")
    )


def rewrite_replay_navigation(text, final_url, replay_origin, page_map=None):
    page_map = page_map or {}
    origin = (replay_origin or "").rstrip("/")

    def rewrite_anchor(match):
        tag = match.group(0)
        href_match = re.search(
            r"(?P<prefix>(?<![\w-])href\s*=\s*)(?P<quote>[\"'])(?P<url>.*?)(?P=quote)",
            tag,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if not href_match:
            return tag
        raw = html.unescape(href_match.group("url").strip())
        if not raw or raw.startswith(("#", "mailto:", "tel:")):
            return tag
        if raw.lower().startswith(("javascript:", "data:")):
            replacement = f'{href_match.group("prefix")}{href_match.group("quote")}#{href_match.group("quote")}'
            return tag[: href_match.start()] + replacement + tag[href_match.end() :]
        absolute = urllib.parse.urljoin(final_url, raw)
        parsed = urllib.parse.urlsplit(absolute)
        local_snapshot_id = page_map.get(replay_link_key(absolute))
        if local_snapshot_id and origin:
            destination = f"{origin}/snapshots/{local_snapshot_id}/content"
            if parsed.fragment:
                destination += f"#{parsed.fragment}"
            replacement = (
                f'{href_match.group("prefix")}{href_match.group("quote")}'
                f'{html.escape(destination, quote=True)}{href_match.group("quote")}'
            )
            return tag[: href_match.start()] + replacement + tag[href_match.end() :]
        if parsed.scheme not in {"http", "https"}:
            return tag
        replacement = (
            f'{href_match.group("prefix")}{href_match.group("quote")}'
            f'{html.escape(absolute, quote=True)}{href_match.group("quote")}'
        )
        tag = tag[: href_match.start()] + replacement + tag[href_match.end() :]
        if re.search(r"(?<![\w-])target\s*=", tag, flags=re.IGNORECASE):
            tag = re.sub(
                r"(?<![\w-])target\s*=\s*([\"']).*?\1",
                'target="_blank"',
                tag,
                count=1,
                flags=re.IGNORECASE | re.DOTALL,
            )
        else:
            tag = tag[:-1] + ' target="_blank">'
        if re.search(r"(?<![\w-])rel\s*=", tag, flags=re.IGNORECASE):
            tag = re.sub(
                r"(?<![\w-])rel\s*=\s*([\"']).*?\1",
                'rel="noopener noreferrer external"',
                tag,
                count=1,
                flags=re.IGNORECASE | re.DOTALL,
            )
        else:
            tag = tag[:-1] + ' rel="noopener noreferrer external">'
        return tag

    def disable_form(match):
        tag = match.group(0)
        tag = re.sub(
            r"(?<![\w-])action\s*=\s*([\"']).*?\1",
            'action="about:blank"',
            tag,
            count=1,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if not re.search(r"(?<![\w-])action\s*=", tag, flags=re.IGNORECASE):
            tag = tag[:-1] + ' action="about:blank">'
        if not re.search(r"(?<![\w-])inert(?:\s|=|>)", tag, flags=re.IGNORECASE):
            tag = tag[:-1] + " inert>"
        return tag

    def disable_script(match):
        tag = match.group(0)
        if "application/x-websnapshot-disabled" in tag.lower():
            return tag
        if re.search(r"(?<![\w-])type\s*=", tag, flags=re.IGNORECASE):
            return re.sub(
                r"(?<![\w-])type\s*=\s*([\"']).*?\1",
                'type="application/x-websnapshot-disabled"',
                tag,
                count=1,
                flags=re.IGNORECASE | re.DOTALL,
            )
        return tag[:-1] + ' type="application/x-websnapshot-disabled">'

    text = re.sub(r"<a\b[^>]*>", rewrite_anchor, text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<form\b[^>]*>", disable_form, text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<script\b[^>]*>", disable_script, text, flags=re.IGNORECASE | re.DOTALL)
    return text


def prepare_html_replay(body, final_url, replay_origin=None, page_map=None):
    text = body.decode("utf-8", errors="replace")
    text = re.sub(
        r"<iframe\b[^>]*\bsrc\s*=\s*([\"'])[^\"']*googletagmanager\.com[^\"']*\1[^>]*>.*?</iframe>",
        "",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    # The original-site base URL must not redirect locally stored assets back to
    # the live site. Make those URLs absolute to this PageHold instance.
    text = absolutize_replay_asset_urls(text, replay_origin)
    text = rewrite_replay_navigation(text, final_url, replay_origin, page_map)
    text = re.sub(
        r'<meta[^>]+http-equiv=["\']?content-security-policy["\']?[^>]*>',
        "",
        text,
        flags=re.IGNORECASE,
    )
    replay_csp = (
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'self\' data: blob:; '
        'img-src \'self\' data: blob:; '
        'style-src \'self\' \'unsafe-inline\' data: blob:; '
        'script-src \'none\'; '
        'font-src \'self\' data: blob:; '
        'media-src \'self\' data: blob:; '
        'connect-src \'none\'; form-action \'none\'; frame-src \'self\';">'
    )
    replay_fixes = (
        '<style id="websnapshot-replay-fixes">'
        '.preloader{display:none!important;opacity:0!important;visibility:hidden!important}'
        'body:has(.sydney-hero-area .header-slider .slide-item) #masthead.site-header'
        '{background-color:rgba(0,0,0,.46)!important}'
        'body:has(.sydney-hero-area .header-slider .slide-item) #masthead .site-title a,'
        'body:has(.sydney-hero-area .header-slider .slide-item) #masthead .site-description,'
        'body:has(.sydney-hero-area .header-slider .slide-item) #masthead #mainnav a'
        '{color:#fff!important}'
        '.sydney-hero-area:has(.header-slider .slide-item)'
        '{height:100vh!important;height:100svh!important;min-height:420px!important;overflow:hidden!important}'
        '.sydney-hero-area .header-slider,'
        '.sydney-hero-area .header-slider .slides-container'
        '{height:100%!important;min-height:inherit!important}'
        '.sydney-hero-area .header-slider .slide-item{display:none!important}'
        '.sydney-hero-area .header-slider .slide-item:first-child'
        '{display:block!important;position:absolute!important;inset:0!important;height:100%!important;'
        'background-size:cover!important;background-position:center!important}'
        '.sydney-hero-area .header-slider .mobile-slide{display:none!important}'
        '.sydney-hero-area .header-slider .slide-inner'
        '{top:50%!important;transform:translateY(-50%)!important}'
        '.menu-item-has-children:hover>.sub-menu,.menu-item-has-children:focus-within>.sub-menu,'
        '.page_item_has_children:hover>.children,.page_item_has_children:focus-within>.children'
        '{display:block!important;visibility:visible!important;opacity:1!important}'
        '@media(max-width:1024px){'
        'body:has(.sydney-hero-area .header-slider .slide-item) #masthead .btn-menu{display:none!important}'
        'body:has(.sydney-hero-area .header-slider .slide-item) #masthead #mainnav'
        '{display:block!important;float:none!important;clear:both!important;width:100%!important}'
        'body:has(.sydney-hero-area .header-slider .slide-item) #masthead #mainnav>div>ul'
        '{display:flex!important;flex-wrap:wrap!important;justify-content:flex-end!important;gap:4px 16px!important}'
        'body:has(.sydney-hero-area .header-slider .slide-item) #masthead #mainnav>div>ul>li'
        '{float:none!important}'
        '}'
        '</style>'
    )
    safe_base = (replay_origin or "").rstrip("/") + "/" if replay_origin else final_url
    if "<base" not in text.lower():
        base = f'<base href="{esc(safe_base)}">{replay_csp}{replay_fixes}'
        text, count = re.subn(r"(<head\b[^>]*>)", r"\1" + base, text, count=1, flags=re.IGNORECASE)
        if count == 0:
            text = base + text
    else:
        text = re.sub(
            r"<base\b[^>]*>",
            f'<base href="{esc(safe_base)}">',
            text,
            count=1,
            flags=re.IGNORECASE | re.DOTALL,
        )
    if "content-security-policy" not in text.lower():
        injection = replay_csp + replay_fixes
        text, count = re.subn(r"(<head\b[^>]*>)", r"\1" + injection, text, count=1, flags=re.IGNORECASE)
        if count == 0:
            text = injection + text
    elif "websnapshot-replay-fixes" not in text.lower():
        text, count = re.subn(r"(<head\b[^>]*>)", r"\1" + replay_fixes, text, count=1, flags=re.IGNORECASE)
        if count == 0:
            text = replay_fixes + text
    return text.encode("utf-8")


def quality_label(report):
    return {
        "complete": "Complete",
        "warnings": "Warnings",
        "problems": "Problems",
    }.get(report.get("status"), "Unknown")


def snapshot_quality_report(snapshot):
    path = SNAPSHOT_DIR / snapshot.get("file", "")
    if not path.is_file():
        return {
            "status": "problems",
            "asset_count": len(snapshot.get("assets", [])),
            "missing_local_references": [],
            "missing_asset_files": [],
            "remote_dependencies": [],
            "remote_dependency_count": 0,
            "images_without_source": [],
            "images_without_source_count": 0,
            "active_script_count": 0,
            "form_count": 0,
            "frame_count": 0,
            "failed": 1,
            "skipped": 0,
            "warnings": 0,
            "items": [
                {
                    "outcome": "failed",
                    "stage": "snapshot_file",
                    "reason": "The archived page file is missing.",
                }
            ],
            "truncated": 0,
            "browser_rendered": bool(snapshot.get("rendered")),
        }
    replay_body = path.read_bytes()
    if "text/html" in snapshot.get("content_type", "").lower():
        replay_body = prepare_html_replay(
            replay_body,
            snapshot.get("final_url") or snapshot.get("source_url") or "https://replay.invalid/",
            None,
        )
    return replay_quality_report(
        replay_body,
        snapshot.get("assets", []),
        SNAPSHOT_DIR,
        snapshot.get("capture_quality"),
    )


def quality_details(report):
    facts = [
        f"{report['asset_count']} local assets",
        f"{report['remote_dependency_count']} remote dependencies",
        f"{len(report['missing_asset_files']) + len(report['missing_local_references'])} missing local resources",
        f"{report.get('images_without_source_count', 0)} images without a source",
    ]
    if report.get("browser_rendered"):
        facts.append("browser-rendered DOM")
    issue_rows = []
    for item in report.get("items", [])[:20]:
        label = str(item.get("stage", "capture")).replace("_", " ").title()
        detail_parts = [item.get("url"), item.get("reason")]
        detail = ": ".join(str(part) for part in detail_parts if part) or item.get(
            "outcome", "warning"
        )
        issue_rows.append(f"<li><strong>{esc(label)}</strong><span>{esc(detail)}</span></li>")
    for url in report.get("remote_dependencies", [])[:10]:
        issue_rows.append(
            f"<li><strong>Remote dependency</strong><span>{esc(url)}</span></li>"
        )
    for label in report.get("images_without_source", [])[:10]:
        issue_rows.append(
            f"<li><strong>Image without source</strong><span>{esc(label)}</span></li>"
        )
    if report.get("truncated"):
        issue_rows.append(
            f"<li><strong>Additional diagnostics</strong><span>{esc(report['truncated'])} entries omitted from metadata</span></li>"
        )
    issues = (
        f'<ul class="quality-issues">{"".join(issue_rows)}</ul>'
        if issue_rows
        else '<p class="muted">No capture omissions were recorded.</p>'
    )
    return f"""
    <details class="quality-details">
      <summary>Capture quality: {esc(quality_label(report))}</summary>
      <p>{esc(' · '.join(facts))}</p>
      {issues}
    </details>"""


def snapshot_page(user, snap_id):
    db = load_db()
    snap = find_by_id(db["snapshots"], snap_id)
    site = find_by_id(db["sites"], snap["site_id"]) if snap else None
    if not snap or not site or not can_view_snapshot(user, snap, site):
        return error_page(user, HTTPStatus.NOT_FOUND, "Snapshot not found.")
    display_date = wayback_display_date(snap.get("wayback_timestamp")) or esc(snap["created_at"])
    report = snapshot_quality_report(snap)
    quality_panel = quality_details(report) if can_manage_site(user, site) else ""
    evidence_links = "".join(
        f'<a class="button secondary small" target="_blank" rel="noopener" '
        f'href="/snapshots/{esc(snap_id)}/asset/{esc(asset["id"])}">'
        f'{"Screenshot" if asset.get("evidence_kind") == "screenshot" else "PDF"}</a>'
        for asset in snap.get("assets", [])
        if asset.get("evidence_kind") in {"screenshot", "pdf"}
    )
    back_href = f"/sites/{esc(site['id'])}" if can_view_site(user, site) else "/dashboard"
    back_label = "Back to site" if can_view_site(user, site) else "Dashboard"
    history_url = wayback_history_url(site["url"])
    return render_shell(
        "Snapshot",
        f"""
<main class="viewer">
  <section class="viewer-bar">
    <div><strong>{esc(site['name'])}</strong><span>{esc(display_date)} · {esc(snap['kind'])}</span>{quality_panel}</div>
    <div class="viewer-actions">
      {evidence_links}
      <a class="button secondary small" href="{esc(history_url)}" target="_blank" rel="noopener noreferrer external">Wayback history</a>
      <a class="button secondary small" href="{back_href}">{back_label}</a>
    </div>
  </section>
  <iframe sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox" referrerpolicy="no-referrer" src="/snapshots/{esc(snap_id)}/content"></iframe>
</main>
""",
        user,
    )


def archive_page(user=None):
    db = load_db()
    sites = [
        site
        for site in db["sites"]
        if site["visibility"] == "public" and can_view_site(user, site)
    ]
    rows = "".join(site_row(s, db) for s in sites) or '<p class="empty">No public archives yet.</p>'
    return render_shell(
        "Public archive",
        f"""
<main class="workspace">
  <section class="section-head"><div><p class="eyebrow">Public captures</p><h1>Browse public archives</h1></div></section>
  <section class="table-panel">{rows}</section>
</main>
""",
        user,
    )




























def error_page(user, status, message):
    return render_shell(
        status.phrase if hasattr(status, "phrase") else "Error",
        f'<main class="narrow"><div class="panel"><h1>{esc(message)}</h1><a class="button" href="/">Home</a></div></main>',
        user,
    )


def can_view_site(user, site):
    if user and site["owner_id"] == user["id"]:
        return True
    return site["visibility"] == "public"


def can_view_snapshot(user, snap, site=None):
    if not snap:
        return False
    if site is None:
        site = find_by_id(load_db()["sites"], snap["site_id"])
    if not site:
        return False
    return can_view_site(user, site)










def can_manage_site(user, site):
    return bool(user and site and site["owner_id"] == user["id"])


def can_create_sites(user):
    return bool(user)


class Handler(BaseHTTPRequestHandler):
    server_version = f"{PRODUCT_NAME}/{PRODUCT_VERSION}"

    def health_response(self):
        storage = METADATA_STORE.storage_health()
        with WORKER_LOCK:
            worker_count = len(WORKER_THREADS)
        healthy = storage["ok"] and not SHUTDOWN_EVENT.is_set()
        return self.json_response(
            {
                "status": "ok" if healthy else "degraded",
                "mode": "local",
                "time": now_iso(),
                "storage": storage,
                "workers": {
                    "accepting": not SHUTDOWN_EVENT.is_set(),
                    "active": worker_count,
                },
            },
            200 if healthy else 503,
        )

    def do_HEAD(self):
        if not self.valid_request_host():
            return self.send_error(400, "Invalid Host header")
        if urllib.parse.urlparse(self.path).path == "/health":
            return self.health_response()
        return self.send_error(404)

    def do_GET(self):
        if not self.valid_request_host():
            return self.send_error(400, "Invalid Host header")
        user = self.current_user()
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        notice = urllib.parse.parse_qs(parsed_url.query).get("notice", [None])[-1]
        if path.startswith("/static/"):
            return self.serve_static(path)
        if path == "/":
            return self.html(landing(user))
        if path == "/login":
            if user:
                return self.redirect("/dashboard")
            return_to = urllib.parse.parse_qs(parsed_url.query).get("next", [""])[-1]
            return self.html(login_page(user, notice, return_to))
        if path == "/signup":
            if user:
                return self.redirect("/dashboard")
            if not registration_available():
                notice = urllib.parse.quote(
                    "Setup is complete. Log in with the local archive account."
                )
                return self.redirect(f"/login?notice={notice}")
            return self.html(signup_page(user))
        if path == "/account":
            return self.require_user(user, lambda: self.html(account_page(user, notice)))
        if path.startswith("/users/") and path.endswith("/avatar"):
            return self.serve_avatar(user, path.split("/")[2])
        if path == "/dashboard":
            return self.require_user(user, lambda: self.html(dashboard(user, notice)))
        if path == "/search":
            return self.html(
                archive_search_page(user, urllib.parse.parse_qs(parsed_url.query))
            )
        if path == "/sites/new":
            return self.require_user(
                user,
                lambda: self.html(
                    new_site_page(
                        user,
                        notice,
                        urllib.parse.parse_qs(parsed_url.query).get("url", [""])[-1],
                    )
                ),
            )
        if path.startswith("/sites/") and path.endswith("/compare"):
            return self.html(
                capture_comparison(
                    user,
                    path.split("/")[2],
                    urllib.parse.parse_qs(parsed_url.query),
                )
            )
        if path.startswith("/sites/") and path.endswith("/edit"):
            return self.html(site_edit_page(user, path.split("/")[2], notice))
        if path.startswith("/sites/"):
            return self.html(site_page(user, path.split("/", 2)[2], notice))
        if path == "/archive":
            return self.html(archive_page(user))
        if path == "/health":
            return self.health_response()
        if path.startswith("/snapshots/") and "/asset/" in path:
            parts = path.split("/")
            return self.snapshot_asset(user, parts[2], parts[4])
        if path.startswith("/snapshots/") and path.endswith("/content"):
            return self.snapshot_content(user, path.split("/")[2])
        if path.startswith("/snapshots/"):
            return self.html(snapshot_page(user, path.split("/", 2)[2]))
        if path.startswith("/jobs/"):
            job = METADATA_STORE.get_job(path.split("/", 2)[2])
            if not job:
                return self.json_response({"status": "unknown"}, 404)
            site = find_by_id(load_db()["sites"], job["site_id"])
            if not can_manage_site(user, site):
                return self.json_response({"status": "unknown"}, 404)
            return self.json_response(job)
        self.send_error(404)

    def do_POST(self):
        if not self.valid_request_host():
            return self.send_error(400, "Invalid Host header")
        path = urllib.parse.urlparse(self.path).path
        user = self.current_user()
        try:
            form_limit = (
                MAX_AVATAR_BYTES + MAX_REQUEST_BODY_BYTES
                if path == "/account/profile"
                else MAX_REQUEST_BODY_BYTES
            )
            form = self.form(form_limit)
            self.require_valid_csrf(form)
            if path == "/signup":
                if not SIGNUP_LIMITER.allow(self.client_ip()):
                    return self.html(
                        signup_page(None, "Too many setup attempts. Try again later."), 429
                    )
                return self.signup(form)
            if path == "/login":
                if not LOGIN_LIMITER.allow(self.client_ip()):
                    return self.html(
                        login_page(None, "Too many login attempts. Try again later."), 429
                    )
                return self.login(form)
            if path == "/logout":
                return self.logout()
            if path == "/account/profile":
                return self.require_user(user, lambda: self.update_profile(user, form))
            if path == "/account/password":
                return self.require_user(user, lambda: self.update_password(user, form))
            if path == "/sites":
                return self.require_user(user, lambda: self.create_site(user, form))
            if path.startswith("/sites/") and path.endswith("/snapshot"):
                site_id = path.split("/")[2]
                return self.require_user(user, lambda: self.capture_now(user, site_id))
            if path.startswith("/sites/") and path.endswith("/policy"):
                site_id = path.split("/")[2]
                return self.require_user(
                    user, lambda: self.update_site_crawl_policy(user, site_id, form)
                )
            if path.startswith("/sites/") and path.endswith("/schedule"):
                site_id = path.split("/")[2]
                return self.require_user(
                    user, lambda: self.update_site_schedule(user, site_id, form)
                )
            if path.startswith("/sites/") and path.endswith("/import-wayback"):
                site_id = path.split("/")[2]
                return self.require_user(
                    user, lambda: self.retired_wayback_import(user, site_id)
                )
            if path.startswith("/sites/") and path.endswith("/localize-assets"):
                site_id = path.split("/")[2]
                return self.require_user(
                    user, lambda: self.localize_site_assets(user, site_id)
                )
            if path.startswith("/snapshots/") and path.endswith("/delete"):
                snap_id = path.split("/")[2]
                return self.require_user(user, lambda: self.delete_snapshot(user, snap_id))
            if path.startswith("/snapshots/") and path.endswith("/crawl-deeper"):
                snap_id = path.split("/")[2]
                return self.require_user(
                    user, lambda: self.crawl_deeper_from_snapshot(user, snap_id)
                )
            if path.startswith("/jobs/") and path.endswith("/cancel"):
                job_id = path.split("/")[2]
                return self.require_user(user, lambda: self.cancel_crawl_job(user, job_id))
            if path.startswith("/jobs/") and path.endswith("/retry"):
                job_id = path.split("/")[2]
                return self.require_user(user, lambda: self.retry_failed_job(user, job_id))
        except PermissionError as exc:
            return self.html(error_page(user, HTTPStatus.FORBIDDEN, str(exc)), 403)
        except Exception as exc:
            if user and path.startswith("/account/"):
                return self.html(account_page(user, str(exc)), 400)
            return self.html(
                dashboard(user, str(exc)) if user else login_page(None, str(exc)), 400
            )
        self.send_error(404)





    def current_user(self):
        session = self.cookie("session")
        signed_session = unsign(session)
        if not signed_session:
            return None
        legacy = not signed_session.startswith("session:")
        if legacy:
            user_id = signed_session
            presented_version = 1
        else:
            try:
                prefix, user_id, version = signed_session.split(":", 2)
            except ValueError:
                return None
            if prefix != "session" or not version.isdigit():
                return None
            presented_version = int(version)
        db = load_db()
        user = find_by_id(db["users"], user_id)
        if (
            not user
            or user.get("status") != "active"
            or not user.get("email_verified_at")
            or int(user.get("session_version", 1)) != presented_version
        ):
            return None
        return user

    def form(self, max_bytes=MAX_REQUEST_BODY_BYTES):
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request body length.") from exc
        if size < 0 or size > max_bytes:
            raise ValueError("Request body exceeded the configured limit.")
        content_type = self.headers.get("Content-Type", "")
        raw = self.rfile.read(size)
        if "application/x-www-form-urlencoded" in content_type:
            parsed = urllib.parse.parse_qs(raw.decode("utf-8"), max_num_fields=100)
            return {k: v[-1] for k, v in parsed.items()}
        if "multipart/form-data" in content_type:
            message = BytesParser(policy=email_policy.default).parsebytes(
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii") + raw
            )
            if not message.is_multipart():
                raise ValueError("Invalid multipart form.")
            fields = {}
            for part in message.iter_parts():
                if part.get_content_disposition() != "form-data":
                    continue
                name = part.get_param("name", header="content-disposition")
                if not name or len(fields) >= 100:
                    continue
                filename = part.get_filename()
                payload = part.get_payload(decode=True) or b""
                if filename is not None:
                    fields[name] = {
                        "filename": filename,
                        "content_type": part.get_content_type(),
                        "body": payload,
                    }
                else:
                    fields[name] = payload.decode(part.get_content_charset() or "utf-8")
            return fields
        raise ValueError("Unsupported form content type.")

    def signup(self, form):
        email = form.get("email", "").strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
            raise ValueError("Enter a valid email address.")
        validate_new_password(form.get("password", ""))
        created_at = now_iso()
        user = {
            "id": new_id("usr"),
            "email": email,
            "name": form.get("name", "").strip() or email,
            "password": hash_password(form.get("password", "")),
            "role": "user",
            "status": "active",
            "created_at": created_at,
            "last_login_at": None,
            "email_verified_at": created_at,
            "session_version": 1,
        }
        def add_user(db):
            if db["users"]:
                raise ValueError(
                    "Setup is already complete. Log in with the local archive account."
                )
            if find_user_by_email(db, email):
                raise ValueError("An account already exists for that email.")
            db["users"].append(user)
            record_event(
                db, user["id"], "local_setup", f"{user['email']} created the local account"
            )
        try:
            mutate_db(add_user)
        except ValueError as exc:
            if not registration_available():
                notice = urllib.parse.quote(str(exc))
                return self.redirect(f"/login?notice={notice}")
            return self.html(signup_page(None, str(exc)), 400)
        return self.set_session(user["id"], "/dashboard")

    def login(self, form):
        return_to = safe_local_return(form.get("return_to"), home_for_user(None))
        if len(form.get("password", "")) > 256:
            raise ValueError("Invalid credentials.")
        db = load_db()
        user = find_user_by_email(db, form.get("email", "").strip().lower())
        if not user or not verify_password(form.get("password", ""), user["password"]):
            return self.html(login_page(None, "Invalid credentials.", return_to), 401)
        if user["status"] != "active":
            return self.html(login_page(None, "This account is suspended.", return_to), 403)
        if not user.get("email_verified_at"):
            return self.html(
                login_page(
                    None,
                    "Confirm your email address before signing in.",
                    return_to,
                ),
                403,
            )
        def record_login(current_db):
            current_user = find_by_id(current_db["users"], user["id"])
            if not current_user or current_user.get("status") != "active":
                raise ValueError("This account is no longer active.")
            current_user["last_login_at"] = now_iso()
            record_event(current_db, user["id"], "login", f"{user['email']} logged in")
        mutate_db(record_login)
        return self.set_session(user["id"], return_to or home_for_user(user))





    def logout(self):
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", self.cookie_header("session", "", same_site="Lax", max_age=0))
        self.security_headers()
        self.end_headers()

    def update_profile(self, user, form):
        name = str(form.get("name", "")).strip()
        if not name or len(name) > 100:
            raise ValueError("Display name must be between 1 and 100 characters.")
        remove_avatar = form.get("remove_avatar") == "1"
        upload = form.get("avatar")
        avatar_update = None
        if isinstance(upload, dict) and upload.get("body"):
            body = upload["body"]
            if len(body) > MAX_AVATAR_BYTES:
                raise ValueError(f"Profile picture must be no larger than {human_size(MAX_AVATAR_BYTES)}.")
            content_type, extension = avatar_type(body)
            avatar_update = (body, content_type, extension)

        user_dir = PROFILE_DIR / user["id"]
        next_filename = None
        if avatar_update:
            body, content_type, extension = avatar_update
            user_dir.mkdir(parents=True, exist_ok=True)
            next_filename = f"avatar.{extension}"
            temporary = user_dir / f".{next_filename}.{secrets.token_hex(6)}.tmp"
            with temporary.open("wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, user_dir / next_filename)

        def apply_profile(current_db):
            current_user = find_by_id(current_db["users"], user["id"])
            if not current_user or current_user.get("status") != "active":
                raise ValueError("Account not found.")
            current_user["name"] = name
            if avatar_update:
                current_user["avatar_filename"] = next_filename
                current_user["avatar_content_type"] = avatar_update[1]
                current_user["avatar_updated_at"] = now_iso()
            elif remove_avatar:
                current_user.pop("avatar_filename", None)
                current_user.pop("avatar_content_type", None)
                current_user.pop("avatar_updated_at", None)
            record_event(current_db, user["id"], "profile_updated", f"{current_user['email']} updated their profile")

        mutate_db(apply_profile)
        if avatar_update or remove_avatar:
            for path in user_dir.glob("avatar.*") if user_dir.exists() else []:
                if not next_filename or path.name != next_filename:
                    path.unlink(missing_ok=True)
        notice = urllib.parse.quote("Profile updated.")
        return self.redirect(f"/account?notice={notice}")

    def update_password(self, user, form):
        current_password = str(form.get("current_password", ""))
        new_password = str(form.get("new_password", ""))
        confirm_password = str(form.get("confirm_password", ""))
        if not verify_password(current_password, user["password"]):
            raise ValueError("Current password is incorrect.")
        if new_password != confirm_password:
            raise ValueError("New password confirmation does not match.")
        validate_new_password(new_password)
        if verify_password(new_password, user["password"]):
            raise ValueError("Choose a password different from your current password.")

        def apply_password(current_db):
            current_user = find_by_id(current_db["users"], user["id"])
            if not current_user or current_user.get("status") != "active":
                raise ValueError("Account not found.")
            if not verify_password(current_password, current_user["password"]):
                raise ValueError("Current password is incorrect.")
            current_user["password"] = hash_password(new_password)
            current_user["session_version"] = int(
                current_user.get("session_version", 1)
            ) + 1
            record_event(current_db, user["id"], "password_changed", f"{current_user['email']} changed their password")

        mutate_db(apply_password)
        notice = urllib.parse.quote("Password changed.")
        return self.set_session(user["id"], f"/account?notice={notice}")


    def create_site(self, user, form):
        if not can_create_sites(user):
            raise PermissionError("End-user access required.")
        url = normalize_url(form.get("url"))
        site = {
            "id": new_id("site"),
            "owner_id": user["id"],
            "name": provisional_site_name(url),
            "url": url,
            "visibility": form.get("visibility") if form.get("visibility") in {"public", "private"} else "private",
            "interval": form.get("interval") if form.get("interval") in {"daily", "weekly", "monthly", "yearly"} else "monthly",
            "custom_days": None,
            "schedule_timezone": "UTC",
            "schedule_time": "00:00",
            "schedule_weekday": 0,
            "schedule_month_day": 1,
            "schedule_paused": False,
            "change_policy": "homepage_changed",
            "last_source_digest": None,
            "crawl_depth": CRAWL_DEPTH,
            "max_pages": CRAWL_MAX_PAGES,
            "request_delay_seconds": CRAWL_DELAY_SECONDS,
            "wayback_enabled": False,
            "wayback_frequency": "yearly",
            "wayback_limit": 20,
            "created_at": now_iso(),
            "last_snapshot_at": None,
            "next_snapshot_at": now_iso(),
        }
        METADATA_STORE.assert_storage_available(
            user["id"], capture_storage_reservation(site["max_pages"])
        )
        def add_site(db):
            if not find_by_id(db["users"], user["id"]):
                raise ValueError("User account not found.")
            db["sites"].append(site)
            record_event(db, user["id"], "site_added", f"Added {url}")
        mutate_db(add_site)
        try:
            job_id = start_site_crawl(
                site["id"],
                user["id"],
                "live",
                site.get("crawl_depth", CRAWL_DEPTH),
                site.get("max_pages", CRAWL_MAX_PAGES),
            )
            notice = f"Site added. Slow crawl started: {job_id}"
        except Exception as exc:
            notice = f"Site added, but the crawl could not start: {exc}"
        return self.redirect(f"/dashboard?notice={urllib.parse.quote(notice)}")





    def update_site_crawl_policy(self, user, site_id, form):
        db = load_db()
        site = find_by_id(db["sites"], site_id)
        if not site or not can_manage_site(user, site):
            return self.html(error_page(user, HTTPStatus.NOT_FOUND, "Site not found."), 404)
        robots_policy = form.get("robots_policy", "respect")
        if robots_policy not in {"respect", "owner_override"}:
            robots_policy = "respect"
        if robots_policy == "owner_override" and form.get("owner_override_confirmed") != "1":
            raise ValueError("Confirm authorization before overriding robots.txt.")
        query_mode = form.get("query_mode", "normalize")
        if query_mode not in {"preserve", "normalize", "drop"}:
            query_mode = "normalize"
        policy = {
            "request_delay_seconds": max(
                1.0, min(120.0, float(form.get("request_delay_seconds") or CRAWL_DELAY_SECONDS))
            ),
            "request_timeout_seconds": max(
                5.0, min(120.0, float(form.get("request_timeout_seconds") or 25.0))
            ),
            "crawl_user_agent": (form.get("crawl_user_agent") or USER_AGENT).strip()[:240],
            "robots_policy": robots_policy,
            "include_patterns": (form.get("include_patterns") or "")[:4000],
            "exclude_patterns": (form.get("exclude_patterns") or "")[:4000],
            "query_mode": query_mode,
            "crawl_depth": max(0, min(5, int(form.get("crawl_depth") or CRAWL_DEPTH))),
            "max_pages": max(1, min(500, int(form.get("max_pages") or CRAWL_MAX_PAGES))),
        }

        def update(current_db):
            current = find_by_id(current_db["sites"], site_id)
            if not current or not can_manage_site(user, current):
                raise ValueError("Site not found.")
            current.update(policy)
            record_event(
                current_db,
                user["id"],
                "crawl_policy_updated",
                f"Updated crawl policy for {current['url']}",
            )

        mutate_db(update)
        notice = urllib.parse.quote("Crawl policy saved.")
        return self.redirect(f"/sites/{site_id}/edit?notice={notice}")

    def update_site_schedule(self, user, site_id, form):
        db = load_db()
        site = find_by_id(db["sites"], site_id)
        if not site or not can_manage_site(user, site):
            return self.html(error_page(user, HTTPStatus.NOT_FOUND, "Site not found."), 404)
        interval = form.get("interval", "monthly")
        if interval not in {"daily", "weekly", "monthly", "yearly"}:
            raise ValueError("Choose a supported schedule frequency.")
        paused = form.get("schedule_paused") == "1"
        anchor = site.get("last_snapshot_at") or now_iso()
        next_at = next_capture_after(anchor, interval)

        def update(current_db):
            current = find_by_id(current_db["sites"], site_id)
            if not current or not can_manage_site(user, current):
                raise ValueError("Site not found.")
            current.update(
                {
                    "interval": interval,
                    "custom_days": None,
                    "schedule_paused": paused,
                    "change_policy": "homepage_changed",
                    "next_snapshot_at": next_at,
                }
            )
            record_event(
                current_db,
                user["id"],
                "site_schedule_updated",
                f"Updated capture schedule for {current['url']}",
            )

        mutate_db(update)
        notice = urllib.parse.quote("Capture schedule saved.")
        return self.redirect(f"/sites/{site_id}/edit?notice={notice}")



    def cancel_crawl_job(self, user, job_id, return_path=None):
        job = METADATA_STORE.get_job(job_id)
        site = find_by_id(load_db()["sites"], job["site_id"]) if job else None
        if not job or not site or not can_manage_site(user, site):
            return self.html(error_page(user, HTTPStatus.NOT_FOUND, "Crawl job not found."), 404)
        requested = METADATA_STORE.request_job_cancel(job_id, now_iso())
        notice = urllib.parse.quote(
            "Cancellation requested." if requested else "That crawl has already finished."
        )
        destination = return_path or f"/sites/{site['id']}/edit"
        return self.redirect(f"{destination}?notice={notice}")

    def retry_failed_job(self, user, job_id, return_path=None):
        job = METADATA_STORE.get_job(job_id)
        site = find_by_id(load_db()["sites"], job["site_id"]) if job else None
        if not job or not site or not can_manage_site(user, site):
            return self.html(error_page(user, HTTPStatus.NOT_FOUND, "Crawl job not found."), 404)
        if job["status"] == "running":
            raise ValueError("Wait for the current crawl to finish before retrying failures.")
        if job["kind"] not in {"live", "scheduled", "retry"}:
            raise ValueError("Only failed live-site pages can be retried from this control.")
        retry_urls = METADATA_STORE.failed_attempt_urls(job_id)
        if not retry_urls:
            raise ValueError("This crawl has no failed pages to retry.")
        retry_id = start_site_crawl(
            site["id"],
            user["id"],
            "retry",
            depth=0,
            max_pages=min(500, len(retry_urls)),
            retry_urls=retry_urls,
            retry_of_job_id=job_id,
        )
        notice = urllib.parse.quote(f"Retry started: {retry_id}")
        destination = return_path or f"/sites/{site['id']}/edit"
        return self.redirect(f"{destination}?notice={notice}")

    def capture_now(self, user, site_id):
        db = load_db()
        site = find_by_id(db["sites"], site_id)
        if not site or not can_manage_site(user, site):
            return self.html(error_page(user, HTTPStatus.NOT_FOUND, "Site not found."), 404)
        job_id = start_site_crawl(
            site_id,
            user["id"],
            "live",
            site.get("crawl_depth", CRAWL_DEPTH),
            site.get("max_pages", CRAWL_MAX_PAGES),
        )
        notice = urllib.parse.quote(f"Slow crawl started: {job_id}")
        return self.redirect(f"/sites/{site_id}/edit?notice={notice}")

    def retired_wayback_import(self, user, site_id):
        db = load_db()
        site = find_by_id(db["sites"], site_id)
        if not site or not can_manage_site(user, site):
            return self.html(error_page(user, HTTPStatus.NOT_FOUND, "Site not found."), 404)
        notice = urllib.parse.quote(
            "Wayback importing has been retired. Use Browse on Wayback Machine to view its independent history."
        )
        return self.redirect(f"/sites/{site_id}/edit?notice={notice}")

    def localize_site_assets(self, user, site_id):
        db = load_db()
        site = find_by_id(db["sites"], site_id)
        if not site or not can_manage_site(user, site):
            return self.html(error_page(user, HTTPStatus.NOT_FOUND, "Site not found."), 404)
        job_id = start_asset_localization(site_id, user["id"])
        notice = urllib.parse.quote(f"Asset localization started: {job_id}")
        return self.redirect(f"/sites/{site_id}/edit?notice={notice}")

    def delete_snapshot(self, user, snap_id):
        db = load_db()
        snap = find_by_id(db["snapshots"], snap_id)
        site = find_by_id(db["sites"], snap["site_id"]) if snap else None
        if not snap or not can_manage_site(user, site):
            return self.html(error_page(user, HTTPStatus.NOT_FOUND, "Snapshot not found."), 404)
        with DATA_LOCK.shared():
            path = SNAPSHOT_DIR / snap.get("file", "")
            if path.exists() and path.is_file():
                path.unlink()
            for asset in snap.get("assets", []):
                asset_path = SNAPSHOT_DIR / asset.get("file", "")
                if (
                    not str(asset.get("file", "")).startswith("_objects/")
                    and asset_path.exists()
                    and asset_path.is_file()
                ):
                    asset_path.unlink()
            asset_dir = SNAPSHOT_DIR / site["id"] / f"{snap_id}_assets"
            if asset_dir.exists() and asset_dir.is_dir():
                try:
                    asset_dir.rmdir()
                except OSError:
                    pass
            def remove_snapshot(current_db):
                current_snap = find_by_id(current_db["snapshots"], snap_id)
                current_site = find_by_id(current_db["sites"], site["id"])
                if not current_snap or not can_manage_site(user, current_site):
                    raise ValueError("Snapshot not found.")
                current_db["snapshots"] = [s for s in current_db["snapshots"] if s["id"] != snap_id]
                record_event(current_db, user["id"], "snapshot_deleted", f"{site['url']}: {snap_id}")
            mutate_db(remove_snapshot)
            capture_run_id = snap.get("capture_run_id")
            if capture_run_id:
                remaining = [
                    item for item in load_db()["snapshots"]
                    if item.get("capture_run_id") == capture_run_id
                ]
                run = METADATA_STORE.get_capture_run(capture_run_id)
                if not remaining:
                    if run and run.get("manifest_path"):
                        manifest_path = (INTEGRITY_DIR / run["manifest_path"]).resolve()
                        if manifest_path.is_relative_to(INTEGRITY_DIR.resolve()) and manifest_path.is_file():
                            manifest_path.unlink()
                    METADATA_STORE.delete_capture_run(capture_run_id)
                else:
                    if run and run.get("entry_snapshot_id") == snap_id:
                        METADATA_STORE.update_capture_run(
                            capture_run_id,
                            now_iso(),
                            entry_snapshot_id=remaining[0]["id"],
                            captured=len(remaining),
                        )
                    refresh_capture_manifest(capture_run_id)
        notice = urllib.parse.quote("Snapshot deleted.")
        return self.redirect(f"/sites/{site['id']}/edit?notice={notice}")

    def crawl_deeper_from_snapshot(self, user, snap_id):
        db = load_db()
        snap = find_by_id(db["snapshots"], snap_id)
        site = find_by_id(db["sites"], snap["site_id"]) if snap else None
        if not snap or not can_manage_site(user, site):
            return self.html(error_page(user, HTTPStatus.NOT_FOUND, "Snapshot not found."), 404)
        if "text/html" not in snap.get("content_type", "").lower():
            notice = urllib.parse.quote("Only HTML snapshots can be used as a deeper crawl starting point.")
            return self.redirect(f"/sites/{site['id']}/edit?notice={notice}")
        depth = min(5, int(site.get("crawl_depth", CRAWL_DEPTH)) + 1)
        max_pages = min(SNAPSHOT_DEEPER_CRAWL_MAX_PAGES, int(site.get("max_pages", CRAWL_MAX_PAGES)))
        job_id = start_site_crawl(
            site["id"],
            user["id"],
            "live",
            depth,
            max_pages,
            snap.get("source_url") or snap.get("final_url") or site["url"],
        )
        notice = urllib.parse.quote(
            f"Limited deeper crawl started: {job_id}. Depth {depth}, max {max_pages} pages."
        )
        return self.redirect(f"/sites/{site['id']}/edit?notice={notice}")











    def snapshot_content(self, user, snap_id):
        db = load_db()
        snap = find_by_id(db["snapshots"], snap_id)
        site = find_by_id(db["sites"], snap["site_id"]) if snap else None
        if not snap or not site or not can_view_snapshot(user, snap, site):
            self.send_error(404)
            return
        path = SNAPSHOT_DIR / snap["file"]
        body = path.read_bytes()
        if "text/html" in snap["content_type"].lower():
            page_map = {}
            if snap.get("capture_run_id"):
                for captured_page in db["snapshots"]:
                    if captured_page.get("capture_run_id") != snap["capture_run_id"]:
                        continue
                    for page_url in (
                        captured_page.get("source_url"),
                        captured_page.get("final_url"),
                    ):
                        if page_url:
                            page_map[replay_link_key(page_url)] = captured_page["id"]
            body = prepare_html_replay(
                body,
                snap["final_url"],
                self.request_origin(),
                page_map,
            )
        self.send_response(200)
        self.send_header("Content-Type", snap["content_type"])
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store")
        if "text/html" in snap["content_type"].lower():
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self' data: blob:; img-src 'self' data: blob:; "
                "style-src 'self' 'unsafe-inline' data: blob:; script-src 'none'; "
                "font-src 'self' data: blob:; media-src 'self' data: blob:; "
                "connect-src 'none'; form-action 'none'; frame-src 'self'; frame-ancestors 'self'",
            )
        self.security_headers()
        self.end_headers()
        self.wfile.write(body)

    def snapshot_asset(self, user, snap_id, asset_id):
        db = load_db()
        snap = find_by_id(db["snapshots"], snap_id)
        site = find_by_id(db["sites"], snap["site_id"]) if snap else None
        if not snap or not site or not can_view_snapshot(user, snap, site):
            self.send_error(404)
            return
        asset = find_by_id(snap.get("assets", []), asset_id)
        if not asset:
            self.send_error(404)
            return
        path = SNAPSHOT_DIR / asset["file"]
        if not path.exists() or not path.is_file():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", asset.get("content_type") or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'none'; sandbox")
        self.security_headers()
        self.end_headers()
        self.wfile.write(body)

    def request_origin(self):
        trusted_proxy = TRUST_PROXY and self.client_address[0] in {"127.0.0.1", "::1"}
        forwarded_proto = self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
        scheme = "https" if trusted_proxy and forwarded_proto == "https" else "http"
        forwarded_host = self.headers.get("X-Forwarded-Host", "").split(",", 1)[0].strip()
        host = forwarded_host if trusted_proxy and forwarded_host else self.headers.get("Host", "").strip()
        if not re.fullmatch(r"(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?", host):
            host = f"127.0.0.1:{PORT}"
        return f"{scheme}://{host}"

    def valid_request_host(self):
        host = self.headers.get("Host", "").strip().lower()
        if not re.fullmatch(r"(?:[a-z0-9.-]+|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?", host):
            return False
        hostname = host[1:].split("]", 1)[0] if host.startswith("[") else host.split(":", 1)[0]
        return not ALLOWED_HOSTS or hostname in ALLOWED_HOSTS

    def client_ip(self):
        if TRUST_PROXY and self.client_address[0] in {"127.0.0.1", "::1"}:
            candidate = self.headers.get("X-Real-IP", "").strip()
            if re.fullmatch(r"[0-9A-Fa-f:.]+", candidate):
                return candidate
        return self.client_address[0]

    def cookie(self, wanted):
        for chunk in self.headers.get("Cookie", "").split(";"):
            name, _, value = chunk.strip().partition("=")
            if name == wanted:
                return urllib.parse.unquote(value)
        return None

    def csrf_token(self):
        existing = self.cookie("csrf")
        if existing and (unsign(existing) or "").startswith("csrf:"):
            return existing, False
        return sign(f"csrf:{secrets.token_urlsafe(24)}"), True

    def require_valid_csrf(self, form):
        cookie_token = self.cookie("csrf") or ""
        form_token = form.get("csrf_token", "")
        if not form_token or not hmac.compare_digest(cookie_token, form_token):
            raise PermissionError(f"This form expired or did not originate from {PRODUCT_NAME}.")
        if not (unsign(form_token) or "").startswith("csrf:"):
            raise PermissionError("Invalid form security token.")
        origin = self.headers.get("Origin")
        if origin:
            expected = urllib.parse.urlparse(self.request_origin())
            supplied = urllib.parse.urlparse(origin)
            if supplied.scheme != expected.scheme or supplied.netloc.lower() != expected.netloc.lower():
                raise PermissionError("Cross-origin form submission was blocked.")

    def require_user(self, user, callback):
        if not user:
            return_to = safe_local_return(self.path, "/dashboard")
            return self.redirect(f"/login?next={urllib.parse.quote(return_to, safe='')}")
        return callback()

    def html(self, body, status=200):
        token, set_cookie = self.csrf_token()
        hidden = f'<input type="hidden" name="csrf_token" value="{esc(token)}">'
        body = re.sub(r'(<form\b[^>]*\bmethod=["\']post["\'][^>]*>)', r"\1" + hidden, body, flags=re.I)
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'none'; frame-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
        )
        self.security_headers()
        if set_cookie:
            self.send_header("Set-Cookie", self.cookie_header("csrf", token, same_site="Strict"))
        self.end_headers()
        self.wfile.write(payload)

    def json_response(self, data, status=200):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)


    def redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.security_headers()
        self.end_headers()

    def set_session(self, user_id, location):
        user = find_by_id(load_db()["users"], user_id)
        if not user or not user.get("email_verified_at"):
            raise ValueError("A verified active account is required.")
        session_value = f"session:{user_id}:{int(user.get('session_version', 1))}"
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header(
            "Set-Cookie", self.cookie_header("session", sign(session_value), same_site="Lax")
        )
        self.security_headers()
        self.end_headers()

    def cookie_header(self, name, value, same_site="Lax", max_age=None):
        parts = [f"{name}={urllib.parse.quote(value)}", "Path=/", "HttpOnly", f"SameSite={same_site}"]
        if SECURE_COOKIES:
            parts.append("Secure")
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        return "; ".join(parts)

    def security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("X-Frame-Options", "SAMEORIGIN")

    def serve_static(self, path):
        target = (STATIC_DIR / urllib.parse.unquote(path.removeprefix("/static/"))).resolve()
        if STATIC_DIR.resolve() not in target.parents:
            self.send_error(404)
            return
        if not target.exists() or not target.is_file():
            self.send_error(404)
            return
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(str(target))[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.security_headers()
        self.end_headers()
        self.wfile.write(body)

    def serve_avatar(self, user, target_id):
        if not user or user["id"] != target_id:
            self.send_error(404)
            return
        target = find_by_id(load_db()["users"], target_id)
        filename = target.get("avatar_filename") if target else None
        if not filename or not re.fullmatch(r"avatar\.(?:png|jpg|gif|webp)", filename):
            self.send_error(404)
            return
        path = (PROFILE_DIR / target_id / filename).resolve()
        try:
            path.relative_to(PROFILE_DIR.resolve())
        except ValueError:
            self.send_error(404)
            return
        if not path.is_file() or path.is_symlink():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", target.get("avatar_content_type") or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, max-age=300")
        self.security_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


def find_user_by_email(db, email):
    return next((u for u in db["users"] if u["email"] == email), None)




















def run_operations_checks():
    usage = shutil.disk_usage(DATA_DIR)
    if usage.free < MIN_FREE_DISK_BYTES:
        structured_log("low_disk_space", "warning", free_bytes=usage.free)
    for streak in METADATA_STORE.repeated_capture_failure_streaks(
        REPEATED_FAILURE_THRESHOLD
    ):
        structured_log(
            "repeated_capture_failure",
            "warning",
            site_id=streak["site_id"],
            job_id=streak["latest_job_id"],
            consecutive_failures=streak["consecutive_failures"],
        )
    return {
        "free_bytes": usage.free,
        "low_disk": usage.free < MIN_FREE_DISK_BYTES,
    }


def operations_monitor_loop():
    while not SHUTDOWN_EVENT.is_set():
        try:
            run_operations_checks()
        except Exception as exc:
            structured_log("operations_monitor_error", "error", error=str(exc))
        SHUTDOWN_EVENT.wait(300)


def scheduler_loop():
    while not SHUTDOWN_EVENT.is_set():
        try:
            current = datetime.now(timezone.utc)
            settings = METADATA_STORE.scheduler_settings()
            if settings["scheduling_paused"] or not capture_window_open(current, settings):
                SHUTDOWN_EVENT.wait(60)
                continue
            available = max(
                0,
                int(settings["max_concurrent_jobs"])
                - METADATA_STORE.running_job_count(),
            )
            if available == 0:
                SHUTDOWN_EVENT.wait(60)
                continue
            db = load_db()
            due = []
            for site in db["sites"]:
                if site.get("schedule_paused"):
                    continue
                due_at = parse_iso(site.get("next_snapshot_at")) or current
                if due_at <= current:
                    due.append(site)
            due.sort(key=lambda item: item.get("next_snapshot_at") or "")
            for site in due[:available]:
                try:
                    if (
                        site.get("change_policy") == "homepage_changed"
                        and site.get("last_source_digest")
                    ):
                        policy = normalized_site_policy(site, USER_AGENT)
                        try:
                            _final_url, status, _content_type, body = fetch_bytes(
                                site["url"],
                                timeout=policy["request_timeout_seconds"],
                                user_agent=policy["user_agent"],
                            )
                            if status >= 400:
                                raise ValueError(f"Homepage returned HTTP {status}.")
                            source_digest = hashlib.sha256(body).hexdigest()
                        except Exception as exc:
                            structured_log(
                                "scheduled_change_check_failed",
                                "warning",
                                site_id=site["id"],
                                error=str(exc),
                            )
                        else:
                            if source_digest == site["last_source_digest"]:
                                def record_unchanged(current_db):
                                    current_site = find_by_id(
                                        current_db["sites"], site["id"]
                                    )
                                    if not current_site:
                                        return
                                    current_site["next_snapshot_at"] = next_capture_after(
                                        current.isoformat(timespec="seconds"),
                                        current_site.get("interval", "monthly"),
                                        current_site.get("custom_days"),
                                    )
                                    record_event(
                                        current_db,
                                        "system",
                                        "scheduled_capture_unchanged",
                                        f"No homepage source change for {current_site['url']}",
                                    )

                                mutate_db(record_unchanged)
                                structured_log(
                                    "scheduled_capture_unchanged",
                                    site_id=site["id"],
                                    source_content_digest=source_digest,
                                )
                                continue
                    start_site_crawl(
                        site["id"],
                        "system",
                        "scheduled",
                        site.get("crawl_depth", CRAWL_DEPTH),
                        site.get("max_pages", CRAWL_MAX_PAGES),
                    )
                except JobCapacityExceeded:
                    break
                except Exception as exc:
                    def record_scheduled_failure(current_db):
                        record_event(
                            current_db,
                            "system",
                            "scheduled_capture_failed",
                            f"{site['url']}: {exc}",
                        )
                        site2 = find_by_id(current_db["sites"], site["id"])
                        if site2:
                            site2["next_snapshot_at"] = (
                                current + timedelta(hours=6)
                            ).isoformat(timespec="seconds")
                    mutate_db(record_scheduled_failure)
        except Exception as exc:
            structured_log("scheduler_error", "error", error=str(exc))
        SHUTDOWN_EVENT.wait(60)


def main():
    ensure_dirs()
    cleared_capture_work = clear_stale_capture_work(CAPTURE_WORK_DIR)
    if cleared_capture_work:
        structured_log(
            "stale_capture_work_cleared", count=cleared_capture_work
        )
    db = load_db()
    validate_production_configuration(db)
    interrupted = METADATA_STORE.recover_interrupted_jobs(now_iso())
    if interrupted:
        def record_recovery(db):
            for job_id in interrupted:
                record_event(
                    db,
                    "system",
                    "crawl_job_resuming",
                    f"{job_id} will continue automatically after application restart",
                )
        mutate_db(record_recovery)
        structured_log("crawl_jobs_queued_for_resume", count=len(interrupted))
    manifest_backfill = backfill_capture_manifests()
    if manifest_backfill["created"] or manifest_backfill["failed"]:
        structured_log(
            "capture_manifest_backfill",
            created=manifest_backfill["created"],
            failed=manifest_backfill["failed"],
        )
    resume_pending_crawls()
    crawl_recovery_worker = threading.Thread(
        target=crawl_recovery_loop, name="crawl-recovery", daemon=True
    )
    crawl_recovery_worker.start()
    scheduler = threading.Thread(target=scheduler_loop, name="scheduler", daemon=True)
    scheduler.start()
    operations_monitor = threading.Thread(
        target=operations_monitor_loop, name="operations-monitor", daemon=True
    )
    operations_monitor.start()
    server = ThreadingHTTPServer((BIND, PORT), Handler)

    def stop_server(_signum, _frame):
        if SHUTDOWN_EVENT.is_set():
            return
        SHUTDOWN_EVENT.set()
        threading.Thread(target=server.shutdown, name="http-shutdown", daemon=True).start()

    signal.signal(signal.SIGTERM, stop_server)
    signal.signal(signal.SIGINT, stop_server)
    structured_log(
        "service_started",
        bind=BIND,
        port=PORT,
        mode="local",
        schema=METADATA_STORE.storage_health()["schema_version"],
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        SHUTDOWN_EVENT.set()
        server.server_close()
        crawl_recovery_worker.join(timeout=2)
        scheduler.join(timeout=2)
        operations_monitor.join(timeout=2)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with WORKER_LOCK:
                workers = list(WORKER_THREADS)
            if not workers:
                break
            for worker in workers:
                worker.join(timeout=min(1, max(0, deadline - time.monotonic())))


if __name__ == "__main__":
    main()
