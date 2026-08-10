"""Security policy helpers kept independent from HTTP and capture code."""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
import urllib.parse
import urllib.request
from collections import defaultdict, deque


class OutboundAddressError(ValueError):
    """An outbound URL violates the installation's network policy."""


def validate_outbound_url(url: str, allow_private_networks: bool = False) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise OutboundAddressError("Only absolute HTTP or HTTPS URLs may be fetched.")
    if parsed.username is not None or parsed.password is not None:
        raise OutboundAddressError("URLs containing credentials are not allowed.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise OutboundAddressError("The URL contains an invalid port.") from exc
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise OutboundAddressError("The URL hostname could not be resolved.") from exc
    if not addresses:
        raise OutboundAddressError("The URL hostname resolved to no addresses.")
    for raw_address in addresses:
        address = ipaddress.ip_address(raw_address.split("%", 1)[0])
        always_blocked = (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        )
        if always_blocked or (not address.is_global and not allow_private_networks):
            raise OutboundAddressError(
                f"The URL resolves to a blocked network address ({address})."
            )
    return url


class ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow_private_networks: bool = False):
        super().__init__()
        self.allow_private_networks = allow_private_networks

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_outbound_url(newurl, self.allow_private_networks)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class RateLimiter:
    """Small per-process sliding-window limiter for authentication endpoints."""

    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window_seconds = window_seconds
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        cutoff = current - self.window_seconds
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(current)
            if not events:
                self._events.pop(key, None)
            return True
