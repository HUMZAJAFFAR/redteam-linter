"""HTTP hardening for the RedTeam Linter console.

The console is a local review tool, so the threat model is: another page in the
same browser trying to drive it (CSRF / clickjacking), a hostile payload trying
to exhaust it, and a bug in a template leaking script execution.  This module
adds four ASGI middlewares that address those without pulling in new
dependencies:

*   :class:`SecurityHeadersMiddleware` — a strict CSP (no inline script, no
    inline style, no objects, no forms), `nosniff`, no referrer, no-store on
    API responses.
*   :class:`OriginGuardMiddleware` — rejects state-changing requests whose
    ``Origin`` header does not match the host they arrived on.
*   :class:`BodyLimitMiddleware` — rejects bodies over the scan limit before
    they are buffered, including chunked requests.
*   :class:`RateLimiterMiddleware` — sliding-window limits per client and
    route, with ``Retry-After``.

Everything is configurable through environment variables so a self-hosted
deployment can tighten or relax a single knob without editing code.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from starlette.types import ASGIApp, Message, Receive, Scope, Send

#: Hard ceiling for a request body.  The scan API caps submissions at 2 MB, so
#: 2.5 MB leaves room for JSON overhead while still bounding memory.
MAX_BODY_BYTES = int(os.environ.get("REDTEAM_MAX_BODY_BYTES", str(5 * 1024 * 1024 // 2)))

#: ``frame-ancestors`` for the CSP.  Defaults to first-party only.  A hosted
#: preview embedder can be allowed explicitly, e.g.
#: ``REDTEAM_FRAME_ANCESTORS="'self' https://*.style.dev"``.
FRAME_ANCESTORS = os.environ.get("REDTEAM_FRAME_ANCESTORS", "'self'")

#: Per-route limits as ``path prefix -> (requests, window seconds)``.
RATE_LIMITS: Tuple[Tuple[str, int, int], ...] = (
    ("/api/assistant", 20, 60),
    ("/api/scan", 40, 60),
    ("/api/report", 20, 60),
    ("/api", 120, 60),
)

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_SECURITY_HEADERS: Dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "manifest-src 'self'; "
        "frame-src 'none'; "
        "worker-src 'none'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        f"frame-ancestors {FRAME_ANCESTORS}"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "X-Permitted-Cross-Domain-Policies": "none",
}

_HEADER_BYTES = [(key.lower().encode("latin-1"), value.encode("latin-1")) for key, value in _SECURITY_HEADERS.items()]


def _is_api(path: str) -> bool:
    """True for JSON endpoints, which must never be cached."""
    return path.startswith("/api")


class SecurityHeadersMiddleware:
    """Attach the CSP and the rest of the hardening headers to every response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.extend(_HEADER_BYTES)
                if _is_api(scope.get("path", "")):
                    headers.append((b"cache-control", b"no-store, max-age=0"))
                    headers.append((b"pragma", b"no-cache"))
                    headers.append((b"expires", b"0"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


class OriginGuardMiddleware:
    """Reject cross-site state-changing requests (CSRF defence in depth).

    The API only accepts ``application/json``, which already defeats classic
    form-based CSRF, but an explicit origin check makes the intent obvious and
    also blocks browser extensions replaying requests with a foreign origin.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in _UNSAFE_METHODS:
            await self.app(scope, receive, send)
            return

        headers = {key.decode("latin-1"): value.decode("latin-1") for key, value in scope.get("headers", [])}
        origin = headers.get("origin")
        if origin and not self._same_origin(origin, headers.get("host", "")):
            await self._reject(send)
            return
        await self.app(scope, receive, send)

    @staticmethod
    def _same_origin(origin: str, host: str) -> bool:
        """Compare the ``Origin`` host with the ``Host`` header, scheme-agnostic."""
        candidate = origin.split("://", 1)[-1].rstrip("/")
        return bool(host) and candidate.lower() == host.lower()

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail":"Cross-origin request blocked."}'
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("latin-1")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class _BodyTooLarge(Exception):
    """Internal signal: the request body exceeded :data:`MAX_BODY_BYTES`."""


class BodyLimitMiddleware:
    """Cap request body size, including chunked uploads without a length header."""

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") in {"GET", "HEAD", "OPTIONS"}:
            await self.app(scope, receive, send)
            return

        for key, value in scope.get("headers", []):
            if key == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    await self._reject(send, 400, "Malformed Content-Length.")
                    return
                if declared > self.max_bytes:
                    await self._reject(send, 413, "Payload too large.")
                    return

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except _BodyTooLarge:
            if not started:
                await self._reject(send, 413, "Payload too large.")

    @staticmethod
    async def _reject(send: Send, status: int, detail: str) -> None:
        body = ('{"detail":"%s"}' % detail).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("latin-1")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class RateLimiterMiddleware:
    """Sliding-window rate limiting per client address and route family."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._hits: Dict[Tuple[str, str], List[float]] = {}
        self._lock = threading.Lock()

    def _limit_for(self, path: str) -> Optional[Tuple[int, int]]:
        for prefix, limit, window in RATE_LIMITS:
            if path.startswith(prefix):
                return limit, window
        return None

    def _check(self, client: str, path: str) -> Optional[int]:
        """Record a hit; return seconds to wait when the limit is exceeded."""
        rule = self._limit_for(path)
        if rule is None:
            return None
        limit, window = rule
        now = time.monotonic()
        family = "/".join(part for part in path.split("/")[:3] if part)
        key = (client, family)
        with self._lock:
            stamps = [stamp for stamp in self._hits.get(key, []) if now - stamp < window]
            if len(stamps) >= limit:
                self._hits[key] = stamps
                return max(1, int(window - (now - stamps[0])) + 1)
            stamps.append(now)
            self._hits[key] = stamps
            if len(self._hits) > 2048:  # opportunistic cleanup of idle clients
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < window}
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not _is_api(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        client = (scope.get("client") or ("unknown", 0))[0]
        retry_after = self._check(client, scope.get("path", ""))
        if retry_after is not None:
            body = b'{"detail":"Rate limit exceeded. Slow down."}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("latin-1")),
                        (b"retry-after", str(retry_after).encode("latin-1")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)


def apply_security(app: Any) -> None:
    """Register the hardening stack on a FastAPI/Starlette application.

    Middleware added last runs first, so headers are attached even to the
    rejections produced by the rate limiter and the body guard.
    """
    app.add_middleware(RateLimiterMiddleware)
    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(OriginGuardMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)


__all__ = [
    "apply_security",
    "SecurityHeadersMiddleware",
    "OriginGuardMiddleware",
    "BodyLimitMiddleware",
    "RateLimiterMiddleware",
    "MAX_BODY_BYTES",
    "FRAME_ANCESTORS",
]
