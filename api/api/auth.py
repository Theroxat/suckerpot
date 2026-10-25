"""Dashboard authentication: one admin account, signed session cookie, CSRF double-submit.

Design
------
* ``POST /api/v1/auth/login`` checks the username and an argon2id hash (taken from the
  environment) and answers ``204`` with an ``sp_session`` cookie (httpOnly, Secure unless
  ``COOKIE_SECURE=false``, SameSite=Strict).
* The cookie is an HMAC-signed token ``v1.<iat>.<exp>.<nonce>.<sig>``. The signing key is derived
  from ``SESSION_SECRET`` and the password hash, so changing the password logs everybody out.
  There is no server-side session table; logout puts the nonce in a small in-memory revocation set
  (single admin, single process).
* CSRF is a double-submit token: ``GET /auth/csrf`` sets a readable ``sp_csrf`` cookie (itself
  HMAC-signed, so a planted cookie is rejected) and every unsafe request must echo it in
  ``X-CSRF-Token``. Login is exempt from the token but requires a same-origin ``Origin`` or
  ``Referer``.
* A pure ASGI middleware guards every ``/api/v1`` HTTP path except ``/api/v1/auth/*``. The live
  WebSocket checks the cookie in its handshake (see ``api.live``). ``/healthz`` and the static SPA
  stay public.

Nothing in this module ever logs a password, a hash or a cookie value.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import logging
import os
import secrets
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from urllib.parse import urlsplit

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from api.live import allowed_origins, normalize_origin

log = logging.getLogger(__name__)

COOKIE_SESSION = "sp_session"
COOKIE_CSRF = "sp_csrf"
HOST_PREFIX = "__Host-"
HEADER_CSRF = "x-csrf-token"
API_PREFIX = "/api/v1"
AUTH_PREFIX = "/api/v1/auth"
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
MIN_SECRET_BYTES = 32
TRUE_VALUES = {"1", "true", "yes", "on"}
FAILURE_DELAY_S = 0.3
RATE_WINDOW_S = 60.0
MAX_TRACKED_IPS = 10_000
MAX_REVOKED = 1_000
MAX_VERIFY_CONCURRENCY = 1  # one argon2 verify holds ~64 MiB: more would risk the memory limit
MAX_VERIFY_PENDING = 3  # running + queued; beyond this login answers 429 immediately
LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")


class AuthConfigError(RuntimeError):
    """The auth environment is unusable: the API refuses to start."""


class LoginBusy(RuntimeError):
    """Too many password checks are already queued."""


def _truthy(value: str | None, default: bool) -> bool:
    if value is None or not value.strip():
        return default
    return value.strip().lower() in TRUE_VALUES


@dataclass(frozen=True)
class AuthSettings:
    username: str = "admin"
    password_hash: str | None = None
    secret: bytes = b""
    ttl_hours: float = 12.0
    cookie_secure: bool = True
    disabled: bool = False
    rate_per_ip: int = 5
    rate_global: int = 30
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AuthSettings:
        env = os.environ if env is None else env
        disabled = _truthy(env.get("API_AUTH_DISABLED"), False)
        username = env.get("ADMIN_USERNAME", "").strip() or "admin"
        ttl = float(env.get("SESSION_TTL_HOURS", "").strip() or 12)
        proxies: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for item in env.get("AUTH_TRUSTED_PROXIES", "").split(","):
            if item.strip():
                try:
                    proxies.append(ipaddress.ip_network(item.strip(), strict=False))
                except ValueError as exc:
                    raise AuthConfigError("AUTH_TRUSTED_PROXIES must be a list of CIDRs") from exc
        base = cls(
            username=username,
            ttl_hours=ttl,
            cookie_secure=_truthy(env.get("COOKIE_SECURE"), True),
            rate_per_ip=int(env.get("LOGIN_RATE", "").strip() or 5),
            rate_global=int(env.get("LOGIN_RATE_GLOBAL", "").strip() or 30),
            trusted_proxies=tuple(proxies),
        )
        if disabled:
            if env.get("SUCKERPOT_DEMO") != "1":
                raise AuthConfigError(
                    "API_AUTH_DISABLED=true is only accepted together with SUCKERPOT_DEMO=1"
                )
            log.warning(
                "API_AUTH_DISABLED=true: the dashboard API is OPEN to anyone who can reach it. "
                "Use this for demo or CI only."
            )
            return replace(base, disabled=True, secret=secrets.token_bytes(32))

        allow_default = env.get("SUCKERPOT_ALLOW_DEFAULT_SECRETS") == "1"
        secret = env.get("SESSION_SECRET", "").encode()
        pw_hash: str | None = env.get("ADMIN_PASSWORD_HASH", "").strip() or None
        problems: list[str] = []
        if len(secret) < MIN_SECRET_BYTES:
            problems.append(f"SESSION_SECRET must be at least {MIN_SECRET_BYTES} bytes")
            secret = secret or secrets.token_bytes(32)
        if pw_hash is None or not _is_argon2(pw_hash):
            problems.append("ADMIN_PASSWORD_HASH must be an argon2 hash (python -m api.hashpw)")
            pw_hash = None
        if problems:
            if not allow_default:
                raise AuthConfigError("; ".join(problems))
            log.warning(
                "SUCKERPOT_ALLOW_DEFAULT_SECRETS=1: weak auth configuration accepted (%s). "
                "Never use this in production.",
                "; ".join(problems),
            )
        return replace(base, password_hash=pw_hash, secret=secret)


def _is_argon2(value: str) -> bool:
    if not value.startswith("$argon2"):
        return False
    try:
        extract_parameters(value)
    except InvalidHashError:
        return False
    return True


@dataclass(frozen=True)
class SessionInfo:
    username: str
    issued_at: int
    expires_at: int
    nonce: str


@dataclass
class _Window:
    hits: deque[float] = field(default_factory=deque)

    def prune(self, now: float) -> None:
        while self.hits and now - self.hits[0] >= RATE_WINDOW_S:
            self.hits.popleft()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class AuthService:
    def __init__(self, settings: AuthSettings, clock: Callable[[], float] = time.time) -> None:
        self.settings = settings
        self.clock = clock
        # __Host- cookies must be Secure, so the prefix only exists when COOKIE_SECURE is on.
        prefix = HOST_PREFIX if settings.cookie_secure else ""
        self.cookie_name = prefix + COOKIE_SESSION
        self.csrf_cookie_name = prefix + COOKIE_CSRF
        self._hasher = PasswordHasher()
        # With no usable hash (CI-only mode) login always fails, with the same cost as a real check.
        self._hash = settings.password_hash or self._hasher.hash(secrets.token_urlsafe(16))
        self._login_possible = settings.password_hash is not None
        # A per-boot random value: every restart signs everybody out (revocations are in memory).
        material = settings.secret + b"|" + self._hash.encode() + b"|" + secrets.token_bytes(16)
        self._session_key = hashlib.sha256(b"sp-session|" + material).digest()
        self._csrf_key = hashlib.sha256(b"sp-csrf|" + settings.secret).digest()
        self._revoked: dict[str, int] = {}
        self._per_ip: dict[str, _Window] = {}
        self._global = _Window()
        self._scoped_global: dict[str, _Window] = {}
        self._verify_sem = asyncio.Semaphore(MAX_VERIFY_CONCURRENCY)
        self._pending = 0

    # -- session tokens -------------------------------------------------------------------------

    def _sign(self, key: bytes, body: str) -> str:
        return _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())

    def issue(self) -> tuple[str, SessionInfo]:
        now = int(self.clock())
        info = SessionInfo(
            username=self.settings.username,
            issued_at=now,
            expires_at=now + int(self.settings.ttl_hours * 3600),
            nonce=secrets.token_urlsafe(16),
        )
        body = f"v1.{info.issued_at}.{info.expires_at}.{info.nonce}"
        user_tag = _b64(self.settings.username.encode())
        return f"{body}.{self._sign(self._session_key, f'{body}|{user_tag}')}", info

    def validate(self, token: str | None) -> SessionInfo | None:
        """The session behind ``token``, or None if forged, expired, revoked or disabled."""
        if self.settings.disabled:
            now = int(self.clock())
            return SessionInfo(self.settings.username, now, now + 3600, "disabled")
        if not token or len(token) > 512:
            return None
        parts = token.split(".")
        if len(parts) != 5 or parts[0] != "v1":
            return None
        body = ".".join(parts[:4])
        user_tag = _b64(self.settings.username.encode())
        expected = self._sign(self._session_key, f"{body}|{user_tag}")
        if not hmac.compare_digest(expected.encode(), parts[4].encode()):
            return None
        try:
            issued_at, expires_at = int(parts[1]), int(parts[2])
        except ValueError:
            return None
        if self.clock() >= expires_at or parts[3] in self._revoked:
            return None
        return SessionInfo(self.settings.username, issued_at, expires_at, parts[3])

    def revoke(self, info: SessionInfo) -> None:
        now = self.clock()
        for nonce in [n for n, exp in self._revoked.items() if exp <= now]:
            del self._revoked[nonce]
        if len(self._revoked) >= MAX_REVOKED:  # drop the oldest-expiring entry
            del self._revoked[min(self._revoked, key=lambda n: self._revoked[n])]
        self._revoked[info.nonce] = info.expires_at

    # -- CSRF -----------------------------------------------------------------------------------

    def new_csrf(self, session_nonce: str = "") -> str:
        """A token bound to the session it was issued for (empty nonce: no session yet)."""
        nonce = secrets.token_urlsafe(16)
        return f"{nonce}.{self._sign(self._csrf_key, f'{nonce}|{session_nonce}')}"

    def csrf_ok(self, cookie: str | None, header: str | None, session_nonce: str = "") -> bool:
        if not cookie or not header or len(cookie) > 128 or len(header) > 128:
            return False
        if not hmac.compare_digest(cookie.encode(), header.encode()):
            return False
        nonce, _, sig = cookie.partition(".")
        expected = self._sign(self._csrf_key, f"{nonce}|{session_nonce}")
        return hmac.compare_digest(expected.encode(), sig.encode())

    # -- cookies (one parser for HTTP and WebSocket) ----------------------------------------------

    def session_token(self, scope: Scope) -> str | None:
        return _cookie_from_headers(scope, self.cookie_name)

    def csrf_cookie(self, scope: Scope) -> str | None:
        return _cookie_from_headers(scope, self.csrf_cookie_name)

    # -- credentials and rate limit -------------------------------------------------------------

    async def check_credentials(self, username: str, password: str) -> bool:
        """Constant work whether the user exists or not: the hash is always verified."""
        if self._pending >= MAX_VERIFY_PENDING:
            raise LoginBusy
        self._pending += 1
        try:
            async with self._verify_sem:
                password_ok = await asyncio.to_thread(self._verify, password)
        finally:
            self._pending -= 1
        user_ok = hmac.compare_digest(username.encode(), self.settings.username.encode())
        return password_ok and user_ok and self._login_possible

    def _verify(self, password: str) -> bool:
        try:
            return self._hasher.verify(self._hash, password)
        except VerificationError:
            return False
        except InvalidHashError:
            return False

    def rate_limited(self, ip: str, scope: str = "") -> int | None:
        """Record an attempt. Returns Retry-After seconds when over the limit, else None.

        ``scope`` gives another action (e.g. password re-authentication) its own budget, with the
        same limits as login, so it cannot be used to guess the password around the login limit.
        """
        ip = rate_key(ip)
        glob = self._global
        if scope:
            ip = f"{scope}|{ip}"
            glob = self._scoped_global.setdefault(scope, _Window())
        now = self.clock()
        glob.prune(now)
        win = self._per_ip.get(ip)
        if win is None:
            if len(self._per_ip) >= MAX_TRACKED_IPS:
                for w in self._per_ip.values():
                    w.prune(now)
                for key in [k for k, w in self._per_ip.items() if not w.hits]:
                    del self._per_ip[key]
                if len(self._per_ip) >= MAX_TRACKED_IPS:
                    return int(RATE_WINDOW_S)
            win = self._per_ip[ip] = _Window()
        win.prune(now)
        for w, limit in (
            (win, self.settings.rate_per_ip),
            (glob, self.settings.rate_global),
        ):
            if len(w.hits) >= limit:
                return max(1, int(RATE_WINDOW_S - (now - w.hits[0])) + 1)
        win.hits.append(now)
        glob.hits.append(now)
        return None

    def client_ip(self, conn: HTTPConnection) -> str:
        """The peer address, or the forwarded client when the peer is a trusted proxy."""
        peer = conn.client.host if conn.client else ""
        proxies = self.settings.trusted_proxies
        if not proxies or not _in_networks(peer, proxies):
            return peer
        cf = _parse_ip(conn.headers.get("cf-connecting-ip", ""))
        if cf:
            return cf
        hops = [h for h in conn.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        for hop in reversed(hops):  # rightmost address that is not one of our proxies
            ip = _parse_ip(hop)
            if ip and not _in_networks(ip, proxies):
                return ip
        return peer


def _parse_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _in_networks(ip: str, nets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets if n.version == addr.version)


def rate_key(ip: str) -> str:
    """Rate-limit key: IPv4 as is, IPv6 by /64 (one subscriber owns a whole /64)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip[:64]
    if isinstance(addr, ipaddress.IPv6Address):
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def allowed_hosts_from_env(env: Mapping[str, str] | None = None) -> list[str]:
    """Hosts accepted in the Host header. ``["*"]`` means unrestricted.

    ``API_ALLOWED_HOSTS`` (comma list) wins. Otherwise the hosts of ``API_ALLOWED_ORIGINS`` plus
    localhost and 127.0.0.1. With neither variable set the API cannot know its public name, so it
    does not restrict (a warning is logged): set one of them in production.
    """
    env = os.environ if env is None else env
    explicit = [h.strip().lower() for h in env.get("API_ALLOWED_HOSTS", "").split(",") if h.strip()]
    if explicit:
        return [*explicit, *(h for h in LOCAL_HOSTS if h not in explicit)]
    origins = allowed_origins(env.get("API_ALLOWED_ORIGINS", ""))
    if not origins:
        log.warning("API_ALLOWED_HOSTS and API_ALLOWED_ORIGINS are empty: Host is not restricted")
        return ["*"]
    hosts = {urlsplit(o).hostname or "" for o in origins}
    return sorted(h for h in hosts if h) + list(LOCAL_HOSTS)


# -- origin check -----------------------------------------------------------------------------


def _hostport(origin: str) -> str:
    return origin.split("://", 1)[-1]


def same_origin(request: Request) -> bool:
    """Origin (or Referer) must be an allowed origin, or the host the request was sent to.

    When ``API_ALLOWED_ORIGINS`` is set the full origin (scheme, host, port) must be listed.
    When it is empty the scheme is ignored and the host must equal the Host header: behind a
    TLS-terminating tunnel the app sees http while the browser's Origin is https.
    """
    raw = request.headers.get("origin")
    if raw is None:
        referer = request.headers.get("referer")
        if not referer:
            return False
        try:
            parts = urlsplit(referer)
        except ValueError:
            return False
        raw = f"{parts.scheme}://{parts.netloc}"
    norm = normalize_origin(raw)
    if norm is None:
        return False
    configured = allowed_origins(os.environ.get("API_ALLOWED_ORIGINS", ""))
    if configured:
        return norm in configured
    own = normalize_origin(f"{norm.split('://', 1)[0]}://{request.headers.get('host', '')}")
    return own is not None and _hostport(own) == _hostport(norm)


# -- middleware -------------------------------------------------------------------------------


def _cookie_from_headers(scope: Scope, name: str) -> str | None:
    for key, value in scope["headers"]:
        if key == b"cookie":
            for item in value.decode("latin-1").split(";"):
                k, _, v = item.strip().partition("=")
                if k == name:
                    return str(v)
    return None


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope["headers"]:
        if key == name:
            return str(value.decode("latin-1"))
    return None


class AuthMiddleware:
    """Require a valid session (and CSRF token on unsafe methods) for ``/api/v1`` HTTP paths."""

    def __init__(self, app: ASGIApp, *, auth: AuthService) -> None:
        self.app = app
        self.auth = auth

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.auth.settings.disabled:
            await self.app(scope, receive, send)
            return
        path: str = scope["path"]
        guarded = path == API_PREFIX or path.startswith(API_PREFIX + "/")
        public = path == AUTH_PREFIX or path.startswith(AUTH_PREFIX + "/")
        if not guarded or public:
            await self.app(scope, receive, send)
            return
        session = self.auth.validate(self.auth.session_token(scope))
        if session is None:
            await JSONResponse({"detail": "Not authenticated"}, status_code=401)(
                scope, receive, send
            )
            return
        if scope["method"] in UNSAFE_METHODS and not self.auth.csrf_ok(
            self.auth.csrf_cookie(scope), _header(scope, HEADER_CSRF.encode()), session.nonce
        ):
            await JSONResponse({"detail": "CSRF token missing or invalid"}, status_code=403)(
                scope, receive, send
            )
            return
        await self.app(scope, receive, send)


# -- router -----------------------------------------------------------------------------------

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    username: str = Field(max_length=128)
    password: str = Field(max_length=1024)


class Me(BaseModel):
    username: str


class CsrfToken(BaseModel):
    token: str


def _service(request: Request) -> AuthService:
    service: AuthService = request.app.state.auth
    return service


def _set_cookie(response: Response, service: AuthService, token: str, max_age: int) -> None:
    response.set_cookie(
        service.cookie_name,
        token,
        max_age=max_age,
        httponly=True,
        secure=service.settings.cookie_secure,
        samesite="strict",
        path="/",
    )


def _set_csrf(response: Response, service: AuthService, token: str) -> None:
    response.set_cookie(
        service.csrf_cookie_name,
        token,
        max_age=int(service.settings.ttl_hours * 3600),
        httponly=False,
        secure=service.settings.cookie_secure,
        samesite="strict",
        path="/",
    )


@router.post("/login", status_code=204)
async def login(body: LoginBody, request: Request) -> Response:
    service = _service(request)
    if service.settings.disabled:
        return Response(status_code=204)
    if not same_origin(request):
        return JSONResponse({"detail": "Cross-origin login refused"}, status_code=403)
    ip = service.client_ip(request)
    retry = service.rate_limited(ip)
    if retry is not None:
        return JSONResponse(
            {"detail": "Too many attempts"}, status_code=429, headers={"Retry-After": str(retry)}
        )
    try:
        ok = await service.check_credentials(body.username, body.password)
    except LoginBusy:
        return JSONResponse(
            {"detail": "Too many attempts"}, status_code=429, headers={"Retry-After": "2"}
        )
    if not ok:
        log.warning("dashboard login failed ip=%s", ip[:64])  # never the submitted values
        await asyncio.sleep(FAILURE_DELAY_S)
        return JSONResponse({"detail": "Invalid credentials"}, status_code=401)
    previous = service.validate(service.session_token(request.scope))
    if previous is not None:
        service.revoke(previous)  # rotate: the old token dies with the new login
    token, info = service.issue()
    response = Response(status_code=204)
    _set_cookie(response, service, token, info.expires_at - info.issued_at)
    _set_csrf(response, service, service.new_csrf(info.nonce))
    log.info("dashboard login ok ip=%s", ip[:64])
    return response


@router.post("/logout", status_code=204)
async def logout(request: Request) -> Response:
    service = _service(request)
    response = Response(status_code=204)
    if service.settings.disabled:
        return response
    info = service.validate(service.session_token(request.scope))
    if info is not None:
        # Same CSRF rule as every unsafe request: a cross-site page must not log you out.
        header = request.headers.get(HEADER_CSRF)
        if not service.csrf_ok(service.csrf_cookie(request.scope), header, info.nonce):
            return JSONResponse({"detail": "CSRF token missing or invalid"}, status_code=403)
        service.revoke(info)
    for name, httponly in ((service.cookie_name, True), (service.csrf_cookie_name, False)):
        response.delete_cookie(
            name,
            path="/",
            secure=service.settings.cookie_secure,
            httponly=httponly,
            samesite="strict",
        )
    return response


@router.get("/me", response_model=Me)
async def me(request: Request) -> Response:
    service = _service(request)
    info = service.validate(service.session_token(request.scope))
    if info is None:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return JSONResponse({"username": info.username})


@router.get("/csrf", response_model=CsrfToken)
async def csrf(request: Request) -> Response:
    service = _service(request)
    info = service.validate(service.session_token(request.scope))
    token = service.new_csrf(info.nonce if info else "")
    response = JSONResponse({"token": token})
    _set_csrf(response, service, token)
    return response
