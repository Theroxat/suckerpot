"""Dashboard authentication: the owner account, database users, signed session cookie, CSRF.

Design
------
* Two kinds of account. The **owner** is ``ADMIN_USERNAME`` / ``ADMIN_PASSWORD_HASH`` from the
  environment: always an admin, usable even when the database is down, changed only in ``.env``.
  **Users** live in the ``users`` table (``api.users``), with the role ``admin`` or ``viewer``.
* ``POST /api/v1/auth/login`` checks the username and an argon2id hash and answers ``204`` with
  an ``sp_session`` cookie (httpOnly, Secure unless ``COOKIE_SECURE=false``, SameSite=Strict).
  Unknown usernames cost the same argon2 verification as known ones.
* The cookie is an HMAC-signed token ``v2.<subject>.<version>.<iat>.<exp>.<nonce>.<sig>``. The
  subject is ``o`` (owner) or ``u<id>``; the version is the user's ``session_version``, which
  any password change, reset, disable, role change, deletion or "revoke sessions" bumps, so
  every existing session of that user dies on its next request. The signing key is derived
  from ``SESSION_SECRET``, the owner password hash and a per-boot random value. Logout puts the
  nonce in a small in-memory revocation set.
* CSRF is a double-submit token: ``GET /auth/csrf`` sets a readable ``sp_csrf`` cookie (itself
  HMAC-signed, so a planted cookie is rejected) and every unsafe request must echo it in
  ``X-CSRF-Token``. Login is exempt from the token but requires a same-origin ``Origin`` or
  ``Referer``.
* A pure ASGI middleware guards every ``/api/v1`` HTTP path except ``/api/v1/auth/*``: it checks
  the session, resolves the account (``Principal``), holds back a user who still has to choose
  a password, and checks CSRF. Roles are enforced per route in ``api.authz``. The live
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
from datetime import UTC, datetime
from urllib.parse import urlsplit

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send
from suckerpot_db import UserRow

from api import accounts, audit, passwords
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
MAX_REAUTH_FAILURES = 5  # consecutive wrong re-authentication passwords before the session dies
MAX_VERIFY_CONCURRENCY = 1  # one argon2 verify holds ~64 MiB: more would risk the memory limit
MAX_VERIFY_PENDING = 3  # running + queued; beyond this login answers 429 immediately
OWNER = "o"  # token subject of the owner account; database users are "u<id>"
TOKEN_VERSION = "v2"  # noqa: S105 - the token format tag, not a password
MAX_USER_WINDOWS = MAX_TRACKED_IPS
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
    rate_per_user: int = 10
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
            rate_per_user=int(env.get("LOGIN_RATE_USER", "").strip() or 10),
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
    """What a valid session token says. ``subject`` is ``o`` or ``u<id>``."""

    subject: str
    version: int
    issued_at: int
    expires_at: int
    nonce: str

    @property
    def user_id(self) -> int | None:
        if self.subject.startswith("u") and self.subject[1:].isdigit():
            return int(self.subject[1:])
        return None


@dataclass(frozen=True)
class Principal:
    """Who is making the request: resolved by the middleware, read by ``api.authz``."""

    username: str
    display_name: str
    role: str  # "admin" or "viewer"
    is_owner: bool
    user_id: int | None
    must_change_password: bool
    session: SessionInfo
    last_login_at: datetime | None = None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


@dataclass(frozen=True)
class LoginResult:
    subject: str
    version: int


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
        # Checked in place of a user's hash when the username does not exist.
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(16))
        self._login_possible = settings.password_hash is not None
        # A per-boot random value: every restart signs everybody out (revocations are in memory).
        material = settings.secret + b"|" + self._hash.encode() + b"|" + secrets.token_bytes(16)
        self._session_key = hashlib.sha256(b"sp-session|" + material).digest()
        self._csrf_key = hashlib.sha256(b"sp-csrf|" + settings.secret).digest()
        self._revoked: dict[str, int] = {}
        self._per_ip: dict[str, _Window] = {}
        self._global = _Window()
        self._reauth_failures: dict[str, int] = {}
        self._verify_sem = asyncio.Semaphore(MAX_VERIFY_CONCURRENCY)
        self._pending = 0

    # -- session tokens -------------------------------------------------------------------------

    def _sign(self, key: bytes, body: str) -> str:
        return _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())

    def issue(self, subject: str = OWNER, version: int = 0) -> tuple[str, SessionInfo]:
        now = int(self.clock())
        info = SessionInfo(
            subject=subject,
            version=version,
            issued_at=now,
            expires_at=now + int(self.settings.ttl_hours * 3600),
            nonce=secrets.token_urlsafe(16),
        )
        body = f"{TOKEN_VERSION}.{info.subject}.{info.version}.{info.issued_at}.{info.expires_at}"
        body = f"{body}.{info.nonce}"
        return f"{body}.{self._sign(self._session_key, self._signed(body))}", info

    def _signed(self, body: str) -> str:
        # The owner name is part of the signed text: renaming the owner ends every session.
        return f"{body}|{_b64(self.settings.username.encode())}"

    def validate(self, token: str | None) -> SessionInfo | None:
        """The session behind ``token``, or None if forged, expired, revoked or disabled.

        For a database user this only proves the token is genuine; ``resolve`` checks that the
        user still exists, is enabled and that the session version is current.
        """
        if self.settings.disabled:
            now = int(self.clock())
            return SessionInfo(OWNER, 0, now, now + 3600, "disabled")
        if not token or len(token) > 512:
            return None
        parts = token.split(".")
        if len(parts) != 7 or parts[0] != TOKEN_VERSION:
            return None
        body = ".".join(parts[:6])
        expected = self._sign(self._session_key, self._signed(body))
        if not hmac.compare_digest(expected.encode(), parts[6].encode()):
            return None
        try:
            version, issued_at, expires_at = int(parts[2]), int(parts[3]), int(parts[4])
        except ValueError:
            return None
        subject = parts[1]
        if subject != OWNER and not (subject.startswith("u") and subject[1:].isdigit()):
            return None
        if self.clock() >= expires_at or parts[5] in self._revoked:
            return None
        return SessionInfo(subject, version, issued_at, expires_at, parts[5])

    async def resolve(
        self, token: str | None, factory: async_sessionmaker[AsyncSession] | None
    ) -> Principal | None:
        """The account behind a session token, or None when the session is no longer valid."""
        info = self.validate(token)
        if info is None:
            return None
        if info.user_id is None:
            name = self.settings.username
            return Principal(name, name, "admin", True, None, False, info)
        if factory is None:
            return None
        async with factory() as db:
            row = await accounts.get_by_id(db, info.user_id)
        if row is None or row.disabled or row.session_version != info.version:
            return None
        return principal_of(row, info)

    def reauth_failed(self, info: SessionInfo) -> bool:
        """Count a wrong re-authentication password. True once the session was revoked."""
        n = self._reauth_failures.get(info.nonce, 0) + 1
        if n >= MAX_REAUTH_FAILURES:
            self._reauth_failures.pop(info.nonce, None)
            self.revoke(info)
            return True
        if len(self._reauth_failures) >= MAX_REVOKED:
            self._reauth_failures.clear()
        self._reauth_failures[info.nonce] = n
        return False

    def reauth_ok(self, info: SessionInfo) -> None:
        self._reauth_failures.pop(info.nonce, None)

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

    async def _limited[T](self, fn: Callable[[], T]) -> T:
        """Run one slow argon2 call in a thread, at most one at a time, a few waiting."""
        if self._pending >= MAX_VERIFY_PENDING:
            raise LoginBusy
        self._pending += 1
        try:
            async with self._verify_sem:
                return await asyncio.to_thread(fn)
        finally:
            self._pending -= 1

    async def check_credentials(self, username: str, password: str) -> bool:
        """The owner's credentials. Constant work whether the name matches or not."""
        password_ok = await self._limited(lambda: self._verify(password))
        user_ok = hmac.compare_digest(username.encode(), self.settings.username.encode())
        return password_ok and user_ok and self._login_possible

    def _verify(self, password: str) -> bool:
        return self.verify_hash(self._hash, password)

    def verify_hash(self, hashed: str, password: str) -> bool:
        try:
            return self._hasher.verify(hashed, password)
        except (VerificationError, InvalidHashError):
            return False

    async def check_hash(self, hashed: str | None, password: str) -> bool:
        """Verify against ``hashed``; with None a dummy hash is checked, so the cost is equal."""
        real = hashed is not None
        target = hashed if hashed is not None else self._dummy_hash
        ok = await self._limited(lambda: self.verify_hash(target, password))
        return ok and real

    async def hash_password(self, password: str) -> str:
        """An argon2id hash (library defaults, like ``python -m api.hashpw``)."""
        return await self._limited(lambda: self._hasher.hash(password))

    def is_owner_name(self, username: str) -> bool:
        return hmac.compare_digest(username.encode(), self.settings.username.encode())

    def _window(self, key: str, now: float) -> _Window | None:
        win = self._per_ip.get(key)
        if win is None:
            if len(self._per_ip) >= MAX_TRACKED_IPS:
                for w in self._per_ip.values():
                    w.prune(now)
                for stale in [k for k, w in self._per_ip.items() if not w.hits]:
                    del self._per_ip[stale]
                if len(self._per_ip) >= MAX_TRACKED_IPS:
                    return None
            win = self._per_ip[key] = _Window()
        win.prune(now)
        return win

    def rate_limited(self, ip: str, scope: str = "", username: str | None = None) -> int | None:
        """Record an attempt. Returns Retry-After seconds when over the limit, else None.

        ``scope`` gives another action (e.g. password re-authentication) its own per-address
        window, but every attempt is also charged to the same global window as login, so
        re-authentication cannot be used to guess the password around the login limit.
        ``username`` adds a per-account window (case-insensitive), so one account cannot be
        hammered from many addresses.
        """
        ip = rate_key(ip)
        glob = self._global
        if scope:
            ip = f"{scope}|{ip}"
        now = self.clock()
        glob.prune(now)
        windows = [(self._window(ip, now), self.settings.rate_per_ip)]
        if username is not None:
            windows.append(
                (
                    self._window(f"user|{username.strip().lower()[:64]}", now),
                    self.settings.rate_per_user,
                )
            )
        windows.append((glob, self.settings.rate_global))
        charged: list[_Window] = []
        for w, limit in windows:
            if w is None:
                return int(RATE_WINDOW_S)
            if len(w.hits) >= limit:
                return max(1, int(RATE_WINDOW_S - (now - w.hits[0])) + 1)
            charged.append(w)
        for w in charged:
            w.hits.append(now)
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


def principal_of(row: UserRow, info: SessionInfo) -> Principal:
    return Principal(
        username=row.username,
        display_name=row.display_name,
        role=row.role,
        is_owner=False,
        user_id=row.id,
        must_change_password=row.must_change_password,
        session=info,
        last_login_at=row.prev_login_at,
    )


def _session_factory(app: object) -> async_sessionmaker[AsyncSession] | None:
    state = getattr(app, "state", None)
    factory: async_sessionmaker[AsyncSession] | None = getattr(state, "session_factory", None)
    return factory


def allow_any_role[F: Callable[..., object]](fn: F) -> F:
    """Mark a state-changing endpoint that every signed-in role may call (sign in or out, change
    one's own password). Every other unsafe endpoint needs an administrator (``api.authz``)."""
    fn.__allow_any_role__ = True  # type: ignore[attr-defined]
    return fn


async def current_principal(request: Request) -> Principal | None:
    """The signed-in account, resolved once per request (None without a valid session)."""
    state: dict[str, object] = request.scope.setdefault("state", {})
    cached = state.get("principal")
    if isinstance(cached, Principal):
        return cached
    service = _service(request)
    principal = await service.resolve(
        service.session_token(request.scope), _session_factory(request.app)
    )
    if principal is not None:
        state["principal"] = principal
    return principal


class AuthMiddleware:
    """Require a valid session (and CSRF token on unsafe methods) for ``/api/v1`` HTTP paths.

    The account behind the session is resolved here and stored in ``scope["state"]``. A user who
    still has to choose a password may only reach ``/api/v1/auth/*``.
    """

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
        try:
            principal = await self.auth.resolve(
                self.auth.session_token(scope), _session_factory(scope.get("app"))
            )
        except (SQLAlchemyError, OSError):
            log.warning("session lookup failed: database unavailable")
            await JSONResponse({"detail": "Service unavailable"}, status_code=503)(
                scope, receive, send
            )
            return
        if principal is None:
            await JSONResponse({"detail": "Not authenticated"}, status_code=401)(
                scope, receive, send
            )
            return
        if principal.must_change_password:
            await JSONResponse(
                {"detail": "Choose a new password first", "code": "password_change_required"},
                status_code=403,
            )(scope, receive, send)
            return
        session = principal.session
        if scope["method"] in UNSAFE_METHODS and not self.auth.csrf_ok(
            self.auth.csrf_cookie(scope), _header(scope, HEADER_CSRF.encode()), session.nonce
        ):
            await JSONResponse({"detail": "CSRF token missing or invalid"}, status_code=403)(
                scope, receive, send
            )
            return
        scope.setdefault("state", {})["principal"] = principal
        await self.app(scope, receive, send)


# -- router -----------------------------------------------------------------------------------

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    username: str = Field(max_length=128)
    password: str = Field(max_length=1024, repr=False)


class Me(BaseModel):
    username: str
    display_name: str
    role: str
    is_owner: bool
    must_change_password: bool
    read_only: bool
    last_login_at: datetime | None


class CsrfToken(BaseModel):
    token: str


class PasswordBody(BaseModel):
    current_password: str = Field(max_length=1024, repr=False)
    new_password: str = Field(max_length=1024, repr=False)


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


async def _authenticate(
    request: Request, service: AuthService, body: LoginBody, ip: str
) -> LoginResult | None:
    """Check the credentials. Exactly one argon2 verification runs, whoever the user is."""
    factory = _session_factory(request.app)
    if service.is_owner_name(body.username):
        if not await service.check_credentials(body.username, body.password):
            return None
        if factory is not None:  # the audit entry is best effort: the owner must always get in
            try:
                async with factory() as db:
                    name = service.settings.username
                    await audit.record(db, actor=name, action="auth.login", target=name, ip=ip)
                    await db.commit()
            except (SQLAlchemyError, OSError):
                log.warning("owner login could not be written to the audit log")
        return LoginResult(OWNER, 0)
    if factory is None:
        await service.check_hash(None, body.password)
        return None
    async with factory() as db:
        row = await accounts.find_by_username(db, body.username)
        ok = await service.check_hash(row.password_hash if row else None, body.password)
        if row is None:
            return None
        usable = not row.disabled and not accounts.is_locked(row)
        if ok and usable:
            await accounts.register_success(db, row.id)
            await audit.record(
                db, actor=row.username, action="auth.login", target=row.username, ip=ip
            )
            await db.commit()
            return LoginResult(f"u{row.id}", row.session_version)
        if not ok and not row.disabled and usable and await accounts.register_failure(db, row.id):
            await audit.record(
                db, actor=row.username, action="user.locked", target=row.username, ip=ip,
                details={"failures": accounts.LOCK_AFTER_FAILURES},
            )  # fmt: skip
            log.warning("account locked after repeated failures")
        await db.commit()
        return None


@router.post("/login", status_code=204)
@allow_any_role
async def login(body: LoginBody, request: Request) -> Response:
    service = _service(request)
    if service.settings.disabled:
        return Response(status_code=204)
    if not same_origin(request):
        return JSONResponse({"detail": "Cross-origin login refused"}, status_code=403)
    ip = service.client_ip(request)
    retry = service.rate_limited(ip, username=body.username)
    if retry is not None:
        return JSONResponse(
            {"detail": "Too many attempts"}, status_code=429, headers={"Retry-After": str(retry)}
        )
    try:
        result = await _authenticate(request, service, body, ip)
    except LoginBusy:
        return JSONResponse(
            {"detail": "Too many attempts"}, status_code=429, headers={"Retry-After": "2"}
        )
    except (SQLAlchemyError, OSError):
        log.warning("dashboard login failed: database unavailable")
        return JSONResponse({"detail": "Sign-in is temporarily unavailable"}, status_code=503)
    if result is None:
        log.warning("dashboard login failed ip=%s", ip[:64])  # never the submitted values
        await asyncio.sleep(FAILURE_DELAY_S)
        return JSONResponse({"detail": "Invalid credentials"}, status_code=401)
    previous = service.validate(service.session_token(request.scope))
    if previous is not None:
        service.revoke(previous)  # rotate: the old token dies with the new login
    token, info = service.issue(result.subject, result.version)
    response = Response(status_code=204)
    _set_cookie(response, service, token, info.expires_at - info.issued_at)
    _set_csrf(response, service, service.new_csrf(info.nonce))
    log.info("dashboard login ok ip=%s", ip[:64])
    return response


@router.post("/logout", status_code=204)
@allow_any_role
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
    try:
        principal = await current_principal(request)
    except (SQLAlchemyError, OSError):
        return JSONResponse({"detail": "Service unavailable"}, status_code=503)
    if principal is None:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return JSONResponse(
        Me(
            username=principal.username,
            display_name=principal.display_name,
            role=principal.role,
            is_owner=principal.is_owner,
            must_change_password=principal.must_change_password,
            read_only=not principal.is_admin,
            last_login_at=principal.last_login_at,
        ).model_dump(mode="json")
    )


@router.get("/csrf", response_model=CsrfToken)
async def csrf(request: Request) -> Response:
    service = _service(request)
    info = service.validate(service.session_token(request.scope))
    token = service.new_csrf(info.nonce if info else "")
    response = JSONResponse({"token": token})
    _set_csrf(response, service, token)
    return response


def _problem(status: int, detail: str, code: str, **extra: object) -> Response:
    return JSONResponse({"detail": detail, "code": code, **extra}, status_code=status)


@router.post("/password", status_code=204)
@allow_any_role
async def change_password(body: PasswordBody, request: Request) -> Response:
    """Change one's own password. Needs the current one; every other session of the user ends."""
    service = _service(request)
    if service.settings.disabled:
        return _problem(409, "Sign-in is turned off on this server.", "auth_disabled")
    if not same_origin(request):
        return _problem(403, "Cross-origin request refused", "origin")
    try:
        principal = await current_principal(request)
    except (SQLAlchemyError, OSError):
        return _problem(503, "Service unavailable", "unavailable")
    if principal is None:
        return _problem(401, "Not authenticated", "unauthenticated")
    info = principal.session
    header = request.headers.get(HEADER_CSRF)
    if not service.csrf_ok(service.csrf_cookie(request.scope), header, info.nonce):
        return _problem(403, "CSRF token missing or invalid", "csrf")
    if principal.is_owner or principal.user_id is None:
        return _problem(
            403, "The owner password is changed in .env, not here.", "owner_password_in_env"
        )
    ip = service.client_ip(request)
    retry = service.rate_limited(ip, "reauth")
    if retry is not None:
        return JSONResponse(
            {"detail": "Too many attempts", "code": "rate_limited"},
            status_code=429,
            headers={"Retry-After": str(retry)},
        )
    factory = _session_factory(request.app)
    assert factory is not None  # noqa: S101 - a signed-in user implies a session factory
    try:
        async with factory() as db:
            row = await accounts.get_by_id(db, principal.user_id)
            ok = await service.check_hash(row.password_hash if row else None, body.current_password)
            if row is None:
                return _problem(401, "Not authenticated", "unauthenticated")
            if not ok:
                await asyncio.sleep(FAILURE_DELAY_S)
                if service.reauth_failed(info):
                    return _problem(
                        401, "Signed out after too many wrong passwords.", "session_revoked"
                    )
                return _problem(403, "The current password is incorrect.", "reauth_failed")
            service.reauth_ok(info)
            reason = passwords.check_password(body.new_password, row.username)
            if reason is None and body.new_password == body.current_password:
                reason = "same_password"
            if reason is not None:
                message = passwords.MESSAGES.get(reason, "Choose a different password.")
                return _problem(422, message, "weak_password", reason=reason)
            row.password_hash = await service.hash_password(body.new_password)
            row.must_change_password = False
            row.password_changed_at = datetime.now(UTC)
            row.session_version += 1
            await audit.record(
                db, actor=row.username, action="password.change", target=row.username, ip=ip
            )
            await db.commit()
            version = row.session_version
    except LoginBusy:
        return JSONResponse(
            {"detail": "Too many attempts", "code": "rate_limited"},
            status_code=429,
            headers={"Retry-After": "2"},
        )
    except (SQLAlchemyError, OSError):
        return _problem(503, "Service unavailable", "unavailable")
    # The browser that changed the password stays signed in; every other session just died.
    service.revoke(info)
    token, fresh = service.issue(info.subject, version)
    response = Response(status_code=204)
    _set_cookie(response, service, token, fresh.expires_at - fresh.issued_at)
    _set_csrf(response, service, service.new_csrf(fresh.nonce))
    return response
