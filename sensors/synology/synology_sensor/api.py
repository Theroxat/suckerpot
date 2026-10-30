"""The fake DSM: routes, canned answers and the facts that go into events.

Only data is looked at. Nothing here runs, evaluates or fetches anything, and no login is ever
accepted: every authenticated API answers DSM's "SID not found" (119).
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from synology_sensor import detect, dsm
from synology_sensor.config import Config
from synology_sensor.httpio import Request
from synology_sensor.profile import Profile

_NO_AUTH_APIS = frozenset({"SYNO.API.Info", "SYNO.API.Auth", "SYNO.API.Encryption"})
_SYSTEM_ACCOUNTS = frozenset({"nobody", "daemon", "ftp", "sshd", "postgres", "www-data", "mysql"})
_SEVERE_FLAGS = frozenset({"sid_forge", "scgi_injection", "file_write", "ransom_indicator"})
_ASSET_PREFIXES = ("/webman/resources/", "/synoSDSjslib/", "/scripts/", "/webman/modules/")
_JSON = 'application/json; charset="UTF-8"'
_HTML = "text/html; charset=utf-8"
_REASONS = {404: "Not Found", 405: "Not Allowed", 301: "Moved Permanently", 400: "Bad Request"}


@dataclass
class Resp:
    status: int
    body: bytes = b""
    ctype: str = _HTML
    headers: dict[str, str] = field(default_factory=dict)
    close: bool = False


@dataclass
class Outcome:
    analysis: detect.Analysis = field(default_factory=detect.Analysis)
    flags: set[str] = field(default_factory=set)
    logins: list[dict[str, Any]] = field(default_factory=list)
    downloads: list[dict[str, Any]] = field(default_factory=list)
    route: str = ""
    important: bool = False


@dataclass(frozen=True)
class Ctx:
    ip: str
    tls: bool
    plain_on_tls: bool = False


class LoginTracker:
    """Failures per source IP in a sliding window; bounded, least recently seen out first."""

    def __init__(self, limit: int, window: float, max_ips: int) -> None:
        self._limit = limit
        self._window = window
        self._max = max_ips
        self._items: OrderedDict[str, tuple[int, float]] = OrderedDict()

    def blocked(self, ip: str) -> bool:
        item = self._items.get(ip)
        return (
            item is not None
            and time.monotonic() - item[1] < self._window
            and item[0] >= self._limit
        )

    def fail(self, ip: str) -> None:
        now = time.monotonic()
        count, start = self._items.get(ip, (0, now))
        if now - start >= self._window:
            count, start = 0, now
        self._items[ip] = (count + 1, start)
        self._items.move_to_end(ip)
        while len(self._items) > self._max:
            self._items.popitem(last=False)


def _bucket(account: str, mod: int) -> int:
    return hashlib.sha256(account.lower().encode("utf-8", "replace")).digest()[0] % mod


class SynologyApi:
    def __init__(self, cfg: Config, profile: Profile, public_key_pem: str = "") -> None:
        self.cfg = cfg
        self.profile = profile
        self.logins = LoginTracker(cfg.login_fail_limit, cfg.login_fail_window, cfg.login_state_ips)
        self.page = dsm.login_page(profile.hostname, cfg.dsm_version)
        self.public_key = public_key_pem

    # -- helpers ---------------------------------------------------------------------------

    def _json(self, body: bytes, status: int = 200) -> Resp:
        return Resp(status, body, _JSON, {"Cache-Control": "no-store"})

    def error_page(self, status: int) -> Resp:
        reason = _REASONS.get(status, "Error")
        return Resp(status, dsm.nginx_page(status, reason), "text/html", close=status == 400)

    def _redirect(self, req: Request, ctx: Ctx) -> Resp | None:
        if ctx.tls or not self.cfg.http_redirect:
            return None
        host = (req.header("host") or "").split(":")[0][:100]
        ok = host and all(c.isalnum() or c in ".-" for c in host)
        target = (
            f"https://{host if ok else 'localhost'}:{self.cfg.https_public_port}{req.target[:200]}"
        )
        if not all(32 < ord(c) < 127 for c in target):
            target = f"https://localhost:{self.cfg.https_public_port}/"
        return Resp(
            301, dsm.nginx_page(301, "Moved Permanently"), "text/html", {"Location": target}
        )

    # -- login -----------------------------------------------------------------------------

    def _login_code(self, ip: str, account: str, otp: bool) -> int:
        """DSM error code for a failed login. Never a success."""
        if not account:
            return 400
        if self.logins.blocked(ip):
            return 407
        low = account.lower()
        if low == "guest":
            return 401
        if low in _SYSTEM_ACCOUNTS:
            return 402
        if low not in ("admin", "root") and _bucket(account, 11) == 0:
            return 404 if otp else 403  # an account with 2-step verification
        return 400

    def _do_login(self, req: Request, ip: str, a: detect.Analysis, out: Outcome) -> bytes:
        user, password, otp, encrypted = detect.login_fields(a)
        code = self._login_code(ip, user, otp)
        if code in (400, 403, 404) and not self.logins.blocked(ip):
            self.logins.fail(ip)
        out.logins.append(
            {
                "username": user,
                "password": password,
                "otp_present": otp,
                "success": False,
                "api": a.api or "SYNO.API.Auth",
                "path": req.path[:256],
                "api_version": a.api_version,
                "encrypted": encrypted,
                "error_code": code,
                "session": a.get("session")[:64],
            }
        )
        return dsm.error_json(code)

    # -- API endpoints ---------------------------------------------------------------------

    def _api(self, req: Request, ctx: Ctx, a: detect.Analysis, out: Outcome) -> Resp:
        name = a.api
        method = a.api_method
        version = a.api_version
        if not name or not method or not version:
            return self._json(dsm.error_json(101))
        if name not in dsm.API_TABLE:
            return self._json(dsm.error_json(102))
        _, lo, hi = dsm.API_TABLE[name]
        if not version.isascii() or not version.isdigit() or not lo <= int(version) <= hi:
            return self._json(dsm.error_json(104))
        if name == "SYNO.API.Info":
            if method != "query":
                return self._json(dsm.error_json(103))
            query = a.get("query")
            if query in ("", "all"):
                return self._json(dsm.INFO_ALL)
            return self._json(dsm.info_subset(query))
        if name == "SYNO.API.Auth":
            if method == "login":
                return self._json(self._do_login(req, ctx.ip, a, out))
            if method == "logout":
                return self._json(dsm.OK_EMPTY)
            return self._json(dsm.error_json(103))
        if name == "SYNO.API.Encryption":
            if method != "getinfo":
                return self._json(dsm.error_json(103))
            doc = (
                '{"data":{"cipherkey":"__cIpHeRtExT","ciphertoken":"__cIpHeRtOkEn",'
                f'"public_key":{_json_str(self.public_key)},"server_time":{int(time.time())}}},'
                '"success":true}'
            )
            return self._json(doc.encode())
        return self._json(dsm.error_json(119))

    def _legacy_login(self, req: Request, ctx: Ctx, a: detect.Analysis, out: Outcome) -> Resp:
        if not a.get("account", "username", "user", "passwd", "password") and req.method != "POST":
            return Resp(200, b'{"result":"error","success":false,"reason":"error_noparam"}', _JSON)
        out.flags.add("dsm_login")
        self._do_login(req, ctx.ip, a, out)
        return Resp(200, b'{"result":"error","success":false,"reason":"error_cantlogin"}', _JSON)

    # -- routing ---------------------------------------------------------------------------

    def handle(self, req: Request, ctx: Ctx) -> tuple[Resp, Outcome]:
        a = detect.collect(req)
        out = Outcome(analysis=a)
        path = req.path
        low = path.lower()
        route = self._route(low)
        out.route = route
        legacy = route == "legacy_login" and bool(
            a.get("account", "username", "user", "passwd", "password") or req.method == "POST"
        )
        out.flags = detect.analyse(req, a, is_login_path=legacy)
        if route in ("api", "legacy_login", "info") or low.startswith("/webman/"):
            for param, url in detect.request_urls(a):
                tool = "download_station" if a.api.startswith("SYNO.DownloadStation") else "dsm_api"
                out.downloads.append(
                    {"url": url, "tool": tool, "source": "dsm_api", "param": param, "api": a.api}
                )
        if ctx.plain_on_tls:
            resp = Resp(
                400,
                dsm.nginx_page(400, "Bad Request", "The plain HTTP request was sent to HTTPS port"),
                "text/html",
                close=True,
            )
            out.flags.add("plain_http_on_tls")
        elif req.method not in ("GET", "HEAD", "POST"):
            resp = self.error_page(405)
        elif route == "api":
            resp = self._api(req, ctx, a, out)
        elif route == "legacy_login":
            resp = self._legacy_login(req, ctx, a, out)
        elif route == "info":
            resp = self._json(
                b'{"success":true,"data":{"version":"%s","hostname":"%s"}}'
                % (self.cfg.dsm_version.split("-")[1].encode(), self.profile.hostname.encode())
            )
        elif route == "login_page" or route == "asset":
            resp = self._static(req, ctx, low, route)
        else:
            resp = self.error_page(404)
        out.important = bool(out.flags & _SEVERE_FLAGS) or bool(out.downloads) or bool(out.logins)
        return resp, out

    @staticmethod
    def _route(low: str) -> str:
        if low.startswith("/webapi/") and low.endswith(".cgi"):
            return "api"
        if low == "/webman/login.cgi":
            return "legacy_login"
        if low in ("/webman/info.cgi", "/webman/get_status.cgi"):
            return "info"
        if low in ("/", "/index.html", "/webman/index.cgi", "/webman/index.cgi/", "/index.cgi"):
            return "login_page"
        if low in ("/webman/favicon.ico", "/favicon.ico") or low.startswith(_ASSET_PREFIXES):
            return "asset"
        return "other"

    def _static(self, req: Request, ctx: Ctx, low: str, route: str) -> Resp:
        if req.method == "POST":
            return self.error_page(405)
        redirect = self._redirect(req, ctx)
        if redirect is not None and route == "login_page":
            return redirect
        if route == "login_page":
            return Resp(200, self.page, _HTML, {"Cache-Control": "no-cache"})
        if low.endswith(".ico"):
            return Resp(200, dsm.FAVICON, "image/x-icon", {"Cache-Control": "max-age=86400"})
        if low.endswith(".js"):
            return Resp(
                200,
                dsm.asset_body(low, "js"),
                "application/javascript",
                {"Cache-Control": "max-age=86400"},
            )
        if low.endswith(".css"):
            return Resp(
                200, dsm.asset_body(low, "css"), "text/css", {"Cache-Control": "max-age=86400"}
            )
        if low.endswith((".png", ".gif")):
            return Resp(200, dsm.PNG_1X1, "image/png", {"Cache-Control": "max-age=86400"})
        return self.error_page(404)


def _json_str(text: str) -> str:
    return json.dumps(text)
