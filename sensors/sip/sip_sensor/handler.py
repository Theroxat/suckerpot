"""SIP request handling: decide the (tiny) reply and record what happened.

Replies are canned and generated; nothing is ever established. There is no 200 OK with SDP, no
RTP, no dialog state. The only 200 OK to a REGISTER is for a configured weak credential pair
and it carries no state either. Responses are never answered (no ping-pong between reflectors).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from suckerpot_common import EventType

from sip_sensor import sip
from sip_sensor.config import Config
from sip_sensor.events import Session, Tracker
from sip_sensor.identity import Profile

SCANNER_UAS = (
    "friendly-scanner",
    "sipvicious",
    "sipcli",
    "sundayddr",
    "iwar",
    "sip-scan",
    "sipp",
    "vaxsipuseragent",
    "pplsip",
    "voipbuster",
    "eyebeam",
    "zoiper",
    "sipsak",
    "nmap",
)
INJECTION_MARKERS = ("${jndi", "<?php", "$(", "`", "/bin/sh", "/etc/passwd", "../..", "<script")
MAX_INPUT = 300


@dataclass(slots=True)
class Reply:
    data: bytes | None
    code: int


ReplyFn = Callable[..., Reply]


def _scanner(ua: str) -> bool:
    low = ua.lower()
    return any(m in low for m in SCANNER_UAS)


class Handler:
    def __init__(self, cfg: Config, profile: Profile, tracker: Tracker) -> None:
        self.cfg = cfg
        self.profile = profile
        self.tracker = tracker
        self.weak = dict(cfg.weak_credentials)
        self.parse_errors = 0

    # -- helpers ---------------------------------------------------------------------------

    def _challenge(self, header: str, ip: str) -> str:
        nonce = self.profile.nonce(ip)
        return f'{header}: Digest algorithm=MD5, realm="{self.profile.realm}", nonce="{nonce}"'

    def _short_challenge(self, header: str, ip: str) -> str:
        """Same challenge without ``algorithm`` (MD5 is the default), for tiny requests."""
        return f'{header}: Digest realm="{self.profile.realm}", nonce="{self.profile.nonce(ip)}"'

    def _auth(self, msg: sip.Message, ip: str) -> tuple[dict[str, str], bool, str | None]:
        """Digest parameters of the request, whether they verify, and the matched password."""
        raw = msg.get("authorization") or msg.get("proxy-authorization")
        params = sip.parse_digest(raw) if raw else {}
        if not params:
            return {}, False, None
        password = self.weak.get(params.get("username", ""))
        ok = (
            password is not None
            and params.get("realm", "") == self.profile.realm
            and self.profile.nonce_valid(params.get("nonce", ""), ip)
            and sip.digest_matches(params, msg.method, password)
        )
        return params, ok, password if ok else None

    # -- entry point -----------------------------------------------------------------------

    def handle(
        self,
        data: bytes,
        ip: str,
        port: int,
        transport: str,
        now: float,
        *,
        can_reply: bool,
        max_reply: int | None,
    ) -> Reply:
        try:
            msg = sip.parse(data)
        except sip.ParseError as exc:
            self.parse_errors += 1
            sess = self.tracker.session(ip, port, now, verified=transport == "tcp")
            if sess is not None:
                sess.note("INVALID", "", "", len(data), transport)
                sess.silent += 1
                self.tracker.low(
                    sess,
                    port,
                    {
                        "kind": "sip_malformed",
                        "reason": str(exc),
                        "size": len(data),
                        "transport": transport,
                        "preview": data[:120].decode("latin-1"),
                    },
                )
            return Reply(None, 0)
        # A valid, IP-bound nonce proves the source address is not spoofed; so does a TCP
        # handshake. Such sources get their own session-admission lane.
        raw_auth = msg.get("authorization") or msg.get("proxy-authorization")
        verified = transport == "tcp" or (
            bool(raw_auth)
            and self.profile.nonce_valid(sip.parse_digest(raw_auth).get("nonce", ""), ip)
        )
        sess = self.tracker.session(ip, port, now, verified=verified)
        ua = msg.get("user-agent")[:200]
        flags: list[str] = []
        if _scanner(ua):
            flags.append("scanner_ua")
        blob = (ua + msg.uri + msg.get("from") + msg.get("to") + msg.get("contact")).lower()
        if any(m in blob for m in INJECTION_MARKERS):
            flags.append("injection_attempt")
        if not msg.is_request:
            return self._record_low(sess, msg, ip, port, transport, ua, [*flags, "response"], "", 0)
        method = msg.method
        to_uri = sip.uri_of(msg.get("to"))
        from_uri = sip.uri_of(msg.get("from"))
        tag = "as" + secrets.token_hex(4)

        def reply(
            code: int,
            required: tuple[str, ...] = (),
            optional: tuple[str, ...] = (),
            fallback: tuple[str, ...] = (),
        ) -> Reply:
            if not can_reply:
                return Reply(None, code)
            extra = (f"Server: {self.profile.user_agent}", *optional, "Content-Length: 0")
            out = sip.build_response(
                msg,
                code,
                to_tag=tag,
                required=required,
                optional=extra,
                max_size=max_reply,
                source=(ip, port),
            )
            if out is None and fallback:
                out = sip.build_response(
                    msg,
                    code,
                    to_tag=tag,
                    required=fallback,
                    optional=extra,
                    max_size=max_reply,
                    source=(ip, port),
                )
            return Reply(out, code)

        if method == "OPTIONS":
            r = reply(
                200,
                optional=(
                    f"Allow: {sip.ALLOW}",
                    f"Supported: {sip.SUPPORTED}",
                    "Accept: application/sdp",
                    f"Contact: <{msg.uri[:120]}>",
                ),
            )
            return self._record_low(
                sess,
                msg,
                ip,
                port,
                transport,
                ua,
                [*flags, "options_scan"],
                sip.user_part(to_uri),
                r.code,
                r,
            )
        if method == "REGISTER":
            return self._register(
                sess, msg, ip, port, transport, ua, flags, reply, to_uri, from_uri
            )
        if method == "INVITE":
            return self._invite(sess, msg, ip, port, transport, ua, flags, reply, to_uri, from_uri)
        if method == "ACK":
            return self._record_low(sess, msg, ip, port, transport, ua, flags, "", 0)
        if method in ("CANCEL", "BYE"):
            r = reply(481)
            return self._record_low(sess, msg, ip, port, transport, ua, flags, "", r.code, r)
        if method in sip.KNOWN_METHODS:
            r = reply(405, optional=(f"Allow: {sip.ALLOW}",))
        else:
            r = reply(501)
        return self._record_low(
            sess,
            msg,
            ip,
            port,
            transport,
            ua,
            [*flags, "unknown_method"] if method not in sip.KNOWN_METHODS else flags,
            sip.user_part(to_uri),
            r.code,
            r,
        )

    # -- per method ------------------------------------------------------------------------

    def _record_low(
        self,
        sess: Session | None,
        msg: sip.Message,
        ip: str,
        port: int,
        transport: str,
        ua: str,
        flags: list[str],
        target: str,
        code: int,
        rep: Reply | None = None,
    ) -> Reply:
        rep = rep or Reply(None, code)
        if sess is None:
            return rep
        method = msg.method if msg.is_request else "RESPONSE"
        sess.note(method, ua, target, msg.size, transport)
        sess.flags.update(flags)
        if rep.data is not None:
            sess.replies += 1
        else:
            sess.silent += 1
        self.tracker.low(
            sess,
            port,
            {
                "kind": "options_scan" if "options_scan" in flags else "sip_probe",
                "method": method,
                "input": msg.request_line if msg.is_request else f"{msg.version} {msg.status}",
                "request_uri": msg.uri[:200],
                "to": sip.uri_of(msg.get("to"))[:200],
                "from": sip.uri_of(msg.get("from"))[:200],
                "user_agent": ua,
                "transport": transport,
                "response_code": code,
                "flags": flags,
            },
        )
        return rep

    def _credentials(
        self,
        sess: Session,
        msg: sip.Message,
        port: int,
        transport: str,
        ua: str,
        flags: list[str],
        params: dict[str, str],
        ok: bool,
        password: str | None,
        code: int,
        from_uri: str,
    ) -> None:
        response = params.get("response", "")
        self.tracker.high(
            sess,
            port,
            EventType.login_attempt,
            {
                "username": params.get("username", "")[:64],
                "password": password,  # only ever a configured weak password, never cracked
                "success": ok,
                "method": msg.method,
                "realm": params.get("realm", "")[:64],
                "uri": params.get("uri", "")[:200],
                "algorithm": params.get("algorithm", "MD5")[:16],
                "response_preview": response[:8],
                "from": from_uri[:200],
                "user_agent": ua,
                "transport": transport,
                "response_code": code,
                "flags": list(
                    dict.fromkeys([*flags, "register" if msg.method == "REGISTER" else "invite"])
                ),
            },
        )

    def _register(
        self,
        sess: Session | None,
        msg: sip.Message,
        ip: str,
        port: int,
        transport: str,
        ua: str,
        flags: list[str],
        reply: ReplyFn,
        to_uri: str,
        from_uri: str,
    ) -> Reply:
        flags = [*flags, "register"]
        params, ok, password = self._auth(msg, ip)
        if ok:
            contact = msg.get("contact")
            optional = (f"Contact: {contact[:160]};expires=120",) if contact else ()
            r: Reply = reply(200, optional=optional)
        else:
            r = reply(
                401,
                required=(self._challenge("WWW-Authenticate", ip),),
                fallback=(self._short_challenge("WWW-Authenticate", ip),),
            )
        if sess is None:
            return r
        if params:
            sess.note("REGISTER", ua, sip.user_part(to_uri), msg.size, transport)
            sess.flags.update(flags)
            sess.replies += r.data is not None
            sess.silent += r.data is None
            self._credentials(
                sess, msg, port, transport, ua, flags, params, ok, password, r.code, from_uri
            )
            return r
        return self._record_low(
            sess,
            msg,
            ip,
            port,
            transport,
            ua,
            flags,
            sip.user_part(to_uri) or sip.user_part(from_uri),
            r.code,
            r,
        )

    def _invite(
        self,
        sess: Session | None,
        msg: sip.Message,
        ip: str,
        port: int,
        transport: str,
        ua: str,
        flags: list[str],
        reply: ReplyFn,
        to_uri: str,
        from_uri: str,
    ) -> Reply:
        dialled = sip.user_part(sip.uri_of(msg.uri)) or sip.user_part(to_uri)
        flags = [*flags, "invite"]
        if sip.is_international(dialled):
            flags.append("toll_fraud")
        params, ok, password = self._auth(msg, ip)
        if ok:
            r: Reply = reply(486)
        else:
            r = reply(
                407,
                required=(self._challenge("Proxy-Authenticate", ip),),
                fallback=(self._short_challenge("Proxy-Authenticate", ip),),
            )
        if sess is None:
            return r
        sess.note("INVITE", ua, dialled, msg.size, transport)
        sess.flags.update(flags)
        sess.replies += r.data is not None
        sess.silent += r.data is None
        if params:
            self._credentials(
                sess, msg, port, transport, ua, flags, params, ok, password, r.code, from_uri
            )
        self.tracker.high(
            sess,
            port,
            EventType.command,
            {
                "input": msg.request_line[:MAX_INPUT],
                "method": "INVITE",
                "to": to_uri[:200],
                "from": from_uri[:200],
                "dialled": dialled,
                "user_agent": ua,
                "transport": transport,
                "response_code": r.code,
                "output_preview": f"SIP/2.0 {r.code}",
                "body_preview": msg.body.decode("latin-1")[:200],
                "flags": flags,
            },
        )
        return r
