"""Hand-written SIP parsing and response building, with strict bounds.

No regular expressions: every step is a bounded ``str`` / ``bytes`` operation on at most
``MAX_MESSAGE`` bytes. Nothing in this module touches the network.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

MAX_MESSAGE = 4096  # bytes of a UDP datagram (or a TCP message) that are ever processed
MAX_HEADERS = 64
MAX_LINE = 1024
MAX_START_LINE = 512
MAX_VIAS = 8
MAX_BODY_PREVIEW = 256
MAX_DIGEST_PARAMS = 24
MAX_PARAM = 256

COMPACT = {
    "v": "via",
    "f": "from",
    "t": "to",
    "i": "call-id",
    "m": "contact",
    "c": "content-type",
    "l": "content-length",
    "k": "supported",
    "s": "subject",
    "u": "allow-events",
}
KNOWN_METHODS = frozenset(
    {
        "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "INFO", "MESSAGE", "NOTIFY",
        "PRACK", "PUBLISH", "REFER", "SUBSCRIBE", "UPDATE",
    }
)  # fmt: skip
ALLOW = "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE"
SUPPORTED = "replaces, timer"


class ParseError(ValueError):
    """The datagram is not a SIP message we are willing to look at."""


@dataclass(slots=True)
class Message:
    is_request: bool
    method: str  # request method, or "" for a response
    uri: str
    version: str
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    size: int = 0

    def get(self, name: str) -> str:
        for key, value in self.headers:
            if key == name:
                return value
        return ""

    def get_all(self, name: str, limit: int = MAX_VIAS) -> list[str]:
        out: list[str] = []
        for key, value in self.headers:
            if key == name:
                out.append(value)
                if len(out) >= limit:
                    break
        return out

    @property
    def request_line(self) -> str:
        return f"{self.method} {self.uri} {self.version}"[:MAX_START_LINE]


def _split_head(data: bytes) -> tuple[bytes, bytes]:
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = data.find(sep)
        if idx >= 0:
            return data[:idx], data[idx + len(sep) :]
    return data, b""


def parse(data: bytes) -> Message:
    """Parse one SIP message. Raises :class:`ParseError` on anything out of bounds."""
    if len(data) > MAX_MESSAGE:
        raise ParseError("message too large")
    if not data or b"\x00" in data[:MAX_START_LINE]:
        raise ParseError("empty or binary")
    head, body = _split_head(data)
    lines = head.decode("latin-1").replace("\r\n", "\n").split("\n")
    # Keep-alives and padding before the start line (CRLF CRLF) are tolerated.
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        raise ParseError("no start line")
    start = lines[0]
    if len(start) > MAX_START_LINE:
        raise ParseError("start line too long")
    parts = start.split(" ", 2)
    if len(parts) != 3:
        raise ParseError("bad start line")
    if parts[0].startswith("SIP/"):
        if not parts[0].startswith("SIP/2.") or not parts[1].isdigit() or len(parts[1]) != 3:
            raise ParseError("bad status line")
        msg = Message(False, "", "", parts[0], int(parts[1]))
    else:
        method, uri, version = parts
        if not (method.isalpha() and method.isascii() and 2 <= len(method) <= 16):
            raise ParseError("bad method")
        if not version.startswith("SIP/2."):
            raise ParseError("bad version")
        if not uri or " " in uri:
            raise ParseError("bad uri")
        msg = Message(True, method.upper(), uri, version, 0)
    msg.size = len(data)
    count = 0
    for line in lines[1:]:
        if not line:
            continue
        if len(line) > MAX_LINE:
            raise ParseError("header line too long")
        if line[0] in " \t" and msg.headers:  # folded continuation
            name, value = msg.headers[-1]
            if len(value) + len(line) <= MAX_LINE:
                msg.headers[-1] = (name, value + " " + line.strip())
            continue
        name, sep, value = line.partition(":")
        name = name.strip().lower()
        if not sep or not name or len(name) > 40 or not name.isascii():
            raise ParseError("bad header")
        count += 1
        if count > MAX_HEADERS:
            raise ParseError("too many headers")
        msg.headers.append((COMPACT.get(name, name), value.strip()))
    length = msg.get("content-length")
    if length:
        if not length.isdigit() or len(length) > 6:
            raise ParseError("bad content-length")
        declared = int(length)
        if declared > MAX_MESSAGE:
            raise ParseError("content-length too large")
        body = body[:declared]
    msg.body = body[:MAX_BODY_PREVIEW]
    return msg


# --- URI helpers (plain string operations) -----------------------------------------------


def uri_of(header: str) -> str:
    """The URI inside ``"Name" <sip:user@host>;tag=x`` (or a bare URI)."""
    start = header.find("<")
    if start >= 0:
        end = header.find(">", start)
        return header[start + 1 : end if end > start else len(header)].strip()[:MAX_PARAM]
    return header.split(";", 1)[0].strip()[:MAX_PARAM]


def user_part(uri: str) -> str:
    """The user part of ``sip:user@host`` / ``tel:+41...`` (empty if there is none)."""
    low = uri.lower()
    for scheme in ("sips:", "sip:", "tel:"):
        if low.startswith(scheme):
            uri = uri[len(scheme) :]
            break
    if "@" not in uri and not low.startswith("tel:"):
        return ""
    return uri.split("@", 1)[0].split(";", 1)[0].split(":", 1)[0][:64]


def is_international(number: str) -> bool:
    """Does the dialled number look like an international / premium call?"""
    if number.startswith("+"):
        digits = number[1:]
        return digits.isdigit() and len(digits) >= 7
    if not number.isdigit():
        return False
    return (number.startswith("00") and len(number) >= 9) or (
        number.startswith("011") and len(number) >= 10
    )


# --- Digest ------------------------------------------------------------------------------


def parse_digest(value: str) -> dict[str, str]:
    """Parse ``Digest a="b", c=d`` into a dict (lower-case keys), with strict bounds."""
    value = value.strip()[:1024]
    if value[:6].lower() != "digest":
        return {}
    rest = value[6:]
    out: dict[str, str] = {}
    i, n = 0, len(rest)
    while i < n and len(out) < MAX_DIGEST_PARAMS:
        while i < n and rest[i] in " ,\t":
            i += 1
        j = i
        while j < n and rest[j] not in "=,":
            j += 1
        key = rest[i:j].strip().lower()
        if j >= n or rest[j] == ",":
            i = j + 1
            continue
        i = j + 1
        while i < n and rest[i] == " ":
            i += 1
        if i < n and rest[i] == '"':
            i += 1
            chunk: list[str] = []
            while i < n and rest[i] != '"':
                if rest[i] == "\\" and i + 1 < n:
                    i += 1
                chunk.append(rest[i])
                i += 1
            i += 1
            val = "".join(chunk)
        else:
            j = i
            while j < n and rest[j] != ",":
                j += 1
            val = rest[i:j].strip()
            i = j
        if key and len(key) <= 24:
            out.setdefault(key, val[:MAX_PARAM])
    return out


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", "replace"), usedforsecurity=False).hexdigest()


def digest_matches(params: dict[str, str], method: str, password: str) -> bool:
    """RFC 2617 MD5 check against a *known* cleartext password. Never used to crack anything."""
    algo = params.get("algorithm", "md5").lower()
    if algo != "md5":
        return False
    ha1 = _md5(f"{params.get('username', '')}:{params.get('realm', '')}:{password}")
    ha2 = _md5(f"{method}:{params.get('uri', '')}")
    response = params.get("response", "").lower()
    nonce = params.get("nonce", "")
    # Our challenge has no qop, so RFC 2069 is the right form, but real clients (SIPVicious
    # for one) send qop=auth without nc / cnonce, and others do the full RFC 2617 form.
    if _md5(f"{ha1}:{nonce}:{ha2}") == response:
        return True
    nc, cnonce = params.get("nc", ""), params.get("cnonce", "")
    qop = params.get("qop", "").lower()
    return bool(qop) and _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}") == response


# --- Responses ---------------------------------------------------------------------------

REASONS = {
    200: "OK",
    401: "Unauthorized",
    403: "Forbidden",
    405: "Method Not Allowed",
    407: "Proxy Authentication Required",
    481: "Call/Transaction Does Not Exist",
    486: "Busy Here",
    501: "Not Implemented",
}


def with_source(via: str, ip: str, port: int) -> str:
    """Add ``received`` and fill ``rport`` on a Via value (RFC 3581), like a real server."""
    head, *params = via.split(";")
    out = [head]
    has_rport = False
    for param in params:
        key = param.strip().lower()
        if key == "rport":
            has_rport = True
        elif key.startswith("received=") or key.startswith("rport="):
            return via  # already marked
        else:
            out.append(param)
    out.append(f"received={ip}")
    if has_rport:
        out.append(f"rport={port}")
    return ";".join(out)


def build_response(
    req: Message,
    code: int,
    *,
    to_tag: str,
    required: tuple[str, ...] = (),
    optional: tuple[str, ...] = (),
    max_size: int | None = None,
    source: tuple[str, int] | None = None,
) -> bytes | None:
    """Build a response to ``req``.

    ``required`` header lines must fit or no response is made; ``optional`` ones are added in
    order while the total stays within ``max_size``. Returns ``None`` when even the required
    part does not fit (the caller then stays silent), so a response is never larger than the
    request it answers.
    """
    vias = req.get_all("via")
    to_value = req.get("to")
    from_value = req.get("from")
    call_id = req.get("call-id")
    cseq = req.get("cseq")
    if not (vias and to_value and from_value and call_id and cseq):
        return None
    if "tag=" not in to_value.lower():
        to_value = f"{to_value};tag={to_tag}"
    lines = [f"SIP/2.0 {code} {REASONS.get(code, 'Unknown')}"]
    lines += [f"Via: {v}" for v in vias]
    lines += [f"From: {from_value}", f"To: {to_value}", f"Call-ID: {call_id}", f"CSeq: {cseq}"]
    lines += list(required)
    size = sum(len(x) + 2 for x in lines) + 2
    if max_size is not None and size > max_size:
        return None
    if source is not None:  # ;received= / ;rport= on the top Via, only if it still fits
        marked = f"Via: {with_source(vias[0], source[0], source[1])}"
        if max_size is None or size - len(lines[1]) + len(marked) <= max_size:
            size += len(marked) - len(lines[1])
            lines[1] = marked
    for line in optional:
        if max_size is None or size + len(line) + 2 <= max_size:
            lines.append(line)
            size += len(line) + 2
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")
