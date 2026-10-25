"""WordPress ``xmlrpc.php``: safe XML-RPC parsing and canned responses.

Parsing uses defusedxml with DTDs and entities forbidden, so external entities are never
resolved and entity expansion bombs are rejected. Input is size-capped by the caller; nesting
and element counts are bounded here.
"""

from __future__ import annotations

import hashlib
import html
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from xml.etree.ElementTree import Element, ParseError

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from web_sensor import apache

MAX_DEPTH = 8
MAX_ITEMS = 2000
MAX_STR = 1024

METHODS = [
    "system.multicall", "system.listMethods", "system.getCapabilities", "demo.addTwoNumbers",
    "demo.sayHello", "pingback.extensions.getPingbacks", "pingback.ping", "mt.publishPost",
    "mt.getTrackbackPings", "mt.supportedTextFilters", "mt.supportedMethods",
    "mt.setPostCategories", "mt.getPostCategories", "mt.getRecentPostTitles", "mt.getCategoryList",
    "metaWeblog.getUsersBlogs", "metaWeblog.deletePost", "metaWeblog.newMediaObject",
    "metaWeblog.getCategories", "metaWeblog.getRecentPosts", "metaWeblog.getPost",
    "metaWeblog.editPost", "metaWeblog.newPost", "blogger.deletePost", "blogger.editPost",
    "blogger.newPost", "blogger.getRecentPosts", "blogger.getPost", "blogger.getUserInfo",
    "blogger.getUsersBlogs", "wp.restoreRevision", "wp.getRevisions", "wp.getPostTypes",
    "wp.getPostType", "wp.getPostFormats", "wp.getMediaLibrary", "wp.getMediaItem",
    "wp.getCommentStatusList", "wp.newComment", "wp.editComment", "wp.deleteComment",
    "wp.getComments", "wp.getComment", "wp.setOptions", "wp.getOptions", "wp.getPageTemplates",
    "wp.getUsersBlogs", "wp.deleteCategory", "wp.newCategory", "wp.getTags", "wp.getCategories",
    "wp.getAuthors", "wp.getPageList", "wp.editPage", "wp.deletePage", "wp.newPage", "wp.getPages",
    "wp.getPage", "wp.editProfile", "wp.getProfile", "wp.getUsers", "wp.getUser",
    "wp.getTaxonomies", "wp.getTaxonomy", "wp.getTerms", "wp.getTerm", "wp.deleteTerm",
    "wp.editTerm", "wp.newTerm", "wp.getPosts", "wp.getPost", "wp.deletePost", "wp.editPost",
    "wp.newPost", "wp.getUsersBlogs",
]  # fmt: skip
_METHOD_SET = frozenset(METHODS)


class XmlRpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Call:
    method: str
    params: list[Any] = field(default_factory=list)


def _value(el: Element, depth: int, budget: list[int]) -> Any:
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_DEPTH:
        raise XmlRpcError(-32700, "parse error. not well formed")
    children = list(el)
    if not children:
        return (el.text or "")[:MAX_STR]
    node = children[0]
    tag = node.tag
    if tag in ("string", "int", "i4", "boolean", "double", "base64", "dateTime.iso8601"):
        text = (node.text or "")[:MAX_STR]
        if tag in ("int", "i4"):
            try:
                return int(text.strip())
            except ValueError:
                return 0
        return text
    if tag == "array":
        data = node.find("data")
        items = list(data) if data is not None else []
        return [_value(v, depth + 1, budget) for v in items[:MAX_ITEMS] if v.tag == "value"]
    if tag == "struct":
        out: dict[str, Any] = {}
        for member in list(node)[:MAX_ITEMS]:
            name_el = member.find("name")
            val_el = member.find("value")
            if name_el is not None and val_el is not None:
                out[(name_el.text or "")[:128]] = _value(val_el, depth + 1, budget)
        return out
    return (node.text or "")[:MAX_STR]


def parse_call(body: bytes) -> Call:
    """Parse a ``methodCall`` document. Raises :class:`XmlRpcError` with WordPress's codes."""
    try:
        root = SafeET.fromstring(body, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (ParseError, DefusedXmlException, ValueError, RecursionError):
        raise XmlRpcError(-32700, "parse error. not well formed") from None
    if root.tag != "methodCall":
        raise XmlRpcError(
            -32600,
            "server error. invalid xml-rpc. not conforming to spec. Request must be a methodCall",
        )
    name_el = root.find("methodName")
    if name_el is None or not (name_el.text or "").strip():
        raise XmlRpcError(
            -32600,
            "server error. invalid xml-rpc. not conforming to spec. Request must be a methodCall",
        )
    budget = [20_000]
    params: list[Any] = []
    params_el = root.find("params")
    if params_el is not None:
        for p in list(params_el)[:MAX_ITEMS]:
            v = p.find("value")
            if v is not None:
                params.append(_value(v, 0, budget))
    return Call((name_el.text or "").strip()[:128], params)


def credentials(call: Call) -> tuple[str, str] | None:
    """The (username, password) a method call carries, per WordPress's argument layouts."""
    m = call.method
    if m in ("wp.getUsersBlogs", "metaWeblog.getUsersBlogs"):
        idx = 0
    elif m == "blogger.getUsersBlogs":
        idx = 1
    elif m.startswith("blogger."):
        idx = 2
    elif m in ("mt.supportedMethods", "mt.supportedTextFilters", "mt.getTrackbackPings"):
        return None
    elif m.startswith(("wp.", "metaWeblog.", "mt.")):
        idx = 1
    else:
        return None
    p = call.params
    if len(p) > idx + 1 and isinstance(p[idx], str) and isinstance(p[idx + 1], str):
        return p[idx][:256], p[idx + 1][:256]
    return None


def _fault_struct(code: int, message: str, indent: str = "") -> str:
    return (
        f"{indent}<struct>\n{indent}  <member>\n{indent}    <name>faultCode</name>\n"
        f"{indent}    <value><int>{code}</int></value>\n{indent}  </member>\n"
        f"{indent}  <member>\n{indent}    <name>faultString</name>\n"
        f"{indent}    <value><string>{html.escape(message, quote=False)}</string></value>\n"
        f"{indent}  </member>\n{indent}</struct>"
    )


def fault(code: int, message: str) -> bytes:
    xml = (
        '<?xml version="1.0"?>\n<methodResponse>\n  <fault>\n    <value>\n'
        + _fault_struct(code, message, "      ")
        + "\n    </value>\n  </fault>\n</methodResponse>\n"
    )
    return xml.encode()


def _string_value(text: str) -> str:
    return f"<string>{html.escape(text, quote=False)}</string>"


def _to_xml(value: Any) -> str:
    if isinstance(value, bool):
        return f"<boolean>{int(value)}</boolean>"
    if isinstance(value, int):
        return f"<int>{value}</int>"
    if isinstance(value, list):
        inner = "".join(f"<value>{_to_xml(v)}</value>" for v in value)
        return f"<array><data>{inner}</data></array>"
    if isinstance(value, dict):
        members = "".join(
            f"<member><name>{html.escape(str(k), quote=False)}</name><value>{_to_xml(v)}</value></member>"
            for k, v in value.items()
        )
        return f"<struct>{members}</struct>"
    return _string_value(str(value))


def success(value: Any) -> bytes:
    return (
        '<?xml version="1.0"?>\n<methodResponse>\n  <params>\n    <param>\n      <value>'
        + _to_xml(value)
        + "</value>\n    </param>\n  </params>\n</methodResponse>\n"
    ).encode()


_MC_HEAD = (
    b'<?xml version="1.0"?>\n<methodResponse>\n  <params>\n    <param>\n      <value><array><data>'
)
_MC_TAIL = b"</data></array></value>\n    </param>\n  </params>\n</methodResponse>\n"


def _mc_entry(is_fault: bool, val: Any) -> bytes:
    if is_fault:
        code, message = val
        return ("<value>" + _fault_struct(code, message) + "</value>").encode()
    return f"<value><array><data><value>{_to_xml(val)}</value></data></array></value>".encode()


# ``system.listMethods`` answers with this very list object; its encoded multicall entry is
# built once, so a multicall full of listMethods costs a size computation, not a rebuild.
LIST_METHODS: list[str] = list(dict.fromkeys(METHODS))
_LIST_ENTRY = _mc_entry(False, LIST_METHODS)


def _entry(is_fault: bool, val: Any) -> bytes:
    return _LIST_ENTRY if not is_fault and val is LIST_METHODS else _mc_entry(is_fault, val)


def multicall_size(entries: list[tuple[bool, Any]]) -> int:
    """Exact size of :func:`multicall`'s output, computed without building it."""
    return len(_MC_HEAD) + len(_MC_TAIL) + sum(len(_entry(f, v)) for f, v in entries)


def multicall(entries: list[tuple[bool, Any]]) -> bytes:
    """``entries`` holds (is_fault, value); a fault value is (code, message)."""
    return b"".join([_MC_HEAD, *(_entry(f, v) for f, v in entries), _MC_TAIL])


def is_known(method: str) -> bool:
    return method in _METHOD_SET


class MulticallLimiter:
    """CPU guard for ``system.multicall``: per-IP and global rates, and cached compression.

    A multicall of ~1300 ``listMethods`` entries is a 250 KB request that becomes a 4.7 MB
    response, ~70 ms of gzip on the sensor's half CPU. So:

    * multicalls are limited per source IP (1/s, burst 3) and globally (4/s, burst 8);
    * the gzipped response is cached by the SHA-256 of the uncompressed one (attackers repeat
      the same payload), so a repeat costs a join and a hash, not a compression;
    * fresh compressions draw on a global byte budget (4 MB/s, burst 8 MB).

    Whatever is over a limit gets the 503 Apache sends when it is overloaded.
    """

    def __init__(
        self,
        ip_rate: float = 1.0,
        ip_burst: float = 3.0,
        global_rate: float = 4.0,
        global_burst: float = 8.0,
        gzip_rate: float = 4e6,
        gzip_burst: float = 8e6,
        cache_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        from web_sensor.events import _Buckets  # local: keeps xmlrpc free of import cycles

        self._ip = _Buckets(ip_rate, ip_burst)
        self._global = _Buckets(global_rate, global_burst, max_keys=1)
        self._gz_rate = gzip_rate
        self._gz_burst = gzip_burst
        self._gz_tokens = gzip_burst
        self._gz_last = time.monotonic()
        self._cache: OrderedDict[bytes, bytes] = OrderedDict()
        self._cache_bytes = 0
        self._cache_cap = cache_bytes
        self.limited = 0
        self.cache_hits = 0

    def allow(self, ip: str) -> bool:
        ok = self._ip.allow(ip) and self._global.allow("*")
        if not ok:
            self.limited += 1
        return ok

    def gzip(self, body: bytes) -> bytes | None:
        """Gzip ``body`` like mod_deflate, from the cache when possible; None if over budget."""
        key = hashlib.sha256(body).digest()
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            self.cache_hits += 1
            return cached
        now = time.monotonic()
        self._gz_tokens = min(
            self._gz_burst, self._gz_tokens + (now - self._gz_last) * self._gz_rate
        )
        self._gz_last = now
        if self._gz_tokens < len(body):
            return None
        self._gz_tokens -= len(body)
        packed = apache.gzip_bytes(body)
        if len(packed) <= self._cache_cap // 4:
            self._cache[key] = packed
            self._cache_bytes += len(packed)
            while self._cache_bytes > self._cache_cap:
                _, old = self._cache.popitem(last=False)
                self._cache_bytes -= len(old)
        return packed
