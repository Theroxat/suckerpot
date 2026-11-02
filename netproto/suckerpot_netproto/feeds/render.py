"""Feed renderers (design M30 section 6): text, nftables, ipset, MikroTik, CSV, JSON, STIX 2.1.

Every renderer works on entries that were re-validated from scratch (``clean_entries``): a value
that is not a canonical single global address or an exact host name is dropped and counted, so
no newline, quote, space, prefix, wildcard or script character can reach firewall syntax. The
output is deterministic (sorted, no clock reads) and uses ``\\n`` line ends (CSV: CRLF).
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from .errors import FeedError
from .models import (
    DIRECTIONS,
    DOMAIN_LISTS,
    FORMATS,
    INDEX_SCHEMA,
    LICENCE,
    LIST_SCHEMA,
    LIST_TIERS,
    MAX_ENTRIES,
    MAX_FILE_BYTES,
    FeedEntry,
    IndexFile,
    IndexFileRef,
    IndexList,
    IndexOther,
    check_entry_for_list,
    coerce_entry,
    format_ts,
)

_FORMULA_STARTS: Final = ("=", "+", "-", "@", "\t", "\r")
CSV_COLUMNS: Final = (
    "value", "family", "list", "tier", "categories", "services", "tags", "families", "ports",
    "first_seen", "last_seen", "expires", "reported",
)  # fmt: skip
# ipset maxelem: the list cap rounded up to a power of two. Fixed per list, never derived from
# the current content, because `create -exist` fails when an existing set has other parameters.
IPSET_MAXELEM: Final[dict[str, int]] = {
    lst: 1 << (cap - 1).bit_length() for lst, cap in MAX_ENTRIES.items()
}
IPSET_HASHSIZE: Final = {4: 4096, 6: 1024}
RSC_TIMEOUT: Final = "1d6h"
MIKROTIK_PREFIX: Final = "selfhostr"
_STIX_NS: Final = uuid.UUID("5b0f4b7e-3d52-4d59-9f0e-7c6a2f1a9e11")
# Core STIX 2.1 marking definition for TLP:CLEAR (called TLP:WHITE by the 2.1 standard).
_TLP_CLEAR_ID: Final = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
_TLP_CREATED: Final = "2017-01-20T00:00:00.000Z"


@dataclass(frozen=True)
class RenderContext:
    """What the file headers say. ``allow_documentation`` is for tests only."""

    list_id: str
    serial: int
    generated_at: datetime
    valid_until: datetime
    allow_documentation: bool = False

    def __post_init__(self) -> None:
        if self.list_id not in DIRECTIONS:
            raise FeedError("bad_value", "unknown list")
        if not 0 <= self.serial < 2**53:
            raise FeedError("bad_value", "serial out of range")
        try:
            if format_ts(self.valid_until) <= format_ts(self.generated_at):
                raise FeedError("bad_value", "valid_until must be after generated_at")
        except ValueError as exc:
            raise FeedError("bad_value", "timestamps must be timezone aware") from exc

    @property
    def is_domains(self) -> bool:
        return self.list_id in DOMAIN_LISTS

    @property
    def direction(self) -> str:
        return DIRECTIONS[self.list_id]

    @property
    def header(self) -> str:
        return (
            f"# selfhostr {self.list_id} serial {self.serial} "
            f"generated {format_ts(self.generated_at)} licence {LICENCE}"
        )


@dataclass(frozen=True)
class Rendered:
    """Every file of one list. ``files`` maps file name to bytes, ``formats`` to its format id."""

    list_id: str
    entries: list[FeedEntry]
    dropped: int
    files: dict[str, bytes] = field(default_factory=dict)
    formats: dict[str, str] = field(default_factory=dict)

    @property
    def v4(self) -> int:
        return sum(1 for e in self.entries if e.family == 4)

    @property
    def v6(self) -> int:
        return sum(1 for e in self.entries if e.family == 6)


# --- validation and ordering ----------------------------------------------------------------


def _sort_key(entry: FeedEntry) -> tuple[int, int | str]:
    if entry.family == "dns":
        return (0, entry.value)
    return (int(entry.family), int(ipaddress.ip_address(entry.value)))


def clean_entries(
    ctx: RenderContext, raw: Iterable[FeedEntry | Mapping[str, Any]]
) -> tuple[list[FeedEntry], int]:
    """Re-validate, de-duplicate and sort. Returns (entries, dropped).

    Raises ``FeedError('too_large')`` when more than the list cap survives.
    """
    cap = MAX_ENTRIES[ctx.list_id]
    items = list(raw)
    if len(items) > cap * 2:  # refuse before doing per-entry work on absurd input
        raise FeedError("too_large", f"{len(items)} entries for a cap of {cap}")
    seen: set[str] = set()
    kept: list[FeedEntry] = []
    dropped = 0
    for item in items:
        try:
            entry = coerce_entry(item if isinstance(item, FeedEntry) else dict(item))
            check_entry_for_list(ctx.list_id, entry, allow_documentation=ctx.allow_documentation)
        except (FeedError, ValueError):
            dropped += 1
            continue
        if entry.value in seen:
            dropped += 1
            continue
        seen.add(entry.value)
        kept.append(entry)
    if len(kept) > cap:
        raise FeedError("too_large", f"{len(kept)} entries for a cap of {cap}")
    kept.sort(key=_sort_key)
    return kept, dropped


def _addresses(entries: Sequence[FeedEntry], family: int) -> list[str]:
    return [e.value for e in entries if e.family == family]


def _need_ip_list(ctx: RenderContext) -> None:
    if ctx.is_domains:
        raise FeedError("bad_value", "this format is for address lists only")


def _lines(lines: Sequence[str]) -> str:
    return "".join(f"{line}\n" for line in lines)


# --- plain text -----------------------------------------------------------------------------


def render_txt(ctx: RenderContext, entries: Sequence[FeedEntry]) -> str:
    """One value per line, IPv4 then IPv6, sorted. No comments, no blank lines."""
    return _lines([e.value for e in entries])


def render_txt_family(ctx: RenderContext, entries: Sequence[FeedEntry], family: int) -> str:
    _need_ip_list(ctx)
    return _lines(_addresses(entries, family))


# --- nftables -------------------------------------------------------------------------------


def nft_set_name(list_id: str, family: int) -> str:
    return f"{list_id.replace('-', '_')}_v{family}"


def render_nft(ctx: RenderContext, entries: Sequence[FeedEntry]) -> str:
    _need_ip_list(ctx)
    v4, v6 = _addresses(entries, 4), _addresses(entries, 6)
    n4, n6 = nft_set_name(ctx.list_id, 4), nft_set_name(ctx.list_id, 6)
    out = [
        ctx.header,
        "table inet selfhostr {",
        f"  set {n4} {{ type ipv4_addr; flags interval; auto-merge; }}",
        f"  set {n6} {{ type ipv6_addr; flags interval; auto-merge; }}",
        "}",
        f"flush set inet selfhostr {n4}",
        f"flush set inet selfhostr {n6}",
    ]
    for name, values in ((n4, v4), (n6, v6)):
        if values:  # empty braces are a syntax error
            out.append(f"add element inet selfhostr {name} {{ {', '.join(values)} }}")
    return _lines(out)


# --- ipset ----------------------------------------------------------------------------------


def render_ipset(ctx: RenderContext, entries: Sequence[FeedEntry]) -> str:
    _need_ip_list(ctx)
    out = [ctx.header]
    maxelem = IPSET_MAXELEM[ctx.list_id]
    for family, kind in ((4, "inet"), (6, "inet6")):
        name = f"selfhostr-{ctx.list_id}-v{family}"
        params = f"hash:net family {kind} hashsize {IPSET_HASHSIZE[family]} maxelem {maxelem}"
        out += [
            f"create {name} {params} -exist",
            f"create {name}-new {params} -exist",
            f"flush {name}-new",
            *[f"add {name}-new {v}" for v in _addresses(entries, family)],
            f"swap {name}-new {name}",
            f"destroy {name}-new",
        ]
    return _lines(out)


# --- MikroTik -------------------------------------------------------------------------------


def render_rsc(ctx: RenderContext, entries: Sequence[FeedEntry]) -> str:
    _need_ip_list(ctx)
    lst = f"{MIKROTIK_PREFIX}-{ctx.list_id}"
    out = [f"# selfhostr {ctx.list_id} serial {ctx.serial}", f":local t {RSC_TIMEOUT}"]
    for family, section, suffix in ((4, "/ip firewall address-list", ""),
                                    (6, "/ipv6 firewall address-list", "/128")):  # fmt: skip
        values = _addresses(entries, family)
        if not values:
            continue
        out.append(section)
        for v in values:
            addr = f"{v}{suffix}"
            out.append(
                f":do {{ add list={lst} address={addr} timeout=$t comment={MIKROTIK_PREFIX} }} "
                f"on-error={{ set [find list={lst} address={addr}] timeout=$t }}"
            )
    return _lines(out)


# --- CSV ------------------------------------------------------------------------------------


def csv_cell(value: object) -> str:
    """One spreadsheet-safe cell: control characters removed, formula starts defused."""
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, list | tuple):
        text = ";".join(csv_cell(v) for v in value)
    else:
        text = str(value)
    text = "".join(c for c in text if c in "\t\r\n" or (ord(c) >= 0x20 and ord(c) != 0x7F))
    if text.startswith(_FORMULA_STARTS):
        text = "'" + text
    return text.replace("\t", " ").replace("\r", " ").replace("\n", " ")


def render_csv(ctx: RenderContext, entries: Sequence[FeedEntry]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)
    for e in entries:
        writer.writerow(
            [
                csv_cell(c)
                for c in (
                    e.value, e.family, ctx.list_id, e.tier, e.categories, e.services, e.tags,
                    e.families, e.ports, e.first_seen, e.last_seen, e.expires, e.reported,
                )
            ]
        )  # fmt: skip
    return buf.getvalue()


# --- JSON -----------------------------------------------------------------------------------


def dumps_json(obj: object) -> str:
    """Compact, ASCII only, key order kept, one trailing newline."""
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n"


def _entry_json(direction: str, e: FeedEntry) -> dict[str, Any]:
    out: dict[str, Any] = {
        "value": e.value,
        "family": e.family,
        "tier": e.tier,
        "categories": e.categories,
    }
    if direction == "inbound":
        out["services"] = e.services
        out["tags"] = e.tags
    else:
        out["tags"] = e.tags
        out["families"] = e.families
        out["ports"] = e.ports
    out.update(
        first_seen=e.first_seen, last_seen=e.last_seen, expires=e.expires, reported=e.reported
    )
    return out


def render_json(ctx: RenderContext, entries: Sequence[FeedEntry], *, policy: str = "") -> str:
    return dumps_json(
        {
            "schema": LIST_SCHEMA,
            "list": ctx.list_id,
            "direction": ctx.direction,
            "serial": ctx.serial,
            "generated_at": format_ts(ctx.generated_at),
            "valid_until": format_ts(ctx.valid_until),
            "licence": LICENCE,
            "policy": policy,
            "entries": [_entry_json(ctx.direction, e) for e in entries],
        }
    )


# --- STIX 2.1 -------------------------------------------------------------------------------


def _stix_pattern(e: FeedEntry) -> str:
    # The value is a validated address or name: no quote or backslash can occur.
    if e.family == "dns":
        return f"[domain-name:value = '{e.value}']"
    return f"[{'ipv6-addr' if e.family == 6 else 'ipv4-addr'}:value = '{e.value}']"


def render_stix(ctx: RenderContext, entries: Sequence[FeedEntry]) -> str:
    """Outbound lists only. No identity, no ``created_by_ref``. Ids and times are derived from the
    entries, so an unchanged list renders to identical bytes."""
    if ctx.direction != "outbound":
        raise FeedError("bad_value", "STIX is published for the outbound lists only")
    objects: list[dict[str, Any]] = [
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": _TLP_CLEAR_ID,
            "created": _TLP_CREATED,
            "definition_type": "tlp",
            "name": "TLP:WHITE",
            "definition": {"tlp": "white"},
        }
    ]
    ids: list[str] = []
    for e in entries:
        oid = f"indicator--{uuid.uuid5(_STIX_NS, f'{ctx.list_id}|{e.value}')}"
        ids.append(oid)
        ind: dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": oid,
            "created": f"{e.first_seen}T00:00:00.000Z",
            "modified": f"{e.last_seen}T00:00:00.000Z",
            "name": e.value,
            "indicator_types": ["malicious-activity"],
            "pattern": _stix_pattern(e),
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": f"{e.first_seen}T00:00:00Z",
            "labels": [*e.categories, *e.families],
        }
        if e.expires > e.first_seen:
            ind["valid_until"] = f"{e.expires}T00:00:00Z"
        ind["object_marking_refs"] = [_TLP_CLEAR_ID]
        objects.append(ind)
    digest = hashlib.sha256(("|".join(ids) + ctx.list_id).encode()).digest()
    bundle_id = f"bundle--{uuid.UUID(bytes=digest[:16], version=5)}"
    return dumps_json({"type": "bundle", "id": bundle_id, "objects": objects})


# --- everything for one list ------------------------------------------------------------------


def render_list(
    ctx: RenderContext,
    raw_entries: Iterable[FeedEntry | Mapping[str, Any]],
    *,
    policy: str = "",
) -> Rendered:
    """Render every file of a list. Raises ``FeedError('too_large')`` over a cap."""
    entries, dropped = clean_entries(ctx, raw_entries)
    name = ctx.list_id
    texts: dict[str, tuple[str, str]] = {
        f"{name}.txt": ("txt", render_txt(ctx, entries)),
        f"{name}.csv": ("csv", render_csv(ctx, entries)),
        f"{name}.json": ("json", render_json(ctx, entries, policy=policy)),
    }
    if not ctx.is_domains:
        texts[f"{name}.v4.txt"] = ("txt-v4", render_txt_family(ctx, entries, 4))
        texts[f"{name}.v6.txt"] = ("txt-v6", render_txt_family(ctx, entries, 6))
        texts[f"{name}.nft"] = ("nft", render_nft(ctx, entries))
        texts[f"{name}.ipset"] = ("ipset", render_ipset(ctx, entries))
        texts[f"{name}.rsc"] = ("rsc", render_rsc(ctx, entries))
    if ctx.direction == "outbound" and not ctx.is_domains:
        texts[f"{name}.stix.json"] = ("stix", render_stix(ctx, entries))
    files: dict[str, bytes] = {}
    formats: dict[str, str] = {}
    for fname, (fmt, text) in texts.items():
        data = text.encode("utf-8")
        if len(data) > MAX_FILE_BYTES:
            raise FeedError("too_large", f"{fname} is over {MAX_FILE_BYTES} bytes")
        files[fname] = data
        formats[fname] = fmt
    return Rendered(name, entries, dropped, files, formats)


# --- index.json -----------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def index_list(rendered: Rendered, modified: Mapping[str, datetime]) -> IndexList:
    """The ``lists[]`` item for a rendered list. ``modified`` maps file name to its mtime; a
    file that did not change keeps its old value, so the caller owns this mapping."""
    refs = []
    for fname, data in rendered.files.items():
        fmt = rendered.formats[fname]
        if fmt not in FORMATS:  # pragma: no cover - guarded by render_list
            raise FeedError("bad_value", "unknown format")
        refs.append(
            IndexFileRef(
                name=fname,
                format=fmt,
                bytes=len(data),
                sha256=sha256_hex(data),
                modified=format_ts(modified[fname]),
            )
        )
    return IndexList(
        id=rendered.list_id,
        direction=DIRECTIONS[rendered.list_id],
        tier=LIST_TIERS[rendered.list_id],
        entries=len(rendered.entries),
        v4=rendered.v4,
        v6=rendered.v6,
        files=refs,
    )


def index_other(name: str, data: bytes) -> IndexOther:
    return IndexOther(name=name, bytes=len(data), sha256=sha256_hex(data))


def build_index(
    *,
    serial: int,
    generated_at: datetime,
    valid_until: datetime,
    key_id: str,
    lists: Sequence[IndexList],
    other: Sequence[IndexOther] = (),
    next_key_id: str | None = None,
) -> IndexFile:
    return IndexFile(
        schema=INDEX_SCHEMA,
        serial=serial,
        generated_at=format_ts(generated_at),
        valid_until=format_ts(valid_until),
        licence=LICENCE,
        key_id=key_id,
        next_key_id=next_key_id,
        lists=list(lists),
        other=list(other),
    )


def render_index(index: IndexFile) -> bytes:
    """``index.json`` bytes (the bytes that get signed)."""
    return dumps_json(index.model_dump(by_alias=True)).encode("utf-8")
