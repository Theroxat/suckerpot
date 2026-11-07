"""External tier of the public feeds (design M36 section 7): a CC0 third-party list republished
under its own manifest.

The external tier is deliberately separate from the five network lists of ``selfhostr-feeds/1``:
its index has another schema (``selfhostr-external/1``), another directory on the feed site and
its own serial sequence, so ``IndexFile`` and ``LIST_IDS`` never change and an older node keeps
reading ``/v1/index.json`` untouched. Entries say which upstream source they come from and carry
no tier, no tag and no network-derived field: they are not confirmed by the SuckerPot network.

Pure functions, no I/O. Reuses the checks, the minisign chain and the bounded parsers of the
main feeds. Only the formats that make sense for an address list exist (no STIX, no domains).
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Any, Final, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError, model_validator

from .errors import FeedError
from .minisign import PublicKey, parse_trusted_comment, verify, verify_feed_file
from .models import (
    _KEY_ID,
    LICENCE,
    MAX_FILE_BYTES,
    MAX_INDEX_BYTES,
    MAX_PARSE_BYTES,
    MAX_SERIAL,
    Day,
    IndexFileRef,
    IndexOther,
    Ts,
    _check_families,
    _check_ports,
    check_ip_global,
    check_ip_syntax,
    format_ts,
    parse_ts,
)
from .parse import _bounded, _check_ratio, _load_object, parse_txt
from .render import _lines, csv_cell, dumps_json, sha256_hex

EXTERNAL_LIST_SCHEMA: Final = "selfhostr-external-feed/1"
EXTERNAL_INDEX_SCHEMA: Final = "selfhostr-external/1"
EXTERNAL_LIST_IDS: Final[tuple[str, ...]] = ("external-outbound",)
EXTERNAL_MAX_ENTRIES: Final = 20_000
EXTERNAL_FORMATS: Final = ("txt", "txt-v4", "txt-v6", "nft", "ipset", "rsc", "csv", "json")
EXTERNAL_CATEGORIES: Final = frozenset({"c2"})
# Wording every consumer shows next to an external entry (design M36 X6).
NOTICE: Final = "Not confirmed by the SuckerPot network."
NFT_TABLE: Final = "selfhostr_ext"
IPSET_MAXELEM: Final = 1 << (EXTERNAL_MAX_ENTRIES - 1).bit_length()
IPSET_HASHSIZE: Final = {4: 4096, 6: 1024}
RSC_TIMEOUT: Final = "1d6h"
MIKROTIK_PREFIX: Final = "selfhostr"
CSV_COLUMNS: Final = (
    "value", "family", "list", "categories", "sources", "families", "ports",
    "first_seen", "last_seen", "expires",
)  # fmt: skip

_SOURCE_ID = "^[a-z][a-z0-9_-]{0,31}$"


def _unique_sorted(values: list[str]) -> list[str]:
    if len(set(values)) != len(values):
        raise ValueError("duplicates")
    return sorted(values)


def _check_categories(values: list[str]) -> list[str]:
    if not values or not set(values) <= EXTERNAL_CATEGORIES:
        raise ValueError("unknown or empty categories")
    return _unique_sorted(values)


def _check_sources(values: list[str]) -> list[str]:
    if not values or len(values) > 8 or not all(re.fullmatch(_SOURCE_ID, v) for v in values):
        raise ValueError("unknown or empty sources")
    return _unique_sorted(values)


def _check_text(value: str) -> str:
    """Printable ASCII, no control character: a source name goes into file headers."""
    if not value.isascii() or not all(0x20 <= ord(c) < 0x7F for c in value):
        raise ValueError("not printable ASCII")
    return value


class ExternalEntry(BaseModel):
    """One external address (design M36 7.1). Unknown fields are ignored on read."""

    model_config = ConfigDict(frozen=True, extra="ignore", populate_by_name=True)

    value: str
    family: Literal[4, 6]
    list_id: Annotated[Literal["external-outbound"], Field(alias="list")] = "external-outbound"
    categories: Annotated[list[str], AfterValidator(_check_categories)]
    sources: Annotated[list[str], AfterValidator(_check_sources)]
    families: Annotated[list[str], AfterValidator(_check_families)] = Field(default_factory=list)
    ports: Annotated[list[int], AfterValidator(_check_ports)] = Field(default_factory=list)
    first_seen: Day
    last_seen: Day
    expires: Day

    @model_validator(mode="after")
    def _consistent(self) -> ExternalEntry:
        if ipaddress.ip_address(check_ip_syntax(self.value)).version != self.family:
            raise ValueError("family does not match the address")
        if not self.first_seen <= self.last_seen <= self.expires:
            raise ValueError("dates out of order")
        return self


class ExternalSource(BaseModel):
    """Where the data comes from (attribution is not required for CC0, but always given)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    id: Annotated[str, Field(pattern=_SOURCE_ID)]
    name: Annotated[str, Field(min_length=1, max_length=64), AfterValidator(_check_text)]
    licence: Literal["CC0-1.0"] = "CC0-1.0"
    url: Annotated[str, Field(pattern=r"^https://[A-Za-z0-9.-]+/[\x21-\x7e]{0,200}$")]


def check_external_entry(entry: ExternalEntry, *, allow_documentation: bool = False) -> None:
    check_ip_global(entry.value, allow_documentation=allow_documentation)


def coerce_external_entry(raw: ExternalEntry | Mapping[str, Any]) -> ExternalEntry:
    """Re-validate from scratch (a ``model_construct`` bypass is caught here)."""
    data = raw.model_dump(by_alias=True) if isinstance(raw, ExternalEntry) else dict(raw)
    try:
        return ExternalEntry.model_validate(data)
    except ValueError as exc:
        raise FeedError("bad_value", "invalid entry") from exc


class ExternalFeedList(BaseModel):
    """``external-outbound.json``. Consumers must ignore unknown fields."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    schema_: Literal["selfhostr-external-feed/1"] = Field(
        alias="schema", default=EXTERNAL_LIST_SCHEMA
    )
    list_id: Literal["external-outbound"] = Field(alias="list")
    direction: Literal["outbound"] = "outbound"
    serial: Annotated[int, Field(ge=0, le=MAX_SERIAL)]
    generated_at: Ts
    valid_until: Ts
    licence: Literal["CC0-1.0"] = LICENCE
    notice: Annotated[str, Field(max_length=256)] = ""
    sources: Annotated[list[ExternalSource], Field(max_length=8)] = Field(default_factory=list)
    entries: list[ExternalEntry]

    @model_validator(mode="after")
    def _consistent(self) -> ExternalFeedList:
        if parse_ts(self.valid_until) <= parse_ts(self.generated_at):
            raise ValueError("valid_until must be after generated_at")
        return self


class ExternalIndexList(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Literal["external-outbound"]
    direction: Literal["outbound"] = "outbound"
    entries: Annotated[int, Field(ge=0, le=100_000)]
    v4: Annotated[int, Field(ge=0, le=100_000)]
    v6: Annotated[int, Field(ge=0, le=100_000)]
    files: Annotated[list[IndexFileRef], Field(max_length=16)]

    @model_validator(mode="after")
    def _consistent(self) -> ExternalIndexList:
        if self.v4 + self.v6 > self.entries:
            raise ValueError("address counts exceed the entry count")
        if len({f.name for f in self.files}) != len(self.files):
            raise ValueError("duplicate file names")
        if not all(f.format in EXTERNAL_FORMATS for f in self.files):
            raise ValueError("format not offered by the external tier")
        return self


class ExternalIndexFile(BaseModel):
    """``/v1/external/index.json``, the signed manifest of the external tier."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    schema_: Literal["selfhostr-external/1"] = Field(alias="schema", default=EXTERNAL_INDEX_SCHEMA)
    serial: Annotated[int, Field(ge=0, le=MAX_SERIAL)]
    generated_at: Ts
    valid_until: Ts
    licence: Literal["CC0-1.0"] = LICENCE
    key_id: Annotated[str, Field(pattern=_KEY_ID)]
    next_key_id: Annotated[str, Field(pattern=_KEY_ID)] | None = None
    lists: Annotated[list[ExternalIndexList], Field(max_length=4)]
    other: Annotated[list[IndexOther], Field(max_length=8)] = Field(default_factory=list)
    sources: Annotated[list[ExternalSource], Field(max_length=8)] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> ExternalIndexFile:
        if parse_ts(self.valid_until) <= parse_ts(self.generated_at):
            raise ValueError("valid_until must be after generated_at")
        if len({lst.id for lst in self.lists}) != len(self.lists):
            raise ValueError("duplicate list ids")
        names = [f.name for lst in self.lists for f in lst.files] + [o.name for o in self.other]
        if len(set(names)) != len(names):
            raise ValueError("duplicate file names")
        return self

    def find_file(self, name: str) -> IndexFileRef | IndexOther | None:
        for lst in self.lists:
            for f in lst.files:
                if f.name == name:
                    return f
        for o in self.other:
            if o.name == name:
                return o
        return None


# --- rendering -------------------------------------------------------------------------------


@dataclass(frozen=True)
class ExternalContext:
    """What the file headers say. ``allow_documentation`` is for tests only."""

    serial: int
    generated_at: datetime
    valid_until: datetime
    sources: tuple[ExternalSource, ...]
    list_id: str = "external-outbound"
    allow_documentation: bool = False

    def __post_init__(self) -> None:
        if self.list_id not in EXTERNAL_LIST_IDS:
            raise FeedError("bad_value", "unknown list")
        if not 0 <= self.serial < 2**53:
            raise FeedError("bad_value", "serial out of range")
        if not self.sources:
            raise FeedError("bad_value", "an external file names its source")
        try:
            if format_ts(self.valid_until) <= format_ts(self.generated_at):
                raise FeedError("bad_value", "valid_until must be after generated_at")
        except ValueError as exc:
            raise FeedError("bad_value", "timestamps must be timezone aware") from exc

    @property
    def header(self) -> str:
        names = ", ".join(s.name for s in self.sources)
        return (
            f"# selfhostr {self.list_id} serial {self.serial} "
            f"generated {format_ts(self.generated_at)} licence {LICENCE} "
            f"source {names}. {NOTICE}"
        )


@dataclass(frozen=True)
class ExternalRendered:
    list_id: str
    entries: list[ExternalEntry]
    dropped: int
    files: dict[str, bytes] = field(default_factory=dict)
    formats: dict[str, str] = field(default_factory=dict)

    @property
    def v4(self) -> int:
        return sum(1 for e in self.entries if e.family == 4)

    @property
    def v6(self) -> int:
        return sum(1 for e in self.entries if e.family == 6)


def clean_external_entries(
    ctx: ExternalContext, raw: Iterable[ExternalEntry | Mapping[str, Any]]
) -> tuple[list[ExternalEntry], int]:
    """Re-validate, de-duplicate and sort. Returns (entries, dropped)."""
    items = list(raw)
    if len(items) > EXTERNAL_MAX_ENTRIES * 2:
        raise FeedError("too_large", f"{len(items)} entries")
    seen: set[str] = set()
    kept: list[ExternalEntry] = []
    dropped = 0
    for item in items:
        try:
            entry = coerce_external_entry(item)
            check_external_entry(entry, allow_documentation=ctx.allow_documentation)
        except FeedError, ValueError:
            dropped += 1
            continue
        if entry.value in seen:
            dropped += 1
            continue
        seen.add(entry.value)
        kept.append(entry)
    if len(kept) > EXTERNAL_MAX_ENTRIES:
        raise FeedError("too_large", f"{len(kept)} entries")
    kept.sort(key=lambda e: (e.family, int(ipaddress.ip_address(e.value))))
    return kept, dropped


def _addresses(entries: Sequence[ExternalEntry], family: int) -> list[str]:
    return [e.value for e in entries if e.family == family]


def set_name(family: int) -> str:
    return f"external_outbound_v{family}"


def render_external_txt(entries: Sequence[ExternalEntry]) -> str:
    return _lines([e.value for e in entries])


def render_external_txt_family(entries: Sequence[ExternalEntry], family: int) -> str:
    return _lines(_addresses(entries, family))


def render_external_nft(ctx: ExternalContext, entries: Sequence[ExternalEntry]) -> str:
    n4, n6 = set_name(4), set_name(6)
    out = [
        ctx.header,
        f"table inet {NFT_TABLE} {{",
        f"  set {n4} {{ type ipv4_addr; flags interval; auto-merge; }}",
        f"  set {n6} {{ type ipv6_addr; flags interval; auto-merge; }}",
        "}",
        f"flush set inet {NFT_TABLE} {n4}",
        f"flush set inet {NFT_TABLE} {n6}",
    ]
    for family in (4, 6):
        values = _addresses(entries, family)
        if values:  # empty braces are a syntax error
            out.append(f"add element inet {NFT_TABLE} {set_name(family)} {{ {', '.join(values)} }}")
    return _lines(out)


def render_external_ipset(ctx: ExternalContext, entries: Sequence[ExternalEntry]) -> str:
    out = [ctx.header]
    for family, kind in ((4, "inet"), (6, "inet6")):
        name = set_name(family)
        params = f"hash:net family {kind} hashsize {IPSET_HASHSIZE[family]} maxelem {IPSET_MAXELEM}"
        out += [
            f"create {name} {params} -exist",
            f"create {name}-new {params} -exist",
            f"flush {name}-new",
            *[f"add {name}-new {v}" for v in _addresses(entries, family)],
            f"swap {name}-new {name}",
            f"destroy {name}-new",
        ]
    return _lines(out)


def render_external_rsc(ctx: ExternalContext, entries: Sequence[ExternalEntry]) -> str:
    lst = f"{MIKROTIK_PREFIX}-{ctx.list_id}"
    out = [ctx.header, f":local t {RSC_TIMEOUT}"]
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


def render_external_csv(ctx: ExternalContext, entries: Sequence[ExternalEntry]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)
    for e in entries:
        writer.writerow(
            [
                csv_cell(c)
                for c in (
                    e.value, e.family, ctx.list_id, e.categories, e.sources, e.families,
                    e.ports, e.first_seen, e.last_seen, e.expires,
                )
            ]
        )  # fmt: skip
    return buf.getvalue()


def _entry_json(e: ExternalEntry) -> dict[str, Any]:
    return {
        "value": e.value,
        "family": e.family,
        "list": e.list_id,
        "categories": e.categories,
        "sources": e.sources,
        "families": e.families,
        "ports": e.ports,
        "first_seen": e.first_seen,
        "last_seen": e.last_seen,
        "expires": e.expires,
    }


def _source_json(s: ExternalSource) -> dict[str, str]:
    return {"id": s.id, "name": s.name, "licence": s.licence, "url": s.url}


def render_external_json(ctx: ExternalContext, entries: Sequence[ExternalEntry]) -> str:
    return dumps_json(
        {
            "schema": EXTERNAL_LIST_SCHEMA,
            "list": ctx.list_id,
            "direction": "outbound",
            "serial": ctx.serial,
            "generated_at": format_ts(ctx.generated_at),
            "valid_until": format_ts(ctx.valid_until),
            "licence": LICENCE,
            "notice": f"From {', '.join(s.name for s in ctx.sources)}. {NOTICE}",
            "sources": [_source_json(s) for s in ctx.sources],
            "entries": [_entry_json(e) for e in entries],
        }
    )


def render_external_list(
    ctx: ExternalContext, raw_entries: Iterable[ExternalEntry | Mapping[str, Any]]
) -> ExternalRendered:
    """Every file of the external list. Raises ``FeedError('too_large')`` over a cap."""
    entries, dropped = clean_external_entries(ctx, raw_entries)
    name = ctx.list_id
    texts: dict[str, tuple[str, str]] = {
        f"{name}.txt": ("txt", render_external_txt(entries)),
        f"{name}.v4.txt": ("txt-v4", render_external_txt_family(entries, 4)),
        f"{name}.v6.txt": ("txt-v6", render_external_txt_family(entries, 6)),
        f"{name}.nft": ("nft", render_external_nft(ctx, entries)),
        f"{name}.ipset": ("ipset", render_external_ipset(ctx, entries)),
        f"{name}.rsc": ("rsc", render_external_rsc(ctx, entries)),
        f"{name}.csv": ("csv", render_external_csv(ctx, entries)),
        f"{name}.json": ("json", render_external_json(ctx, entries)),
    }
    files: dict[str, bytes] = {}
    formats: dict[str, str] = {}
    for fname, (fmt, text) in texts.items():
        data = text.encode("utf-8")
        if len(data) > MAX_FILE_BYTES:
            raise FeedError("too_large", f"{fname} is over {MAX_FILE_BYTES} bytes")
        files[fname] = data
        formats[fname] = fmt
    return ExternalRendered(name, entries, dropped, files, formats)


def external_index_list(
    rendered: ExternalRendered, modified: Mapping[str, datetime]
) -> ExternalIndexList:
    refs = [
        IndexFileRef.model_validate(
            {
                "name": fname,
                "format": rendered.formats[fname],
                "bytes": len(data),
                "sha256": sha256_hex(data),
                "modified": format_ts(modified[fname]),
            }
        )
        for fname, data in rendered.files.items()
    ]
    return ExternalIndexList.model_validate(
        {
            "id": rendered.list_id,
            "entries": len(rendered.entries),
            "v4": rendered.v4,
            "v6": rendered.v6,
            "files": refs,
        }
    )


def build_external_index(
    *,
    serial: int,
    generated_at: datetime,
    valid_until: datetime,
    key_id: str,
    lists: Sequence[ExternalIndexList],
    sources: Sequence[ExternalSource],
    other: Sequence[IndexOther] = (),
    next_key_id: str | None = None,
) -> ExternalIndexFile:
    return ExternalIndexFile.model_validate(
        {
            "schema": EXTERNAL_INDEX_SCHEMA,
            "serial": serial,
            "generated_at": format_ts(generated_at),
            "valid_until": format_ts(valid_until),
            "licence": LICENCE,
            "key_id": key_id,
            "next_key_id": next_key_id,
            "lists": list(lists),
            "other": list(other),
            "sources": list(sources),
        }
    )


def render_external_index(index: ExternalIndexFile) -> bytes:
    """``index.json`` bytes (the bytes that get signed)."""
    return dumps_json(index.model_dump(by_alias=True)).encode("utf-8")


# --- parsing and verification (node side) ---------------------------------------------------


def parse_external_txt(
    data: bytes, *, max_entries: int | None = None, allow_documentation: bool = False
) -> list[str]:
    """An ``external-outbound*.txt``: one canonical global address per line."""
    parsed = parse_txt(
        "outbound",
        data,
        max_entries=EXTERNAL_MAX_ENTRIES if max_entries is None else max_entries,
        allow_documentation=allow_documentation,
    )
    return parsed.values


@dataclass(frozen=True)
class ParsedExternalList:
    feed: ExternalFeedList  # header fields and the valid entries only
    invalid: int


def parse_external_list_json(
    data: bytes, *, max_bytes: int = MAX_PARSE_BYTES, allow_documentation: bool = False
) -> ParsedExternalList:
    """``external-outbound.json``. Unknown fields ignored, invalid entries dropped and counted."""
    _bounded(data, max_bytes)
    obj = _load_object(data)
    raw_entries = obj.get("entries")
    if not isinstance(raw_entries, list):
        raise FeedError("bad_format", "entries must be a list")
    try:
        header = ExternalFeedList.model_validate({**obj, "entries": []})
    except ValidationError as exc:
        raise FeedError("bad_format", "invalid header") from exc
    if len(raw_entries) > EXTERNAL_MAX_ENTRIES:
        raise FeedError("too_large", f"{len(raw_entries)} entries")
    kept: list[ExternalEntry] = []
    seen: set[str] = set()
    invalid = 0
    for raw in raw_entries:
        try:
            if not isinstance(raw, dict):
                raise ValueError("entry is not an object")
            entry = ExternalEntry.model_validate(raw)
            check_external_entry(entry, allow_documentation=allow_documentation)
        except ValueError:
            invalid += 1
            continue
        if entry.value in seen:
            invalid += 1
            continue
        seen.add(entry.value)
        kept.append(entry)
    _check_ratio(invalid, len(raw_entries))
    return ParsedExternalList(header.model_copy(update={"entries": kept}), invalid)


def parse_external_index(data: bytes) -> ExternalIndexFile:
    _bounded(data, MAX_INDEX_BYTES)
    obj = _load_object(data)
    try:
        return ExternalIndexFile.model_validate(obj)
    except ValidationError as exc:
        raise FeedError("bad_format", "invalid index") from exc


def verify_external_index(
    data: bytes,
    sig_text: str,
    public: PublicKey,
    *,
    now: datetime,
    last_serial: int | None = None,
) -> ExternalIndexFile:
    """Verify and parse the external ``index.json``; same failure codes as ``verify_index``.

    The main index and the external one share a file name and a key, so the schema is what keeps
    one from being replayed as the other: each parser refuses the other's ``schema`` value."""
    _bounded(data, MAX_INDEX_BYTES)
    comment = parse_trusted_comment(verify(data, sig_text, public))
    if comment.file != "index.json":
        raise FeedError("wrong_file", "signature belongs to another file")
    index = parse_external_index(data)
    if comment.serial != index.serial:
        raise FeedError("wrong_serial", "signed serial differs from the index")
    if index.key_id != public.key_id_hex:
        raise FeedError("wrong_key", "index names another key")
    if parse_ts(index.valid_until) <= now:
        raise FeedError("expired", index.valid_until)
    if last_serial is not None and index.serial < last_serial:
        raise FeedError("rollback", f"{index.serial} < {last_serial}")
    return index


def verify_external_file(
    index: ExternalIndexFile, name: str, data: bytes, sig_text: str, public: PublicKey
) -> None:
    """Size, sha256 and signature of a downloaded file, as listed in a verified index."""
    ref = index.find_file(name)
    if ref is None:
        raise FeedError("bad_format", "file is not listed in the index")
    _bounded(data, MAX_PARSE_BYTES)
    if len(data) != ref.bytes or sha256_hex(data) != ref.sha256:
        raise FeedError("hash_mismatch", name)
    verify_feed_file(data, sig_text, public, name=name, serial=index.serial)


__all__ = [
    "EXTERNAL_INDEX_SCHEMA",
    "EXTERNAL_LIST_IDS",
    "EXTERNAL_LIST_SCHEMA",
    "NOTICE",
    "ExternalContext",
    "ExternalEntry",
    "ExternalFeedList",
    "ExternalIndexFile",
    "ExternalIndexList",
    "ExternalRendered",
    "ExternalSource",
    "ParsedExternalList",
    "build_external_index",
    "clean_external_entries",
    "external_index_list",
    "parse_external_index",
    "parse_external_list_json",
    "parse_external_txt",
    "render_external_csv",
    "render_external_index",
    "render_external_ipset",
    "render_external_json",
    "render_external_list",
    "render_external_nft",
    "render_external_rsc",
    "render_external_txt",
    "render_external_txt_family",
    "verify_external_file",
    "verify_external_index",
]
