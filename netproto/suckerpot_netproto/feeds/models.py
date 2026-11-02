"""Feed documents: entries, ``<list>.json`` and ``index.json`` (design M30 section 6).

Pure data and validation, no I/O. Entry values are single global unicast addresses or exact host
names, always in canonical form. A prefix, a wildcard or a parent domain is refused everywhere.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, date, datetime
from typing import Annotated, Any, Final, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StrictBool, model_validator

from ..blind import canonical_domain
from ..enums import FAMILIES_V1, SERVICES, is_valid_tag
from ..models import parse_global_ip
from .errors import FeedError

LIST_SCHEMA: Final = "selfhostr-feed/1"
INDEX_SCHEMA: Final = "selfhostr-feeds/1"
LICENCE: Final = "CC0-1.0"

LIST_IDS: Final[tuple[str, ...]] = (
    "inbound",
    "inbound-high",
    "outbound",
    "outbound-high",
    "outbound-domains",
)
DIRECTIONS: Final[dict[str, str]] = {
    "inbound": "inbound",
    "inbound-high": "inbound",
    "outbound": "outbound",
    "outbound-high": "outbound",
    "outbound-domains": "outbound",
}
LIST_TIERS: Final[dict[str, str]] = {
    "inbound": "standard",
    "inbound-high": "high",
    "outbound": "standard",
    "outbound-high": "high",
    "outbound-domains": "standard",
}
DOMAIN_LISTS: Final = frozenset({"outbound-domains"})
# Hard caps per list (design 5.5) and per file.
MAX_ENTRIES: Final[dict[str, int]] = {
    "inbound": 50_000,
    "inbound-high": 50_000,
    "outbound": 20_000,
    "outbound-high": 20_000,
    "outbound-domains": 20_000,
}
MAX_FILE_BYTES: Final = 8 * 1024 * 1024  # what the hub may publish
MAX_PARSE_BYTES: Final = 16 * 1024 * 1024  # what a node accepts to read (N14)
MAX_INDEX_BYTES: Final = 256 * 1024

CATEGORIES: Final[frozenset[str]] = frozenset(
    "brute-force login-success command-exec malware-drop exploit payload-host c2".split()
)
TIERS: Final = ("standard", "high")
# index.json "format" values.
FORMATS: Final = ("txt", "txt-v4", "txt-v6", "nft", "ipset", "rsc", "csv", "json", "stix")

_TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
_DAY = re.compile(r"^\d{4}-\d\d-\d\d$")
_IP_CHARS = re.compile(r"^[0-9a-f:.]{2,45}$")
_SHA256 = "^[0-9a-f]{64}$"
_KEY_ID = "^[0-9A-F]{16}$"
_FILE_NAME = "^[a-z0-9][a-z0-9._-]{0,63}$"
# Top-level labels that never resolve publicly: listing them would be a mistake or an attack.
_PRIVATE_TLDS = frozenset(
    "local localhost internal lan home corp intranet arpa onion invalid".split()
)
MAX_SERIAL: Final = 2**53 - 1


def format_ts(value: datetime) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` in UTC. Naive datetimes are refused."""
    if value.tzinfo is None:
        raise ValueError("naive datetime")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(text: str) -> datetime:
    if not _TS.fullmatch(text):
        raise ValueError("invalid timestamp")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def check_ts(text: str) -> str:
    parse_ts(text)
    return text


def check_day(text: str) -> str:
    if not _DAY.fullmatch(text):
        raise ValueError("invalid day")
    date.fromisoformat(text)
    return text


def check_ip_syntax(value: str) -> str:
    """A canonical IPv4 or IPv6 text (compressed, lower case). No prefix, no scope, no spaces."""
    if not _IP_CHARS.fullmatch(value):
        raise ValueError("not a plain address")
    ip = ipaddress.ip_address(value)
    if str(ip) != value:
        raise ValueError("address is not canonical")
    return value


def check_ip_global(value: str, *, allow_documentation: bool = False) -> str:
    """Canonical and global unicast (documentation ranges only when the flag is set)."""
    check_ip_syntax(value)
    if parse_global_ip(value, allow_documentation=allow_documentation) != value:
        raise ValueError("address is not canonical")
    return value


def check_domain(value: str) -> str:
    """An exact, canonical (lower case ASCII/IDNA) host name with at least two labels."""
    if not value.isascii() or len(value) > 253:
        raise ValueError("not a canonical host name")
    name = canonical_domain(value)
    if name != value:
        raise ValueError("host name is not canonical")
    labels = name.split(".")
    if len(labels) < 2:
        raise ValueError("a bare top-level name is not an exact host")
    if labels[-1] in _PRIVATE_TLDS or labels[-1].isdigit():
        raise ValueError("private or non-public top-level name")
    return name


def _unique_sorted(values: list[str]) -> list[str]:
    if len(set(values)) != len(values):
        raise ValueError("duplicates")
    return sorted(values)


def _check_categories(values: list[str]) -> list[str]:
    if not values or not set(values) <= CATEGORIES:
        raise ValueError("unknown or empty categories")
    return _unique_sorted(values)


def _check_services(values: list[str]) -> list[str]:
    if not set(values) <= SERVICES:
        raise ValueError("unknown service")
    return _unique_sorted(values)


def _check_tags(values: list[str]) -> list[str]:
    if len(values) > 32 or not all(is_valid_tag(v) for v in values):
        raise ValueError("unknown tag")
    return _unique_sorted(values)


def _check_families(values: list[str]) -> list[str]:
    if not set(values) <= FAMILIES_V1:
        raise ValueError("unknown family")
    return _unique_sorted(values)


def _check_ports(values: list[int]) -> list[int]:
    if len(values) > 16 or len(set(values)) != len(values):
        raise ValueError("too many or duplicate ports")
    if not all(1 <= p <= 65535 for p in values):
        raise ValueError("port out of range")
    return sorted(values)


Ts = Annotated[str, AfterValidator(check_ts)]
Day = Annotated[str, AfterValidator(check_day)]
Sha256 = Annotated[str, Field(pattern=_SHA256)]


class FeedEntry(BaseModel):
    """One listed value with its metadata (design 4.5). Unknown fields are ignored."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    value: str
    family: Literal[4, 6, "dns"]
    tier: Literal["standard", "high"]
    categories: Annotated[list[str], AfterValidator(_check_categories)]
    services: Annotated[list[str], AfterValidator(_check_services)] = Field(default_factory=list)
    tags: Annotated[list[str], AfterValidator(_check_tags)] = Field(default_factory=list)
    families: Annotated[list[str], AfterValidator(_check_families)] = Field(default_factory=list)
    ports: Annotated[list[int], AfterValidator(_check_ports)] = Field(default_factory=list)
    first_seen: Day
    last_seen: Day
    expires: Day
    reported: StrictBool = False

    @model_validator(mode="after")
    def _consistent(self) -> FeedEntry:
        if self.family == "dns":
            check_domain(self.value)
        elif ipaddress.ip_address(check_ip_syntax(self.value)).version != self.family:
            raise ValueError("family does not match the address")
        if not self.first_seen <= self.last_seen <= self.expires:
            raise ValueError("dates out of order")
        return self


def check_entry_for_list(
    list_id: str, entry: FeedEntry, *, allow_documentation: bool = False
) -> FeedEntry:
    """Full check of an entry against its list (kind, tier, global address). Raises ValueError."""
    if list_id not in DIRECTIONS:
        raise ValueError("unknown list")
    if (list_id in DOMAIN_LISTS) != (entry.family == "dns"):
        raise ValueError("value kind does not fit the list")
    if LIST_TIERS[list_id] == "high" and entry.tier != "high":
        raise ValueError("standard entry in a high list")
    if entry.family != "dns":
        check_ip_global(entry.value, allow_documentation=allow_documentation)
    if DIRECTIONS[list_id] == "outbound" and entry.services:
        raise ValueError("services belong to inbound lists")
    if DIRECTIONS[list_id] == "inbound" and (entry.families or entry.ports):
        raise ValueError("families and ports belong to outbound lists")
    return entry


class FeedList(BaseModel):
    """``<list>.json`` (design 6.3). Consumers must ignore unknown fields."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    schema_: Literal["selfhostr-feed/1"] = Field(alias="schema", default=LIST_SCHEMA)
    list_id: str = Field(alias="list")
    direction: Literal["inbound", "outbound"]
    serial: Annotated[int, Field(ge=0, le=MAX_SERIAL)]
    generated_at: Ts
    valid_until: Ts
    licence: Literal["CC0-1.0"] = LICENCE
    policy: Annotated[str, Field(max_length=256)] = ""
    entries: list[FeedEntry]

    @model_validator(mode="after")
    def _consistent(self) -> FeedList:
        if self.list_id not in DIRECTIONS or DIRECTIONS[self.list_id] != self.direction:
            raise ValueError("list and direction do not match")
        if parse_ts(self.valid_until) <= parse_ts(self.generated_at):
            raise ValueError("valid_until must be after generated_at")
        return self


class IndexFileRef(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: Annotated[str, Field(pattern=_FILE_NAME)]
    format: Literal["txt", "txt-v4", "txt-v6", "nft", "ipset", "rsc", "csv", "json", "stix"]
    bytes: Annotated[int, Field(ge=0, le=MAX_FILE_BYTES)]
    sha256: Sha256
    modified: Ts


class IndexList(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    direction: Literal["inbound", "outbound"]
    tier: Literal["standard", "high"]
    entries: Annotated[int, Field(ge=0, le=100_000)]
    v4: Annotated[int, Field(ge=0, le=100_000)]
    v6: Annotated[int, Field(ge=0, le=100_000)]
    files: Annotated[list[IndexFileRef], Field(max_length=16)]

    @model_validator(mode="after")
    def _consistent(self) -> IndexList:
        if self.id not in DIRECTIONS or DIRECTIONS[self.id] != self.direction:
            raise ValueError("list and direction do not match")
        if LIST_TIERS[self.id] != self.tier:
            raise ValueError("tier does not match the list")
        if self.v4 + self.v6 > self.entries:
            raise ValueError("address counts exceed the entry count")
        if len({f.name for f in self.files}) != len(self.files):
            raise ValueError("duplicate file names")
        return self


class IndexOther(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: Annotated[str, Field(pattern=_FILE_NAME)]
    bytes: Annotated[int, Field(ge=0, le=MAX_FILE_BYTES)]
    sha256: Sha256


class IndexFile(BaseModel):
    """``index.json`` (design 6.4), the signed manifest."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    schema_: Literal["selfhostr-feeds/1"] = Field(alias="schema", default=INDEX_SCHEMA)
    serial: Annotated[int, Field(ge=0, le=MAX_SERIAL)]
    generated_at: Ts
    valid_until: Ts
    licence: Literal["CC0-1.0"] = LICENCE
    key_id: Annotated[str, Field(pattern=_KEY_ID)]
    next_key_id: Annotated[str, Field(pattern=_KEY_ID)] | None = None
    lists: Annotated[list[IndexList], Field(max_length=16)]
    other: Annotated[list[IndexOther], Field(max_length=32)] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> IndexFile:
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


def coerce_entry(raw: FeedEntry | dict[str, Any]) -> FeedEntry:
    """Re-validate an entry from scratch (a ``model_construct`` bypass is caught here)."""
    data = raw.model_dump() if isinstance(raw, FeedEntry) else raw
    try:
        return FeedEntry.model_validate(data)
    except ValueError as exc:  # pydantic ValidationError is a ValueError
        raise FeedError("bad_value", "invalid entry") from exc
