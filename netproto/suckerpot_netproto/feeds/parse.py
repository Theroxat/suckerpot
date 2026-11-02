"""Bounded feed parsers and the verification chain a node runs on downloaded files.

Order for a node (design 6.5, N13/N14): ``verify_index`` (signature, schema, freshness,
rollback), then for each file ``verify_file_against_index`` (size, sha256, signature naming this
file and this serial), then ``parse_txt`` / ``parse_list_json``. Everything is size capped and
refuses malformed input; a few invalid entries are dropped and counted, more than 1 % rejects
the whole file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from pydantic import ValidationError

from .errors import FeedError
from .minisign import (
    PublicKey,
    TrustedComment,
    parse_trusted_comment,
    verify,
    verify_feed_file,
)
from .models import (
    DIRECTIONS,
    DOMAIN_LISTS,
    MAX_ENTRIES,
    MAX_INDEX_BYTES,
    MAX_PARSE_BYTES,
    FeedEntry,
    FeedList,
    IndexFile,
    check_domain,
    check_entry_for_list,
    check_ip_global,
    parse_ts,
)
from .render import sha256_hex

MAX_INVALID_RATIO = 0.01
MAX_LINE = 253
_MAX_DEPTH = 8


@dataclass(frozen=True)
class ParsedTxt:
    values: list[str]
    invalid: int


@dataclass(frozen=True)
class ParsedList:
    feed: FeedList  # header fields and the valid entries only
    invalid: int


def _bounded(data: bytes, max_bytes: int) -> None:
    if len(data) > max_bytes:
        raise FeedError("too_large", f"{len(data)} bytes, cap {max_bytes}")


def _check_ratio(invalid: int, total: int) -> None:
    # "more than 1 %" is rejected; a single bad line in a small file is not.
    if total and invalid > 0 and invalid / total > MAX_INVALID_RATIO:
        raise FeedError("too_many_invalid", f"{invalid} of {total}")


def _check_count(count: int, list_id: str, max_entries: int | None) -> None:
    cap = MAX_ENTRIES[list_id] if max_entries is None else max_entries
    if count > cap:
        raise FeedError("too_large", f"{count} entries, cap {cap}")


def parse_txt(
    list_id: str,
    data: bytes,
    *,
    max_bytes: int = MAX_PARSE_BYTES,
    max_entries: int | None = None,
    allow_documentation: bool = False,
) -> ParsedTxt:
    """A ``<list>.txt`` (or ``.v4.txt`` / ``.v6.txt``): one canonical value per line.

    Prefixes, private addresses, wildcards, comments, blank lines, duplicates and anything not
    canonical count as invalid. A carriage return or NUL anywhere rejects the file.
    """
    if list_id not in DIRECTIONS:
        raise FeedError("bad_format", "unknown list")
    _bounded(data, max_bytes)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FeedError("bad_format", "not UTF-8") from exc
    if "\r" in text or "\x00" in text:
        raise FeedError("bad_format", "control characters")
    if text and not text.endswith("\n"):
        raise FeedError("bad_format", "missing final newline")
    lines = text.split("\n")[:-1] if text else []
    _check_count(len(lines), list_id, max_entries)
    domains = list_id in DOMAIN_LISTS
    seen: set[str] = set()
    values: list[str] = []
    invalid = 0
    for line in lines:
        try:
            if len(line) > MAX_LINE:
                raise ValueError("line too long")
            if domains:
                check_domain(line)
            else:
                check_ip_global(line, allow_documentation=allow_documentation)
        except ValueError:
            invalid += 1
            continue
        if line in seen:
            invalid += 1
            continue
        seen.add(line)
        values.append(line)
    _check_ratio(invalid, len(lines))
    return ParsedTxt(values, invalid)


def parse_list_json(
    data: bytes,
    *,
    expected_list: str | None = None,
    max_bytes: int = MAX_PARSE_BYTES,
    max_entries: int | None = None,
    allow_documentation: bool = False,
) -> ParsedList:
    """A ``<list>.json``. Unknown fields are ignored, invalid entries dropped and counted."""
    _bounded(data, max_bytes)
    obj = _load_object(data)
    raw_entries = obj.get("entries")
    if not isinstance(raw_entries, list):
        raise FeedError("bad_format", "entries must be a list")
    try:
        header = FeedList.model_validate({**obj, "entries": []})
    except ValidationError as exc:
        raise FeedError("bad_format", "invalid header") from exc
    if expected_list is not None and header.list_id != expected_list:
        raise FeedError("bad_format", "unexpected list")
    _check_count(len(raw_entries), header.list_id, max_entries)
    kept: list[FeedEntry] = []
    seen: set[str] = set()
    invalid = 0
    for raw in raw_entries:
        try:
            if not isinstance(raw, dict):
                raise ValueError("entry is not an object")
            entry = FeedEntry.model_validate(raw)
            check_entry_for_list(header.list_id, entry, allow_documentation=allow_documentation)
        except ValueError:
            invalid += 1
            continue
        if entry.value in seen:
            invalid += 1
            continue
        seen.add(entry.value)
        kept.append(entry)
    _check_ratio(invalid, len(raw_entries))
    return ParsedList(header.model_copy(update={"entries": kept}), invalid)


def _load_object(data: bytes) -> dict[str, object]:
    try:
        obj = json.loads(data.decode("utf-8"), parse_constant=_refuse_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise FeedError("bad_format", "not valid JSON") from exc
    if not isinstance(obj, dict) or _depth(obj) > _MAX_DEPTH:
        raise FeedError("bad_format", "unexpected JSON shape")
    return obj


def _refuse_constant(name: str) -> object:
    raise ValueError(name)  # NaN, Infinity


def _depth(value: object, level: int = 1) -> int:
    if level > _MAX_DEPTH:
        return level
    deepest = level
    children: list[object] = []
    if isinstance(value, dict):
        children = list(value.values())
    elif isinstance(value, list):
        children = list(value)
    for child in children:
        if isinstance(child, dict | list):
            deepest = max(deepest, _depth(child, level + 1))
    return deepest


# --- index.json and file verification -------------------------------------------------------


def parse_index(data: bytes) -> IndexFile:
    _bounded(data, MAX_INDEX_BYTES)
    obj = _load_object(data)
    try:
        return IndexFile.model_validate(obj)
    except ValidationError as exc:
        raise FeedError("bad_format", "invalid index") from exc


def verify_index(
    data: bytes,
    sig_text: str,
    public: PublicKey,
    *,
    now: datetime,
    last_serial: int | None = None,
) -> IndexFile:
    """Verify and parse ``index.json``. Raises ``FeedError`` with a code for every failure:
    ``bad_signature``, ``wrong_key``, ``wrong_file``, ``wrong_serial``, ``bad_format``,
    ``expired``, ``rollback``. A serial equal to ``last_serial`` is accepted (same data)."""
    _bounded(data, MAX_INDEX_BYTES)
    comment = _verify_signature(data, sig_text, public, "index.json", None)
    index = parse_index(data)
    if comment.serial != index.serial:
        raise FeedError("wrong_serial", "signed serial differs from the index")
    if index.key_id != public.key_id_hex:
        raise FeedError("wrong_key", "index names another key")
    if parse_ts(index.valid_until) <= now:
        raise FeedError("expired", index.valid_until)
    if last_serial is not None and index.serial < last_serial:
        raise FeedError("rollback", f"{index.serial} < {last_serial}")
    return index


def _verify_signature(
    data: bytes, sig_text: str, public: PublicKey, name: str, serial: int | None
) -> TrustedComment:
    # With serial None the caller compares the serial itself (the index is where it comes from).
    if serial is not None:
        return verify_feed_file(data, sig_text, public, name=name, serial=serial)
    comment = parse_trusted_comment(verify(data, sig_text, public))
    if comment.file != name:
        raise FeedError("wrong_file", "signature belongs to another file")
    return comment


def verify_file_against_index(
    index: IndexFile, name: str, data: bytes, sig_text: str, public: PublicKey
) -> None:
    """Size, sha256 and signature of a downloaded file, as listed in a verified index."""
    ref = index.find_file(name)
    if ref is None:
        raise FeedError("bad_format", "file is not listed in the index")
    _bounded(data, MAX_PARSE_BYTES)
    if len(data) != ref.bytes or sha256_hex(data) != ref.sha256:
        raise FeedError("hash_mismatch", name)
    verify_feed_file(data, sig_text, public, name=name, serial=index.serial)
