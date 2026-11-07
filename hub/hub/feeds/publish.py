"""Render, sign and publish the feed files (design M30 section 6.6).

* Every file is rendered by ``suckerpot_netproto.feeds`` into a temporary directory on the same
  volume, then moved into place with ``os.replace``. ``index.json`` and its signature go last, so
  a consumer that reads the index never sees a file older than the one it lists.
* A file whose entries did not change keeps its bytes, its ``.gz`` sidecar and its mtime (so its
  ``ETag`` and ``Last-Modified`` stay stable). The comparison ignores what the headers carry
  (serial and time): the ``# selfhostr`` comment line of the text formats and the ``serial``,
  ``generated_at`` and ``valid_until`` keys of the JSON ones. Its ``.minisig`` is rewritten because
  the signed comment names the serial of the index.
* The size cap fails closed: the run raises before anything is replaced.
* ``.gz`` sidecars are deterministic (level 9, ``mtime = 0``).
"""

from __future__ import annotations

import gzip
import json
import os
import secrets
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from suckerpot_netproto.feeds import (
    FeedEntry,
    IndexFile,
    IndexOther,
    RenderContext,
    build_index,
    index_list,
    index_other,
    minisign,
    render_index,
    render_list,
)
from suckerpot_netproto.feeds.errors import FeedError
from suckerpot_netproto.feeds.external import (
    ExternalContext,
    ExternalIndexFile,
    ExternalRendered,
    ExternalSource,
    build_external_index,
    external_index_list,
    render_external_index,
    render_external_list,
)
from suckerpot_netproto.feeds.models import LIST_IDS, parse_ts

INDEX = "index.json"
HEADER_PREFIX = "# selfhostr "
VOLATILE_KEYS = ("serial", "generated_at", "valid_until")
POLICY = (
    "Values are validated by at least five independent members. Report a wrong entry at the "
    "delisting address in README.txt."
)
FILE_MODE = 0o644
DIR_MODE = 0o755


class PublishError(RuntimeError):
    """A run that must fail closed. The message is a short code, never a value."""


@dataclass(frozen=True)
class Published:
    serial: int
    written: list[str] = field(default_factory=list)  # data files rewritten this run
    kept: list[str] = field(default_factory=list)  # data files left untouched
    index: IndexFile | None = None


def normalize(name: str, data: bytes) -> bytes:
    """The content of a feed file without what changes on every run."""
    if name.endswith(".json") and not name.endswith(".stix.json"):
        try:
            doc: Any = json.loads(data)
        except ValueError:
            return data
        if isinstance(doc, dict):
            for key in VOLATILE_KEYS:
                doc.pop(key, None)
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    lines = data.decode("utf-8", "replace").split("\n")
    return "\n".join(ln for ln in lines if not ln.startswith(HEADER_PREFIX)).encode()


def gz(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=9, mtime=0)


def read_index(root: Path) -> IndexFile | None:
    path = root / INDEX
    try:
        return IndexFile.model_validate_json(path.read_bytes())
    except OSError, ValueError:
        return None


def current_serial(root: Path) -> int:
    idx = read_index(root)
    return idx.serial if idx is not None else 0


def index_remaining(root: Path, now: datetime) -> timedelta | None:
    """Validity left on the published index, or ``None`` when there is none."""
    idx = read_index(root)
    return parse_ts(idx.valid_until) - now if idx is not None else None


def _write(path: Path, data: bytes, when: float | None = None) -> None:
    path.write_bytes(data)
    path.chmod(FILE_MODE)
    if when is not None:
        os.utime(path, (when, when))


def render_all(
    *,
    serial: int,
    now: datetime,
    valid_days: int,
    lists: Mapping[str, Sequence[FeedEntry]],
    allow_documentation: bool,
) -> dict[str, Any]:
    """Render every list. Raises ``PublishError('too_large')`` over a cap."""
    out: dict[str, Any] = {}
    for list_id in LIST_IDS:
        ctx = RenderContext(
            list_id,
            serial,
            now,
            now + timedelta(days=valid_days),
            allow_documentation=allow_documentation,
        )
        try:
            out[list_id] = render_list(ctx, lists.get(list_id, []), policy=POLICY)
        except FeedError as exc:
            raise PublishError("too_large" if exc.code == "too_large" else "render_failed") from exc
    return out


def changed_files(root: Path, rendered: Mapping[str, Any], other: Mapping[str, bytes]) -> list[str]:
    """Names of files whose normalised content differs from the published copy (or is new)."""
    names: dict[str, bytes] = {}
    for r in rendered.values():
        names.update(r.files)
    names.update(other)
    out: list[str] = []
    for name, data in names.items():
        try:
            old = (root / name).read_bytes()
        except OSError:
            out.append(name)
            continue
        if normalize(name, old) != normalize(name, data):
            out.append(name)
    return out


def publish(
    root: Path,
    secret: minisign.SecretKey,
    *,
    serial: int,
    now: datetime,
    valid_days: int,
    rendered: Mapping[str, Any],
    other: Mapping[str, bytes],
    force_all: bool = False,
) -> Published:
    """Write the files of a new serial. ``rendered`` comes from ``render_all``."""
    root.mkdir(parents=True, exist_ok=True)
    for stale in root.glob(".tmp-*"):
        shutil.rmtree(stale, ignore_errors=True)
    tmp = root / f".tmp-{serial}-{secrets.token_hex(4)}"
    tmp.mkdir(mode=DIR_MODE)
    when = now.timestamp()
    previous = read_index(root)
    old_modified: dict[str, datetime] = {}
    if previous is not None:
        for lst in previous.lists:
            for f in lst.files:
                old_modified[f.name] = parse_ts(f.modified)
    try:
        dirty = set(changed_files(root, rendered, other))
        if force_all:
            dirty = {n for r in rendered.values() for n in r.files} | set(other)
        data_files: dict[str, bytes] = {}  # what the index describes (the served bytes)
        move: list[str] = []
        modified: dict[str, datetime] = {}
        lists_idx = []
        written: list[str] = []
        kept: list[str] = []
        for list_id in LIST_IDS:
            r = rendered[list_id]
            served: dict[str, bytes] = {}
            for name, data in r.files.items():
                if name in dirty:
                    served[name] = data
                    _write(tmp / name, data, when)
                    _write(tmp / (name + ".gz"), gz(data), when)
                    move += [name, name + ".gz"]
                    modified[name] = now
                    written.append(name)
                else:
                    served[name] = (root / name).read_bytes()
                    modified[name] = old_modified.get(name) or datetime.fromtimestamp(
                        (root / name).stat().st_mtime, now.tzinfo
                    )
                    kept.append(name)
            data_files.update(served)
            lists_idx.append(index_list(replace(r, files=served), modified))
        others: list[IndexOther] = []
        for name, data in other.items():
            if name in dirty:
                served_bytes = data
                _write(tmp / name, data, when)
                _write(tmp / (name + ".gz"), gz(data), when)
                move += [name, name + ".gz"]
                written.append(name)
            else:
                served_bytes = (root / name).read_bytes()
                kept.append(name)
            data_files[name] = served_bytes
            others.append(index_other(name, served_bytes))
        index = build_index(
            serial=serial,
            generated_at=now,
            valid_until=now + timedelta(days=valid_days),
            key_id=secret.public.key_id_hex,
            lists=lists_idx,
            other=others,
        )
        index_bytes = render_index(index)
        # Every signature names the serial of the index, so all of them are rewritten.
        for name, data in {**data_files, INDEX: index_bytes}.items():
            sig = minisign.sign_feed_file(data, name, serial, secret, timestamp=int(when))
            _write(tmp / (name + ".minisig"), sig.encode("ascii"), when)
        _write(tmp / INDEX, index_bytes, when)
        _write(tmp / (INDEX + ".gz"), gz(index_bytes), when)
        tmp.chmod(DIR_MODE)
        for name in move:
            os.replace(tmp / name, root / name)
        for name in data_files:
            os.replace(tmp / (name + ".minisig"), root / (name + ".minisig"))
        os.replace(tmp / (INDEX + ".gz"), root / (INDEX + ".gz"))
        os.replace(tmp / (INDEX + ".minisig"), root / (INDEX + ".minisig"))
        os.replace(tmp / INDEX, root / INDEX)
    except (OSError, FeedError) as exc:
        raise PublishError("write_failed") from exc
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return Published(serial, written, kept, index)


# --- the external tier: a second manifest root (design M36 X3) ------------------------------------
#
# The external files live in their own directory of the feed volume, with their own index, serial
# sequence and signatures. Nothing above this line reads or writes that directory, so the main
# index and its five lists are byte-identical whatever the external tier does.

EXTERNAL_DIR = "external"
EXTERNAL_LIST = "external-outbound"


def external_root(feed_dir: Path) -> Path:
    return feed_dir / EXTERNAL_DIR


def read_external_index(root: Path) -> ExternalIndexFile | None:
    try:
        return ExternalIndexFile.model_validate_json((root / INDEX).read_bytes())
    except OSError, ValueError:
        return None


def current_external_serial(root: Path) -> int:
    idx = read_external_index(root)
    return idx.serial if idx is not None else 0


def external_index_remaining(root: Path, now: datetime) -> timedelta | None:
    idx = read_external_index(root)
    return parse_ts(idx.valid_until) - now if idx is not None else None


def render_external(
    *,
    serial: int,
    now: datetime,
    valid_days: int,
    sources: Sequence[ExternalSource],
    entries: Sequence[Mapping[str, Any]],
    allow_documentation: bool,
) -> ExternalRendered:
    """Render the external list. Raises ``PublishError('too_large')`` over a cap."""
    ctx = ExternalContext(
        serial,
        now,
        now + timedelta(days=valid_days),
        tuple(sources),
        allow_documentation=allow_documentation,
    )
    try:
        return render_external_list(ctx, entries)
    except FeedError as exc:
        raise PublishError("too_large" if exc.code == "too_large" else "render_failed") from exc


def publish_external(
    root: Path,
    secret: minisign.SecretKey,
    *,
    serial: int,
    now: datetime,
    valid_days: int,
    rendered: ExternalRendered,
    other: Mapping[str, bytes],
    sources: Sequence[ExternalSource],
) -> Published:
    """Write the files of a new external serial under ``root`` (same atomic order as ``publish``:
    data files, signatures, then ``index.json`` last)."""
    root.mkdir(parents=True, exist_ok=True)
    for stale in root.glob(".tmp-*"):
        shutil.rmtree(stale, ignore_errors=True)
    tmp = root / f".tmp-{serial}-{secrets.token_hex(4)}"
    tmp.mkdir(mode=DIR_MODE)
    when = now.timestamp()
    previous = read_external_index(root)
    old_modified: dict[str, datetime] = {}
    if previous is not None:
        for lst in previous.lists:
            for f in lst.files:
                old_modified[f.name] = parse_ts(f.modified)
    try:
        dirty = set(changed_files(root, {EXTERNAL_LIST: rendered}, other))
        data_files: dict[str, bytes] = {}
        move: list[str] = []
        modified: dict[str, datetime] = {}
        written: list[str] = []
        kept: list[str] = []
        served: dict[str, bytes] = {}
        for name, data in rendered.files.items():
            if name in dirty:
                served[name] = data
                _write(tmp / name, data, when)
                _write(tmp / (name + ".gz"), gz(data), when)
                move += [name, name + ".gz"]
                modified[name] = now
                written.append(name)
            else:
                served[name] = (root / name).read_bytes()
                modified[name] = old_modified.get(name) or datetime.fromtimestamp(
                    (root / name).stat().st_mtime, now.tzinfo
                )
                kept.append(name)
        data_files.update(served)
        lists_idx = [external_index_list(replace(rendered, files=served), modified)]
        others: list[IndexOther] = []
        for name, data in other.items():
            if name in dirty:
                served_bytes = data
                _write(tmp / name, data, when)
                _write(tmp / (name + ".gz"), gz(data), when)
                move += [name, name + ".gz"]
                written.append(name)
            else:
                served_bytes = (root / name).read_bytes()
                kept.append(name)
            data_files[name] = served_bytes
            others.append(index_other(name, served_bytes))
        index = build_external_index(
            serial=serial,
            generated_at=now,
            valid_until=now + timedelta(days=valid_days),
            key_id=secret.public.key_id_hex,
            lists=lists_idx,
            sources=sources,
            other=others,
        )
        index_bytes = render_external_index(index)
        for name, data in {**data_files, INDEX: index_bytes}.items():
            sig = minisign.sign_feed_file(data, name, serial, secret, timestamp=int(when))
            _write(tmp / (name + ".minisig"), sig.encode("ascii"), when)
        _write(tmp / INDEX, index_bytes, when)
        _write(tmp / (INDEX + ".gz"), gz(index_bytes), when)
        tmp.chmod(DIR_MODE)
        for name in move:
            os.replace(tmp / name, root / name)
        for name in data_files:
            os.replace(tmp / (name + ".minisig"), root / (name + ".minisig"))
        os.replace(tmp / (INDEX + ".gz"), root / (INDEX + ".gz"))
        os.replace(tmp / (INDEX + ".minisig"), root / (INDEX + ".minisig"))
        os.replace(tmp / INDEX, root / INDEX)
    except (OSError, FeedError) as exc:
        raise PublishError("write_failed") from exc
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return Published(serial, written, kept, None)
