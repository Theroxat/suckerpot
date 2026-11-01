"""MISP event JSON (design M22, section 8.3).

No ``Org``, ``Orgc``, ``event_creator_email`` or ``sharing_group``: MISP sets them on import.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final

from .errors import RenderUnavailable
from .evidence import ExportData, ExportItem
from .ids import cluster_label, derive_id

_FAMILY_TAG: Final = 'misp-galaxy:malware="{}"'
_ATTACK_TAG: Final = 'misp-galaxy:mitre-attack-pattern="{} - {}"'


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")


def _attrs(item: ExportItem) -> list[tuple[str, str, str]]:
    """(misp type, category, value) of the attributes behind one item."""
    if item.type == "ip":
        mtype = "ip-src" if item.role == "attack_source" else "ip-dst"
        return [(mtype, "Network activity", item.value)]
    if item.type == "url":
        cat = "Network activity" if item.role == "c2" else "Payload delivery"
        return [("url", cat, item.value)]
    if item.type == "domain":
        cat = "Network activity" if item.role == "c2" else "Payload delivery"
        return [("domain", cat, item.value)]
    out = [("sha256", "Payload delivery", item.value)]
    if item.sample is not None:
        for mtype, val in (
            ("sha1", item.sample.sha1),
            ("md5", item.sample.md5),
            ("tlsh", item.sample.tlsh),
        ):
            if val:
                out.append((mtype, "Payload delivery", val))
    return out


def render_misp(data: ExportData) -> dict[str, Any]:
    """MISP needs an ``info`` line; it is the owner's ``description`` (none is shipped)."""
    if not data.description.strip():
        raise RenderUnavailable("settings_incomplete")
    stamp = str(int(data.created.timestamp()))
    day = data.created.astimezone(UTC).strftime("%Y-%m-%d")
    tags: list[dict[str, str]] = [{"name": f"tlp:{data.tlp}"}]
    attributes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in sorted(data.items, key=lambda i: (i.type, i.value, i.role)):
        comment_parts = []
        if item.family:
            comment_parts.append(f"family: {item.family}")
        if item.cluster_key:
            comment_parts.append(cluster_label(data.id_seed, item.cluster_key))
        for mtype, category, value in _attrs(item):
            uid = str(derive_id(data.id_seed, "attribute", f"{mtype}:{value}"))
            if uid in seen:
                continue
            seen.add(uid)
            attributes.append(
                {
                    "uuid": uid,
                    "type": mtype,
                    "category": category,
                    "value": value,
                    "to_ids": True,
                    "distribution": "0",
                    "comment": "; ".join(comment_parts),
                    "first_seen": _iso(item.first_seen),
                    "last_seen": _iso(item.last_seen),
                    "timestamp": stamp,
                }
            )
        for tech in item.techniques:
            tag = {"name": _ATTACK_TAG.format(tech.name, tech.id)}
            if tag not in tags:
                tags.append(tag)
        if item.family:
            tag = {"name": _FAMILY_TAG.format(item.family)}
            if tag not in tags:
                tags.append(tag)
    return {
        "Event": {
            "uuid": str(data.export_id),
            "info": data.description,
            "date": day,
            "threat_level_id": "2",
            "analysis": "2",
            "distribution": "0",
            "published": False,
            "timestamp": stamp,
            "Tag": tags,
            "Attribute": attributes,
        }
    }
