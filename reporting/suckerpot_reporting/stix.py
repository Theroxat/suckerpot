"""STIX 2.1 bundle for CERTs (design M22, section 8.3).

No ``identity`` object, no ``created_by_ref``, no custom ``x_`` property. Object ids come from
the export's private seed; descriptions are owner-provided or absent; internal campaign
names never appear.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from typing import Any, Final

from .evidence import ExportData, ExportItem, Technique
from .ids import cluster_label, stix_id

# Core STIX 2.1 TLP marking definitions (fixed ids and creation time defined by the standard).
TLP_MARKINGS: Final[dict[str, tuple[str, str]]] = {
    "clear": ("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", "white"),
    "green": ("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da", "green"),
    "amber": ("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "amber"),
    "red": ("marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", "red"),
}
_TLP_CREATED: Final = "2017-01-20T00:00:00.000Z"


def stix_ts(value: datetime) -> str:
    return (
        value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"
    )


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _sco(item: ExportItem) -> tuple[str, dict[str, Any], str]:
    """(stix type, extra properties, pattern) of the observable behind an item."""
    if item.type == "ip":
        version = ipaddress.ip_address(item.value).version
        t = "ipv6-addr" if version == 6 else "ipv4-addr"
        return t, {"value": item.value}, f"[{t}:value = '{_quote(item.value)}']"
    if item.type == "url":
        return "url", {"value": item.value}, f"[url:value = '{_quote(item.value)}']"
    if item.type == "domain":
        return "domain-name", {"value": item.value}, f"[domain-name:value = '{_quote(item.value)}']"
    hashes = {"SHA-256": item.value}
    props: dict[str, Any] = {"hashes": hashes}
    if item.sample is not None:
        if item.sample.sha1:
            hashes["SHA-1"] = item.sample.sha1
        if item.sample.md5:
            hashes["MD5"] = item.sample.md5
        if item.sample.size is not None:
            props["size"] = item.sample.size
    return "file", props, f"[file:hashes.'SHA-256' = '{_quote(item.value)}']"


def _attack_ref(t: Technique) -> dict[str, str]:
    path = t.id.replace(".", "/")
    return {
        "source_name": "mitre-attack",
        "external_id": t.id,
        "url": f"https://attack.mitre.org/techniques/{path}/",
    }


def render_stix(data: ExportData) -> dict[str, Any]:
    seed = data.id_seed
    now = stix_ts(data.created)
    marking_id, level = TLP_MARKINGS[data.tlp]
    objects: list[dict[str, Any]] = [
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": marking_id,
            "created": _TLP_CREATED,
            "definition_type": "tlp",
            "name": f"TLP:{level.upper()}",
            "definition": {"tlp": level},
        }
    ]
    seen: set[str] = {marking_id}

    def add(obj: dict[str, Any]) -> None:
        if obj["id"] not in seen:
            seen.add(obj["id"])
            objects.append(obj)

    def sdo(stix_type: str, key: str, **props: Any) -> str:
        oid = stix_id(seed, stix_type, key)
        add(
            {
                "type": stix_type,
                "spec_version": "2.1",
                "id": oid,
                "created": now,
                "modified": now,
                **props,
                "object_marking_refs": [marking_id],
            }
        )
        return oid

    def rel(source: str, kind: str, target: str) -> None:
        sdo_id = stix_id(seed, "relationship", f"{source}|{kind}|{target}")
        add(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": sdo_id,
                "created": now,
                "modified": now,
                "relationship_type": kind,
                "source_ref": source,
                "target_ref": target,
                "object_marking_refs": [marking_id],
            }
        )

    for item in sorted(data.items, key=lambda i: (i.type, i.value, i.role)):
        sco_type, sco_props, pattern = _sco(item)
        sco_id = stix_id(seed, sco_type, item.value)
        add(
            {
                "type": sco_type,
                "spec_version": "2.1",
                "id": sco_id,
                **sco_props,
                "object_marking_refs": [marking_id],
            }
        )
        ind = sdo(
            "indicator",
            f"{item.type}:{item.value}",
            **({"description": data.description} if data.description else {}),
            indicator_types=["malicious-activity"],
            pattern=pattern,
            pattern_type="stix",
            pattern_version="2.1",
            valid_from=stix_ts(item.first_seen),
        )
        rel(ind, "based-on", sco_id)
        family_id: str | None = None
        if item.family:
            family_id = sdo("malware", item.family.casefold(), name=item.family, is_family=True)
            rel(ind, "indicates", family_id)
        if item.cluster_key:
            camp = sdo(
                "campaign",
                item.cluster_key,
                name=cluster_label(seed, item.cluster_key),
                **({"description": data.description} if data.description else {}),
            )
            rel(ind, "indicates", camp)
        for tech in item.techniques:
            ap = sdo(
                "attack-pattern",
                tech.id,
                name=tech.name,
                external_references=[_attack_ref(tech)],
            )
            if family_id is not None:
                rel(family_id, "uses", ap)
            else:
                rel(ind, "indicates", ap)
    return {"type": "bundle", "id": f"bundle--{data.export_id}", "objects": objects}


def dumps(obj: dict[str, Any]) -> str:
    """Stable JSON text: ASCII only, two-space indent, trailing newline."""
    return json.dumps(obj, indent=2, ensure_ascii=True) + "\n"
