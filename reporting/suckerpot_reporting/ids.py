"""Identifiers that are random or derived from a private seed, never from internal ids (R6)."""

from __future__ import annotations

import uuid


def new_public_id() -> uuid.UUID:
    """The only id of a report that appears in file names and exports."""
    return uuid.uuid4()


def new_seed() -> uuid.UUID:
    """Seed for object ids. Stored with the report, never exported."""
    return uuid.uuid4()


def derive_id(seed: uuid.UUID, kind: str, value: str) -> uuid.UUID:
    """Stable for one seed and one object, unlinkable across seeds."""
    return uuid.uuid5(seed, f"{kind}:{value}")


def stix_id(seed: uuid.UUID, stix_type: str, value: str) -> str:
    return f"{stix_type}--{derive_id(seed, stix_type, value)}"


def cluster_label(seed: uuid.UUID, key: str) -> str:
    """Neutral replacement for an internal campaign name."""
    return f"Activity cluster {derive_id(seed, 'cluster', key).hex[:8]}"


def report_stem(public_id: uuid.UUID) -> str:
    return f"abuse-{public_id.hex[:8]}"


def export_names(export_id: uuid.UUID) -> dict[str, str]:
    short = export_id.hex[:8]
    return {
        "stix": f"indicators-{short}.stix.json",
        "misp": f"indicators-{short}.misp.json",
        "samples": f"samples-{short}.zip",
    }
