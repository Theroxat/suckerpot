"""Build tiny MMDB files for tests (no network, no licensed data)."""

import gzip
import io
import tarfile
from pathlib import Path
from typing import Any

from mmdb_writer import MMDBWriter
from netaddr import IPSet


def build_mmdb(path: Path, db_type: str, records: dict[str, dict[str, Any]]) -> Path:
    writer = MMDBWriter(ip_version=4, database_type=db_type, languages=["en"], description="test")
    for network, record in records.items():
        writer.insert_network(IPSet([network]), record)
    writer.to_db_file(str(path))
    return path


def city_db(path: Path) -> Path:
    return build_mmdb(
        path,
        "GeoLite2-City",
        {
            "198.18.0.0/24": {
                "country": {"iso_code": "nl"},
                "city": {"names": {"en": "Amsterdam"}},
            },
            "198.19.0.0/24": {"country": {"iso_code": "CH"}},
        },
    )


def asn_db(path: Path) -> Path:
    return build_mmdb(
        path,
        "GeoLite2-ASN",
        {
            "198.18.0.0/24": {
                "autonomous_system_number": 64496,
                "autonomous_system_organization": "Example Hosting",
            }
        },
    )


def gz_bytes(path: Path) -> bytes:
    return gzip.compress(path.read_bytes())


def tar_gz_bytes(path: Path, member: str = "GeoLite2-City_20261020/GeoLite2-City.mmdb") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = path.read_bytes()
        info = tarfile.TarInfo(member)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()
