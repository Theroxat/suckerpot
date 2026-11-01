"""Sample bundle, identifiers and the deny-set loader."""

from __future__ import annotations

import base64
import hashlib
import io
import struct
import uuid
from datetime import UTC, datetime

import pytest
import pyzipper

from suckerpot_reporting import (
    BundleLimitError,
    BundleSample,
    GuardFailed,
    SampleRef,
    SelfTermRow,
    SelfTerms,
    build_encrypted_zip,
    build_sample_bundle,
    cluster_label,
    derive_id,
    export_names,
    load_self_terms,
    mask_value,
    new_public_id,
    report_stem,
    scan_binary,
)
from tests.conftest import OWNER_DOMAIN, SEED, SELF_ADDRESS


def sample(data: bytes, **kw: object) -> BundleSample:
    ref = SampleRef(sha256=hashlib.sha256(data).hexdigest(), size=len(data), kind="elf", **kw)
    return BundleSample(ref=ref, data=data)


def _open(blob: bytes) -> pyzipper.AESZipFile:
    return pyzipper.AESZipFile(io.BytesIO(blob))


def test_zip_metadata_is_neutral() -> None:
    blob = build_encrypted_zip([("b.bin", b"two"), ("a.bin", b"one")])
    zf = _open(blob)
    zf.setpassword(b"infected")
    assert [i.filename for i in zf.infolist()] == ["b.bin", "a.bin"]  # order kept
    for info in zf.infolist():
        assert info.date_time == (1980, 1, 1, 0, 0, 0)
        assert info.comment == b""
    assert zf.comment == b""
    assert zf.read("a.bin") == b"one"
    # end-of-central-directory record: comment length is zero
    assert struct.unpack("<H", blob[-2:])[0] == 0
    with pytest.raises(RuntimeError):
        _open(blob).read("a.bin")  # no password: encrypted


def test_bundle_excludes_samples_with_self_terms(terms: SelfTerms) -> None:
    clean = sample(b"\x7fELF clean payload")
    ascii_leak = sample(f"#!/bin/sh\nwget http://{SELF_ADDRESS}/x\n".encode())
    wide_leak = sample(f"{OWNER_DOMAIN}".encode("utf-16-le"))
    project = sample(b"if grep -q Honeypot /etc/hosts")
    result = build_sample_bundle([ascii_leak, clean, wide_leak, project], terms)
    assert result.included == (clean.ref.sha256,)
    reasons = dict(result.excluded)
    assert reasons[ascii_leak.ref.sha256] == ("self_address",)
    assert reasons[wide_leak.ref.sha256] == ("owner_domain",)
    assert reasons[project.ref.sha256] == ("project_term",)
    assert result.data is not None
    zf = _open(result.data)
    zf.setpassword(b"infected")
    assert [i.filename for i in zf.infolist()] == ["hashes.csv", f"{clean.ref.sha256}.bin"]
    assert zf.read(f"{clean.ref.sha256}.bin") == clean.data
    csv_text = zf.read("hashes.csv").decode()
    assert csv_text.splitlines()[0].startswith("sha256,sha1,md5,tlsh,size,kind,arch,family")
    assert ascii_leak.ref.sha256 not in csv_text


def test_bundle_all_excluded_and_limits(terms: SelfTerms) -> None:
    leak = sample(SELF_ADDRESS.encode())
    assert build_sample_bundle([leak], terms).data is None
    with pytest.raises(BundleLimitError):
        build_sample_bundle([sample(bytes([i])) for i in range(11)], terms)
    with pytest.raises(BundleLimitError):
        build_sample_bundle([], terms)
    forged = BundleSample(ref=sample(b"a").ref, data=b"b")
    with pytest.raises(BundleLimitError):
        build_sample_bundle([forged], terms)


def test_bundle_fails_closed(terms: SelfTerms) -> None:
    with pytest.raises(GuardFailed) as exc:
        build_sample_bundle([sample(b"a")], None)
    assert exc.value.codes == ("self_terms_unavailable",)
    with pytest.raises(GuardFailed):
        build_sample_bundle([sample(b"a")], load_self_terms([], {}))


def test_bundle_manifest_is_guarded(terms: SelfTerms) -> None:
    bad = sample(b"clean bytes", family=f"x {SELF_ADDRESS}")
    with pytest.raises(GuardFailed) as exc:
        build_sample_bundle([bad], terms)
    assert SELF_ADDRESS not in str(exc.value) and exc.value.codes == ("self_address",)


@pytest.mark.parametrize(
    "blob",
    [
        bytes([203, 0, 113, 77]),
        bytes([77, 113, 0, 203]),
        b"id=3405803853;",
        b"0xcb00714d",
        b"cb00714d",
        base64.b64encode(b"A" + SELF_ADDRESS.encode()),
        base64.b64encode(b"AA" + OWNER_DOMAIN.encode()),
        bytes.fromhex("20010db8123400000000000000000077"),
    ],
)
def test_scan_binary_encoded_forms(terms: SelfTerms, blob: bytes) -> None:
    assert scan_binary(b"\x00\x01pad" + blob + b"pad", terms) != ()


def test_scan_binary_codes_only(terms: SelfTerms) -> None:
    assert scan_binary(b"nothing here", terms) == ()
    assert scan_binary(b"xx srv-web01 xx", terms) == ("self_name",)


def test_ids_are_random_and_seeded() -> None:
    assert new_public_id() != new_public_id()
    assert derive_id(SEED, "ip", "198.51.100.23") == derive_id(SEED, "ip", "198.51.100.23")
    assert derive_id(SEED, "ip", "198.51.100.23") != derive_id(uuid.uuid4(), "ip", "198.51.100.23")
    assert cluster_label(SEED, "campaign-17").startswith("Activity cluster ")
    pid = uuid.UUID("12345678-1234-4234-8234-1234567890ab")
    assert report_stem(pid) == "abuse-12345678"
    names = export_names(pid)
    assert names["stix"] == "indicators-12345678.stix.json"
    assert names["samples"] == "samples-12345678.zip"
    low = " ".join(names.values()).lower() + report_stem(pid)
    assert "sucker" not in low and "honey" not in low


def test_load_self_terms_env_and_rows() -> None:
    now = datetime(2026, 10, 31, tzinfo=UTC)
    terms = load_self_terms(
        [
            SelfTermRow(kind="address", value="203.0.113.1", source="learned", last_seen=now),
            SelfTermRow(kind="cidr", value="198.51.100.0/28", source="manual"),
            SelfTermRow(kind="name", value="Home.Example.Org.", source="sensor", last_seen=now),
            SelfTermRow(kind="text", value="Villa Example", source="manual"),
        ],
        {
            "API_ALLOWED_HOSTS": "dash.example.net, localhost, *",
            "API_ALLOWED_ORIGINS": "https://panel.example.net:8443",
            "ALERTS_DASHBOARD_URL": "https://alerts.example.net/x",
            "AUTH_TRUSTED_PROXIES": "192.0.2.0/24",
            "VPN_WG_ENDPOINT_IP": "192.0.2.50",
            "SSH_HOSTNAME": "srv-ssh09",
            "SMB_DOMAIN": "",
        },
        vpn_exit="198.51.100.222",
        now=now,
    )
    names = {n.value: n.code for n in terms.names}
    assert names["home.example.org"] == "self_name"
    assert names["dash.example.net"] == names["panel.example.net"] == "owner_domain"
    assert names["alerts.example.net"] == "owner_domain"
    assert names["srv-ssh09"] == "self_name" and names["srv-web01"] == "self_name"
    assert "localhost" not in names and "*" not in names
    assert "192.0.2.50" in terms.vpn_addresses and "198.51.100.222" in terms.vpn_addresses
    assert terms.has_self_address  # the manual CIDR counts
    assert "villa example" in terms.texts
    assert "203.0.113.1" not in terms.addresses  # unconfirmed learned row
    import ipaddress

    assert terms.is_self(ipaddress.ip_address("198.51.100.5")) == "self_address"
    assert terms.is_self(ipaddress.ip_address("192.0.2.9")) == "self_address"
    assert terms.is_self(ipaddress.ip_address("198.51.100.222")) == "vpn_address"
    assert terms.is_self(ipaddress.ip_address("198.51.100.99")) is None


def test_mask_value() -> None:
    assert mask_value("address", "203.0.113.77") == "203.0.•••.•••"
    assert "113" not in mask_value("address", "203.0.113.77")
    assert mask_value("name", "dash.example.net").endswith("•••")


def test_generic_sensor_words_are_not_deny_terms() -> None:
    rows = [SelfTermRow(kind="name", value=v, source="manual") for v in ("CORP", "Storage", "ab-c")]
    terms = load_self_terms(
        rows,
        {
            "SMB_HOSTNAME": "FileServer",
            "SMB_DOMAIN": "WORKGROUP",
            "RDP_HOSTNAME": "DiskStation",
            "SSH_HOSTNAME": "srv-ssh09",
            "WEB_HOSTNAME": "OFFICE",
            "API_ALLOWED_HOSTS": "host7.example.net,admin,intra,workgroup.local,group",
        },
    )
    names = {n.value for n in terms.names}
    assert not names & {"corp", "storage", "fileserver", "workgroup", "diskstation", "office"}
    assert not names & {"admin", "intra", "group", "workgroup.local"}
    assert {"srv-ssh09", "ab-c", "host7.example.net", "srv-web01"} <= names
    # a bare word without digit or hyphen is refused even when it is not on the list
    assert "plainword" not in {
        n.value for n in load_self_terms([SelfTermRow(kind="name", value="plainword")], {}).names
    }
