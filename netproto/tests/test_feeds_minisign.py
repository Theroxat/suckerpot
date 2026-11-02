"""minisign: vectors, format cross-checks and negatives."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from suckerpot_netproto.feeds import FeedError, minisign
from suckerpot_netproto.feeds.minisign import PublicKey

from .test_feeds_common import GOLDEN, SECRET, SECRET2, SERIAL, SIGN_TS, VECTORS, build_signed_index

# The example key from the upstream minisign documentation: only parsed, never trusted.
UPSTREAM_PUBLIC = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
UPSTREAM_KEY_ID = "E7620F1842B4E81F"


def test_upstream_public_key_parses_and_prints_its_documented_id() -> None:
    key = minisign.parse_public_key(UPSTREAM_PUBLIC)
    assert key.key_id_hex == UPSTREAM_KEY_ID  # reversed byte order, as minisign prints it
    assert key.encoded == UPSTREAM_PUBLIC
    assert len(key.raw) == 32
    Ed25519PublicKey.from_public_bytes(key.raw)  # a valid curve point


def test_public_key_file_forms() -> None:
    pub = SECRET.public
    assert minisign.parse_public_key(pub.encoded) == pub
    assert minisign.parse_public_key(pub.to_file()) == pub
    assert minisign.parse_public_key(f"  {pub.encoded}\n") == pub
    assert (
        pub.to_file().splitlines()[0] == f"untrusted comment: minisign public key {pub.key_id_hex}"
    )


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "RW",
        UPSTREAM_PUBLIC[:-1],
        UPSTREAM_PUBLIC + "A",
        UPSTREAM_PUBLIC.replace("RWQ", "RWR", 1),  # wrong key id bytes still parse...
        "ED" + UPSTREAM_PUBLIC[2:],
        "!" * 56,
        UPSTREAM_PUBLIC + "\n" + UPSTREAM_PUBLIC,
    ],
)
def test_bad_public_keys(bad: str) -> None:
    if bad == UPSTREAM_PUBLIC.replace("RWQ", "RWR", 1):
        minisign.parse_public_key(bad)  # base64 with a different id is simply a different key
        return
    with pytest.raises(FeedError):
        minisign.parse_public_key(bad)


def test_signature_layout_matches_the_minisign_spec() -> None:
    sig = minisign.sign(b"hello", SECRET, "timestamp:1 file:x.txt serial:2")
    lines = sig.split("\n")
    assert lines[0] == "untrusted comment: signature from minisign secret key"
    assert lines[2] == "trusted comment: timestamp:1 file:x.txt serial:2"
    assert lines[4] == "" and len(lines) == 5
    raw = base64.b64decode(lines[1])
    assert raw[:2] == b"ED" and raw[2:10] == SECRET.key_id and len(raw) == 74
    # an independent re-derivation: signature over BLAKE2b-512, global over sig || comment
    pub = Ed25519PublicKey.from_public_bytes(SECRET.public.raw)
    pub.verify(raw[10:], hashlib.blake2b(b"hello", digest_size=64).digest())
    pub.verify(base64.b64decode(lines[3]), raw[10:] + b"timestamp:1 file:x.txt serial:2")


def test_sign_verify_roundtrip() -> None:
    data = b"198.51.100.9\n"
    sig = minisign.sign_feed_file(data, "outbound.txt", 7, SECRET, timestamp=1_700_000_000)
    comment = minisign.verify_feed_file(data, sig, SECRET.public, name="outbound.txt", serial=7)
    assert str(comment) == "timestamp:1700000000 file:outbound.txt serial:7"
    assert comment.timestamp == 1_700_000_000


def test_verify_negatives() -> None:
    data = b"198.51.100.9\n"
    sig = minisign.sign_feed_file(data, "outbound.txt", 7, SECRET, timestamp=1)
    pub = SECRET.public

    def code(fn_data: bytes = data, text: str = sig, key: PublicKey = pub, **kw: object) -> str:
        args = {"name": "outbound.txt", "serial": 7, **kw}
        with pytest.raises(FeedError) as e:
            minisign.verify_feed_file(fn_data, text, key, **args)  # type: ignore[arg-type]
        return e.value.code

    assert code(fn_data=data + b"\n") == "bad_signature"
    assert code(key=SECRET2.public) == "wrong_key"
    # same key id, different key
    forged = PublicKey(SECRET.key_id, SECRET2.public.raw)
    assert code(key=forged) == "bad_signature"
    assert code(name="inbound.txt") == "wrong_file"
    assert code(serial=8) == "wrong_serial"
    lines = sig.split("\n")
    swapped = "\n".join(
        [lines[0], lines[1], "trusted comment: timestamp:1 file:x.txt serial:7", lines[3], ""]
    )
    assert code(text=swapped) == "bad_signature"  # the trusted comment is signed
    assert code(text=sig.replace(lines[1], lines[1][:-4] + "AAAA")) in {
        "bad_signature",
        "bad_format",
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: "",
        lambda s: s.replace("untrusted comment: ", "comment: "),
        lambda s: s.replace("trusted comment: ", "comment: "),
        lambda s: "\n".join(s.split("\n")[:3]),
        lambda s: s + "extra\n",
        lambda s: s.replace("\n", "\r\n"),
        lambda s: s.replace("signature from", "signature\x07from"),
        lambda s: s + "A" * 2000,
        lambda s: s.replace("trusted comment: ", "trusted comment: " + "a" * 300),
        lambda s: s.replace("ED", "Ed", 1) if False else s.replace(s.split("\n")[1], "!" * 100),
        lambda s: s.replace("\n", "\n\n", 1),
    ],
)
def test_malformed_signature_files_are_refused(mutate) -> None:  # type: ignore[no-untyped-def]
    sig = minisign.sign_feed_file(b"x", "a.txt", 1, SECRET, timestamp=1)
    with pytest.raises(FeedError) as e:
        minisign.verify(b"x", mutate(sig), SECRET.public)
    assert e.value.code in {"bad_format", "bad_signature"}


def test_legacy_and_unknown_algorithms_are_refused() -> None:
    sig = minisign.sign(b"x", SECRET, "timestamp:1 file:a.txt serial:1")
    lines = sig.split("\n")
    raw = bytearray(base64.b64decode(lines[1]))
    for alg in (b"Ed", b"XX"):
        raw[:2] = alg
        lines[1] = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(FeedError) as e:
            minisign.verify(b"x", "\n".join(lines), SECRET.public)
        assert e.value.code == "bad_format"


def test_trusted_comment_must_be_well_formed() -> None:
    for bad in (
        "timestamp:1 file:../etc/passwd serial:1",
        "timestamp:1 file:a.txt serial:1 extra",
        "file:a.txt timestamp:1 serial:1",
        "timestamp:-1 file:a.txt serial:1",
        "timestamp:1 file:A.TXT serial:1",
        "",
    ):
        sig = minisign.sign(b"x", SECRET, bad)
        with pytest.raises(FeedError) as e:
            minisign.verify_feed_file(b"x", sig, SECRET.public, name="a.txt", serial=1)
        assert e.value.code == "bad_format"
    with pytest.raises(FeedError):
        minisign.sign(b"x", SECRET, "multi\nline")
    with pytest.raises(FeedError):
        minisign.sign(b"x", SECRET, "x" * 257)
    with pytest.raises(FeedError):
        minisign.sign_feed_file(b"x", "../a", 1, SECRET, timestamp=1)


def test_signature_key_id_picks_the_key_during_rotation() -> None:
    sig = minisign.sign(b"x", SECRET2, "timestamp:1 file:a.txt serial:1")
    assert minisign.signature_key_id(sig) == SECRET2.public.key_id_hex
    with pytest.raises(FeedError):
        minisign.signature_key_id("nonsense")


def test_secret_key_file_roundtrip_and_refusals() -> None:
    text = minisign.serialize_secret_key(SECRET)
    assert minisign.parse_secret_key(text) == SECRET
    raw = bytearray(base64.b64decode(text.split("\n")[1]))
    assert len(raw) == 158 and raw[:2] == b"Ed" and raw[4:6] == b"B2"
    raw[126] ^= 1  # checksum
    broken = text.split("\n")[0] + "\n" + base64.b64encode(bytes(raw)).decode()
    with pytest.raises(FeedError):
        minisign.parse_secret_key(broken)
    enc = bytearray(base64.b64decode(text.split("\n")[1]))
    enc[2:4] = b"Sc"  # scrypt: an encrypted key
    with pytest.raises(FeedError, match="encrypted"):
        minisign.parse_secret_key(
            text.split("\n")[0] + "\n" + base64.b64encode(bytes(enc)).decode()
        )
    with pytest.raises(FeedError):
        minisign.parse_secret_key("garbage")


def test_upstream_unencrypted_key_has_a_zero_checksum() -> None:
    """`minisign -G -W` writes 32 zero bytes where the checksum would be (found against 0.11)."""
    text = minisign.serialize_secret_key(SECRET)
    raw = bytearray(base64.b64decode(text.split("\n")[1]))
    raw[126:] = bytes(32)
    upstream = text.split("\n")[0] + "\n" + base64.b64encode(bytes(raw)).decode()
    assert minisign.parse_secret_key(upstream) == SECRET


def test_generate_keypair_is_usable() -> None:
    key = minisign.generate_keypair()
    assert len(key.seed) == 32 and len(key.key_id) == 8
    sig = minisign.sign(b"abc", key, "timestamp:1 file:a.txt serial:1")
    assert minisign.verify(b"abc", sig, key.public).startswith("timestamp:")
    assert minisign.generate_keypair().seed != key.seed


# --- golden vectors -------------------------------------------------------------------------


def test_keys_vector_matches_the_fixed_test_key() -> None:
    keys = json.loads((VECTORS / "keys.json").read_text())
    assert keys["public_key"] == SECRET.public.encoded
    assert keys["key_id"] == SECRET.public.key_id_hex
    assert keys["secret_seed_hex"] == SECRET.seed.hex()
    assert keys["serial"] == SERIAL and keys["sign_timestamp"] == SIGN_TS
    assert minisign.parse_secret_key(keys["secret_key_file"]) == SECRET


def test_golden_signatures_verify_and_are_reproduced_byte_for_byte() -> None:
    pub = minisign.parse_public_key(json.loads((VECTORS / "keys.json").read_text())["public_key"])
    raw, sig, _files, sigs = build_signed_index()
    assert (GOLDEN / "index.json").read_bytes() == raw
    assert (GOLDEN / "index.json.minisig").read_text() == sig  # Ed25519 is deterministic
    minisign.verify_feed_file(raw, sig, pub, name="index.json", serial=SERIAL)
    for name in ("outbound.txt", "inbound.json", "outbound-domains.txt"):
        golden_sig = (GOLDEN / f"{name}.minisig").read_text()
        assert golden_sig == sigs[name]
        minisign.verify_feed_file(
            (GOLDEN / name).read_bytes(), golden_sig, pub, name=name, serial=SERIAL
        )
