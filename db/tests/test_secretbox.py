import base64

import pytest

from suckerpot_db.secretbox import (
    Credential,
    SecretBox,
    SecretError,
    ValidationError,
    box_from_env,
    last4,
    validate_credential,
)

MASTER = bytes(range(32))
SAMPLE = "placeholder-key-for-tests-0003456"


def test_round_trip() -> None:
    box = SecretBox(MASTER)
    ct, nonce = box.encrypt("abuseipdb", Credential(SAMPLE))
    assert SAMPLE.encode() not in ct and len(nonce) == 12
    assert box.decrypt("abuseipdb", ct, nonce) == Credential(SAMPLE)


def test_round_trip_maxmind_account() -> None:
    box = SecretBox(MASTER)
    ct, nonce = box.encrypt("maxmind", Credential(SAMPLE, "123456"))
    assert box.decrypt("maxmind", ct, nonce).account_id == "123456"


def test_nonce_is_unique() -> None:
    box = SecretBox(MASTER)
    assert box.encrypt("greynoise", Credential(SAMPLE)) != box.encrypt(
        "greynoise", Credential(SAMPLE)
    )


def test_wrong_master_key() -> None:
    ct, nonce = SecretBox(MASTER).encrypt("abuseipdb", Credential(SAMPLE))
    with pytest.raises(SecretError) as exc:
        SecretBox(bytes(reversed(MASTER))).decrypt("abuseipdb", ct, nonce)
    assert SAMPLE not in str(exc.value) and exc.value.__cause__ is None


def test_tampered_ciphertext_and_nonce() -> None:
    box = SecretBox(MASTER)
    ct, nonce = box.encrypt("abuseipdb", Credential(SAMPLE))
    flipped = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(SecretError):
        box.decrypt("abuseipdb", flipped, nonce)
    with pytest.raises(SecretError):
        box.decrypt("abuseipdb", ct, bytes([nonce[0] ^ 1]) + nonce[1:])
    with pytest.raises(SecretError):
        box.decrypt("abuseipdb", ct[:-1], nonce)


def test_row_cannot_be_moved_to_another_provider() -> None:
    box = SecretBox(MASTER)
    ct, nonce = box.encrypt("abuseipdb", Credential(SAMPLE))
    with pytest.raises(SecretError):
        box.decrypt("greynoise", ct, nonce)


def test_short_master_rejected() -> None:
    with pytest.raises(SecretError):
        SecretBox(b"x" * 31)


def test_reprs_do_not_leak() -> None:
    box = SecretBox(MASTER)
    assert SAMPLE not in repr(Credential(SAMPLE, "1")) and "redacted" in repr(box)


def test_box_from_env() -> None:
    assert box_from_env({}) is None
    assert box_from_env({"SETTINGS_ENCRYPTION_KEY": "  "}) is None
    good = base64.b64encode(MASTER).decode()
    assert box_from_env({"SETTINGS_ENCRYPTION_KEY": good}) is not None
    assert box_from_env({"SETTINGS_ENCRYPTION_KEY": good.rstrip("=")}) is not None
    with pytest.raises(SecretError):
        box_from_env({"SETTINGS_ENCRYPTION_KEY": "not base64 !!"})
    short = base64.b64encode(b"short-master-value").decode()
    with pytest.raises(SecretError) as exc:
        box_from_env({"SETTINGS_ENCRYPTION_KEY": short})
    assert short not in str(exc.value)


@pytest.mark.parametrize(
    ("provider", "key", "account"),
    [
        ("abuseipdb", "short", None),
        ("abuseipdb", "x" * 129, None),
        ("abuseipdb", SAMPLE + " ", None),
        ("abuseipdb", SAMPLE[:10] + "\n" + SAMPLE[11:], None),
        ("abuseipdb", SAMPLE[:10] + "é" + SAMPLE[11:], None),
        ("abuseipdb", SAMPLE, "123"),
        ("maxmind", SAMPLE, None),
        ("maxmind", SAMPLE, "12ab"),
        ("maxmind", SAMPLE, "1" * 17),
        ("other", SAMPLE, None),
    ],
)
def test_validation_rejects(provider: str, key: str, account: str | None) -> None:
    with pytest.raises(ValidationError) as exc:
        validate_credential(provider, key, account)
    assert key not in str(exc.value)


def test_validation_accepts_and_last4() -> None:
    assert validate_credential("greynoise", SAMPLE, None).key == SAMPLE
    assert validate_credential("maxmind", SAMPLE, "42").account_id == "42"
    assert last4(SAMPLE) == "3456"


def test_low_entropy_master_rejected() -> None:
    with pytest.raises(SecretError):
        SecretBox(b"A" * 32)
    with pytest.raises(SecretError):
        SecretBox(bytes(range(8)) * 4)  # 8 distinct bytes
    SecretBox(bytes(range(16)) * 2)  # 16 distinct bytes is enough
    weak = base64.b64encode(b"A" * 32).decode()
    with pytest.raises(SecretError):
        box_from_env({"SETTINGS_ENCRYPTION_KEY": weak})


def test_master_must_differ_from_other_secrets() -> None:
    good = base64.b64encode(MASTER).decode()
    for other in ("SESSION_SECRET", "REDIS_PASSWORD", "POSTGRES_API_PASSWORD"):
        with pytest.raises(SecretError) as exc:
            box_from_env({"SETTINGS_ENCRYPTION_KEY": good, other: good})
        assert other in str(exc.value) and good not in str(exc.value)
    assert (
        box_from_env({"SETTINGS_ENCRYPTION_KEY": good, "SESSION_SECRET": "different"}) is not None
    )
