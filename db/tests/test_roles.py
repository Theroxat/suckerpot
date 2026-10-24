import base64
import hashlib
import hmac

import pytest

from suckerpot_db.entrypoint import is_upgrade
from suckerpot_db.roles import RoleError, scram_verifier


def test_scram_verifier_structure() -> None:
    salt = b"0123456789abcdef"
    v = scram_verifier("pa ss/w:rd", salt)
    head, rest = v.split("$", 1)
    assert head == "SCRAM-SHA-256"
    iters_salt, keys = rest.split("$")
    iters, salt_b64 = iters_salt.split(":")
    assert int(iters) == 4096 and base64.b64decode(salt_b64) == salt
    stored_b64, server_b64 = keys.split(":")
    salted = hashlib.pbkdf2_hmac("sha256", b"pa ss/w:rd", salt, 4096)
    ck = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    assert base64.b64decode(stored_b64) == hashlib.sha256(ck).digest()
    assert base64.b64decode(server_b64) == hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    assert "pa ss" not in v


def test_scram_random_salt_and_ascii_only() -> None:
    assert scram_verifier("x") != scram_verifier("x")
    with pytest.raises(RoleError):
        scram_verifier("pässword")


def test_is_upgrade() -> None:
    assert is_upgrade(["alembic", "upgrade", "head"])
    assert not is_upgrade(["alembic", "downgrade", "0001"])
    assert is_upgrade(["python", "-m", "alembic", "upgrade", "head"])
    assert not is_upgrade(["true"])
