"""The password policy and the temporary passwords."""

import pytest

from api import passwords


@pytest.mark.parametrize(
    ("password", "username", "expected"),
    [
        ("short-one", "", passwords.TOO_SHORT),
        ("x" * 11, "", passwords.TOO_SHORT),
        ("x" * 257, "", passwords.TOO_LONG),
        ("q1w2e3r4t5y6", "", passwords.COMMON),  # in the bundled list
        ("Q1W2E3R4T5Y6", "", passwords.COMMON),  # case does not help
        ("password12345678", "", passwords.COMMON),  # a common root plus digits
        ("Password!!2026", "", passwords.COMMON),
        ("Jordan-is-the-best", "jordan", passwords.CONTAINS_USERNAME),
        ("xxJORDANxx9f3kq", "jordan", passwords.CONTAINS_USERNAME),
        ("correct horse battery staple", "jordan", None),
        ("x" * 12 + "7Kd", "", None),
        ("é" * 12, "", None),  # characters, not bytes
        ("x" * 256, "", None),
    ],
)
def test_check_password(password: str, username: str, expected: str | None) -> None:
    assert passwords.check_password(password, username) == expected


def test_the_bundled_list_is_loaded_and_lower_case() -> None:
    common = passwords.common_passwords()
    assert 900 <= len(common) <= 1100
    assert all(p == p.lower() and len(p) >= passwords.MIN_LENGTH for p in common)
    assert not any(p.startswith("#") for p in common)


def test_every_message_has_a_code() -> None:
    assert set(passwords.MESSAGES) == {
        passwords.TOO_SHORT,
        passwords.TOO_LONG,
        passwords.COMMON,
        passwords.CONTAINS_USERNAME,
    }


def test_temporary_passwords_are_strong_and_acceptable() -> None:
    seen = {passwords.generate_temporary_password() for _ in range(200)}
    assert len(seen) == 200
    for p in seen:
        assert len(p) == 23 and p.count("-") == 3
        assert passwords.check_password(p) is None
        assert not set(p.replace("-", "")) & set("0O1lIi5SB")
