import pytest

from suckerpot_db.diskguard import DEFAULT_MAX_GB, DiskGuardError, max_db_bytes


def test_default_is_ten_gigabytes() -> None:
    assert max_db_bytes({}) == int(DEFAULT_MAX_GB * 1024**3)
    assert max_db_bytes({"DB_MAX_SIZE_GB": " "}) == 10 * 1024**3


def test_gigabytes_and_megabyte_override() -> None:
    assert max_db_bytes({"DB_MAX_SIZE_GB": "2.5"}) == int(2.5 * 1024**3)
    assert max_db_bytes({"DB_MAX_SIZE_GB": "2", "DB_MAX_SIZE_MB": "64"}) == 64 * 1024 * 1024


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("DB_MAX_SIZE_GB", "0"),
        ("DB_MAX_SIZE_GB", "0.5"),
        ("DB_MAX_SIZE_GB", "-3"),
        ("DB_MAX_SIZE_GB", "lots"),
        ("DB_MAX_SIZE_GB", "nan"),
        ("DB_MAX_SIZE_MB", "0"),
    ],
)
def test_invalid_values_are_rejected(name: str, value: str) -> None:
    with pytest.raises(DiskGuardError, match=name):
        max_db_bytes({name: value})
