"""M32: the verification switch and the fetch target origin, without a database."""

from collector.config import CollectorSettings
from collector.service import VERIFY_ORIGIN, Target


def test_verification_is_on_unless_the_owner_turns_it_off() -> None:
    assert CollectorSettings.from_env({}).verify_enabled is True
    assert CollectorSettings.from_env({"COLLECTOR_VERIFY_ENABLED": "false"}).verify_enabled is False
    assert CollectorSettings.from_env({"COLLECTOR_VERIFY_ENABLED": "true"}).verify_enabled is True


def test_a_target_is_local_unless_marked() -> None:
    assert Target(1, "http://files.example.test/x", "files.example.test", 0, 0).origin == "local"
    assert VERIFY_ORIGIN == "network_verify"
