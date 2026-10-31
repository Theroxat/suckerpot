import pytest

from collector.identity import BUSYBOX_UA, POWERSHELL_UA, WGET_UA, user_agent_for


@pytest.mark.parametrize(
    ("url", "ua"),
    [
        ("http://files.example.test/bins/x.arm7", BUSYBOX_UA),
        ("http://files.example.test/mips", BUSYBOX_UA),
        ("http://files.example.test/bot_x86", BUSYBOX_UA),
        ("http://files.example.test/bins/anything", BUSYBOX_UA),
        ("http://files.example.test/setup.ps1", POWERSHELL_UA),
        ("http://files.example.test/a.EXE", POWERSHELL_UA),
        ("http://files.example.test/install.sh", WGET_UA),
        ("http://files.example.test/", WGET_UA),
    ],
)
def test_user_agent(url: str, ua: str) -> None:
    assert user_agent_for(url) == ua


def test_identity_never_names_the_project() -> None:
    for ua in (BUSYBOX_UA, WGET_UA, POWERSHELL_UA):
        assert "sucker" not in ua.lower()
        assert "honey" not in ua.lower()
        assert "@" not in ua
