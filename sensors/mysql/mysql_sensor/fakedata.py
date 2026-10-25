"""Synthetic table contents for the fake ``shop`` database.

Every value is generated from the row number with simple arithmetic, so nothing is stored and
the data is stable between queries. Names are common first and last names, e-mail addresses
use the reserved ``example.com`` domain and phone numbers the fictional 555-01xx range.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

FIRST = (
    "James", "Mary", "Liam", "Olivia", "Noah", "Emma", "Lucas", "Sofia", "Ethan", "Mia",
    "Leo", "Nora", "Hugo", "Clara", "Adam", "Julia", "Felix", "Lena", "Oscar", "Alice",
    "Louis", "Anna", "Jules", "Chloe",
)  # fmt: skip
LAST = (
    "Smith", "Martin", "Meyer", "Dubois", "Rossi", "Muller", "Weber", "Garcia", "Bernard",
    "Keller", "Brown", "Wilson", "Moreau", "Fischer", "Lopez", "Schmid", "Gerber", "Baker",
    "Clark", "Lambert", "Roth", "Huber", "Morel", "Evans",
)  # fmt: skip
CITIES = (
    "Zurich", "Geneva", "Basel", "Lausanne", "Bern", "Lyon", "Munich", "Milan", "Vienna",
    "Lisbon", "Dublin", "Utrecht",
)  # fmt: skip
PRODUCTS = (
    "Desk Lamp", "Notebook A5", "Wireless Mouse", "USB-C Cable", "Ceramic Mug", "Backpack",
    "Water Bottle", "Phone Stand", "Bluetooth Speaker", "Mechanical Keyboard", "Webcam HD",
    "Laptop Sleeve", "Monitor Arm", "Desk Mat", "Headphones", "Power Bank",
)  # fmt: skip
STATUSES = ("paid", "shipped", "pending", "paid", "paid", "refunded")

_BASE = datetime(2023, 1, 9, 8, 15, 0)


def _mix(i: int, salt: int) -> int:
    x = (i * 2654435761 + salt * 40503) & 0xFFFFFFFF
    x ^= x >> 15
    return (x * 2246822519) & 0xFFFFFFFF


def _stamp(i: int, salt: int) -> str:
    h = _mix(i, salt)
    when = _BASE + timedelta(days=h % 1000, seconds=(h >> 10) % 86400)
    return when.strftime("%Y-%m-%d %H:%M:%S")


def customer(i: int) -> tuple[str | None, ...]:
    first, last = FIRST[_mix(i, 1) % len(FIRST)], LAST[_mix(i, 2) % len(LAST)]
    email = f"{first}.{last}{i + 1}@example.com".lower()
    phone = f"+1-555-01{_mix(i, 3) % 100:02d}"
    return (str(i + 1), first, last, email, phone, CITIES[_mix(i, 4) % len(CITIES)], _stamp(i, 5))


def order(i: int) -> tuple[str | None, ...]:
    cents = 500 + _mix(i, 6) % 90000
    return (
        str(i + 1),
        str(1 + _mix(i, 7) % 1284),
        f"{cents // 100}.{cents % 100:02d}",
        STATUSES[_mix(i, 8) % len(STATUSES)],
        _stamp(i, 9),
    )


def product(i: int) -> tuple[str | None, ...]:
    cents = 299 + _mix(i, 10) % 20000
    name = f"{PRODUCTS[i % len(PRODUCTS)]} {1 + i // len(PRODUCTS)}"
    return (
        str(i + 1),
        f"SKU-{1000 + i}",
        name,
        f"{cents // 100}.{cents % 100:02d}",
        str(_mix(i, 11) % 400),
    )


GENERATORS: dict[str, Callable[[int], tuple[str | None, ...]]] = {
    "customers": customer,
    "orders": order,
    "products": product,
}

# (column name, wire type name, SQL type text)
SHOP_SCHEMAS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "customers": (
        ("id", "long", "int"),
        ("first_name", "str", "varchar(64)"),
        ("last_name", "str", "varchar(64)"),
        ("email", "str", "varchar(128)"),
        ("phone", "str", "varchar(32)"),
        ("city", "str", "varchar(64)"),
        ("created_at", "datetime", "datetime"),
    ),
    "orders": (
        ("id", "long", "int"),
        ("customer_id", "long", "int"),
        ("total", "decimal", "decimal(10,2)"),
        ("status", "str", "varchar(16)"),
        ("created_at", "datetime", "datetime"),
    ),
    "products": (
        ("id", "long", "int"),
        ("sku", "str", "varchar(32)"),
        ("name", "str", "varchar(128)"),
        ("price", "decimal", "decimal(10,2)"),
        ("stock", "long", "int"),
    ),
}
SHOP_ROWS = {"customers": 1284, "orders": 5310, "products": 96}

SYSTEM_TABLES: dict[str, tuple[str, ...]] = {
    "information_schema": (
        "CHARACTER_SETS", "COLLATIONS", "COLUMNS", "ENGINES", "EVENTS", "FILES", "PLUGINS",
        "PROCESSLIST", "ROUTINES", "SCHEMATA", "STATISTICS", "TABLES", "TRIGGERS",
        "USER_PRIVILEGES", "VIEWS",
    ),
    "mysql": (
        "columns_priv", "component", "db", "default_roles", "engine_cost", "func",
        "general_log", "global_grants", "gtid_executed", "help_category", "help_topic",
        "innodb_index_stats", "innodb_table_stats", "plugin", "procs_priv", "proxies_priv",
        "role_edges", "server_cost", "servers", "slow_log", "tables_priv", "time_zone",
        "user",
    ),
    "performance_schema": (
        "accounts", "events_statements_current", "events_waits_current", "global_status",
        "global_variables", "hosts", "session_status", "session_variables", "threads", "users",
    ),
    "sys": (
        "host_summary", "innodb_lock_waits", "processlist", "session", "sys_config",
        "version",
    ),
}  # fmt: skip
SYSTEM_DATABASES = tuple(SYSTEM_TABLES)


def now_stamp(_uptime: int = 0) -> str:
    """The current time as a MySQL DATETIME string (UTC, like the fake server's clock)."""
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
