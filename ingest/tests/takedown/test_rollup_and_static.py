"""The monthly roll-up counting (pure) and the static guarantees of the takedown package."""

from __future__ import annotations

import ast
import dataclasses
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from ingest.takedown import rollup
from ingest.takedown.rollup import RollReport, RollTarget, build_rollup, months_to_compute
from tests.test_egress_static import scan_source

PACKAGE = Path(__file__).resolve().parents[2] / "ingest" / "takedown"
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


def target(day: int, down_after_h: float | None, **kw: object) -> RollTarget:
    reported = datetime(2026, 10, day, 12, 0, tzinfo=UTC)
    base: dict[str, object] = {
        "role": "payload_url", "provider_key": "as64500", "channels": ("mail",),
        "reported_at": reported, "observed_until": reported + timedelta(days=30),
        "first_down_at": None if down_after_h is None else reported + timedelta(hours=down_after_h),
    }  # fmt: skip
    base.update(kw)
    return RollTarget(**base)  # type: ignore[arg-type]


def test_months_to_compute() -> None:
    months, start = months_to_compute(NOW)
    assert months == {date(2026, 11, 1), date(2026, 10, 1)}
    assert start == datetime(2026, 10, 1, tzinfo=UTC)
    jan, _ = months_to_compute(datetime(2027, 1, 5, tzinfo=UTC))
    assert jan == {date(2027, 1, 1), date(2026, 12, 1)}


def test_targets_are_counted_per_provider_kind_and_channel() -> None:
    targets = [
        target(1, 5), target(2, 30), target(3, None),
        target(4, 2, provider_key="as64501", channels=("mail", "urlhaus")),
        target(5, None, role="c2"),
    ]  # fmt: skip
    rows = build_rollup(targets, [], {date(2026, 10, 1)})
    by = {(r.provider_key, r.kind, r.channel): r for r in rows}
    main = by[("as64500", "payload_url", "mail")]
    assert main.counts["targets"] == 3
    assert main.counts["targets_eligible_48h"] == 3 and main.counts["targets_down_48h"] == 2
    assert main.counts["targets_eligible_30d"] == 3 and main.counts["targets_down_30d"] == 2
    assert main.ttd_p50_s is None  # fewer than five values
    both = {k: v for k, v in by.items() if k[0] == "as64501"}
    assert set(both) == {("as64501", "payload_url", "mail"), ("as64501", "payload_url", "urlhaus")}
    c2 = by[("as64500", "c2", "mail")]
    assert c2.counts["targets"] == 1
    assert "targets_eligible_48h" not in c2.counts  # c2 has no takedown percentage


def test_other_months_are_left_out() -> None:
    assert build_rollup([target(1, 5)], [], {date(2026, 11, 1)}) == []


def test_demo_free_and_no_values_in_the_rows() -> None:
    rows = build_rollup([target(1, 5)], [], {date(2026, 10, 1)})
    fields = {f.name for f in dataclasses.fields(rows[0])}
    assert not fields & {"value", "url", "ip", "address"}


def test_report_outcomes_and_first_reply_median() -> None:
    month = date(2026, 10, 1)
    reps = [
        RollReport("payload_url", "as64500", "mail", month, "resolved", 3600),
        RollReport("payload_url", "as64500", "mail", month, "auto_ack", 60),
        RollReport("payload_url", "as64500", "mail", month, "bounce", None),
        RollReport("payload_url", "as64500", "mail", month, None, None),
        RollReport("payload_url", "as64500", "urlhaus", month),
    ]
    rows = build_rollup([], reps, {month})
    by = {(r.provider_key, r.kind, r.channel): r for r in rows}
    mail = by[("as64500", "payload_url", "mail")]
    assert mail.counts["reports_sent"] == 4
    assert mail.counts["reports_answered"] == 2
    assert (mail.counts["resolved"], mail.counts["auto_ack"], mail.counts["bounced"]) == (1, 1, 1)
    assert mail.first_reply_p50_s == 1830
    assert by[("as64500", "payload_url", "urlhaus")].counts["reports_sent"] == 1


def test_the_rollup_sql_never_deletes() -> None:
    src = (PACKAGE / "rollup.py").read_text().upper()
    assert "DELETE" not in src and "TRUNCATE" not in src
    assert rollup.UPSERT.lstrip().startswith("INSERT INTO outcome_rollup_monthly")


# ---- static guarantees ----------------------------------------------------------------------


def test_takedown_package_opens_no_connection_of_its_own() -> None:
    files = sorted(PACKAGE.rglob("*.py"))
    assert files
    problems: list[str] = []
    for path in files:
        problems += scan_source(path.read_text(), str(path.relative_to(PACKAGE)))
    assert not problems, "\n".join(problems)


def test_nothing_is_ever_reported_to_abuseipdb() -> None:
    """Only the read-only ``check`` client is used: no report endpoint, no write call."""
    for path in sorted(PACKAGE.rglob("*.py")):
        source = path.read_text()
        low = source.lower()
        assert "v2/report" not in low and "bulk-report" not in low and "/report" not in low, path
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in {"post", "put", "delete", "patch", "request"}, (
                    f"{path.name}:{node.lineno}"
                )
            if isinstance(node, ast.ImportFrom) and node.module and "reputation" in node.module:
                names = {a.name for a in node.names}
                assert "ABUSEIPDB_URL" not in names, path


def test_the_package_only_uses_the_existing_lookup_clients() -> None:
    names = {
        n.attr
        for path in PACKAGE.rglob("*.py")
        for n in ast.walk(ast.parse(path.read_text()))
        if isinstance(n, ast.Attribute) and n.attr in {"check_abuseipdb", "urlhaus", "threatfox"}
    }
    assert names == {"check_abuseipdb", "urlhaus", "threatfox"}
