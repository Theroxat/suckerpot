"""Demo sessions never become hub claims: both readers of sessions exclude demo events."""

from __future__ import annotations

import inspect

from ingest.network import demo, source, store


def test_the_fragment_reads_only_the_demo_flag_inside_a_time_window() -> None:
    sql = demo.not_demo("se", ":d0", ":d2")
    assert sql.startswith("NOT EXISTS (SELECT 1 FROM events e ")
    assert "e.session_id = se.session_id" in sql
    assert "e.ts >= :d0 AND e.ts < :d2" in sql
    assert "e.data ->> 'demo'" in sql
    assert sql.count("e.data") == 1


def test_the_session_reader_excludes_sessions_with_a_demo_event() -> None:
    assert 'demo.not_demo("se", ":d0", ":d2")' in inspect.getsource(source.SqlSource.sessions)


def test_the_mine_flagging_excludes_sessions_with_a_demo_event() -> None:
    assert 'demo.not_demo("s"' in inspect.getsource(store.SqlStore.refresh_mine)
