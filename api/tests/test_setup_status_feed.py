"""The community lists item of the setup checklist: plain words, never a raw error code."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from api import network_feed, setup_status
from api.network_feed import FeedInfo

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


def _patch(monkeypatch: pytest.MonkeyPatch, info: FeedInfo) -> None:
    async def load_state(_db: Any, _now: datetime | None = None) -> FeedInfo:
        return info

    monkeypatch.setattr(network_feed, "feed_enabled", lambda: True)
    monkeypatch.setattr(network_feed, "public_base_url", lambda: "https://feeds.example.org/v1")
    monkeypatch.setattr(network_feed, "load_state", load_state)


def _info(state: str, code: str | None) -> FeedInfo:
    return FeedInfo(state, code, 7, NOW, NOW - timedelta(hours=1), NOW)


async def test_stale_lists_say_this_dashboard_stopped_serving_its_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _info("stale", "feed_expired"))
    item = await setup_status._network_feed(None, NOW)  # type: ignore[arg-type]
    assert item.state == "warning"
    assert "this dashboard stopped serving its copy to firewalls" in item.detail
    assert "nothing is served" not in item.detail
    assert "feed_expired" not in item.detail


@pytest.mark.parametrize(
    ("code", "words"),
    [
        ("feed_rollback", "older than the ones already stored"),
        ("http_503", "answered with an error (503)"),
        ("unreachable", "could not be reached"),
    ],
)
async def test_error_codes_become_words(
    monkeypatch: pytest.MonkeyPatch, code: str, words: str
) -> None:
    _patch(monkeypatch, _info("error", code))
    item = await setup_status._network_feed(None, NOW)  # type: ignore[arg-type]
    assert words in item.detail and code not in item.detail


async def test_an_unknown_code_is_left_out(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _info("error", "something_new"))
    item = await setup_status._network_feed(None, NOW)  # type: ignore[arg-type]
    assert item.detail == "The last fetch of the community lists failed."
