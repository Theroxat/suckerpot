"""The daily update check (M28, invariant P4): gate, request shape, parsing, schedule."""

from __future__ import annotations

import ast
import json
import random
from pathlib import Path
from typing import Any

import httpx
import pytest

from ingest import updatecheck as uc
from ingest.updatecheck import UpdateChecker

from .helpers import fake_gate

RUNNING = "v0.8.0"


class Harness:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, handler: Any = None) -> None:
        self.requests: list[httpx.Request] = []
        self.made: list[dict[str, Any]] = []
        self.published: list[dict[str, Any]] = []
        self.old: dict[str, Any] = {}
        self.handler = handler or (lambda r: httpx.Response(200, json={"tag_name": "v0.9.0"}))
        monkeypatch.setattr(uc, "make_client", self._make_client)

    def _make_client(self, timeout: httpx.Timeout, **kw: Any) -> httpx.AsyncClient:
        self.made.append({"timeout": timeout, **kw})

        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return self.handler(request)

        return httpx.AsyncClient(
            transport=httpx.MockTransport(handle), headers=kw.get("headers"), timeout=timeout
        )

    async def _publish(self, detail: dict[str, Any]) -> None:
        self.published.append(detail)

    async def _previous(self) -> dict[str, Any]:
        return self.old

    def checker(self, *, gate: Any = None, enabled: bool = True, **kw: Any) -> UpdateChecker:
        return UpdateChecker(
            None,  # type: ignore[arg-type]
            enabled=enabled,
            repo=kw.pop("repo", "example-org/selfhostr"),
            gate=gate if gate is not None else fake_gate(),
            publish=self._publish,
            previous=self._previous,
            **kw,
        )


async def test_a_closed_gate_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch)
    h.old = {"latest": "v0.8.5", "published_at": "2026-10-01", "state": "ok"}
    state = await h.checker(gate=fake_gate(open_=False, reason="tunnel_down")).check_once()
    assert state == "no_egress"
    assert h.requests == [] and h.made == []
    assert h.published[0]["state"] == "no_egress"
    assert h.published[0]["latest"] == "v0.8.5"  # what we knew is kept


async def test_disabled_sends_nothing_and_says_off(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch)
    c = h.checker(enabled=False)
    await c.run()  # returns at once instead of looping
    assert h.requests == [] and h.made == []
    assert [p["state"] for p in h.published] == ["off"]


async def test_the_request_is_exactly_as_documented(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch)
    assert await h.checker().check_once() == "ok"
    (req,) = h.requests
    assert req.method == "GET" and req.url.scheme == "https"
    assert str(req.url) == "https://api.github.com/repos/example-org/selfhostr/releases/latest"
    assert h.made[0]["follow_redirects"] is False if "follow_redirects" in h.made[0] else True
    assert h.made[0]["timeout"] == httpx.Timeout(10.0)
    assert dict(h.made[0]["headers"]) == {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Mozilla/5.0",
    }
    sent = {k.lower(): v for k, v in req.headers.items()}
    for forbidden in ("cookie", "authorization", "if-none-match", "if-modified-since"):
        assert forbidden not in sent
    assert sent["user-agent"] == "Mozilla/5.0"
    blob = str(req.url) + json.dumps(sent) + req.content.decode()
    for needle in (RUNNING, "suckerpot", "selfhostr/", "version", "instance"):
        assert needle not in blob.replace("example-org/selfhostr", "")


async def test_a_good_release_is_stored(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {"tag_name": "v1.2.3", "published_at": "2026-11-01T08:00:00Z", "body": "notes <b>x</b>",
            "html_url": "https://evil.example.org/x"}  # fmt: skip
    h = Harness(monkeypatch, lambda r: httpx.Response(200, json=body))
    assert await h.checker().check_once() == "ok"
    got = h.published[0]
    assert set(got) == {"latest", "published_at", "state", "checked_at"}
    assert got["latest"] == "v1.2.3" and got["published_at"] == "2026-11-01T08:00:00Z"
    assert "evil" not in json.dumps(got) and "notes" not in json.dumps(got)


@pytest.mark.parametrize(
    "tag", ["1.2.3", "v1.2", "v1.2.3-rc1", "v1.2.3\n", "v1234.0.0", "latest", "", 3, None]
)
async def test_a_bad_tag_is_ignored(monkeypatch: pytest.MonkeyPatch, tag: Any) -> None:
    h = Harness(monkeypatch, lambda r: httpx.Response(200, json={"tag_name": tag}))
    h.old = {"latest": "v0.8.5", "state": "ok"}
    await h.checker().check_once()
    assert h.published[0].get("latest") == "v0.8.5"  # unchanged, the bad tag never lands
    assert tag not in h.published[0].values() or tag == "v0.8.5"


@pytest.mark.parametrize("flag", ["prerelease", "draft"])
async def test_prereleases_and_drafts_are_skipped(
    monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    h = Harness(monkeypatch, lambda r: httpx.Response(200, json={"tag_name": "v9.9.9", flag: True}))
    await h.checker().check_once()
    assert "latest" not in h.published[0]


async def test_errors_and_oversized_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch, lambda r: httpx.Response(503))
    assert await h.checker().check_once() == "error"
    h = Harness(
        monkeypatch, lambda r: httpx.Response(302, headers={"location": "https://x.example.org/"})
    )
    assert await h.checker().check_once() == "error"  # redirects are never followed
    assert len(h.requests) == 1
    big = b'{"tag_name": "v1.0.0", "pad": "' + b"a" * (uc.MAX_BODY + 10) + b'"}'
    h = Harness(monkeypatch, lambda r: httpx.Response(200, content=big))
    assert await h.checker().check_once() == "error"
    h = Harness(monkeypatch, lambda r: httpx.Response(200, content=b"not json"))
    assert await h.checker().check_once() == "error"


def test_repo_and_enable_switches() -> None:
    assert uc.repo_from_env({}) == uc.DEFAULT_REPO
    assert uc.repo_from_env({"UPDATE_CHECK_REPO": "a/b"}) == "a/b"
    assert uc.repo_from_env({"UPDATE_CHECK_REPO": "a/b/../c"}) == uc.DEFAULT_REPO
    assert uc.repo_from_env({"UPDATE_CHECK_REPO": "x@evil.example.org/y"}) == uc.DEFAULT_REPO
    assert uc.enabled_from_env({})
    assert uc.enabled_from_env({"UPDATE_CHECK_ENABLED": "true"})
    for off in ("false", "0", "no", "OFF"):
        assert not uc.enabled_from_env({"UPDATE_CHECK_ENABLED": off})


def test_jitter_bounds() -> None:
    rng = random.Random(7)  # noqa: S311
    first = [uc.first_delay(rng) for _ in range(500)]
    nxt = [uc.next_delay(rng) for _ in range(500)]
    assert all(3600 <= d <= 6 * 3600 for d in first)
    assert all(18 * 3600 <= d <= 30 * 3600 for d in nxt)
    assert max(nxt) - min(nxt) > 3600  # really spread out, not a fixed 24 h


async def test_run_schedule(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch)
    sleeps: list[float] = []

    class Stop(Exception):
        pass

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 4:
            raise Stop

    c = h.checker(
        gate=fake_gate(open_=False),
        sleep=sleep,
        rng=random.Random(1),  # noqa: S311
    )
    with pytest.raises(Stop):
        await c.run()
    assert 3600 <= sleeps[0] <= 6 * 3600
    assert sleeps[1:] == [uc.RETRY_CLOSED_S] * 3  # closed gate: look again soon, send nothing
    assert h.requests == []


def test_module_uses_the_egress_factory_only() -> None:
    src = Path(uc.__file__).read_text()
    tree = ast.parse(src)
    calls = {ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert "make_client" in calls
    assert not {
        c for c in calls if c.startswith(("httpx.AsyncClient", "httpx.Client", "httpx.get"))
    }
    for token in ("subprocess", "os.system", "docker", "pull(", "SUCKERPOT_RUNNING_VERSION"):
        assert token not in src.replace("Never downloads", "")
