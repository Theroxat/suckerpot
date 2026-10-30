"""Protocol tests against the running sensor with a real HTTP / HTTPS client."""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

from conftest import Harness, start
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

INFO = "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all"


async def test_login_page_http_and_https(harness: Harness) -> None:
    for tls in (False, True):
        r = await harness.http("GET", "/", tls=tls)
        assert r.status == 200
        assert r.headers["Server"] == "nginx"
        assert r.headers["Content-Type"] == "text/html; charset=utf-8"
        text = r.body.decode()
        assert "<title>" in text and "SYNO.SDS.Session" in text
        assert '"version":"69057"' in text and "7.2.1-69057 Update 11" in text
        assert "/webman/resources/" in text and "/synoSDSjslib/" in text
        low = text.lower()
        assert "honeypot" not in low and "suckerpot" not in low
    same = await harness.http("GET", "/webman/index.cgi")
    assert same.body == r.body


async def test_assets_and_head(harness: Harness) -> None:
    r = await harness.http("GET", "/webman/favicon.ico")
    assert r.status == 200 and r.headers["Content-Type"] == "image/x-icon" and len(r.body) == 70
    r = await harness.http("GET", "/webman/resources/js/login.js?v=69057")
    assert r.status == 200 and r.headers["Content-Type"] == "application/javascript"
    r = await harness.http("HEAD", "/")
    assert r.status == 200 and r.body == b"" and int(r.headers["Content-Length"]) > 500
    r = await harness.http("GET", "/nope")
    assert r.status == 404 and b"<center>nginx</center>" in r.body
    r = await harness.http("DELETE", "/")
    assert r.status == 405


async def test_info_query_all_shape(harness: Harness) -> None:
    r = await harness.http("GET", INFO)
    assert r.status == 200
    assert r.headers["Content-Type"] == 'application/json; charset="UTF-8"'
    doc = r.json()
    assert doc["success"] is True
    data = doc["data"]
    assert data["SYNO.API.Auth"] == {"maxVersion": 7, "minVersion": 1, "path": "entry.cgi"}
    assert data["SYNO.API.Info"]["path"] == "entry.cgi"
    assert data["SYNO.DownloadStation.Task"]["path"] == "DownloadStation/task.cgi"
    assert any(k.startswith("SYNO.FileStation.") for k in data)
    assert any(k.startswith("SYNO.Core.") for k in data)
    assert "SYNO.API.Encryption" in data
    for entry in data.values():
        assert set(entry) >= {"maxVersion", "minVersion", "path"}
        assert entry["minVersion"] <= entry["maxVersion"]
    assert len(r.body) < 8192


async def test_info_query_subset(harness: Harness) -> None:
    path = "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth,Nope"
    doc = (await harness.http("GET", path)).json()
    assert list(doc["data"]) == ["SYNO.API.Auth"]


async def test_login_always_fails_and_is_recorded(harness: Harness) -> None:
    body = "api=SYNO.API.Auth&version=7&method=login&account=admin&passwd=hunter2&session=webui"
    r = await harness.form("/webapi/entry.cgi", body)
    assert r.status == 200
    assert r.json() == {"error": {"code": 400}, "success": False}
    evs = await harness.events("login_attempt")
    assert len(evs) == 1
    d = evs[0].data
    assert d["username"] == "admin" and d["password"] == "hunter2"
    assert d["otp_present"] is False and d["success"] is False
    assert d["api"] == "SYNO.API.Auth" and d["path"] == "/webapi/entry.cgi"
    assert evs[0].sensor == "synology" and evs[0].dst_port == harness.cfg.http_public_port


async def test_login_error_codes(harness: Harness) -> None:
    async def code(account: str, extra: str = "") -> int:
        q = f"api=SYNO.API.Auth&version=3&method=login&account={account}&passwd=x{extra}"
        r = await harness.http("GET", f"/webapi/auth.cgi?{q}")
        doc = r.json()
        assert doc["success"] is False
        return int(doc["error"]["code"])

    assert await code("admin") == 400
    assert await code("guest") == 401
    assert await code("sshd") == 402
    two_fa = next(n for n in (f"user{i}" for i in range(200)) if _needs_2fa(n))
    assert await code(two_fa) == 403
    assert await code(two_fa, "&otp_code=123456") == 404
    r = await harness.http("GET", "/webapi/auth.cgi?api=SYNO.API.Auth&version=3&method=login")
    assert r.json()["error"]["code"] == 400
    evs = await harness.events("login_attempt")
    assert any(e.data["otp_present"] for e in evs)
    assert not any(e.data["success"] for e in evs)


def _needs_2fa(name: str) -> bool:
    import hashlib

    return hashlib.sha256(name.lower().encode()).digest()[0] % 11 == 0


async def test_login_blocked_after_many_failures(tmp_path: Path) -> None:
    async with start(tmp_path, {"login_fail_limit": 3}) as h:
        codes = []
        for i in range(5):
            r = await h.http(
                "GET",
                f"/webapi/auth.cgi?api=SYNO.API.Auth&version=3&method=login&account=a{i}&passwd=b",
            )
            codes.append(r.json()["error"]["code"])
        assert codes[:3] == [400, 400, 400] or 403 in codes[:3] or 404 in codes[:3]
        assert codes[-1] == 407
        assert len(await h.events("login_attempt")) == 5


async def test_authenticated_apis_answer_119(harness: Harness) -> None:
    for api, method, version in [
        ("SYNO.FileStation.List", "list_share", 2),
        ("SYNO.Core.System", "info", 1),
        ("SYNO.DownloadStation.Task", "list", 1),
    ]:
        r = await harness.http(
            "GET", f"/webapi/entry.cgi?api={api}&version={version}&method={method}"
        )
        assert r.json() == {"error": {"code": 119}, "success": False}
    r = await harness.http("GET", "/webapi/entry.cgi?api=SYNO.Nope&version=1&method=x")
    assert r.json()["error"]["code"] == 102
    r = await harness.http("GET", "/webapi/entry.cgi?api=SYNO.Core.System&version=99&method=info")
    assert r.json()["error"]["code"] == 104
    r = await harness.http("GET", "/webapi/entry.cgi")
    assert r.json()["error"]["code"] == 101


async def test_encryption_getinfo(harness: Harness) -> None:
    r = await harness.http(
        "GET", "/webapi/entry.cgi?api=SYNO.API.Encryption&version=1&method=getinfo&format=module"
    )
    data = r.json()["data"]
    assert data["cipherkey"] == "__cIpHeRtExT" and "BEGIN PUBLIC KEY" in data["public_key"]


async def test_encrypted_login_recorded(harness: Harness) -> None:
    body = "api=SYNO.API.Auth&version=7&method=login&__cIpHeRtExT=U2FsdGVkX19abc%3D%3D"
    await harness.form("/webapi/entry.cgi", body)
    d = (await harness.events("login_attempt"))[0].data
    assert d["encrypted"] is True and d["password"].startswith("U2FsdGVk")


async def test_legacy_login_cgi(harness: Harness) -> None:
    r = await harness.form("/webman/login.cgi", "username=admin&passwd=admin&OTPcode=")
    assert r.json()["success"] is False
    evs = await harness.events("login_attempt")
    assert evs[0].data["username"] == "admin"


async def test_https_cert_looks_like_dsm(harness: Harness, tmp_path: Path) -> None:
    pem = (tmp_path / "tls" / "server.crt").read_bytes()
    cert = x509.load_pem_x509_certificate(pem)
    subject = cert.subject.rfc4514_string()
    assert "CN=synology" in subject and "O=Synology Inc." in subject
    key = cert.public_key()
    assert isinstance(key, RSAPublicKey) and key.key_size == 2048


async def test_sni_and_tls_in_events(harness: Harness) -> None:
    out = await harness.raw(
        b"GET / HTTP/1.1\r\nHost: nas.example.invalid\r\nUser-Agent: t\r\nConnection: close\r\n\r\n",
        tls=True,
        sni="nas.example.invalid",
    )
    assert out.startswith(b"HTTP/1.1 200")
    evs = await harness.events("http_request")
    d = evs[0].data
    assert d["tls"] is True and d["sni"] == "nas.example.invalid"
    assert evs[0].dst_port == harness.cfg.https_public_port
    conn = (await harness.events("connect"))[0]
    assert conn.data["tls"] is True and conn.data["handshake"] is True


async def test_plain_http_on_tls_port(harness: Harness) -> None:
    out = await harness.raw(b"GET /x HTTP/1.1\r\nHost: a\r\nUser-Agent: t\r\n\r\n", wait=1.0)
    assert out == b"" or out.startswith(b"HTTP/1.1")  # plain port: normal answer
    port = harness.tls_port
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET /x HTTP/1.1\r\nHost: a\r\nUser-Agent: t\r\n\r\n")
    await writer.drain()
    data = await asyncio.wait_for(reader.read(4096), 3)
    writer.close()
    assert data.startswith(b"HTTP/1.1 400")
    assert b"plain HTTP request was sent to HTTPS port" in data
    evs = [e for e in await harness.events("http_request") if e.data["path"] == "/x"]
    assert "plain_http_on_tls" in evs[-1].data["flags"]


async def test_http_redirect_option(tmp_path: Path) -> None:
    async with start(tmp_path, {"http_redirect": True, "https_public_port": 5001}) as h:
        r = await h.http("GET", "/", headers={"Host": "nas.example.invalid:5000"})
        assert r.status == 301 and r.headers["Location"] == "https://nas.example.invalid:5001/"
        out = await h.raw(
            b'GET / HTTP/1.1\r\nHost: x"y<z:5000\r\nUser-Agent: t\r\nConnection: close\r\n\r\n'
        )
        assert b"Location: https://localhost:5001/" in out
        r = await h.http("GET", INFO)
        assert r.status == 200


async def test_session_events_and_disconnect(harness: Harness) -> None:
    await harness.http("GET", "/")
    evs = await harness.events()
    kinds = [e.type for e in evs]
    assert kinds[0] == "connect" and "http_request" in kinds and kinds[-1] == "disconnect"
    assert len({e.session_id for e in evs}) == 1
    assert evs[-1].data["requests"] == 1


async def test_malformed_gets_nginx_400(harness: Harness) -> None:
    out = await harness.raw(b"\x16\x03\x01garbage\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 400") and b"nginx" in out
    scans = await harness.events("scan")
    assert scans and scans[0].data["kind"] == "non_http"
    assert json.dumps(scans[0].data)


async def test_plain_http_on_tls_page_matches_nginx(harness: Harness) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", harness.tls_port)
    writer.write(b"GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: t\r\n\r\n")
    await writer.drain()
    data = await asyncio.wait_for(reader.read(4096), 3)
    writer.close()
    assert b"Content-Type: text/html\r\n" in data
    body = data.split(b"\r\n\r\n", 1)[1]
    assert body == (
        b"<html>\r\n<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>"
        b"\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n"
        b"<center>The plain HTTP request was sent to HTTPS port</center>\r\n"
        b"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
    )


async def test_error_pages_use_plain_text_html(harness: Harness) -> None:
    assert (await harness.http("GET", "/nope")).headers["Content-Type"] == "text/html"
    assert (await harness.http("DELETE", "/")).headers["Content-Type"] == "text/html"


async def test_asset_sizes_vary_and_are_stable(harness: Harness) -> None:
    paths = [f"/webman/resources/js/m{i}.js" for i in range(8)] + ["/synoSDSjslib/sds.js"]
    sizes = [len((await harness.http("GET", p)).body) for p in paths]
    assert len(set(sizes)) > 5 and max(sizes) <= 48 * 1024
    again = len((await harness.http("GET", paths[0])).body)
    assert again == sizes[0]
    css = await harness.http("GET", "/webman/resources/css/synology.css")
    assert css.status == 200 and css.body.startswith(b"/* Synology DSM css */")
    js = await harness.http("GET", paths[0])
    assert js.body.startswith(b"/* Synology DSM js */") and js.body.endswith(b"\n")


async def test_reset_by_peer_is_not_an_error(harness: Harness, caplog) -> None:  # type: ignore[no-untyped-def]
    import logging
    import struct

    s = socket.create_connection(("127.0.0.1", harness.port))
    s.sendall(b"POST /webapi/entry.cgi HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\na=")
    await asyncio.sleep(0.1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()  # RST
    with caplog.at_level(logging.ERROR):
        await asyncio.sleep(0.3)
    assert "connection handler failed" not in caplog.text
    assert (await harness.events("disconnect"))[-1].data["reason"] == "client-closed"
