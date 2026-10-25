"""Manual tool: diff our responses against a real Apache 2.4.58 (Ubuntu 24.04) reference.

Start the reference (throwaway container, never part of the sensor):

    docker run -d --rm --name sp-ref -p 127.0.0.1:18080:80 <ubuntu:24.04 + apache2 + libapache2-mod-php>

then ``python tests/ref_compare.py 18080``. Only Apache-owned behaviour is compared (error pages,
header order, malformed requests); WordPress content has no counterpart in the reference.
Dates, the server address and Content-Length derived from them are normalised.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from conftest import FakePublisher

from web_sensor.config import Config
from web_sensor.events import EventSink
from web_sensor.profile import build_profile
from web_sensor.server import WebSensor, WebServer
from web_sensor.site import Site
from web_sensor.tls import ensure_certificate, make_context

H = b"Host: srv-web01\r\n"
CASES: dict[str, bytes] = {
    "http10": b"GET /.env HTTP/1.0\r\n\r\n",
    "http10_ka": b"GET /.env HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    "http11_nohost": b"GET /.env HTTP/1.1\r\n\r\n",
    "head404": b"HEAD /.env HTTP/1.1\r\n" + H + b"\r\n",
    "options_star": b"OPTIONS * HTTP/1.1\r\n" + H + b"\r\n",
    "options_404": b"OPTIONS /.env HTTP/1.1\r\n" + H + b"\r\n",
    "trace": b"TRACE / HTTP/1.1\r\n" + H + b"\r\n",
    "bogusmethod": b"FOO / HTTP/1.1\r\n" + H + b"\r\n",
    "lowercase": b"get / HTTP/1.1\r\n" + H + b"\r\n",
    "post404": b"POST /.env HTTP/1.1\r\n" + H + b"Content-Length: 3\r\n\r\nabc",
    "put": b"PUT /.env HTTP/1.1\r\n" + H + b"Content-Length: 3\r\n\r\nabc",
    "delete": b"DELETE /.env HTTP/1.1\r\n" + H + b"Content-Length: 0\r\n\r\n",
    "propfind": b"PROPFIND /.env HTTP/1.1\r\n" + H + b"Content-Length: 0\r\n\r\n",
    "connect": b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    "garbage": b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n\r\n",
    "garbage2": b"hello\r\n\r\n",
    "badver": b"GET /.env HTTP/9.9\r\n" + H + b"\r\n",
    "badver_h2": b"GET /.env HTTP/2.0\r\n" + H + b"\r\n",
    "badver_h0": b"GET /.env HTTP/0.9\r\n" + H + b"\r\n",
    "badver_h1dot": b"GET /.env HTTP/1.\r\n" + H + b"\r\n",
    "proto_foo": b"GET /.env FOO/1.1\r\n" + H + b"\r\n",
    "http09": b"GET /.env\r\n",
    "http09_head": b"HEAD /.env\r\n",
    "absform": b"GET http://example.com/.env HTTP/1.1\r\n" + H + b"\r\n",
    "absform10": b"GET http://example.com/.env HTTP/1.0\r\n\r\n",
    "badhdr": b"GET /.env HTTP/1.1\r\n" + H + b"Bad Header: a\r\n\r\n",
    "nocolon": b"GET /.env HTTP/1.1\r\n" + H + b"foo\r\n\r\n",
    "bare_lf": b"GET /.env HTTP/1.1\nHost: x\n\n",
    "badpct": b"GET /%zz HTTP/1.1\r\n" + H + b"\r\n",
    "nullbyte": b"GET /%00 HTTP/1.1\r\n" + H + b"\r\n",
    "dotdot": b"GET /../../etc/passwd HTTP/1.1\r\n" + H + b"\r\n",
    "dotdot_enc": b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\n" + H + b"\r\n",
    "enc_slash": b"GET /a%2fb HTTP/1.1\r\n" + H + b"\r\n",
    "long_uri": b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\n" + H + b"\r\n",
    "long_hdr": b"GET /.env HTTP/1.1\r\n" + H + b"X-A: " + b"a" * 9000 + b"\r\n\r\n",
    "many_hdr": b"GET /.env HTTP/1.1\r\n"
    + H
    + b"".join(b"X-%d: a\r\n" % i for i in range(120))
    + b"\r\n",
    "bigbody": b"POST /.env HTTP/1.1\r\n" + H + b"Content-Length: 99999999999\r\n\r\n",
    "badcl": b"POST /.env HTTP/1.1\r\n" + H + b"Content-Length: abc\r\n\r\n",
    "negcl": b"POST /.env HTTP/1.1\r\n" + H + b"Content-Length: -1\r\n\r\n",
    "chunked_post": b"POST /.env HTTP/1.1\r\n"
    + H
    + b"Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    "te_cl": b"POST /.env HTTP/1.1\r\n"
    + H
    + b"Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    "te_bad": b"POST /.env HTTP/1.1\r\n"
    + H
    + b"Transfer-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc",
    "expect": b"POST /.env HTTP/1.1\r\n"
    + H
    + b"Content-Length: 3\r\nExpect: 100-continue\r\n\r\nabc",
    "ka2": b"GET /.env HTTP/1.1\r\n"
    + H
    + b"\r\nGET /.env HTTP/1.1\r\n"
    + H
    + b"Connection: close\r\n\r\n",
    "htaccess": b"GET /.htaccess HTTP/1.1\r\n" + H + b"\r\n",
    "ctrl": b"GET /\x01 HTTP/1.1\r\n" + H + b"\r\n",
    "tab_uri": b"GET /a\tb HTTP/1.1\r\n" + H + b"\r\n",
    "dblspace": b"GET  /.env HTTP/1.1\r\n" + H + b"\r\n",
    "hostbad": b"GET /.env HTTP/1.1\r\nHost: a b\r\n\r\n",
    "dup_host": b"GET /.env HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
    "obsfold": b"GET /.env HTTP/1.1\r\nHost: a\r\nX: y\r\n z\r\n\r\n",
    "hostport": b"GET /.env HTTP/1.1\r\nHost: Example.com:8081\r\n\r\n",
    "hdr_ctl": b"GET /.env HTTP/1.1\r\n" + H + b"X-A: a\x01b\r\n\r\n",
    "hdr_8bit": b"GET /.env HTTP/1.1\r\n" + H + b"X-A: a\xffb\r\n\r\n",
    "frag": b"GET /.env#frag HTTP/1.1\r\n" + H + b"\r\n",
    "space_uri": b"GET /a b HTTP/1.1\r\n" + H + b"\r\n",
    "star_get": b"GET * HTTP/1.1\r\n" + H + b"\r\n",
    "dblslash": b"GET //.env HTTP/1.1\r\n" + H + b"\r\n",
    "icons_dir": b"GET /icons/ HTTP/1.1\r\n" + H + b"\r\n",
    "server_status": b"GET /server-status HTTP/1.1\r\n" + H + b"\r\n",
    "cgi_bin": b"GET /cgi-bin/ HTTP/1.1\r\n" + H + b"\r\n",
}


def raw(port: int, data: bytes, wait: float = 1.0) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(data)
    s.settimeout(wait)
    out = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            out += c
    except OSError:
        pass
    s.close()
    return out


def normalise(resp: bytes, ref_ip: str, our_ip: str) -> bytes:
    lines = resp.split(b"\r\n")
    out = []
    has_ip = ref_ip.encode() in resp or our_ip.encode() in resp
    for ln in lines:
        if ln.startswith(b"Date: "):
            ln = b"Date: <date>"
        if has_ip and ln.startswith(b"Content-Length: "):
            ln = b"Content-Length: <n>"
        out.append(ln)
    text = b"\r\n".join(out)
    return text.replace(ref_ip.encode(), b"<ip>").replace(our_ip.encode(), b"<ip>")


async def main(ref_port: int, ref_ip: str) -> int:
    tmp = tempfile.mkdtemp()
    profile = build_profile(b"y" * 32, 1_790_000_000.0)
    cfg = replace(Config(), host="127.0.0.1", http_port=0, https_port=0, quiet_loopback=False)
    cert, key = ensure_certificate(tmp, "srv-web01", profile)
    holder: list[WebSensor] = []
    sink = EventSink(FakePublisher())
    sink.start()
    sensor = WebSensor(
        cfg, sink, Site(cfg, profile, "x"), make_context(cert, key, lambda o, n: None)
    )
    holder.append(sensor)
    server = WebServer(cfg, sensor)
    ports = await server.start()
    loop = asyncio.get_running_loop()
    bad = 0
    for name, data in CASES.items():
        ours = await loop.run_in_executor(None, raw, ports["http"], data)
        ref = await loop.run_in_executor(None, raw, ref_port, data)
        a = normalise(ours, ref_ip, profile.server_ip)
        b = normalise(ref, ref_ip, profile.server_ip)
        # The reference listens on a mapped port; its pages say "Port 80" via the Host header or
        # the container port, which equals ours.
        if a != b:
            bad += 1
            print(f"DIFF {name}\n--- ours\n{a[:700]!r}\n--- reference\n{b[:700]!r}\n")
        else:
            print(f"same {name}")
    await server.stop()
    print(f"{len(CASES) - bad}/{len(CASES)} identical")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent))
    sys.exit(asyncio.run(main(int(sys.argv[1]), sys.argv[2])))
