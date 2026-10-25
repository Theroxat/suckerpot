import asyncio
import os
import shutil
import sys

sys.path.insert(0, __import__("os").path.dirname(__file__))
from dataclasses import replace

from conftest import FakePublisher
from ref_compare import normalise, raw

from web_sensor.config import Config
from web_sensor.events import EventSink
from web_sensor.profile import build_profile
from web_sensor.server import WebSensor, WebServer
from web_sensor.site import Site

REF_IP = sys.argv[2] if len(sys.argv) > 2 else "192.0.2.10"  # reference container address
profile = build_profile(b"y" * 32, 1_790_000_000.0)
cfg = replace(Config(), host="127.0.0.1", http_port=0, https_port=0, quiet_loopback=False)
site = Site(cfg, profile, "x")


def build(root: str) -> None:
    shutil.rmtree(root, ignore_errors=True)
    for p, f in site.static.items():
        if p.startswith(("/phpmyadmin", "/pma")):
            continue
        fp = root + p
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        open(fp, "wb").write(f.body)
        os.utime(fp, (f.mtime, f.mtime))
    for d in sorted(site.dirs, key=len, reverse=True):
        os.makedirs(root + d, exist_ok=True)
        for name, is_dir, size, mt in site.dirs[d]:
            if is_dir:
                os.makedirs(root + d + name, exist_ok=True)
                os.utime(root + d + name, (mt, mt))
    os.makedirs(root + "/wp-includes", exist_ok=True)


async def compare(ref_port: int) -> None:
    sensor = WebSensor(cfg, EventSink(FakePublisher()), site, None)
    server = WebServer(cfg, sensor)
    ports = await server.start()
    loop = asyncio.get_running_loop()
    reqs = [
        "/license.txt",
        "/readme.html",
        "/wp-content/themes/twentytwentyfour/style.css",
        "/wp-includes/images/w-logo-blue-white-bg.png",
        "/wp-content/uploads/",
        "/wp-content/uploads",
        "/wp-includes/js/jquery/jquery.min.js",
    ]
    for y in sorted(k for k in site.dirs if k.count("/") == 4):
        reqs.append(y)
    cases = {}
    for r in reqs:
        cases[r] = f"GET {r} HTTP/1.1\r\nHost: srv-web01\r\n\r\n".encode()
        cases[r + " gz"] = (
            f"GET {r} HTTP/1.1\r\nHost: srv-web01\r\nAccept-Encoding: gzip\r\n\r\n".encode()
        )
        cases[r + " HEAD"] = f"HEAD {r} HTTP/1.1\r\nHost: srv-web01\r\n\r\n".encode()
    cases["range"] = b"GET /license.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=5-20\r\n\r\n"
    cases["range-bad"] = b"GET /license.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=99999-\r\n\r\n"
    cases["range-suffix"] = b"GET /license.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=-10\r\n\r\n"
    cases["ims-old"] = (
        b"GET /license.txt HTTP/1.1\r\nHost: x\r\nIf-Modified-Since: Sat, 24 Oct 2026 19:43:35 GMT\r\n\r\n"
    )
    cases["post-static"] = b"POST /license.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\na"
    bad = 0
    for name, data in cases.items():
        a = normalise(
            await loop.run_in_executor(None, raw, ports["http"], data), REF_IP, profile.server_ip
        )
        b = normalise(
            await loop.run_in_executor(None, raw, ref_port, data), REF_IP, profile.server_ip
        )
        if a != b:
            bad += 1
            print("DIFF", name)
            print(" ours", a[:600])
            print(" ref ", b[:600])
    print(len(cases) - bad, "/", len(cases), "identical")
    await server.stop()


if sys.argv[1] == "build":
    build("/tmp/sp-tree")
else:
    asyncio.run(compare(18080))
