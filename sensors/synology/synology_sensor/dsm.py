"""Static DSM content: the Web API table, the login page and small asset bodies.

Everything here is plain data built once at import. Nothing depends on attacker input, so the
answers cannot be made larger than they are.
"""

from __future__ import annotations

import hashlib
import json
import random
import struct

# name -> (path, minVersion, maxVersion). Values follow what DSM 7.2 reports in SYNO.API.Info.
_E = "entry.cgi"
_RAW: list[tuple[str, str, int, int]] = [
    ("SYNO.API.Info", _E, 1, 1),
    ("SYNO.API.Auth", _E, 1, 7),
    ("SYNO.API.Encryption", _E, 1, 1),
    ("SYNO.Entry.Request", _E, 1, 1),
    ("SYNO.DSM.Info", _E, 1, 2),
    ("SYNO.DSM.Target", _E, 1, 1),
    ("SYNO.Core.Desktop.Initdata", _E, 1, 1),
    ("SYNO.Core.Desktop.SessionData", _E, 1, 1),
    ("SYNO.Core.Desktop.Defs", _E, 1, 1),
    ("SYNO.Core.Desktop.Timeout", _E, 1, 1),
    ("SYNO.Core.System", _E, 1, 3),
    ("SYNO.Core.System.Utilization", _E, 1, 1),
    ("SYNO.Core.System.Status", _E, 1, 1),
    ("SYNO.Core.Upgrade", _E, 1, 1),
    ("SYNO.Core.Upgrade.Server", _E, 1, 2),
    ("SYNO.Core.Storage.Volume", _E, 1, 1),
    ("SYNO.Core.Storage.Disk", _E, 1, 1),
    ("SYNO.Core.Share", _E, 1, 1),
    ("SYNO.Core.User", _E, 1, 1),
    ("SYNO.Core.Group", _E, 1, 1),
    ("SYNO.Core.Network", _E, 1, 2),
    ("SYNO.Core.Terminal", _E, 1, 3),
    ("SYNO.Core.Security.DSM", _E, 1, 5),
    ("SYNO.Core.TaskScheduler", _E, 1, 4),
    ("SYNO.Core.Package", _E, 1, 2),
    ("SYNO.Core.Package.Installation", _E, 1, 1),
    ("SYNO.Core.Package.Uninstallation", _E, 1, 1),
    ("SYNO.Core.Package.Server", _E, 1, 2),
    ("SYNO.Core.Package.Control", _E, 1, 1),
    ("SYNO.Core.Package.Setting", _E, 1, 1),
    ("SYNO.Core.Package.Log", _E, 1, 1),
    ("SYNO.Core.Notification.Mail", _E, 1, 1),
    ("SYNO.Core.OTP", _E, 1, 2),
    ("SYNO.Core.Service", _E, 1, 3),
    ("SYNO.FileStation.Info", _E, 1, 2),
    ("SYNO.FileStation.List", _E, 1, 2),
    ("SYNO.FileStation.Search", _E, 1, 2),
    ("SYNO.FileStation.VirtualFolder", _E, 1, 2),
    ("SYNO.FileStation.Favorite", _E, 1, 2),
    ("SYNO.FileStation.Thumb", _E, 1, 2),
    ("SYNO.FileStation.DirSize", _E, 1, 2),
    ("SYNO.FileStation.MD5", _E, 1, 2),
    ("SYNO.FileStation.CheckPermission", _E, 1, 3),
    ("SYNO.FileStation.Upload", _E, 1, 3),
    ("SYNO.FileStation.Download", _E, 1, 2),
    ("SYNO.FileStation.Sharing", _E, 1, 3),
    ("SYNO.FileStation.CreateFolder", _E, 1, 2),
    ("SYNO.FileStation.Rename", _E, 1, 2),
    ("SYNO.FileStation.CopyMove", _E, 1, 3),
    ("SYNO.FileStation.Delete", _E, 1, 2),
    ("SYNO.FileStation.Extract", _E, 1, 2),
    ("SYNO.FileStation.Compress", _E, 1, 3),
    ("SYNO.FileStation.BackgroundTask", _E, 1, 3),
    ("SYNO.DownloadStation.Info", "DownloadStation/info.cgi", 1, 2),
    ("SYNO.DownloadStation.Task", "DownloadStation/task.cgi", 1, 3),
    ("SYNO.DownloadStation.Schedule", "DownloadStation/schedule.cgi", 1, 1),
    ("SYNO.DownloadStation.Statistic", "DownloadStation/statistic.cgi", 1, 1),
    ("SYNO.DownloadStation2.Task", _E, 1, 2),
    ("SYNO.AudioStation.Info", "AudioStation/info.cgi", 1, 4),
    ("SYNO.SurveillanceStation.Info", "SurveillanceStation/info.cgi", 1, 8),
    ("SYNO.Backup.Task", _E, 1, 1),
    ("SYNO.Docker.Container", _E, 1, 1),
]
API_TABLE: dict[str, tuple[str, int, int]] = {n: (p, lo, hi) for n, p, lo, hi in _RAW}
MAX_QUERY_NAMES = 40


def _entry(name: str) -> dict[str, object]:
    path, lo, hi = API_TABLE[name]
    out: dict[str, object] = {"maxVersion": hi, "minVersion": lo, "path": path}
    if name == "SYNO.Entry.Request":
        out["requestFormat"] = "JSON"
    return out


def _dump(doc: object) -> bytes:
    return json.dumps(doc, separators=(",", ":")).encode()


INFO_ALL: bytes = _dump({"data": {n: _entry(n) for n in API_TABLE}, "success": True})


def info_subset(names: str) -> bytes:
    """``SYNO.API.Info`` for a comma separated list (at most 40 names are looked at)."""
    parts = names.split(",", MAX_QUERY_NAMES)[:MAX_QUERY_NAMES]
    wanted = [p.strip() for p in parts if p.strip() in API_TABLE]
    return _dump({"data": {n: _entry(n) for n in dict.fromkeys(wanted)}, "success": True})


def error_json(code: int, extra: dict[str, object] | None = None) -> bytes:
    err: dict[str, object] = {"code": code}
    if extra:
        err["errors"] = extra
    return _dump({"error": err, "success": False})


OK_EMPTY: bytes = _dump({"success": True})

# Codes of SYNO.API.Auth login, as documented for DSM.
LOGIN_CODES = {
    400: "No such account or incorrect password",
    401: "Account disabled",
    402: "Permission denied",
    403: "2-step verification code required",
    404: "Failed to authenticate 2-step verification code",
    407: "IP blocked (too many failed login attempts)",
}


def login_page(hostname: str, version: str, language: str = "enu") -> bytes:
    """A DSM 7 style login shell: title, asset paths and the ``SYNO.SDS.Session`` globals."""
    build, _, update = version.partition("-")[2].partition("-")
    major = version.split("-", 1)[0]
    full = f"{major}-{build}" + (f" Update {update}" if update else "")
    session = {
        "hostname": hostname,
        "isLogined": False,
        "version": build,
        "fullversion": full,
        "lang": language,
        "_S": {"lang": language, "SynoToken": ""},
    }
    session_js = json.dumps(session, separators=(",", ":")).replace("<", "\\u003c")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta name="description" content="{hostname}">
<title>{hostname}</title>
<link rel="shortcut icon" href="webman/favicon.ico?v={build}" type="image/x-icon">
<link rel="stylesheet" type="text/css" href="/webman/resources/css/login.css?v={build}">
<link rel="stylesheet" type="text/css" href="/webman/resources/css/synology.css?v={build}">
<script type="text/javascript">
window.SYNO = window.SYNO || {{}};
SYNO.SDS = SYNO.SDS || {{}};
SYNO.SDS.Session = {session_js};
window._S = SYNO.SDS.Session;
</script>
<script type="text/javascript" src="/synoSDSjslib/sds.js?v={build}"></script>
<script type="text/javascript" src="/webman/resources/js/login.js?v={build}"></script>
</head>
<body class="syno-login">
<div id="sds-loading"><div class="syno-loading-logo"></div></div>
<noscript>
<div class="syno-noscript">Please enable JavaScript to use {hostname}.</div>
</noscript>
<div id="sds-login-root" data-version="{build}"></div>
</body>
</html>
"""
    return html.encode()


def _favicon() -> bytes:
    """A valid 1x1 32-bit ICO."""
    bmp = struct.pack("<IiiHHIIiiII", 40, 1, 2, 1, 32, 0, 4, 0, 0, 0, 0)
    bmp += b"\x2e\x2e\xd8\xff" + b"\x00\x00\x00\x00"
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, len(bmp), 22)
    return header + entry + bmp


FAVICON: bytes = _favicon()
PNG_1X1: bytes = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c63f8cfc0f01f0005000201a5f645400000000049454e44ae426082"
)


def nginx_page(status: int, reason: str, detail: str = "") -> bytes:
    """nginx's built-in error page; ``detail`` is the extra line of the plain-HTTP-on-TLS 400."""
    title = f"{status} {detail}" if detail else f"{status} {reason}"
    extra = f"<center>{detail}</center>\r\n" if detail else ""
    return (
        f"<html>\r\n<head><title>{title}</title></head>\r\n<body>\r\n"
        f"<center><h1>{status} {reason}</h1></center>\r\n{extra}<hr><center>nginx</center>\r\n"
        "</body>\r\n</html>\r\n"
    ).encode()


def _filler(seed: int, kind: str, size: int) -> bytes:
    """Deterministic JS-like or CSS-like text, so asset sizes vary without storing real files."""
    rng = random.Random(seed)  # noqa: S311 - content only
    out: list[str] = [f"/* Synology DSM {kind} */\n"]
    total = len(out[0])
    while total < size:
        n = f"{rng.randrange(36**5):x}"
        if kind == "css":
            line = f".syno-{n}{{margin:{rng.randrange(9)}px;padding:{rng.randrange(9)}px}}\n"
        else:
            line = f"SYNO.SDS._{n}=function(a,b){{return a+b*{rng.randrange(1000)};}};\n"
        out.append(line)
        total += len(line)
    return "".join(out).encode()[:size].rstrip(b"\n") + b"\n"


JS_POOL: bytes = _filler(1, "js", 48 * 1024)
CSS_POOL: bytes = _filler(2, "css", 24 * 1024)


def asset_body(path: str, kind: str) -> bytes:
    """A stable, plausible body for ``path``: a prefix of a fixed pool, sized from the path."""
    pool, lo = (CSS_POOL, 600) if kind == "css" else (JS_POOL, 1500)
    h = int.from_bytes(hashlib.sha256(path.encode("utf-8", "replace")).digest()[:4], "big")
    size = lo + h % (len(pool) - lo)
    return pool[:size].rsplit(b"\n", 1)[0] + b"\n"
