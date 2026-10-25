"""The ``phpinfo()`` bait page.

The template (``data/phpinfo.html``) comes from a real PHP 8.3.6 build on Ubuntu 24.04 with the
``apache2handler`` SAPI (see ``tools/make_phpinfo_template.py``); only the host- and
request-specific parts are filled in here. ``session.upload_progress.enabled`` is On, as in a
stock build, which is exactly what PHP2Shell abuses.
"""

from __future__ import annotations

import html
from pathlib import Path

from web_sensor.httpio import Request, to_text

_TEMPLATE = (Path(__file__).resolve().parent.parent / "data" / "phpinfo.html").read_text(
    encoding="utf-8"
)
_MAX_VARS = 32
_MAX_VALUE = 256  # characters of one reflected value
_MAX_REFLECTED = 64 * 1024  # characters reflected in total, over the whole page
_HDR_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")


class _Reflect:
    """Caps request data reflected into the page (it appears several times), before escaping."""

    def __init__(self) -> None:
        self.left = _MAX_REFLECTED

    def e(self, value: str) -> str:
        """Escape ``value``; the budget counts escaped characters (what is actually sent)."""
        value = to_text(value[:_MAX_VALUE])
        out = html.escape(value, quote=True)
        while len(out) > max(self.left, 0) and value:
            value = value[: len(value) // 2]
            out = html.escape(value, quote=True)
        self.left -= len(out)
        return out

    def row_env(self, key: str, value: str) -> str:
        shown = "<i>no value</i>" if value == "" else self.e(value)
        return f'<tr><td class="e">{key} </td><td class="v">{shown} </td></tr>\n'

    def row_var(self, key: str, value: str) -> str:
        shown = "<i>no value</i>" if value == "" else self.e(value)
        return f'<tr><td class="e">{key}</td><td class="v">{shown}</td></tr>\n'


def _pairs(raw: str, sep: str) -> list[tuple[str, str]]:
    from urllib.parse import unquote_plus

    out: list[tuple[str, str]] = []
    for item in raw.split(sep)[:_MAX_VARS]:
        if not item.strip():
            continue
        k, _, v = item.partition("=")
        out.append(
            (unquote_plus(k.strip(), errors="replace"), unquote_plus(v.strip(), errors="replace"))
        )
    return out


def render(
    req: Request,
    *,
    php_version: str,
    hostname: str,
    kernel: str,
    kernel_build: str,
    server_ip: str,
    server_token: str,
    public_port: int,
    remote_ip: str,
    remote_port: int,
    scheme: str,
    started: str,
    expose: bool,
    now: float,
    script: str,
) -> str:
    rf = _Reflect()
    host = (req.host or server_ip)[:255]
    port = req.host_port or public_port
    uri = (req.path + ("?" + req.query if req.query else ""))[:_MAX_VALUE]
    signature = f"<address>{server_token} Server at {host} Port {port}</address>\n"
    env: list[tuple[str, str]] = []
    for k, v in req.headers[:100]:
        if k and len(k) <= 64 and all(c in _HDR_CHARS for c in k):
            env.append(("HTTP_" + k.upper().replace("-", "_"), v))
    env += [
        ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        ("SERVER_SIGNATURE", signature),
        ("SERVER_SOFTWARE", server_token),
        ("SERVER_NAME", host),
        ("SERVER_ADDR", server_ip),
        ("SERVER_PORT", str(port)),
        ("REMOTE_ADDR", remote_ip),
        ("DOCUMENT_ROOT", "/var/www/html"),
        ("REQUEST_SCHEME", scheme),
        ("CONTEXT_PREFIX", ""),
        ("CONTEXT_DOCUMENT_ROOT", "/var/www/html"),
        ("SERVER_ADMIN", "webmaster@localhost"),
        ("SCRIPT_FILENAME", "/var/www/html" + script),
        ("REMOTE_PORT", str(remote_port)),
        ("GATEWAY_INTERFACE", "CGI/1.1"),
        ("SERVER_PROTOCOL", req.version),
        ("REQUEST_METHOD", req.method),
        ("QUERY_STRING", req.query),
        ("REQUEST_URI", uri),
        ("SCRIPT_NAME", script),
    ]
    apache_env = "".join(rf.row_env(k, v) for k, v in env[:200])
    headers = f'<tr><td class="e">HTTP Request </td><td class="v">{rf.e(req.method)} {rf.e(uri)} {rf.e(req.version)} </td></tr>\n'
    headers += "".join(
        f'<tr><td class="e">{rf.e(k)} </td><td class="v">{rf.e(v)} </td></tr>\n'
        for k, v in req.headers[:100]
    )

    rows: list[str] = []
    get = _pairs(req.query, "&")
    cookies = _pairs(req.header("cookie") or "", ";")
    post: list[tuple[str, str]] = []
    ctype = (req.header("content-type") or "").lower()
    if req.method == "POST" and "x-www-form-urlencoded" in ctype:
        post = _pairs(req.body[:4096].decode("latin-1"), "&")
    for label, items in (
        ("_REQUEST", get + post + cookies),
        ("_GET", get),
        ("_POST", post),
        ("_COOKIE", cookies),
    ):
        rows += [rf.row_var(f"${label}['{rf.e(k)}']", v) for k, v in items[:_MAX_VARS]]
    for k, v in env:
        rows.append(rf.row_var(f"$_SERVER['{k}']", v))
    rows.append(rf.row_var("$_SERVER['PHP_SELF']", script))
    rows.append(rf.row_var("$_SERVER['REQUEST_TIME_FLOAT']", f"{now:.4f}"))
    rows.append(rf.row_var("$_SERVER['REQUEST_TIME']", str(int(now))))

    zend = "4.3." + php_version.rsplit(".", 1)[1]
    page = _TEMPLATE
    # Fixed values first, then the blocks that contain request data (so the request cannot
    # smuggle a marker into a later substitution).
    for marker, value in (
        ("@@HOSTNAME@@", hostname),
        ("@@KERNEL@@", kernel),
        ("@@KERNEL_BUILD@@", kernel_build),
        ("@@SERVER_IP@@", server_ip),
        ("@@PORT@@", str(public_port)),
        ("@@START@@", started),
        ("@@EXPOSE@@", "On" if expose else "Off"),
        ("@@ZENDV@@", zend),
        ("@@PHPV@@", php_version),
        ("@@APACHE_ENV@@", apache_env),
        ("@@REQ_HEADERS@@", headers),
        ("@@PHPVARS@@", "".join(rows)),
    ):
        page = page.replace(marker, value)
    return page
