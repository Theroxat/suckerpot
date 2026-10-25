"""Derive ``web_sensor/data/phpinfo.html`` from a real ``phpinfo()`` page.

Usage: ``python tools/make_phpinfo_template.py raw_phpinfo.html web_sensor/data/phpinfo.html``

The input is the output of ``<?php phpinfo();`` served by a stock Ubuntu 24.04 ``apache2`` +
``libapache2-mod-php8.3`` (a throwaway reference container, never part of the sensor). The
request- and host-specific parts are replaced by ``@@MARKERS@@`` that ``content/phpinfo.py``
fills in per request.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import sys

ROW = '<tr><td class="e">{k} </td><td class="v">{v} </td></tr>'


def between(text: str, start: str, end: str, repl: str, *, after: int = 0) -> str:
    a = text.index(start, after) + len(start)
    b = text.index(end, a)
    return text[:a] + repl + text[b:]


def main(src: str, dst: str) -> None:
    t = open(src, encoding="utf-8").read()
    # System row
    a = t.index('<tr><td class="e">System </td><td class="v">') + len(
        '<tr><td class="e">System </td><td class="v">'
    )
    b = t.index(" </td></tr>", a)
    t = t[:a] + "Linux @@HOSTNAME@@ @@KERNEL@@ @@KERNEL_BUILD@@ x86_64" + t[b:]
    # Hostname:Port
    a = t.index('<tr><td class="e">Hostname:Port </td><td class="v">') + len(
        '<tr><td class="e">Hostname:Port </td><td class="v">'
    )
    b = t.index(" </td></tr>", a)
    t = t[:a] + "@@SERVER_IP@@:@@PORT@@" + t[b:]
    # Apache Environment
    hdr = '<tr class="h"><th>Variable</th><th>Value</th></tr>\n'
    start = t.index("<h2>Apache Environment</h2>")
    t = between(t, hdr, "</table>", "@@APACHE_ENV@@\n", after=start)
    # HTTP request headers
    marker = '<tr class="h"><th colspan="2">HTTP Request Headers</th></tr>\n'
    t = between(
        t,
        marker,
        '<tr class="h"><th colspan="2">HTTP Response Headers</th></tr>',
        "@@REQ_HEADERS@@\n",
    )
    # Environment: HOSTNAME
    start = t.index("<h2>Environment</h2>")
    a = t.index('<tr><td class="e">HOSTNAME </td><td class="v">', start) + len(
        '<tr><td class="e">HOSTNAME </td><td class="v">'
    )
    b = t.index(" </td></tr>", a)
    t = t[:a] + "@@HOSTNAME@@" + t[b:]
    # PHP variables
    start = t.index("<h2>PHP Variables</h2>")
    t = between(t, hdr, "</table>", "@@PHPVARS@@\n", after=start)
    # Opcache start time
    a = t.index('<tr><td class="e">Start time </td><td class="v">') + len(
        '<tr><td class="e">Start time </td><td class="v">'
    )
    b = t.index(" </td></tr>", a)
    t = t[:a] + "@@START@@" + t[b:]
    # expose_php (the sensor sends X-Powered-By)
    t = t.replace(
        '<tr><td class="e">expose_php</td><td class="v">Off</td><td class="v">Off</td></tr>',
        '<tr><td class="e">expose_php</td><td class="v">@@EXPOSE@@</td><td class="v">@@EXPOSE@@</td></tr>',
    )
    t = t.replace("8.3.6", "@@PHPV@@").replace("v4.3.6", "v@@ZENDV@@")
    leaks = [platform.release(), socket.gethostname(), "127.0.0.1", "docker"]
    for leak in leaks:
        if leak and leak in t:
            raise SystemExit("leftover host-specific string in the template")
    for quad in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", t):
        try:
            private = ipaddress.ip_address(quad).is_private
        except ValueError:
            continue
        if private:
            raise SystemExit("leftover private address in the template")
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(t)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
