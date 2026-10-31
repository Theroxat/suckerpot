"""Client identity: a generic downloader User-Agent chosen from the URL. Never the project name."""

from __future__ import annotations

from urllib.parse import urlsplit

IOT_SUFFIXES = (
    "arm", "arm5", "arm6", "arm7", "mips", "mpsl", "m68k", "ppc", "sh4", "spc", "x86", "i686",
)  # fmt: skip
BUSYBOX_UA = "Wget"
WGET_UA = "Wget/1.21.4"
POWERSHELL_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WindowsPowerShell/5.1"


def user_agent_for(url: str) -> str:
    path = urlsplit(url).path.lower()
    name = path.rsplit("/", 1)[-1]
    if name.endswith((".ps1", ".exe")):
        return POWERSHELL_UA
    suffix = name.rsplit(".", 1)[-1] if "." in name else name
    stem_suffix = name.rsplit("_", 1)[-1] if "_" in name else ""
    if "/bins/" in path or suffix in IOT_SUFFIXES or stem_suffix in IOT_SUFFIXES:
        return BUSYBOX_UA
    return WGET_UA
