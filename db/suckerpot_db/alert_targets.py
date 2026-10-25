"""Where alerts may go: validation of webhook URLs and e-mail addresses, and their encryption.

Shared by the API (which validates what the admin types) and ingest (which validates again right
before every send and is the only service that connects to the internet).

* A webhook URL must be ``https`` on port 443 with a host that belongs to the official Discord or
  Microsoft Teams (Workflows and Office 365 connector) domains and a path of the shape those
  services use. No user info, no fragment, no IP literal, no percent-encoding, no ``..``.
* A target is stored as ``nonce || AES-GCM ciphertext`` (``SecretBox``) with the associated data
  ``alert_channel:<id>``, so a row cannot be moved to another channel.

Nothing here puts a target into an exception message.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from suckerpot_db.secretbox import NONCE_BYTES, Credential, SecretBox, SecretError

ChannelKind = Literal["discord", "teams", "email"]
CHANNEL_KINDS: tuple[str, ...] = ("discord", "teams", "email")

MAX_URL_LEN = 512
MAX_EMAIL_LEN = 254

DISCORD_HOSTS = frozenset(
    {"discord.com", "ptb.discord.com", "canary.discord.com", "discordapp.com"}
)
DISCORD_PATH = re.compile(r"^/api(?:/v[0-9]{1,2})?/webhooks/[0-9]{15,25}/[A-Za-z0-9_-]{20,128}$")
# Microsoft: the Workflows (Power Automate) webhooks and the Office 365 connector webhooks.
TEAMS_HOST_SUFFIXES = (
    ".webhook.office.com",
    ".logic.azure.com",
    ".api.powerplatform.com",
)
TEAMS_HOSTS = frozenset({"outlook.office.com", "outlook.office365.com"})
TEAMS_PATH_PREFIXES = (
    "/webhookb2/",
    "/webhook/",
    "/IncomingWebhook/",
    "/workflows/",
    "/powerautomate/",
)
_PATH_CHARS = re.compile(r"^/[A-Za-z0-9._~@:/+=,-]*$")
_QUERY_CHARS = re.compile(r"^(?:[A-Za-z0-9._~@:/+=,&-]|%[0-9A-Fa-f]{2}){0,300}$")
_HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$")


class TargetError(ValueError):
    """The target is not acceptable. The message is safe to show to the admin."""


@dataclass(frozen=True, slots=True)
class WebhookTarget:
    url: str
    host: str


def validate_webhook(kind: str, url: str) -> WebhookTarget:
    """Check a Discord or Teams webhook URL. Returns it with its host, or raises TargetError."""
    if kind not in ("discord", "teams"):
        raise TargetError("Unknown channel kind.")
    if not url.isascii() or not url.isprintable() or " " in url or len(url) > MAX_URL_LEN:
        raise TargetError("The webhook URL is not valid.")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise TargetError("The webhook URL is not valid.") from None
    if parts.scheme != "https":
        raise TargetError("The webhook URL must use https.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise TargetError("The webhook URL must not contain credentials.")
    if parts.fragment or port not in (None, 443):
        raise TargetError("The webhook URL must use the standard https port and no fragment.")
    host = (parts.hostname or "").lower()
    if not _HOST_RE.match(host) or _is_ip_literal(host):
        raise TargetError("The webhook host is not valid.")
    path = parts.path
    if ".." in path or "//" in path or not _PATH_CHARS.match(path):
        raise TargetError("The webhook URL path is not valid.")
    if kind == "discord":
        if host not in DISCORD_HOSTS or not DISCORD_PATH.match(path) or parts.query:
            raise TargetError("This is not a Discord webhook URL (discord.com/api/webhooks/...).")
    else:
        host_ok = host in TEAMS_HOSTS or host.endswith(TEAMS_HOST_SUFFIXES)
        if not host_ok or not path.startswith(TEAMS_PATH_PREFIXES) or len(path) < 24:
            raise TargetError("This is not a Microsoft Teams webhook URL.")
        if not _QUERY_CHARS.match(parts.query):
            raise TargetError("The webhook URL query is not valid.")
    return WebhookTarget(url=url, host=host)


def validate_email(address: str) -> str:
    """One plain mailbox address (no display name, no list)."""
    value = address.strip()
    if len(value) > MAX_EMAIL_LEN or not _EMAIL_RE.match(value):
        raise TargetError("The e-mail address is not valid.")
    return value


def validate_target(kind: str, target: str) -> str:
    if kind == "email":
        return validate_email(target)
    return validate_webhook(kind, target).url


def target_hint(kind: str, target: str) -> str:
    """A short, non-secret reminder of where a channel goes (at most 32 characters)."""
    if kind == "email":
        local, _, domain = target.partition("@")
        return f"{local[:1]}***@{domain}"[:32]
    return (urlsplit(target).hostname or "")[:32]


def is_public_ip(value: str) -> bool:
    """True for a globally routable unicast address (IPv4-mapped IPv6 is unwrapped)."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _aad(channel_id: int) -> str:
    return f"alert_channel:{channel_id}"


def encrypt_target(box: SecretBox, channel_id: int, target: str) -> bytes:
    ciphertext, nonce = box.encrypt(_aad(channel_id), Credential(key=target))
    return nonce + ciphertext


def decrypt_target(box: SecretBox, channel_id: int, blob: bytes) -> str:
    if len(blob) <= NONCE_BYTES:
        raise SecretError("cannot decrypt the stored key")
    return box.decrypt(_aad(channel_id), blob[NONCE_BYTES:], blob[:NONCE_BYTES]).key
