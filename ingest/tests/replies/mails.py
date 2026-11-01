"""Synthetic hostile and friendly mail for the reply tests. Everything is made up: documentation
domains (``example.org``, ``example.net``) and sample tokens only."""

from __future__ import annotations

import base64
import quopri
from typing import Any

TOKEN = "3f9a1c7b2e4d"  # gitleaks:allow (a sample reply token)
OUR_ID = "<Zm9vYmFyYmF6cXV4@mail.example.org>"


def mail(
    *,
    from_: str = "Abuse Desk <abuse@example.net>",
    subject: str = "Re: Abuse report for 198.51.100.23",
    body: str = "Hello,\r\n\r\nWe looked into it.\r\n",
    extra: dict[str, str] | None = None,
    message_id: str | None = "<reply-1@example.net>",
    in_reply_to: str | None = OUR_ID,
    ctype: str = "text/plain; charset=utf-8",
) -> bytes:
    headers = {
        "From": from_,
        "To": "reports@example.org",
        "Subject": subject,
        "Date": "Sat, 31 Oct 2026 10:00:00 +0000",
        "MIME-Version": "1.0",
        "Content-Type": ctype,
    }
    if message_id:
        headers["Message-ID"] = message_id
    if in_reply_to:
        headers["In-Reply-To"] = in_reply_to
        headers["References"] = in_reply_to
    headers.update(extra or {})
    head = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    return (head + "\r\n" + body).encode("utf-8")


def multipart(parts: list[tuple[str, str, bytes]], *, subtype: str = "mixed", **kw: Any) -> bytes:
    """``parts`` are (content type, extra headers, payload)."""
    boundary = "=_b0undary_1"
    body = b""
    for ctype, headers, payload in parts:
        body += (
            f"--{boundary}\r\nContent-Type: {ctype}\r\n{headers}\r\n".encode() + payload + b"\r\n"
        )
    body += f"--{boundary}--\r\n".encode()
    raw = mail(ctype=f'multipart/{subtype}; boundary="{boundary}"', body="", **kw)
    return raw[: raw.index(b"\r\n\r\n") + 4] + body


def with_pdf(text: str = "Thank you.\r\n") -> bytes:
    pdf = base64.b64encode(b"%PDF-1.4 not a real pdf " * 50)
    return multipart(
        [
            ("text/plain; charset=utf-8", "", text.encode()),
            (
                'application/pdf; name="invoice.pdf"',
                'Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="invoice.pdf"\r\n',
                pdf,
            ),
        ]
    )


def html_only(html: str) -> bytes:
    return mail(ctype="text/html; charset=utf-8", body=html)


def quoted_printable(text: str) -> bytes:
    encoded = quopri.encodestring(text.encode("utf-8")).decode("ascii").replace("\n", "\r\n")
    return mail(
        ctype="text/plain; charset=utf-8",
        body=encoded,
        extra={"Content-Transfer-Encoding": "quoted-printable"},
    )


def dsn(*, action: str = "failed", status: str = "5.1.1", original_id: str = OUR_ID) -> bytes:
    returned = (
        f"Message-ID: {original_id}\r\nSubject: Abuse report for 198.51.100.23 (ref {TOKEN})\r\n"
        "To: abuse@example.net\r\n"
    )
    status_block = (
        "Reporting-MTA: dns; mx.example.org\r\n\r\n"
        f"Final-Recipient: rfc822; abuse@example.net\r\nAction: {action}\r\nStatus: {status}\r\n"
    )
    return multipart(
        [
            ("text/plain; charset=utf-8", "", b"Your message could not be delivered.\r\n"),
            ("message/delivery-status", "", status_block.encode()),
            ("text/rfc822-headers", "", returned.encode()),
        ],
        subtype="report; report-type=delivery-status",
        from_="Mail Delivery System <MAILER-DAEMON@mx.example.org>",
        subject="Undelivered Mail Returned to Sender",
        in_reply_to=original_id,
    )


def many_headers(count: int = 300) -> bytes:
    extra = {f"X-Filler-{i}": "x" for i in range(count)}
    return mail(extra=extra, subject="Late subject")


def many_parts(count: int = 60) -> bytes:
    return multipart(
        [("text/plain; charset=utf-8", "", f"part {i}".encode()) for i in range(count)]
    )


def nested(depth: int = 10) -> bytes:
    body = "deep text\r\n"
    ctype = "text/plain; charset=utf-8"
    inner = f"Content-Type: {ctype}\r\n\r\n{body}"
    for level in range(depth):
        boundary = f"=_nest_{level}"
        inner = (
            f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n\r\n'
            f"--{boundary}\r\n{inner}\r\n--{boundary}--\r\n"
        )
    return ("From: a@example.net\r\nSubject: nested\r\nMIME-Version: 1.0\r\n" + inner).encode()
