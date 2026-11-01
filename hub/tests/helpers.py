"""Test helpers: a signing node client and a controllable clock."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from suckerpot_netproto import pow, sign

START = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self, now: datetime = START) -> None:
        self.current = now

    def __call__(self) -> datetime:
        return self.current

    def advance(self, **kwargs: float) -> None:
        self.current += timedelta(**kwargs)


@dataclass
class Reply:
    status: int
    json: Any
    raw: bytes
    headers: httpx.Headers
    signature_ok: bool

    @property
    def has_signature(self) -> bool:
        return sign.H_HUB_SIGNATURE in self.headers

    @property
    def error(self) -> str | None:
        return self.json.get("error") if isinstance(self.json, dict) else None


@dataclass
class NodeClient:
    http: httpx.AsyncClient
    clock: FakeClock
    hub_key: str
    private: bytes = field(default_factory=sign.generate_private_key)
    node_id: str | None = None

    @property
    def public(self) -> bytes:
        return sign.public_key_of(self.private)

    @property
    def key(self) -> str:
        return sign.node_key(self.public)

    @property
    def fingerprint(self) -> str:
        return sign.fingerprint(self.public)

    def _reply(self, resp: httpx.Response, binding: sign.RequestBinding) -> Reply:
        ok = sign.verify_response(
            self.hub_key,
            resp.headers.get(sign.H_HUB_SIGNATURE),
            binding,
            resp.status_code,
            resp.content,
        )
        try:
            data = resp.json()
        except ValueError:
            data = None
        return Reply(resp.status_code, data, resp.content, resp.headers, ok)

    async def unsigned(self, method: str, path: str, obj: dict[str, Any] | None = None) -> Reply:
        nonce = sign.new_nonce()
        body = sign.pad_body(obj) if obj is not None else b""
        resp = await self.http.request(
            method,
            path,
            content=body,
            headers={sign.H_NONCE: nonce, "Content-Type": "application/json"},
        )
        binding = sign.RequestBinding.unsigned(method, path, nonce, body)
        return self._reply(resp, binding)

    async def call(
        self,
        method: str,
        path: str,
        obj: dict[str, Any] | None = None,
        *,
        raw: bytes | None = None,
        timestamp: int | None = None,
        nonce: str | None = None,
        sign_path: str | None = None,
        sign_body: bytes | None = None,
        drop: tuple[str, ...] = (),
        private: bytes | None = None,
        forge_with: bytes | None = None,
        pad: bool = True,
    ) -> Reply:
        body = (
            raw
            if raw is not None
            else (
                (sign.pad_body(obj) if pad else json.dumps(obj).encode())
                if obj is not None
                else b""
            )
        )
        ts = timestamp if timestamp is not None else int(self.clock().timestamp())
        n = nonce or sign.new_nonce()
        headers = sign.sign_request(
            private or self.private,
            method,
            sign_path or path,
            sign_body if sign_body is not None else body,
            timestamp=ts,
            nonce=n,
        ).as_dict()
        if forge_with is not None:  # right key header, signature made by someone else
            headers[sign.H_SIGNATURE] = sign.sign_request(
                forge_with, method, path, body, timestamp=ts, nonce=n
            ).signature
        for name in drop:
            headers.pop(name, None)
        headers["Content-Type"] = "application/json"
        resp = await self.http.request(method, path, content=body, headers=headers)
        binding = sign.RequestBinding.signed(
            method,
            path,
            headers.get(sign.H_KEY, ""),
            headers.get(sign.H_NONCE, ""),
            headers.get(sign.H_SIGNATURE, ""),
        )
        return self._reply(resp, binding)

    async def enrol(
        self,
        *,
        pseudonym: str | None = None,
        country: str | None = None,
        show_country: bool = False,
    ) -> Reply:
        ch = await self.unsigned(
            "POST", "/v1/enrol/challenge", {"protocol": "spn/1", "node_key": self.key}
        )
        assert ch.status == 200, ch.json
        challenge = sign.b64u_decode(ch.json["challenge"])
        nonce = pow.solve_pow(challenge, self.public, ch.json["difficulty"])
        assert nonce is not None
        body: dict[str, Any] = {
            "protocol": "spn/1",
            "challenge": ch.json["challenge"],
            "pow_nonce": sign.b64u_encode(nonce),
            "show_country": show_country,
        }
        if pseudonym is not None:
            body["pseudonym"] = pseudonym
        if country is not None:
            body["country"] = country
        reply = await self.call("POST", "/v1/enrol", body)
        if reply.status == 200:
            self.node_id = reply.json["node_id"]
        return reply


def batch(day: str, **parts: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"protocol": "spn/1", "batch_id": sign.new_nonce(), "day": day}
    out.update(parts)
    return out


def source(ip: str, **kw: Any) -> dict[str, Any]:
    return {
        "ip": ip,
        "services": ["ssh"],
        "activity": ["login"],
        "tags": [],
        "sessions": 1,
        "attempts": 1,
    } | kw
