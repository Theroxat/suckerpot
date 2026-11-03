"""Protocol error codes (spec section 5.3) and the exception that carries them."""

from __future__ import annotations

# code -> default HTTP status
ERROR_STATUS: dict[str, int] = {
    "too_large": 413,
    "invalid_payload": 400,
    "unsupported_protocol": 400,
    "stale_timestamp": 401,
    "replayed_nonce": 401,
    "bad_signature": 401,
    "unknown_node": 401,
    "pow_invalid": 400,
    "challenge_expired": 400,
    "pseudonym_invalid": 400,
    "pseudonym_taken": 409,
    "not_verifier": 403,
    "enrolment_closed": 503,
    "rate_limited": 429,
    "day_not_closed": 400,
    "day_too_old": 400,
    "server_error": 500,
}

# Raised on the node only, never sent by the hub.
NODE_SIDE_CODES = frozenset({"hub_signature"})


class ProtoError(Exception):
    """A protocol failure. ``code`` is one of ``ERROR_STATUS`` (or a node-side code)."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail

    @property
    def status(self) -> int:
        return ERROR_STATUS.get(self.code, 500)
