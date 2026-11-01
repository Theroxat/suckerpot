"""Hub settings, read from HUB_* environment variables.

Nothing here is a secret except the database passwords inside the URLs; the signing key is read
from the file named by ``HUB_SIGNING_KEY_FILE`` and never from the environment.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from suckerpot_netproto import sign


class ConfigError(RuntimeError):
    """A setting is missing or invalid. The message never contains a value."""


def _int(env: Mapping[str, str], name: str, default: int, lo: int = 0, hi: int = 10**9) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}")
    return value


def _float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc


def _bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str = ""
    worker_database_url: str = ""
    signing_key_file: str = ""
    # Test overlay only: accept documentation address ranges.
    allow_documentation: bool = False
    # Read the client address from the proxy header of the reverse proxy in front of the hub.
    trust_proxy: bool = False

    # Proof of work and enrolment caps.
    pow_difficulty: int = 27
    enrol_soft_cap: int = 50
    enrol_hard_cap: int = 200
    enrol_step: int = 10  # one more proof-of-work bit per this many enrolments above the soft cap
    challenges_per_prefix: int = 20
    challenge_ttl_s: int = 600
    max_pending_challenges: int = 20000

    # Rate limits.
    unsigned_per_min: int = 10
    unsigned_per_day: int = 100
    auth_failures_per_min: int = 30
    signed_per_hour: int = 60
    reveals_per_day: int = 2000
    new_values_per_day: int = 20000

    # Consensus (used by the worker; the API publishes them in /v1/info).
    min_nodes: int = 5
    min_weight: float = 3.0
    node_min_age_days: int = 14
    node_min_active_days: int = 7
    min_reputation: float = 0.3
    window_days: int = 7
    cohort_max_share: float = 0.5
    # Auto mode (reports sent without review) needs this many independent enrolment cohorts.
    auto_min_cohorts: int = 5

    # Retention.
    obs_retention_days: int = 14
    inactive_node_days: int = 30
    contributor_retention_days: int = 30
    vote_retention_days: int = 30

    # Worker.
    worker_interval_s: int = 3600

    # Reports (worker).
    report_mode: str = "review"
    report_hold_hours: int = 24
    report_daily_cap: int = 100
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = field(default="", repr=False)
    smtp_from: str = ""
    smtp_starttls: bool = True
    report_reply_to: str = ""
    report_template_file: str = ""
    # External corroboration (optional keys; empty disables the source).
    abuseipdb_key: str = field(default="", repr=False)
    greynoise_key: str = field(default="", repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e: Mapping[str, str] = os.environ if env is None else env
        mode = e.get("HUB_REPORT_MODE", "review") or "review"
        if mode not in {"review", "auto", "off"}:
            raise ConfigError("HUB_REPORT_MODE must be review, auto or off")
        return cls(
            database_url=e.get("HUB_DATABASE_URL", ""),
            worker_database_url=e.get("HUB_WORKER_DATABASE_URL", ""),
            signing_key_file=e.get("HUB_SIGNING_KEY_FILE", ""),
            allow_documentation=_bool(e, "HUB_ALLOW_DOCUMENTATION"),
            trust_proxy=_bool(e, "HUB_TRUST_PROXY"),
            pow_difficulty=_int(e, "HUB_POW_DIFFICULTY", 27, 0, 40),
            enrol_soft_cap=_int(e, "HUB_ENROL_SOFT_CAP", 50, 0),
            enrol_hard_cap=_int(e, "HUB_ENROL_HARD_CAP", 200, 0),
            enrol_step=_int(e, "HUB_ENROL_STEP", 10, 1),
            challenges_per_prefix=_int(e, "HUB_CHALLENGES_PER_PREFIX", 20, 1),
            unsigned_per_min=_int(e, "HUB_RATE_UNSIGNED_PER_MIN", 10, 1),
            unsigned_per_day=_int(e, "HUB_RATE_UNSIGNED_PER_DAY", 100, 1),
            signed_per_hour=_int(e, "HUB_RATE_SIGNED_PER_HOUR", 60, 1),
            reveals_per_day=_int(e, "HUB_REVEALS_PER_DAY", 2000, 1),
            new_values_per_day=_int(e, "HUB_NEW_VALUES_PER_DAY", 20000, 1),
            min_nodes=_int(e, "HUB_MIN_NODES", 5, 1),
            min_weight=_float(e, "HUB_MIN_WEIGHT", 3.0),
            node_min_age_days=_int(e, "HUB_NODE_MIN_AGE_DAYS", 14, 0),
            node_min_active_days=_int(e, "HUB_NODE_MIN_ACTIVE_DAYS", 7, 0, 14),
            min_reputation=_float(e, "HUB_MIN_REPUTATION", 0.3),
            window_days=_int(e, "HUB_WINDOW_DAYS", 7, 1, 14),
            cohort_max_share=_float(e, "HUB_COHORT_MAX_SHARE", 0.5),
            auto_min_cohorts=_int(e, "HUB_AUTO_MIN_COHORTS", 5, 1),
            obs_retention_days=_int(e, "HUB_OBS_RETENTION_DAYS", 14, 1, 60),
            worker_interval_s=_int(e, "HUB_WORKER_INTERVAL_S", 3600, 5),
            report_mode=mode,
            report_hold_hours=_int(e, "HUB_REPORT_HOLD_HOURS", 24, 0),
            report_daily_cap=_int(e, "HUB_REPORT_DAILY_CAP", 100, 0),
            smtp_host=e.get("HUB_SMTP_HOST", ""),
            smtp_port=_int(e, "HUB_SMTP_PORT", 587, 1, 65535),
            smtp_user=e.get("HUB_SMTP_USER", ""),
            smtp_password=e.get("HUB_SMTP_PASSWORD", ""),
            smtp_from=e.get("HUB_SMTP_FROM", ""),
            smtp_starttls=_bool(e, "HUB_SMTP_STARTTLS", True),
            report_reply_to=e.get("HUB_REPORT_REPLY_TO", ""),
            report_template_file=e.get("HUB_REPORT_TEMPLATE_FILE", ""),
            abuseipdb_key=e.get("HUB_ABUSEIPDB_KEY", ""),
            greynoise_key=e.get("HUB_GREYNOISE_KEY", ""),
        )


def load_signing_key(path: str) -> bytes:
    """The hub's Ed25519 private seed (base64url, 32 bytes) from a secret file."""
    if not path:
        raise ConfigError("HUB_SIGNING_KEY_FILE is not set")
    try:
        text = Path(path).read_text(encoding="ascii").strip()
        seed = sign.b64u_decode(text)
        if len(seed) != 32:
            raise ValueError
        sign.public_key_of(seed)
    except (OSError, ValueError) as exc:
        raise ConfigError("HUB_SIGNING_KEY_FILE does not hold a valid key") from exc
    return seed
