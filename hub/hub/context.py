"""Shared application state, created once in ``create_app``."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.requests import Request
from suckerpot_netproto import sign

from .config import Settings
from .never import NeverCache
from .ratelimit import AddressLimiter, Counter

Clock = Callable[[], datetime]


@dataclass
class AppContext:
    settings: Settings
    sessionmaker: async_sessionmaker[AsyncSession]
    hub_private: bytes
    clock: Clock
    address_limiter: AddressLimiter
    node_limiter: Counter
    reveal_limiter: Counter
    never: NeverCache = field(default_factory=NeverCache)

    @property
    def hub_key(self) -> str:
        return sign.node_key(sign.public_key_of(self.hub_private))

    def now(self) -> datetime:
        return self.clock()

    def today(self) -> date:
        return self.clock().date()


def get_ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx
