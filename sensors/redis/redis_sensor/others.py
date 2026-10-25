"""Commands outside the core set, answered with type-correct replies.

A bot that probes with ``LRANGE``, ``HGETALL``, ``ACL WHOAMI`` or ``CLUSTER INFO`` should get the
reply a real, empty Redis gives, not a generic ``+OK``. Collections are modelled by their kind
and size only (that is enough for ``WRONGTYPE`` errors, ``LLEN`` and friends); no members are
stored. Nothing here connects anywhere: ``MIGRATE`` fails the way an unreachable target does.
"""

from __future__ import annotations

import time

from redis_sensor import resp
from redis_sensor.commands import (
    MAX_KEY_BYTES,
    WRONGTYPE,
    ClientState,
    Handler,
    Outcome,
    _parse_int,
    _unknown_sub,
    _wrong_args,
)

_EMPTY = resp.array([])


def _ok() -> Outcome:
    return Outcome(resp.simple("OK"))


def _int(n: int) -> Outcome:
    return Outcome(resp.integer(n))


def _wrongtype() -> Outcome:
    return Outcome(resp.error(WRONGTYPE))


def _push(kind: str, per_item: int, only_existing: bool = False) -> Handler:
    def handler(state: ClientState, a: list[bytes]) -> Outcome:
        if only_existing and state.kind(a[1]) is None:
            return _int(0)
        count = (len(a) - 2) // per_item
        size = state.grow_collection(a[1], kind, count)
        return _wrongtype() if size is None else _int(size)

    return handler


def _hmset(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) % 2:
        return Outcome(_wrong_args("hmset"))
    size = state.grow_collection(a[1], "hash", (len(a) - 2) // 2)
    return _wrongtype() if size is None else _ok()


def _hsetnx(state: ClientState, a: list[bytes]) -> Outcome:
    size = state.grow_collection(a[1], "hash", 1)
    return _wrongtype() if size is None else _int(1)


def _size(kind: str) -> Handler:
    def handler(state: ClientState, a: list[bytes]) -> Outcome:
        current = state.kind(a[1])
        if current is None:
            return _int(0)
        if current != kind:
            return _wrongtype()
        return _int(state.kinds.get((state.db, a[1]), (kind, 0))[1])

    return handler


def _members(kind: str, tag: bytes = b"*") -> Handler:
    """Reads that return a collection: empty, since no members are kept."""

    def handler(state: ClientState, a: list[bytes]) -> Outcome:
        current = state.kind(a[1])
        if current not in (None, kind):
            return _wrongtype()
        if state.proto == 3 and tag != b"*":
            return Outcome(tag + b"0\r\n")
        return Outcome(_EMPTY)

    return handler


def _element(kind: str) -> Handler:
    def handler(state: ClientState, a: list[bytes]) -> Outcome:
        current = state.kind(a[1])
        if current not in (None, kind):
            return _wrongtype()
        return Outcome(state.reply.null())

    return handler


def _rename(state: ClientState, a: list[bytes]) -> Outcome:
    space = state.keyspace()
    if a[1] not in space:
        return Outcome(resp.error("ERR no such key"))
    if a[1] == a[2]:
        return _ok()
    value, entry = space.pop(a[1]), state.kinds.pop((state.db, a[1]), None)
    state.drop(a[2])
    if len(a[2]) <= MAX_KEY_BYTES:
        space[a[2]] = value
        if entry:
            state.kinds[(state.db, a[2])] = entry
    return _ok()


def _lset(state: ClientState, a: list[bytes]) -> Outcome:
    if a[1] not in state.keyspace():
        return Outcome(resp.error("ERR no such key"))
    return (
        _wrongtype()
        if state.kind(a[1]) != "list"
        else Outcome(resp.error("ERR index out of range"))
    )


def _ltrim(state: ClientState, a: list[bytes]) -> Outcome:
    return _wrongtype() if state.kind(a[1]) not in (None, "list") else _ok()


def _subscribe(name: bytes) -> Handler:
    def handler(state: ClientState, a: list[bytes]) -> Outcome:
        out = b""
        for i, channel in enumerate(a[1:17], 1):
            out += resp.array([resp.bulk(name), resp.bulk(channel), resp.integer(i)])
        return Outcome(out)

    return handler


def _unsubscribe(name: bytes) -> Handler:
    def handler(state: ClientState, a: list[bytes]) -> Outcome:
        return Outcome(resp.array([resp.bulk(name), state.reply.null(), resp.integer(0)]))

    return handler


def _slowlog(state: ClientState, a: list[bytes]) -> Outcome:
    sub = a[1].upper()
    if sub == b"GET":
        return Outcome(_EMPTY)
    if sub == b"LEN":
        return _int(0)
    if sub == b"RESET":
        return _ok()
    return Outcome(_unknown_sub("slowlog", a[1], a[2:]))


def _latency(state: ClientState, a: list[bytes]) -> Outcome:
    sub = a[1].upper()
    if sub in (b"LATEST", b"HISTORY", b"GRAPH", b"HISTOGRAM"):
        return Outcome(_EMPTY)
    if sub == b"RESET":
        return _int(0)
    if sub == b"DOCTOR":
        return Outcome(
            resp.bulk(
                b"Dave, no latency spike was observed during the lifetime of this Redis instance, not in the slightest bit. I honestly think you ought to sit down calmly, take a stress pill, and think things over.\n"
            )
        )
    return Outcome(_unknown_sub("latency", a[1], a[2:]))


def _memory(state: ClientState, a: list[bytes]) -> Outcome:
    sub = a[1].upper()
    if sub == b"USAGE" and len(a) >= 3:
        value = state.keyspace().get(a[2])
        return Outcome(
            state.reply.null() if value is None else resp.integer(56 + len(a[2]) + len(value))
        )
    if sub == b"PURGE":
        return _ok()
    if sub == b"DOCTOR":
        return Outcome(
            resp.bulk(
                b"Hi Sam, I can't find any memory issue in your instance. I can only account for what occurs on this base."
            )
        )
    if sub in (b"STATS", b"MALLOC-STATS"):
        return Outcome(_EMPTY if sub == b"STATS" else resp.bulk(b""))
    return Outcome(_unknown_sub("memory", a[1], a[2:]))


def _object(state: ClientState, a: list[bytes]) -> Outcome:
    sub = a[1].upper()
    if len(a) != 3:
        return Outcome(_wrong_args("object|" + sub.decode("ascii", "replace").lower()))
    kind = state.kind(a[2])
    if kind is None:
        return Outcome(state.reply.null())
    if sub == b"ENCODING":
        value = state.keyspace()[a[2]]
        enc = "listpack" if kind != "string" else ("int" if value.isdigit() else "embstr")
        return Outcome(resp.bulk(enc.encode()))
    if sub == b"FREQ":
        return Outcome(
            resp.error(
                "ERR An LFU maxmemory policy is not selected, access frequency not tracked. "
                "Please note that when switching between policies at runtime LRU and LFU data "
                "will take some time to adjust."
            )
        )
    if sub == b"IDLETIME":
        return _int(0)
    if sub == b"REFCOUNT":
        return _int(1)
    return Outcome(_unknown_sub("object", a[1], a[2:]))


def _xadd(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) < 5 or len(a) % 2 == 0:
        return Outcome(_wrong_args("xadd"))
    size = state.grow_collection(a[1], "stream", 1)
    if size is None:
        return _wrongtype()
    ident = a[2]
    if ident == b"*":
        ident = b"%d-0" % int(time.time() * 1000)
    return Outcome(resp.bulk(ident))


def _acl(state: ClientState, a: list[bytes]) -> Outcome:
    sub = a[1].upper()
    if sub == b"WHOAMI":
        return Outcome(resp.bulk(b"default"))
    if sub == b"USERS":
        return Outcome(resp.array([resp.bulk(b"default")]))
    if sub == b"LIST":
        line = b"user default on nopass sanitize-payload ~* &* +@all"
        return Outcome(resp.array([resp.bulk(line)]))
    if sub == b"SETUSER":
        return Outcome(_ok().reply, {"acl_setuser"})
    if sub == b"DELUSER":
        return _int(0)
    if sub == b"LOG":
        return Outcome(_EMPTY)
    return Outcome(_unknown_sub("acl", a[1], a[2:]))


def _function(state: ClientState, a: list[bytes]) -> Outcome:
    sub = a[1].upper()
    if sub == b"LIST":
        return Outcome(_EMPTY)
    if sub in (b"FLUSH", b"KILL", b"RESTORE"):
        return (
            _ok()
            if sub == b"FLUSH"
            else Outcome(resp.error("NOTBUSY No scripts in execution right now."))
        )
    if sub == b"LOAD":
        return Outcome(resp.error("ERR Missing library metadata"), {"function_load"})
    if sub == b"DELETE":
        return Outcome(resp.error("ERR Library not found"))
    return Outcome(_unknown_sub("function", a[1], a[2:]))


def _cluster(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(resp.error("ERR This instance has cluster support disabled"))


def _migrate(state: ClientState, a: list[bytes]) -> Outcome:
    # Never connects: the target is not even parsed beyond what the event records.
    return Outcome(resp.error("IOERR error or timeout connecting to the client"), {"migrate"})


def _waitaof(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(
        resp.error("ERR WAITAOF cannot be used when numlocal is set but appendonly is disabled.")
    )


def _failover(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(resp.error("ERR FAILOVER requires connected replicas."))


def _pubsub(state: ClientState, a: list[bytes]) -> Outcome:
    sub = a[1].upper()
    if sub in (b"CHANNELS", b"NUMSUB", b"SHARDCHANNELS", b"SHARDNUMSUB"):
        return Outcome(_EMPTY)
    if sub in (b"NUMPAT",):
        return _int(0)
    return Outcome(_unknown_sub("pubsub", a[1], a[2:]))


def _setrange(state: ClientState, a: list[bytes]) -> Outcome:
    offset = _parse_int(a[2])
    if offset is None or offset < 0:
        return Outcome(resp.error("ERR offset is out of range"))
    return _int(offset + len(a[3]) if offset < 1 << 20 else 0)


def _lolwut(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(resp.bulk(f"Redis ver. {state.ctx.profile.version}\n".encode()))


def _const(value: int) -> Handler:
    return lambda state, a: _int(value)


def _ok_handler(state: ClientState, a: list[bytes]) -> Outcome:
    return _ok()


def _pfadd(state: ClientState, a: list[bytes]) -> Outcome:
    return _int(1)


def _geoadd(state: ClientState, a: list[bytes]) -> Outcome:
    return _int(max(0, (len(a) - 2) // 3))


def _dump(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(state.reply.null())


GENERIC: dict[str, tuple[int, Handler]] = {
    "LPUSH": (-3, _push("list", 1)),
    "RPUSH": (-3, _push("list", 1)),
    "LPUSHX": (-3, _push("list", 1, True)),
    "RPUSHX": (-3, _push("list", 1, True)),
    "SADD": (-3, _push("set", 1)),
    "ZADD": (-4, _push("zset", 2)),
    "HSET": (-4, _push("hash", 2)),
    "HMSET": (-4, _hmset),
    "HSETNX": (4, _hsetnx),
    "LLEN": (2, _size("list")),
    "SCARD": (2, _size("set")),
    "HLEN": (2, _size("hash")),
    "ZCARD": (2, _size("zset")),
    "LRANGE": (4, _members("list")),
    "SMEMBERS": (2, _members("set", b"~")),
    "ZRANGE": (-4, _members("zset")),
    "HGETALL": (2, _members("hash", b"%")),
    "HKEYS": (2, _members("hash")),
    "HVALS": (2, _members("hash")),
    "HGET": (3, _element("hash")),
    "LPOP": (-2, _element("list")),
    "RPOP": (-2, _element("list")),
    "RENAME": (3, _rename),
    "LSET": (4, _lset),
    "LTRIM": (4, _ltrim),
    "WATCH": (-2, _ok_handler),
    "UNWATCH": (1, _ok_handler),
    "SUBSCRIBE": (-2, _subscribe(b"subscribe")),
    "PSUBSCRIBE": (-2, _subscribe(b"psubscribe")),
    "UNSUBSCRIBE": (-1, _unsubscribe(b"unsubscribe")),
    "PUNSUBSCRIBE": (-1, _unsubscribe(b"punsubscribe")),
    "PUBLISH": (3, _const(0)),
    "PUBSUB": (-2, _pubsub),
    "SLOWLOG": (-2, _slowlog),
    "LATENCY": (-2, _latency),
    "WAITAOF": (4, _waitaof),
    "WAIT": (3, _const(0)),
    "FAILOVER": (-1, _failover),
    "MEMORY": (-2, _memory),
    "OBJECT": (-2, _object),
    "XADD": (-5, _xadd),
    "PFADD": (-2, _pfadd),
    "GEOADD": (-5, _geoadd),
    "SETRANGE": (4, _setrange),
    "SETBIT": (4, _const(0)),
    "BITOP": (-4, _const(0)),
    "COPY": (-3, _const(0)),
    "MOVE": (3, _const(0)),
    "SWAPDB": (3, _ok_handler),
    "ACL": (-2, _acl),
    "FUNCTION": (-2, _function),
    "CLUSTER": (-2, _cluster),
    "MIGRATE": (-6, _migrate),
    "DUMP": (2, _dump),
    "LOLWUT": (-1, _lolwut),
}


def register(table: dict[str, tuple[int, Handler]]) -> None:
    for name, entry in GENERIC.items():
        table.setdefault(name, entry)
