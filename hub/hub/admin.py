"""Operator CLI: ``python -m hub.admin <command>``. No web admin: a smaller attack surface.

Commands: gen-signing-key, show-public-key, reports list|show|approve|cancel, target dispute,
never add|remove|list, node suspend|unsuspend, stats. Every change writes ``hub_audit`` with the
action and counts only (no node data, no addresses).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_netproto import blind, sign

from . import reputation
from .config import ConfigError, Settings, load_signing_key
from .db import make_engine, make_sessionmaker

Out = Callable[[str], None]


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hub.admin")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-signing-key", help="make the hub signing key and print its public part")
    g.add_argument("--out", required=True, help="file to write (mode 0400)")
    g.add_argument("--force", action="store_true", help="overwrite an existing file")

    k = sub.add_parser("show-public-key", help="print the public key of a signing key file")
    k.add_argument("--key-file", default=os.environ.get("HUB_SIGNING_KEY_FILE", ""))

    r = sub.add_parser("reports")
    rs = r.add_subparsers(dest="action", required=True)
    rl = rs.add_parser("list")
    rl.add_argument("--state", choices=["queued", "approved", "sent", "failed", "cancelled"])
    for name in ("show", "approve", "cancel"):
        rs.add_parser(name).add_argument("id", type=int)

    t = sub.add_parser("target")
    ts = t.add_subparsers(dest="action", required=True)
    td = ts.add_parser("dispute")
    td.add_argument("id")
    td.add_argument("--note", required=True)

    n = sub.add_parser("never")
    ns = n.add_subparsers(dest="action", required=True)
    na = ns.add_parser("add")
    na.add_argument("value")
    na.add_argument("--kind", choices=["ip", "domain", "sha256"])
    na.add_argument("--note", default="")
    ns.add_parser("remove").add_argument("value")
    ns.add_parser("list")

    nd = sub.add_parser("node")
    nds = nd.add_subparsers(dest="action", required=True)
    for name in ("suspend", "unsuspend"):
        nds.add_parser(name).add_argument("fingerprint")

    sub.add_parser("stats")
    return p


def _kind_of(value: str) -> str:
    import ipaddress

    try:
        ipaddress.ip_network(value, strict=False)
        return "ip"
    except ValueError:
        pass
    if len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value):
        return "sha256"
    return "domain"


async def _audit(
    session: AsyncSession, actor: str, action: str, detail: dict[str, Any] | None = None
) -> None:
    await session.execute(
        text("INSERT INTO hub_audit (actor, action, detail) VALUES (:a, :b, CAST(:d AS jsonb))"),
        {"a": actor, "b": action, "d": json.dumps(detail or {})},
    )


def gen_signing_key(out_path: str, force: bool, out: Out) -> int:
    path = Path(out_path)
    seed = sign.generate_private_key()
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        if force and path.exists():
            path.chmod(0o600)
        fd = os.open(path, flags, 0o400)
    except FileExistsError:
        out("refusing to overwrite an existing key file (use --force)")
        return 1
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(sign.b64u_encode(seed) + "\n")
    path.chmod(0o400)
    out(f"hub_key={sign.node_key(sign.public_key_of(seed))}")
    return 0


async def run(
    argv: list[str],
    *,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
    out: Out = print,
    actor: str | None = None,
) -> int:
    args = _parser().parse_args(argv)
    if args.cmd == "gen-signing-key":
        return gen_signing_key(args.out, args.force, out)
    if args.cmd == "show-public-key":
        try:
            seed = load_signing_key(args.key_file)
        except ConfigError as exc:
            out(str(exc))
            return 1
        out(f"hub_key={sign.node_key(sign.public_key_of(seed))}")
        return 0

    engine = None
    if sessionmaker is None:
        engine = make_engine(Settings.from_env().worker_database_url)
        sessionmaker = make_sessionmaker(engine)
    who = actor or os.environ.get("HUB_ADMIN_ACTOR", "cli")
    try:
        async with sessionmaker() as session:
            return await _dispatch(args, session, who, out)
    finally:
        if engine is not None:
            await engine.dispose()


async def _dispatch(args: argparse.Namespace, session: AsyncSession, who: str, out: Out) -> int:
    if args.cmd == "reports":
        return await _reports(args, session, who, out)
    if args.cmd == "target":
        penalised = await reputation.dispute(session, args.id)
        await _audit(
            session, who, "target.dispute", {"penalised": penalised, "note": args.note[:200]}
        )
        await session.commit()
        out(f"disputed {args.id}; {penalised} contributors lowered")
        return 0
    if args.cmd == "never":
        return await _never(args, session, who, out)
    if args.cmd == "node":
        state = "soft_suspended" if args.action == "suspend" else "active"
        result = await session.execute(
            text(
                "UPDATE nodes SET standing = :s WHERE substr(encode(sha256(pubkey), 'hex'), 1, 8) = :fp"
            ),
            {"s": state, "fp": args.fingerprint.lower()},
        )
        count = int(getattr(result, "rowcount", 0) or 0)
        await _audit(session, who, f"node.{args.action}", {"nodes": count})
        await session.commit()
        out(f"{args.action}: {count} node(s)")
        return 0 if count else 1
    if args.cmd == "stats":
        rows = (
            await session.execute(
                text(
                    "SELECT (SELECT count(*) FROM nodes) AS nodes, "
                    "(SELECT count(*) FROM nodes WHERE standing = 'soft_suspended') AS suspended, "
                    "(SELECT count(*) FROM targets WHERE state = 'candidate') AS candidates, "
                    "(SELECT count(*) FROM targets WHERE state = 'confirmed') AS confirmed, "
                    "(SELECT count(*) FROM targets WHERE state = 'reported') AS reported, "
                    "(SELECT count(*) FROM targets WHERE state = 'taken_down') AS taken_down, "
                    "(SELECT count(*) FROM reports WHERE state = 'queued') AS reports_queued"
                )
            )
        ).one()
        for key, value in rows._mapping.items():
            out(f"{key}: {value}")
        return 0
    return 2


async def _reports(args: argparse.Namespace, session: AsyncSession, who: str, out: Out) -> int:
    if args.action == "list":
        sql = "SELECT id, state, kind, recipient, array_length(target_ids, 1) AS n, created_day FROM reports"
        params: dict[str, Any] = {}
        if args.state:
            sql += " WHERE state = :s"
            params["s"] = args.state
        for r in (await session.execute(text(sql + " ORDER BY id DESC LIMIT 200"), params)).all():
            out(f"{r.id}\t{r.state}\t{r.kind}\t{r.recipient}\t{r.n} target(s)\t{r.created_day}")
        return 0
    row = (
        await session.execute(
            text("SELECT id, state, body_text, xarf FROM reports WHERE id = :id"), {"id": args.id}
        )
    ).first()
    if row is None:
        out("no such report")
        return 1
    if args.action == "show":
        out(f"state: {row.state}\n\n{row.body_text}")
        if row.xarf:
            out("\n--- X-ARF ---\n" + row.xarf)
        return 0
    if args.action == "approve":
        if row.state != "queued":
            out(f"only a queued report can be approved (this one is {row.state})")
            return 1
        await session.execute(
            text("UPDATE reports SET state = 'approved', approved_by = :w WHERE id = :id"),
            {"w": who, "id": args.id},
        )
        await _audit(session, who, "report.approve", {"report": args.id})
        await session.commit()
        out(f"approved {args.id}; it is sent by the next worker cycle")
        return 0
    if row.state not in ("queued", "approved"):
        out(f"only a queued or approved report can be cancelled (this one is {row.state})")
        return 1
    await session.execute(
        text("UPDATE reports SET state = 'cancelled' WHERE id = :id"), {"id": args.id}
    )
    await _audit(session, who, "report.cancel", {"report": args.id})
    await session.commit()
    out(f"cancelled {args.id}")
    return 0


async def _never(args: argparse.Namespace, session: AsyncSession, who: str, out: Out) -> int:
    if args.action == "list":
        for r in (
            await session.execute(
                text("SELECT value, kind, note FROM never_list ORDER BY kind, value")
            )
        ).all():
            out(f"{r.kind}\t{r.value}\t{r.note or ''}")
        return 0
    if args.action == "add":
        kind = args.kind or _kind_of(args.value)
        value = (
            blind.canonical_domain(args.value) if kind == "domain" else args.value.strip().lower()
        )
        await session.execute(
            text(
                "INSERT INTO never_list (value, kind, note) VALUES (:v, :k, :n) "
                "ON CONFLICT (value) DO UPDATE SET kind = EXCLUDED.kind, note = EXCLUDED.note"
            ),
            {"v": value, "k": kind, "n": args.note[:200]},
        )
        await _audit(session, who, "never.add", {"kind": kind})
        await session.commit()
        out(f"added {kind} {value}")
        return 0
    result = await session.execute(
        text("DELETE FROM never_list WHERE value = :v"), {"v": args.value.strip().lower()}
    )
    removed = int(getattr(result, "rowcount", 0) or 0)
    await _audit(session, who, "never.remove", {"removed": removed})
    await session.commit()
    out(f"removed {removed}")
    return 0 if removed else 1


def main() -> None:
    sys.exit(asyncio.run(run(sys.argv[1:])))


if __name__ == "__main__":
    main()
