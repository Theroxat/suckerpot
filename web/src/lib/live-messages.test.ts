import { describe, expect, it } from "vitest"
import type { LiveEvent } from "@/lib/api"
import { MAX_BUFFER, mergeEvents, parseLiveMessage } from "./live-messages"

export function liveEvent(id: number, over: Partial<LiveEvent> = {}): LiveEvent {
  return {
    id,
    ts: "2026-10-24T18:02:16Z",
    sensor: "ssh",
    session_id: `s${id}`,
    type: "login_attempt",
    src_ip: "192.0.2.45",
    src_port: 38812,
    dst_port: 22,
    summary: "login root/123456 failed",
    country: null,
    city: null,
    asn: null,
    org: null,
    abuse_score: null,
    known_scanner: null,
    tags: [],
    ...over,
  }
}

const frame = (v: unknown) => JSON.stringify(v)

describe("parseLiveMessage", () => {
  it("parses every documented kind", () => {
    expect(parseLiveMessage(frame({ kind: "event", event: liveEvent(1) }))).toEqual({
      kind: "event",
      event: liveEvent(1),
    })
    expect(
      parseLiveMessage(frame({ kind: "backfill", events: [liveEvent(2), liveEvent(1)] })),
    ).toMatchObject({ kind: "backfill", events: [{ id: 2 }, { id: 1 }] })
    expect(
      parseLiveMessage(
        frame({
          kind: "stats",
          stats: {
            window_seconds: 60,
            events_last_minute: 5,
            sessions_last_minute: 2,
            by_sensor: { ssh: { events: 5, sessions: 2 } },
          },
        }),
      ),
    ).toMatchObject({ kind: "stats", stats: { events_last_minute: 5 } })
    expect(parseLiveMessage(frame({ kind: "dropped", count: 3 }))).toEqual({
      kind: "dropped",
      count: 3,
    })
    expect(parseLiveMessage(frame({ kind: "pong" }))).toEqual({ kind: "pong" })
  })

  it("ignores unknown kinds, bad JSON and non-text frames", () => {
    expect(parseLiveMessage(frame({ kind: "future-thing", x: 1 }))).toBeNull()
    expect(parseLiveMessage("{not json")).toBeNull()
    expect(parseLiveMessage("null")).toBeNull()
    expect(parseLiveMessage("[1,2]")).toBeNull()
    expect(parseLiveMessage(new ArrayBuffer(4))).toBeNull()
    expect(parseLiveMessage(undefined)).toBeNull()
  })

  it("drops invalid events but keeps valid ones in a backfill", () => {
    const msg = parseLiveMessage(
      frame({
        kind: "backfill",
        events: [liveEvent(3), { id: "x" }, null, { ...liveEvent(4), ts: "garbage" }, liveEvent(5)],
      }),
    )
    expect(msg).toMatchObject({ kind: "backfill", events: [{ id: 3 }, { id: 5 }] })
    expect(parseLiveMessage(frame({ kind: "event", event: { id: 1 } }))).toBeNull()
    expect(parseLiveMessage(frame({ kind: "stats", stats: { nope: true } }))).toBeNull()
  })

  it("fills optional fields defensively", () => {
    const msg = parseLiveMessage(
      frame({
        kind: "event",
        event: {
          id: 9,
          ts: "2026-10-24T18:02:16Z",
          sensor: "web",
          session_id: "a",
          type: "scan",
          src_ip: "198.51.100.7",
          tags: ["recon", 4],
        },
      }),
    )
    expect(msg).toMatchObject({
      event: { summary: "scan", country: null, src_port: 0, tags: ["recon"] },
    })
  })
})

describe("mergeEvents", () => {
  it("sorts newest first and de-duplicates by id", () => {
    const merged = mergeEvents([liveEvent(3), liveEvent(1)], [liveEvent(2), liveEvent(3)])
    expect(merged.map((e) => e.id)).toEqual([3, 2, 1])
  })

  it("returns the same array when nothing is new", () => {
    const current = [liveEvent(2), liveEvent(1)]
    expect(mergeEvents(current, [liveEvent(1)])).toBe(current)
    expect(mergeEvents(current, [])).toBe(current)
  })

  it("keeps the buffer bounded and drops the oldest", () => {
    const many = Array.from({ length: MAX_BUFFER + 80 }, (_, i) => liveEvent(i + 1))
    const merged = mergeEvents([], many)
    expect(merged).toHaveLength(MAX_BUFFER)
    expect(merged[0]?.id).toBe(MAX_BUFFER + 80)
    expect(merged.at(-1)?.id).toBe(81)
  })
})
