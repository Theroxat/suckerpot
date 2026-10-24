import { describe, expect, it } from "vitest"
import type { LiveEvent } from "@/lib/api"
import { ArcQueue, latestDistinctArcs, newArcs, type Arc } from "./arc-queue"

const HOME = { lat: 46.8, lon: 8.2 }

function ev(id: number, country: string | null, ip = `198.51.100.${id % 250}`): LiveEvent {
  return {
    id,
    ts: "2026-10-24T10:00:00Z",
    sensor: "ssh",
    session_id: `s${id}`,
    type: "connect",
    src_ip: ip,
    src_port: 40000,
    dst_port: 22,
    summary: "connected",
    country,
    city: null,
    asn: null,
    org: null,
    abuse_score: null,
    known_scanner: null,
    tags: [],
  }
}

function arc(id: number, born: number): Arc {
  return { id, sensor: "web", from: { lat: 0, lon: 0 }, to: HOME, born }
}

describe("ArcQueue", () => {
  it("drops the oldest arcs beyond the maximum", () => {
    const q = new ArcQueue(3, 1_000)
    for (let i = 1; i <= 5; i++) q.add(arc(i, 0))
    expect(q.arcs.map((a) => a.id)).toEqual([3, 4, 5])
  })

  it("keeps at most 60 arcs by default", () => {
    const q = new ArcQueue()
    for (let i = 0; i < 200; i++) q.add(arc(i, 0))
    expect(q.size).toBe(60)
  })

  it("expires arcs by age", () => {
    const q = new ArcQueue(10, 1_000)
    q.add(arc(1, 0))
    q.add(arc(2, 800))
    expect(q.prune(900)).toBe(false)
    expect(q.prune(1_200)).toBe(true)
    expect(q.arcs.map((a) => a.id)).toEqual([2])
  })
})

describe("newArcs", () => {
  it("returns arcs for unseen events, oldest first, and the new watermark", () => {
    const events = [ev(5, "NL"), ev(4, "US"), ev(3, "DE")]
    const out = newArcs(events, 3, HOME, 100)
    expect(out.arcs.map((a) => a.id)).toEqual([4, 5])
    expect(out.lastId).toBe(5)
    expect(out.arcs[0]?.to).toEqual(HOME)
    expect(out.arcs[0]?.born).toBe(100)
  })

  it("skips events without a known country but still advances", () => {
    const out = newArcs([ev(9, null), ev(8, "ZZ"), ev(7, "NL")], 0, HOME, 0)
    expect(out.arcs.map((a) => a.id)).toEqual([7])
    expect(out.lastId).toBe(9)
  })

  it("returns nothing when there is nothing new", () => {
    expect(newArcs([ev(2, "NL")], 2, HOME, 0)).toEqual({ arcs: [], lastId: 2 })
  })
})

describe("latestDistinctArcs", () => {
  it("keeps one arc per address and respects the limit", () => {
    const events = [ev(6, "NL", "192.0.2.1"), ev(5, "NL", "192.0.2.1"), ev(4, "US"), ev(3, "DE")]
    const out = latestDistinctArcs(events, HOME, 2)
    expect(out.map((a) => a.id)).toEqual([6, 4])
  })
})
