import { describe, expect, it } from "vitest"
import type { LiveEvent } from "@/lib/api"
import { ageOpacity, aggregateSources, countWeight } from "./activity"

const NOW = Date.parse("2026-10-25T12:00:00Z")
let id = 0
function ev(country: string | null, ip: string, sensor: string, agoMs: number): LiveEvent {
  id += 1
  return {
    id,
    ts: new Date(NOW - agoMs).toISOString(),
    sensor,
    session_id: `s${id}`,
    type: "login_attempt",
    src_ip: ip,
    src_port: 40000,
    dst_port: 22,
    summary: "login root/root failed",
    country,
    city: null,
    asn: null,
    org: null,
    abuse_score: null,
    known_scanner: null,
    tags: [],
  }
}

describe("aggregateSources", () => {
  it("groups by country, busiest first, with addresses, sensors and family", () => {
    const a = aggregateSources(
      [
        ev("FR", "192.0.2.1", "ssh", 1_000),
        ev("FR", "192.0.2.1", "telnet", 2_000),
        ev("FR", "192.0.2.2", "redis", 3_000),
        ev("de", "198.51.100.1", "mysql", 4_000),
        ev(null, "203.0.113.1", "ssh", 5_000),
        ev("FR", "192.0.2.1", "ssh", 20 * 60_000),
      ],
      NOW,
    )
    expect(a.events).toBe(5)
    expect(a.unlocated).toBe(1)
    expect(a.sources.map((s) => [s.country, s.events, s.ips])).toEqual([
      ["FR", 3, 2],
      ["DE", 1, 1],
    ])
    const fr = a.sources[0]
    expect(fr?.family).toBe("shell")
    expect(fr?.sensors).toEqual(["ssh", "telnet", "redis"])
    expect(fr?.topIp).toBe("192.0.2.1")
    expect(a.sources[1]?.family).toBe("data")
  })
  it("caps the number of sources", () => {
    const events = ["FR", "DE", "NL", "US", "CN"].map((c) => ev(c, "192.0.2.9", "ssh", 0))
    expect(aggregateSources(events, NOW, 60_000, 3).sources).toHaveLength(3)
  })
})

describe("fading and weight", () => {
  it("fades with age but never vanishes inside the window", () => {
    expect(ageOpacity(NOW, NOW)).toBe(1)
    expect(ageOpacity(NOW - 15 * 60_000, NOW)).toBeCloseTo(0.22)
    expect(ageOpacity(NOW - 60 * 60_000, NOW)).toBe(0.22)
  })
  it("grows on a log scale", () => {
    expect(countWeight(1)).toBe(0)
    expect(countWeight(10)).toBeCloseTo(0.5)
    expect(countWeight(1000)).toBe(1)
  })
})
