import { describe, expect, it } from "vitest"
import type { LiveEvent } from "@/lib/api"
import { ageOpacity, aggregateSources, countWeight, rankLeaders } from "./activity"
import { COUNTRY_CENTROIDS } from "./data/centroids"

const NOW = Date.parse("2026-10-25T12:00:00Z")
let id = 0
function ev(
  country: string | null,
  ip: string,
  sensor: string,
  agoMs: number,
  asn: number | null = null,
  org: string | null = null,
): LiveEvent {
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
    asn,
    org,
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

describe("rankLeaders", () => {
  it("ranks addresses and networks in the window, with shares, country and sensors", () => {
    const l = rankLeaders(
      [
        ev("FR", "192.0.2.1", "ssh", 1_000, 64505, "Hexagone Serveurs"),
        ev("FR", "192.0.2.1", "redis", 2_000, 64505, "Hexagone Serveurs"),
        ev("FR", "192.0.2.2", "ssh", 3_000, 64505, "Hexagone Serveurs"),
        ev("DE", "198.51.100.1", "web", 4_000, 64499, "Rhein Compute GmbH"),
        ev(null, "203.0.113.1", "ssh", 5_000),
        ev("FR", "192.0.2.9", "ssh", 20 * 60_000, 64505, "Hexagone Serveurs"),
      ],
      NOW,
    )
    expect(l.events).toBe(5)
    expect(l.addresses.map((a) => [a.key, a.events, a.country])).toEqual([
      ["192.0.2.1", 2, "FR"],
      ["192.0.2.2", 1, "FR"],
      ["198.51.100.1", 1, "DE"],
      ["203.0.113.1", 1, null],
    ])
    expect(l.addresses[0]?.share).toBeCloseTo(0.4)
    expect(l.addresses[0]?.sensors).toEqual(["ssh", "redis"])
    // Unknown networks are left out of the network ranking.
    expect(l.networks.map((n) => [n.key, n.events, n.ips, n.org])).toEqual([
      ["64505", 3, 2, "Hexagone Serveurs"],
      ["64499", 1, 1, "Rhein Compute GmbH"],
    ])
    expect(l.networks[1]?.family).toBe("web")
  })
  it("caps each ranking", () => {
    const events = Array.from({ length: 20 }, (_, i) => ev("FR", `192.0.2.${i}`, "ssh", 0, i))
    const l = rankLeaders(events, NOW, 60_000, 5)
    expect(l.addresses).toHaveLength(5)
    expect(l.networks).toHaveLength(5)
  })
})

describe("country centroids", () => {
  it("covers the common attack origins and small states", () => {
    for (const c of ["US", "CN", "RU", "NL", "DE", "BR", "IN", "VN", "SG", "HK", "CH"]) {
      expect(COUNTRY_CENTROIDS[c], c).toBeDefined()
    }
    expect(Object.keys(COUNTRY_CENTROIDS).length).toBeGreaterThan(200)
  })
  it("places every centroid on the planet, and well-known countries roughly right", () => {
    for (const [code, [lat, lon]] of Object.entries(COUNTRY_CENTROIDS)) {
      expect(Math.abs(lat), code).toBeLessThanOrEqual(90)
      expect(Math.abs(lon), code).toBeLessThanOrEqual(180)
    }
    // Antimeridian countries stay on their side of the planet (Russia in Europe, not near Alaska).
    expect(COUNTRY_CENTROIDS.RU?.[1]).toBeGreaterThan(30)
    expect(COUNTRY_CENTROIDS.FJ?.[1]).toBeGreaterThan(170)
    const [lat, lon] = COUNTRY_CENTROIDS.DE ?? [0, 0]
    expect(lat).toBeGreaterThan(48)
    expect(lat).toBeLessThan(54)
    expect(lon).toBeGreaterThan(7)
    expect(lon).toBeLessThan(14)
  })
})
