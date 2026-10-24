import { describe, expect, it } from "vitest"
import { COUNTRY_CENTROIDS } from "./data/centroids"
import { landDots } from "./data/land-dots"
import {
  arcAltitude,
  drawableArc,
  greatCircleDegrees,
  hashString,
  hasCentroid,
  JITTER_DEGREES,
  sourcePoint,
} from "./geo"

describe("country centroids", () => {
  it("covers the common attack origins and small states", () => {
    for (const c of ["US", "CN", "RU", "NL", "DE", "BR", "IN", "VN", "SG", "HK", "CH"]) {
      expect(hasCentroid(c), c).toBe(true)
    }
    expect(Object.keys(COUNTRY_CENTROIDS).length).toBeGreaterThan(200)
  })

  it("keeps every centroid on the planet", () => {
    for (const [code, [lat, lon]] of Object.entries(COUNTRY_CENTROIDS)) {
      expect(Math.abs(lat), code).toBeLessThanOrEqual(90)
      expect(Math.abs(lon), code).toBeLessThanOrEqual(180)
    }
  })

  it("places well-known countries roughly right", () => {
    const [lat, lon] = COUNTRY_CENTROIDS.DE ?? [0, 0]
    expect(lat).toBeGreaterThan(48)
    expect(lat).toBeLessThan(54)
    expect(lon).toBeGreaterThan(7)
    expect(lon).toBeLessThan(14)
  })
})

describe("land dots", () => {
  it("decodes whole lat/lon pairs inside valid ranges", () => {
    const dots = landDots()
    expect(dots.length % 2).toBe(0)
    expect(dots.length / 2).toBeGreaterThan(1_000)
    for (let i = 0; i < dots.length; i += 2) {
      expect(Math.abs(dots[i] ?? 999)).toBeLessThanOrEqual(90)
      expect(Math.abs(dots[i + 1] ?? 999)).toBeLessThanOrEqual(180)
    }
  })
})

describe("sourcePoint", () => {
  it("is deterministic for an address", () => {
    expect(sourcePoint("NL", "203.0.113.9")).toEqual(sourcePoint("NL", "203.0.113.9"))
  })

  it("spreads different addresses of one country", () => {
    const points = new Set(
      ["203.0.113.1", "203.0.113.2", "203.0.113.3", "198.51.100.7"].map((ip) =>
        JSON.stringify(sourcePoint("US", ip)),
      ),
    )
    expect(points.size).toBe(4)
  })

  it("stays within the jitter radius of the centre", () => {
    const centre = COUNTRY_CENTROIDS.FR ?? [0, 0]
    for (let i = 0; i < 200; i++) {
      const p = sourcePoint("FR", `198.51.100.${i}`)
      expect(p).not.toBeNull()
      expect(Math.abs((p?.lat ?? 0) - centre[0])).toBeLessThanOrEqual(JITTER_DEGREES + 0.01)
    }
  })

  it("accepts lower case and rejects unknown or missing countries", () => {
    expect(sourcePoint("nl", "192.0.2.1")).not.toBeNull()
    expect(sourcePoint("ZZ", "192.0.2.1")).toBeNull()
    expect(sourcePoint(null, "192.0.2.1")).toBeNull()
  })

  it("wraps longitude at the antimeridian", () => {
    for (let i = 0; i < 100; i++) {
      const p = sourcePoint("FJ", `192.0.2.${i}`)
      expect(Math.abs(p?.lon ?? 0)).toBeLessThanOrEqual(180)
    }
  })
})

describe("hashString", () => {
  it("is stable", () => {
    expect(hashString("192.0.2.1")).toBe(hashString("192.0.2.1"))
    expect(hashString("a")).not.toBe(hashString("b"))
  })
})

describe("arc geometry", () => {
  const zurich = { lat: 47.37, lon: 8.54 }
  it("measures great-circle distance", () => {
    expect(greatCircleDegrees(zurich, zurich)).toBe(0)
    expect(greatCircleDegrees({ lat: 0, lon: 0 }, { lat: 0, lon: 90 })).toBeCloseTo(90)
  })
  it("skips degenerate arcs (same spot or antipodal)", () => {
    expect(drawableArc(zurich, { lat: 47.9, lon: 9.1 })).toBe(false)
    expect(drawableArc({ lat: 0, lon: 0 }, { lat: 0, lon: 179.9 })).toBe(false)
    expect(drawableArc(zurich, { lat: 40.7, lon: -74 })).toBe(true)
  })
  it("clamps the altitude", () => {
    expect(arcAltitude(zurich, { lat: 48.9, lon: 2.35 })).toBeGreaterThanOrEqual(0.04)
    expect(arcAltitude({ lat: 0, lon: 0 }, { lat: 0, lon: 170 })).toBeLessThanOrEqual(0.18)
  })
})
