import { beforeEach, describe, expect, it } from "vitest"
import { hasSeenTour, markTourSeen, tourKey, TOUR_STEPS } from "./tour"

describe("tour", () => {
  beforeEach(() => window.localStorage.clear())

  it("has the seven steps of the spec, each with a headline and a few sentences", () => {
    expect(TOUR_STEPS.map((s) => s.id)).toEqual([
      "what",
      "daily",
      "group",
      "payloads",
      "egress",
      "abuse",
      "alerts",
    ])
    for (const s of TOUR_STEPS) {
      expect(s.title.split(/(?<=[.!?])\s+/)).toHaveLength(1)
      expect(s.body.split(/(?<=[.!?])\s+/).length).toBeLessThanOrEqual(3)
    }
  })

  it("remembers who has seen it, per username", () => {
    expect(hasSeenTour("admin")).toBe(false)
    markTourSeen("admin")
    expect(hasSeenTour("admin")).toBe(true)
    expect(hasSeenTour("colleague")).toBe(false)
    expect(window.localStorage.getItem(tourKey("admin"))).toBe("1")
  })

  it("does not open by itself when storage is unavailable", () => {
    const broken = {
      getItem: () => {
        throw new Error("denied")
      },
      setItem: () => {
        throw new Error("denied")
      },
    } as unknown as Storage
    expect(hasSeenTour("admin", broken)).toBe(true)
    expect(() => markTourSeen("admin", broken)).not.toThrow()
  })
})
