import { describe, expect, it } from "vitest"
import { fillDays } from "./chart-time"

describe("fillDays", () => {
  it("returns one slot per day, oldest first, zero for quiet days", () => {
    const now = Date.parse("2026-10-24T15:00:00Z")
    const out = fillDays([{ day: "2026-10-22", events: 7 }], 4, now)
    expect(out).toEqual([
      { day: "2026-10-21", events: 0 },
      { day: "2026-10-22", events: 7 },
      { day: "2026-10-23", events: 0 },
      { day: "2026-10-24", events: 0 },
    ])
  })
})
