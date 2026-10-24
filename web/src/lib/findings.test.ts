import { describe, expect, it } from "vitest"
import type { TimePoint, TopResponse } from "./api"
import {
  deltaRatio,
  describeActivity,
  describeCountries,
  describeCredential,
  describeTimeline,
  splitWindows,
  sumBySensor,
} from "./findings"

const pt = (ts: string, ssh: number, telnet = 0, web = 0, rdp = 0): TimePoint => ({
  ts,
  events: { ssh, telnet, web, rdp },
  sessions: { ssh, telnet, web, rdp },
})

const top = (
  field: TopResponse["field"],
  items: [string, number][],
  total: number,
): TopResponse => ({
  field,
  total,
  items: items.map(([value, count]) => ({ value, count, share: count / total })),
})

describe("describeActivity", () => {
  it("names the leading sensor, its share and the busiest hour", () => {
    const points = [pt("2026-10-24T10:00:00Z", 60, 10), pt("2026-10-24T11:00:00Z", 70, 20, 30, 10)]
    const out = describeActivity(points, (iso) => iso.slice(11, 16))
    expect(out.finding).toBe("SSH drew 65% of all events in the last 24 hours.")
    expect(out.detail).toBe("200 events in all. Busiest hour: 11:00, with 130 events.")
  })
  it("handles a single-sensor day and an empty one", () => {
    expect(describeActivity([pt("2026-10-24T10:00:00Z", 0, 0, 5)], () => "x").finding).toBe(
      "Every event in the last 24 hours hit the Web sensor.",
    )
    expect(describeActivity([pt("2026-10-24T10:00:00Z", 0)], () => "x").finding).toBe(
      "No events in the last 24 hours.",
    )
  })
})

describe("windows and deltas", () => {
  it("splits in halves and sums per sensor", () => {
    const [prev, cur] = splitWindows([pt("a", 1), pt("b", 2), pt("c", 3), pt("d", 4)])
    expect(sumBySensor(prev, "sessions").ssh).toBe(3)
    expect(sumBySensor(cur, "sessions").ssh).toBe(7)
  })
  it("returns null without a baseline", () => {
    expect(deltaRatio(10, 0)).toBeNull()
    expect(deltaRatio(15, 10)).toBeCloseTo(0.5)
    expect(deltaRatio(5, 10)).toBeCloseTo(-0.5)
  })
})

describe("describeCountries", () => {
  it("leads with the top country and names the next two", () => {
    const out = describeCountries(
      top(
        "country",
        [
          ["NL", 230],
          ["US", 140],
          ["CN", 110],
        ],
        1000,
      ),
    )
    expect(out.finding).toBe(
      "Netherlands led with 23% of sessions, ahead of United States (14%) and China (11%).",
    )
  })
  it("copes with no data", () => {
    expect(describeCountries(undefined).finding).toBe("No country data yet.")
  })
})

describe("describeCredential", () => {
  it("quotes the winner and the runner-up", () => {
    const out = describeCredential(
      "username",
      top(
        "username",
        [
          ["root", 42],
          ["admin", 18],
        ],
        100,
      ),
    )
    expect(out.finding).toBe(
      '"root" was the most tried username, in 42% of login attempts, ahead of "admin" (18%).',
    )
  })
})

describe("describeTimeline", () => {
  it("counts active days and names the busiest", () => {
    const out = describeTimeline(
      [
        { day: "2026-10-20", events: 312 },
        { day: "2026-10-21", events: 0 },
        { day: "2026-10-22", events: 40 },
      ],
      (d) => d.slice(5),
    )
    expect(out.finding).toBe("Active on 2 of the last 30 days, busiest on 10-20 with 312 events.")
  })
  it("says so when quiet", () => {
    expect(describeTimeline([], (d) => d).finding).toBe("No activity in the last 30 days.")
  })
})
