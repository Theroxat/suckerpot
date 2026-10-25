import { describe, expect, it } from "vitest"
import {
  dailyFromHourly,
  describeCampaigns,
  describeMatrix,
  describeScale,
  groupByStage,
  heatColour,
  heatStep,
  stageTrailText,
  techniqueDays,
  windowDays,
  type Campaign,
  type Matrix,
  type MatrixRow,
} from "./campaigns"

function campaign(over: Partial<Campaign> = {}): Campaign {
  return {
    id: 1,
    name: "Mirai-style loader over Telnet #1",
    status: "active",
    merged_into: null,
    first_seen: "2026-10-20T10:00:00Z",
    last_seen: "2026-10-24T10:00:00Z",
    sessions: 87,
    sources: 23,
    countries: ["FR", "DE", "NL"],
    asns: [64496],
    sensors: ["telnet"],
    techniques: ["T1110"],
    stages: ["access"],
    tags: [],
    families: [],
    severity: "severe",
    rep_session_id: null,
    demo: false,
    ...over,
  }
}

function row(
  id: string,
  stage: MatrixRow["stage"],
  counts: number[],
  plain = "did a thing",
): MatrixRow {
  return {
    id,
    name: id,
    tactic: "x",
    stage,
    url: "https://attack.example/",
    plain,
    total_sessions: counts.reduce((a, b) => a + b, 0),
    total_events: 0,
    counts,
  }
}

describe("describeCampaigns", () => {
  it("opens with a count and how many are still active", () => {
    const items = [campaign(), campaign({ id: 2, status: "quiet" })]
    expect(describeCampaigns(items, { days: 30, more: false })).toBe(
      "2 campaigns in the last 30 days, 1 still active.",
    )
  })

  it("says so when everything is active, or nothing is", () => {
    expect(describeCampaigns([campaign()], { days: 7, more: false })).toBe(
      "1 campaign in the last 7 days, all still active.",
    )
    expect(describeCampaigns([campaign({ status: "quiet" })], { days: 0, more: false })).toBe(
      "1 campaign on record, all quiet now.",
    )
    expect(describeCampaigns([], { days: 30, more: false })).toBe(
      "No campaigns in the last 30 days.",
    )
  })

  it("does not claim a total while more pages exist", () => {
    expect(describeCampaigns([campaign()], { days: 30, more: true })).toBe(
      "1+ campaigns in the last 30 days, 1 still active.",
    )
  })
})

describe("describeScale", () => {
  it("reads as one phrase", () => {
    expect(describeScale(campaign())).toBe("87 sessions from 23 addresses in 3 countries")
    expect(describeScale(campaign({ sessions: 1, sources: 1, countries: ["FR"] }))).toBe(
      "1 session from 1 address in 1 country",
    )
    expect(describeScale(campaign({ countries: [] }))).toBe("87 sessions from 23 addresses")
  })
})

describe("stageTrailText", () => {
  it("is always in story order", () => {
    expect(stageTrailText(["objective", "recon", "access"])).toBe(
      "Looking around → Getting in → The goal",
    )
    expect(stageTrailText([])).toBe("No stages recorded")
  })
})

describe("windows", () => {
  it("falls back to 30 days", () => {
    expect(windowDays(null)).toBe(30)
    expect(windowDays("all")).toBe(0)
    expect(windowDays("junk")).toBe(30)
    expect(techniqueDays("90")).toBe(90)
    expect(techniqueDays("all")).toBe(30)
  })
})

describe("heat scale", () => {
  it("is empty for zero and tops out at 5", () => {
    expect(heatStep(0, 10)).toBe(0)
    expect(heatStep(1, 0)).toBe(0)
    expect(heatStep(10, 10)).toBe(5)
    expect(heatStep(1, 1000)).toBe(1)
    expect(heatStep(5, 20)).toBeGreaterThan(heatStep(1, 20))
  })

  it("uses theme tokens only", () => {
    expect(heatColour(0)).toBe("var(--surface-hover)")
    expect(heatColour(3)).toContain("var(--fg)")
    expect(heatColour(3)).not.toMatch(/#[0-9a-f]{3,6}/i)
  })
})

describe("matrix helpers", () => {
  const matrix: Matrix = {
    since: "2026-10-18",
    until: "2026-10-24",
    days: ["2026-10-22", "2026-10-23", "2026-10-24"],
    stages: [],
    rows: [
      row("T1110", "access", [4, 6, 10], "guessed passwords"),
      row("T1082", "recon", [1, 1, 1]),
      row("T1078", "access", [0, 1, 1]),
    ],
  }

  it("groups by stage in story order and drops empty stages", () => {
    const groups = groupByStage(matrix)
    expect(groups.map((g) => g.stage)).toEqual(["recon", "access"])
    expect(groups[1]?.rows.map((r) => r.id)).toEqual(["T1110", "T1078"])
    expect(groups[1]?.total).toBe(22)
  })

  it("opens with the most common move", () => {
    expect(describeMatrix(matrix, 33)).toBe(
      "Attackers used 3 techniques of the 33 we watch for in the last 3 days. Most often they guessed passwords.",
    )
    expect(describeMatrix({ ...matrix, rows: [] }, 33)).toBe(
      "No techniques were seen in the last 3 days.",
    )
  })
})

describe("dailyFromHourly", () => {
  it("sums hours into UTC days and fills quiet days", () => {
    const now = Date.parse("2026-10-24T12:00:00Z")
    const points = [
      { ts: "2026-10-24T09:00:00Z", sessions: 2 },
      { ts: "2026-10-24T10:00:00Z", sessions: 3 },
      { ts: "2026-10-22T10:00:00Z", sessions: 1 },
    ]
    expect(dailyFromHourly(points, 3, now)).toEqual([
      { day: "2026-10-22", events: 1 },
      { day: "2026-10-23", events: 0 },
      { day: "2026-10-24", events: 5 },
    ])
  })
})
