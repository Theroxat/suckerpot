import { describe, expect, it } from "vitest"
import {
  defangUrl,
  describeHeatmap,
  describeMalware,
  describeNew,
  describeTags,
  describeTop,
  summariseMalware,
  tagTotals,
  toLocalGrid,
  type MalwareItem,
  type TagPoint,
} from "./trends"

describe("defangUrl", () => {
  it("defangs scheme and host dots, leaves the path alone", () => {
    expect(defangUrl("http://files.example.net/bins/x86.sh")).toBe(
      "hxxp://files[.]example[.]net/bins/x86.sh",
    )
    expect(defangUrl("https://198.51.100.23:8080/a.b")).toBe("hxxps://198[.]51[.]100[.]23:8080/a.b")
    expect(defangUrl("ftp://cdn.example.org/f")).toBe("fxp://cdn[.]example[.]org/f")
  })
  it("handles URLs without a scheme", () => {
    expect(defangUrl("cdn.example.org/x.sh")).toBe("cdn[.]example[.]org/x.sh")
  })
  it("never leaves a live scheme behind", () => {
    expect(defangUrl("HTTP://Example.NET/x")).not.toMatch(/^https?:/i)
  })
})

describe("toLocalGrid", () => {
  it("shifts cells into local time and wraps around the week", () => {
    const cells = [
      { dow: 0, hour: 23, events: 5 },
      { dow: 6, hour: 23, events: 7 },
    ]
    const g = toLocalGrid(cells, 2)
    expect(g[1]?.[1]).toBe(5)
    expect(g[0]?.[1]).toBe(7) // Sunday 23:00 UTC is Monday 01:00 at +2
    const back = toLocalGrid([{ dow: 0, hour: 1, events: 3 }], -2)
    expect(back[6]?.[23]).toBe(3)
  })
  it("ignores invalid cells", () => {
    expect(
      toLocalGrid([{ dow: 9, hour: 3, events: 1 }], 0)
        .flat()
        .reduce((a, b) => a + b, 0),
    ).toBe(0)
  })
})

describe("findings", () => {
  it("names the busiest day and hour", () => {
    const cells = [
      { dow: 1, hour: 14, events: 90 },
      { dow: 3, hour: 2, events: 10 },
    ]
    const f = describeHeatmap(toLocalGrid(cells, 0), 7)
    expect(f.finding).toBe(
      "Tuesday is the busiest day and 14:00 the busiest hour, in your time zone.",
    )
    expect(describeHeatmap(toLocalGrid([], 0), 7).finding).toMatch(/No activity/)
  })

  const points: TagPoint[] = [
    { ts: "2026-10-18T00:00:00Z", tags: { recon: 50, php2shell: 10, other: 5 } },
    { ts: "2026-10-19T00:00:00Z", tags: { recon: 50, php2shell: 10, other: 5 } },
    { ts: "2026-10-20T00:00:00Z", tags: { recon: 40, php2shell: 60, other: 5 } },
    { ts: "2026-10-21T00:00:00Z", tags: { recon: 40, php2shell: 60, other: 5 } },
  ]
  it("totals tags and describes the leader", () => {
    expect(tagTotals(points)[0]).toEqual(["recon", 180])
    const f = describeTags(points, 7)
    expect(f.finding).toContain('"recon" is the most common tag')
    expect(describeTags([], 7).finding).toMatch(/No tagged activity/)
  })
  it("describes top lists", () => {
    const top = {
      field: "username" as const,
      total: 100,
      items: [
        { value: "root", count: 42, share: 0.42 },
        { value: "admin", count: 20, share: 0.2 },
      ],
    }
    expect(describeTop("username", top, 7).finding).toBe(
      '"root" was the most seen username in the last 7 days, in 42% of login attempts, ahead of "admin" (20%).',
    )
    expect(describeTop("url", undefined, 30).finding).toBe("No URLs recorded in the last 30 days.")
  })
  it("describes new values", () => {
    const items = [
      { value: "a", count: 3, first_seen: "2026-10-20T00:00:00Z" },
      { value: "b", count: 9, first_seen: "2026-10-21T00:00:00Z" },
    ]
    expect(describeNew("password", items, 7).finding).toBe(
      '2 passwords were never seen before this week; the most used is "b" (9 times).',
    )
    expect(describeNew("asn", [], 30).finding).toMatch(/No new networks/)
  })
  it("summarises malware", () => {
    const mk = (host: string, attempts: number): MalwareItem => ({
      url: `http://${host}/x`,
      host,
      first_seen: "",
      last_seen: "",
      attempts,
      sessions: 1,
      ips: 1,
      tools: ["wget"],
      sensors: ["ssh"],
      sha256: null,
      size: null,
      virustotal_url: null,
    })
    const s = summariseMalware([
      mk("a.example.net", 5),
      mk("a.example.net", 2),
      mk("b.example.org", 1),
    ])
    expect(s).toMatchObject({ urls: 3, attempts: 8, hosts: 2 })
    expect(describeMalware(s, true).finding).toBe(
      "At least 3 download URLs on 2 hosts, tried 8 times.",
    )
    expect(describeMalware(summariseMalware([]), false).finding).toMatch(/No download/)
  })
})
