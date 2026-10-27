import { describe, expect, it } from "vitest"
import { buildStory } from "@/mocks/story"
import {
  STAGES,
  bucketMs,
  bucketSentence,
  busiestBucket,
  doorRows,
  flowFinding,
  linkHref,
  orderFlow,
  originRows,
  sankeyData,
  type FlowNode,
  type StoryResponse,
} from "./story"

const flow = buildStory(24).flow

const node = (over: Partial<FlowNode>): FlowNode => ({
  id: "x",
  column: "origin",
  key: "x",
  label: "X",
  technical: "",
  sessions: 1,
  href: "/attacks",
  ...over,
})

describe("orderFlow", () => {
  it("orders stages from looked to exploit whatever the API sends", () => {
    const shuffled: StoryResponse["flow"] = { nodes: [...flow.nodes].reverse(), links: flow.links }
    const stages = orderFlow(shuffled)
      .nodes.filter((n) => n.column === "stage")
      .map((n) => n.key)
    expect(stages).toEqual([...STAGES])
  })

  it("puts origins by size with 'other' last, and columns left to right", () => {
    const { nodes } = orderFlow(flow)
    const rank = { origin: 0, door: 1, stage: 2 }
    const columns = nodes.map((n) => rank[n.column])
    expect(columns).toEqual([...columns].sort((a, b) => a - b))
    const origins = nodes.filter((n) => n.column === "origin")
    expect(origins.at(-1)?.key).toBe("other")
    const sized = origins.slice(0, -1).map((n) => n.sessions)
    expect(sized).toEqual([...sized].sort((a, b) => b - a))
  })

  it("drops empty nodes and links that point nowhere", () => {
    const f: StoryResponse["flow"] = {
      nodes: [
        node({ id: "a" }),
        node({ id: "b", column: "door", key: "ssh" }),
        node({ id: "c", sessions: 0 }),
      ],
      links: [
        { source: "a", target: "b", value: 3 },
        { source: "a", target: "c", value: 2 },
        { source: "a", target: "ghost", value: 1 },
        { source: "a", target: "b", value: 0 },
      ],
    }
    const out = orderFlow(f)
    expect(out.nodes.map((n) => n.id)).toEqual(["a", "b"])
    expect(out.links).toEqual([{ source: "a", target: "b", value: 3 }])
  })
})

describe("sankeyData", () => {
  it("uses indexes into the ordered node list", () => {
    const s = sankeyData(flow)
    for (const l of s.links) {
      expect(s.nodes[l.source]).toBeDefined()
      expect(s.nodes[l.target]).toBeDefined()
      expect(s.nodes[l.source]?.column).not.toBe("stage")
    }
  })
})

describe("doorRows (mobile fallback)", () => {
  it("gives one row per door, busiest first, with segments in stage order", () => {
    const rows = doorRows(flow)
    expect(rows.map((r) => r.node.key).sort()).toEqual(["rdp", "ssh", "telnet", "web"])
    const totals = rows.map((r) => r.total)
    expect(totals).toEqual([...totals].sort((a, b) => b - a))
    for (const r of rows) {
      const ranks = r.segments.map((s) => STAGES.indexOf(s.stage))
      expect(ranks).toEqual([...ranks].sort((a, b) => a - b))
      expect(r.segments.reduce((n, s) => n + s.value, 0)).toBe(r.total)
    }
  })

  it("lists origins for the first column", () => {
    expect(originRows(flow)[0]?.key).toBe("NL")
  })
})

describe("linkHref", () => {
  it("narrows a stage view to the door it passes through", () => {
    const door = node({ id: "door:ssh", column: "door", key: "ssh", href: "/attacks?sensor=ssh" })
    const stage = node({
      id: "stage:exploit",
      column: "stage",
      key: "exploit",
      href: "/attacks?tag=php2shell",
    })
    const origin = node({ id: "origin:NL", key: "NL", href: "/attacks?country=NL" })
    expect(linkHref(door, stage)).toBe("/attacks?tag=php2shell&sensor=ssh")
    expect(linkHref(origin, door)).toBe("/attacks?country=NL&sensor=ssh")
  })
})

describe("timeline", () => {
  const { timeline } = buildStory(24)
  it("knows its bucket size and busiest bucket", () => {
    expect(bucketMs(timeline)).toBe(3_600_000)
    expect(bucketMs(buildStory(6).timeline)).toBe(900_000)
    const i = busiestBucket(timeline)
    expect(timeline[i]?.sessions).toBe(Math.max(...timeline.map((b) => b.sessions)))
    expect(busiestBucket([])).toBe(-1)
  })

  it("writes one plain sentence per bucket", () => {
    const b = {
      start: "2026-10-27T10:00:00Z",
      sessions: 912,
      by_door: { ssh: 700, web: 212 },
      by_stage: {},
      severe: 3,
    }
    const s = bucketSentence(b, 3_600_000)
    expect(s).toMatch(/912 visits came in, mostly to SSH\./)
    expect(s).toMatch(/3 tried to install something or sent an exploit\./)
    expect(bucketSentence({ ...b, sessions: 0, severe: 0 }, 3_600_000)).toMatch(/nothing knocked/)
  })
})

describe("flowFinding", () => {
  it("reads as a finding", () => {
    const t = buildStory(24).totals
    expect(flowFinding(t)).toMatch(/^\d+% of visits never got past the door\./)
    expect(flowFinding({ ...t, sessions: 0 })).toBe("Nothing knocked on your doors.")
  })
})
