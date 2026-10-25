import { describe, expect, it } from "vitest"
import {
  buildFlow,
  defangIndicator,
  describeInfrastructure,
  exportHref,
  intelState,
  maskDefanged,
  safeReference,
  windowHours,
  type GraphEdge,
  type GraphNode,
  type GraphSummary,
  type InfrastructureGraph,
} from "./infrastructure"

const summary = (over: Partial<GraphSummary> = {}): GraphSummary => ({
  sources: 60,
  indicators: 14,
  families: 3,
  shared_hosts: 2,
  sources_on_shared_hosts: 40,
  top_host: "203[.]0[.]113[.]66",
  top_host_sources: 18,
  ...over,
})

describe("describeInfrastructure", () => {
  it("opens with the shared-infrastructure finding", () => {
    const f = describeInfrastructure(summary(), 168)
    expect(f.finding).toBe("40 scanning IPs fetched payloads from 2 shared hosts this week.")
    expect(f.detail).toContain("203[.]0[.]113[.]66")
    expect(f.detail).toContain("18 addresses")
    expect(f.detail).toContain("3 malware families")
  })

  it("uses singular forms and the chosen window", () => {
    const f = describeInfrastructure(
      summary({ shared_hosts: 1, sources_on_shared_hosts: 1, families: 0, top_host_sources: 1 }),
      24,
    )
    expect(f.finding).toBe(
      "1 scanning IP fetched payloads from 1 shared host in the last 24 hours.",
    )
    expect(describeInfrastructure(summary(), 720).finding).toContain("this month")
    expect(describeInfrastructure(summary(), 48).finding).toContain("in the last 2 days")
  })

  it("says so when nothing is shared, or nothing is recorded", () => {
    expect(describeInfrastructure(summary({ shared_hosts: 0 }), 168).finding).toBe(
      "60 addresses used 14 indicators this week, and no two shared a payload host.",
    )
    expect(describeInfrastructure(summary({ indicators: 0 }), 168).finding).toBe(
      "No indicators were recorded this week.",
    )
  })
})

describe("defanging", () => {
  it("defangs URLs, hosts and addresses, and leaves hashes alone", () => {
    expect(defangIndicator("url", "http://files.badhost.ru/a.b")).toBe(
      "hxxp://files[.]badhost[.]ru/a.b",
    )
    expect(defangIndicator("url", "https://1.2.3.4:8080/x")).toBe("hxxps://1[.]2[.]3[.]4:8080/x")
    expect(defangIndicator("url", "ftp://h.example/")).toBe("fxp://h[.]example/")
    expect(defangIndicator("domain", "files.badhost.ru")).toBe("files[.]badhost[.]ru")
    expect(defangIndicator("ip", "8.8.4.4")).toBe("8[.]8[.]4[.]4")
    expect(defangIndicator("hash", "ab".repeat(32))).toBe("ab".repeat(32))
  })

  it("masks an address inside defanged text", () => {
    expect(maskDefanged("hxxp://203[.]0[.]113[.]66/bins/x86")).toBe(
      "hxxp://203[.]0[.]x[.]x/bins/x86",
    )
    expect(maskDefanged("files[.]badhost[.]ru")).toBe("files[.]badhost[.]ru")
  })
})

describe("references and verdicts", () => {
  it("links only to the intel services", () => {
    expect(safeReference("https://urlhaus.abuse.ch/url/1/")).not.toBeNull()
    expect(safeReference("https://threatfox.abuse.ch/ioc/1/")).not.toBeNull()
    expect(safeReference("https://www.virustotal.com/gui/file/ab")).not.toBeNull()
    for (const bad of [null, undefined, "", "http://urlhaus.abuse.ch/", "https://evil.example/x"])
      expect(safeReference(bad)).toBeNull()
    expect(safeReference("javascript:alert(1)")).toBeNull()
    expect(safeReference("https://urlhaus.abuse.ch.evil.example/")).toBeNull()
  })

  it("tells known, not listed and not checked apart", () => {
    expect(intelState({ checked: true, known: true })).toBe("known")
    expect(intelState({ checked: true, known: false })).toBe("listed-none")
    expect(intelState({ checked: false, known: null })).toBe("unchecked")
  })
})

describe("exportHref and windowHours", () => {
  it("keeps the active filters, same origin", () => {
    expect(exportHref("csv", { type: "domain", q: "bins" })).toBe(
      "/api/v1/indicators/export?format=csv&type=domain&q=bins",
    )
    expect(exportHref("stix", {})).toBe("/api/v1/indicators/export?format=stix")
    expect(exportHref("csv", { q: "a&b=c" })).toContain("q=a%26b%3Dc")
  })

  it("defaults to a week", () => {
    expect(windowHours(null)).toBe(168)
    expect(windowHours("24")).toBe(24)
    expect(windowHours("720")).toBe(720)
    expect(windowHours("999999")).toBe(168)
  })
})

function bigGraph(sources: number, indicators: number): InfrastructureGraph {
  const nodes: GraphNode[] = []
  const edges: GraphEdge[] = []
  for (let i = 0; i < indicators; i++) {
    nodes.push({
      id: `i:${i}`,
      kind: "indicator",
      label: `h${i}`,
      weight: 100 - i,
      type: "domain",
      role: "download_host",
      known: i % 2 === 0,
      indicator_id: i,
    })
    edges.push({ source: `i:${i}`, target: `f:fam${i % 12}`, weight: 100 - i })
  }
  for (let f = 0; f < 12; f++)
    nodes.push({ id: `f:fam${f}`, kind: "family", label: `Fam${f}`, weight: 50 - f })
  for (let s = 0; s < sources; s++) {
    nodes.push({ id: `s:192.0.2.${s}`, kind: "source", label: `192.0.2.${s}`, weight: s })
    for (let i = 0; i < Math.min(indicators, 1 + (s % 3)); i++)
      edges.push({ source: `s:192.0.2.${s}`, target: `i:${i}`, weight: 1 })
  }
  return { window_hours: 168, nodes, edges, summary: summary(), truncated: false }
}

describe("buildFlow", () => {
  it("shows everything when it fits", () => {
    const flow = buildFlow(bigGraph(5, 3))
    expect(flow.sources).toHaveLength(5)
    expect(flow.indicators).toHaveLength(3)
    expect(flow.hidden).toEqual({ sources: 0, indicators: 0, families: 0 })
    expect(flow.sources.some((s) => s.folded !== undefined)).toBe(false)
  })

  it("caps each column and folds the rest into one honest node", () => {
    const g = bigGraph(200, 40)
    const flow = buildFlow(g)
    expect(flow.indicators).toHaveLength(12)
    expect(flow.families.length).toBeLessThanOrEqual(8)
    expect(flow.sources.length).toBeLessThanOrEqual(15)
    expect(flow.hidden.indicators).toBe(28)
    const folded = flow.sources.find((s) => s.folded !== undefined)
    expect(folded?.folded).toBe(flow.hidden.sources)
    expect(flow.hidden.sources).toBeGreaterThan(0)
    // every edge connects nodes that are on screen
    const ids = new Set([...flow.sources, ...flow.indicators, ...flow.families].map((n) => n.id))
    expect(flow.edges.every((e) => ids.has(e.source) && ids.has(e.target))).toBe(true)
    // the folded node keeps the weight of the addresses it stands for
    const folds = flow.edges.filter((e) => e.source === "s:folded")
    expect(folds.length).toBeGreaterThan(0)
    expect(folded?.weight).toBe(folds.reduce((a, e) => a + e.weight, 0))
  })

  it("is deterministic and handles an empty graph", () => {
    const g = bigGraph(30, 20)
    expect(buildFlow(g)).toEqual(buildFlow(g))
    const empty = buildFlow({ ...g, nodes: [], edges: [] })
    expect(empty.sources).toEqual([])
    expect(empty.indicators).toEqual([])
  })
})

describe("buildFlow ordering", () => {
  const node = (id: string, kind: GraphNode["kind"], weight = 1): GraphNode => ({
    id,
    kind,
    label: id.slice(2),
    weight,
  })
  const g: InfrastructureGraph = {
    window_hours: 168,
    truncated: false,
    summary: summary(),
    nodes: [
      node("i:a", "indicator", 3),
      node("i:b", "indicator", 2),
      node("f:late", "family", 9),
      node("f:early", "family", 1),
      node("s:1", "source"),
      node("s:2", "source"),
      node("s:3", "source"),
    ],
    edges: [
      // s:1 and s:2 (the busiest) only use the second indicator, s:3 the first.
      { source: "s:1", target: "i:b", weight: 5 },
      { source: "s:1", target: "i:a", weight: 1 },
      { source: "s:2", target: "i:b", weight: 4 },
      { source: "s:3", target: "i:a", weight: 1 },
      { source: "i:a", target: "f:early", weight: 1 },
      { source: "i:b", target: "f:late", weight: 1 },
    ],
  }

  it("places addresses and families next to the indicators they use", () => {
    const flow = buildFlow(g)
    expect(flow.indicators.map((n) => n.id)).toEqual(["i:a", "i:b"])
    expect(flow.sources.map((n) => n.id)).toEqual(["s:3", "s:1", "s:2"])
    expect(flow.families.map((n) => n.id)).toEqual(["f:early", "f:late"])
  })

  it("keeps the folded node last", () => {
    const flow = buildFlow(bigGraph(200, 40))
    expect(flow.sources.at(-1)?.folded).toBeGreaterThan(0)
  })
})
