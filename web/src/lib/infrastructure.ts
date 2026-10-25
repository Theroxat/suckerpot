/**
 * Indicators and infrastructure: API shapes (api/api/indicators.py is the source of truth), the
 * plain-English finding the page opens with, and the pure layout of the flow diagram.
 *
 * Passive by design: an indicator is only ever text. The API sends it defanged
 * (`hxxp://files[.]host[.]tld/a.sh`) and nothing in the UI turns one into a link.
 */
import { API_BASE } from "./api"
import { plural } from "./format"

export const INDICATOR_TYPES = ["url", "domain", "ip", "hash"] as const
export type IndicatorType = (typeof INDICATOR_TYPES)[number]
export type IndicatorRole = "download_host" | "contacted_host" | "hash"
export type IntelSource = "urlhaus" | "threatfox" | "virustotal"

export const TYPE_LABELS: Record<IndicatorType, string> = {
  url: "URL",
  domain: "Domain",
  ip: "IP address",
  hash: "File hash",
}

export const ROLE_LABELS: Record<IndicatorRole, string> = {
  download_host: "Payload source",
  contacted_host: "Contacted",
  hash: "File hash",
}

export const SOURCE_LABELS: Record<IntelSource, string> = {
  urlhaus: "URLhaus",
  threatfox: "ThreatFox",
  virustotal: "VirusTotal",
}

export interface IndicatorItem {
  id: number
  type: IndicatorType
  /** Raw value. The UI never renders it: use `defanged`. */
  value: string
  defanged: string
  role: IndicatorRole
  host: string | null
  first_seen: string
  last_seen: string
  sightings: number
  sensors: string[]
  sessions: number
  ips: number
  /** At least one intel service answered. */
  checked: boolean
  known: boolean | null
  family: string | null
  sources: string[]
}

export interface IntelAnswer {
  source: IntelSource
  known: boolean
  family: string | null
  threat_type: string | null
  tags: string[]
  first_seen_ext: string | null
  reference: string | null
  checked_at: string
}

export interface SessionLink {
  session_id: string
  sensor: string
  src_ip: string
  seen_at: string
  country: string | null
  tags: string[]
}

export interface SourceIp {
  ip: string
  sessions: number
  first_seen: string
  last_seen: string
  country: string | null
  asn: number | null
  org: string | null
}

export interface RelatedIndicator {
  id: number
  type: IndicatorType
  defanged: string
  role: IndicatorRole
  sessions: number
}

export interface IndicatorDetail {
  indicator: IndicatorItem
  intel: IntelAnswer[]
  not_checked: boolean
  sessions: SessionLink[]
  source_ips: SourceIp[]
  related: RelatedIndicator[]
  links_truncated: boolean
}

export interface GraphNode {
  id: string
  kind: "source" | "indicator" | "family"
  label: string
  weight: number
  type?: IndicatorType | null
  role?: IndicatorRole | null
  known?: boolean | null
  country?: string | null
  indicator_id?: number | null
}

export interface GraphEdge {
  source: string
  target: string
  weight: number
}

export interface GraphSummary {
  sources: number
  indicators: number
  families: number
  shared_hosts: number
  sources_on_shared_hosts: number
  top_host: string | null
  top_host_sources: number
}

export interface InfrastructureGraph {
  window_hours: number
  nodes: GraphNode[]
  edges: GraphEdge[]
  summary: GraphSummary
  truncated: boolean
}

export interface IndicatorFilters {
  type?: string | undefined
  role?: string | undefined
  known?: string | undefined
  family?: string | undefined
  q?: string | undefined
}

// --- Time window ---------------------------------------------------------------

export const WINDOWS = [
  { value: "24", hours: 24, label: "24 hours", phrase: "in the last 24 hours" },
  { value: "168", hours: 168, label: "7 days", phrase: "this week" },
  { value: "720", hours: 720, label: "30 days", phrase: "this month" },
] as const

export function windowHours(raw: string | null): number {
  return WINDOWS.find((w) => w.value === raw)?.hours ?? 168
}

export function windowPhrase(hours: number): string {
  return (
    WINDOWS.find((w) => w.hours === hours)?.phrase ?? `in the last ${Math.round(hours / 24)} days`
  )
}

// --- Defanging (same rules as the API; used by the mock server) -------------------

/** `http://a.b/x` -> `hxxp://a[.]b/x`, `a.b` -> `a[.]b`, hashes unchanged. */
export function defangIndicator(type: IndicatorType, value: string): string {
  if (type === "hash") return value
  if (type !== "url") return value.replaceAll(".", "[.]")
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/is.exec(value)
  if (!m) return value.replaceAll(".", "[.]")
  const [, proto = "", host = "", rest = ""] = m
  const safe = proto
    .toLowerCase()
    .replace("http", "hxxp")
    .replace("ftp", "fxp")
    .replace("ldap", "ldxp")
  return `${safe}://${host.replaceAll(".", "[.]")}${rest}`
}

const DEFANGED_IPV4 = /\b(\d{1,3}\[\.\]\d{1,3})\[\.\]\d{1,3}\[\.\]\d{1,3}\b/g

/** Screenshot mode for defanged text: `203[.]0[.]113[.]66` -> `203[.]0[.]x[.]x`. */
export function maskDefanged(text: string): string {
  return text.replace(DEFANGED_IPV4, "$1[.]x[.]x")
}

/** A reference link is shown only when it points at one of the intel services. */
const LINK_PREFIXES = [
  "https://urlhaus.abuse.ch/",
  "https://threatfox.abuse.ch/",
  "https://www.virustotal.com/",
] as const

export function safeReference(url: string | null | undefined): string | null {
  return url && LINK_PREFIXES.some((p) => url.startsWith(p)) ? url : null
}

// --- Findings -------------------------------------------------------------------------

export interface Finding {
  finding: string
  detail: string
}

/** The sentence the page opens with, written from the graph summary. */
export function describeInfrastructure(s: GraphSummary, hours: number): Finding {
  const when = windowPhrase(hours)
  if (s.indicators === 0) {
    return {
      finding: `No indicators were recorded ${when}.`,
      detail:
        "Indicators are the URLs, hosts and file hashes attackers use. They appear here once a session mentions one.",
    }
  }
  if (s.shared_hosts > 0) {
    const finding = `${plural(s.sources_on_shared_hosts, "scanning IP")} fetched payloads from ${plural(
      s.shared_hosts,
      "shared host",
    )} ${when}.`
    const top = s.top_host
      ? `The busiest, ${s.top_host}, was used by ${plural(s.top_host_sources, "address", "addresses")}.`
      : ""
    const families =
      s.families > 0 ? ` ${plural(s.families, "malware family", "malware families")} linked.` : ""
    return { finding, detail: `${top}${families}`.trim() }
  }
  return {
    finding: `${plural(s.sources, "address", "addresses")} used ${plural(
      s.indicators,
      "indicator",
    )} ${when}, and no two shared a payload host.`,
    detail: "Hosts used by two or more addresses show up here as shared infrastructure.",
  }
}

export type IntelState = "known" | "listed-none" | "unchecked"

export function intelState(i: Pick<IndicatorItem, "checked" | "known">): IntelState {
  if (!i.checked) return "unchecked"
  return i.known ? "known" : "listed-none"
}

export const INTEL_LABELS: Record<IntelState, string> = {
  known: "Known malicious",
  "listed-none": "Not listed",
  unchecked: "Not checked",
}

// --- Flow diagram layout ------------------------------------------------------------------

export interface FlowNode extends GraphNode {
  /** Number of source addresses folded into a "+N more" node. */
  folded?: number
}

export interface FlowModel {
  sources: FlowNode[]
  indicators: FlowNode[]
  families: FlowNode[]
  edges: GraphEdge[]
  hidden: { sources: number; indicators: number; families: number }
}

export interface FlowLimits {
  sources: number
  indicators: number
  families: number
}

export const DEFAULT_FLOW_LIMITS: FlowLimits = { sources: 14, indicators: 12, families: 8 }

/**
 * Picks what fits on screen: the indicators used by the most addresses, the families they point
 * to, and the busiest source addresses. Every other source address folds into one "+N more"
 * node per picture, with its edges summed, so the diagram stays honest about what it leaves out.
 */
export function buildFlow(
  g: InfrastructureGraph,
  limits: FlowLimits = DEFAULT_FLOW_LIMITS,
): FlowModel {
  const byWeight = (a: GraphNode, b: GraphNode) => b.weight - a.weight || a.id.localeCompare(b.id)
  const allIndicators = g.nodes.filter((n) => n.kind === "indicator").sort(byWeight)
  const indicators = allIndicators.slice(0, limits.indicators)
  const chosen = new Set(indicators.map((n) => n.id))

  const famEdges = g.edges.filter((e) => chosen.has(e.source) && e.target.startsWith("f:"))
  const famIds = new Set(famEdges.map((e) => e.target))
  const allFamilies = g.nodes.filter((n) => n.kind === "family" && famIds.has(n.id)).sort(byWeight)
  const families = allFamilies.slice(0, limits.families)
  const famKept = new Set(families.map((n) => n.id))

  const srcEdges = g.edges.filter((e) => e.source.startsWith("s:") && chosen.has(e.target))
  const degree = new Map<string, { d: number; w: number }>()
  for (const e of srcEdges) {
    const cur = degree.get(e.source) ?? { d: 0, w: 0 }
    degree.set(e.source, { d: cur.d + 1, w: cur.w + e.weight })
  }
  const nodeById = new Map(g.nodes.map((n) => [n.id, n]))
  const ranked = [...degree.entries()]
    .sort((a, b) => b[1].d - a[1].d || b[1].w - a[1].w || a[0].localeCompare(b[0]))
    .map(([id]) => id)
  const shownIds = new Set(ranked.slice(0, limits.sources))
  const sources: FlowNode[] = ranked.slice(0, limits.sources).flatMap((id) => {
    const n = nodeById.get(id)
    return n ? [n] : []
  })
  const foldedCount = ranked.length - shownIds.size

  const edges: GraphEdge[] = []
  const folded = new Map<string, number>()
  for (const e of srcEdges) {
    if (shownIds.has(e.source)) edges.push(e)
    else folded.set(e.target, (folded.get(e.target) ?? 0) + e.weight)
  }
  if (foldedCount > 0) {
    sources.push({
      id: "s:folded",
      kind: "source",
      label: `${foldedCount} more ${foldedCount === 1 ? "address" : "addresses"}`,
      weight: [...folded.values()].reduce((a, b) => a + b, 0),
      folded: foldedCount,
    })
    for (const [target, weight] of folded) edges.push({ source: "s:folded", target, weight })
  }
  for (const e of famEdges) if (famKept.has(e.target)) edges.push(e)

  return {
    sources,
    indicators,
    families,
    edges,
    hidden: {
      sources: foldedCount,
      indicators: allIndicators.length - indicators.length,
      families: allFamilies.length - families.length,
    },
  }
}

// --- Export -------------------------------------------------------------------------------

export type ExportFormat = "csv" | "stix"

/** Same-origin API URL of the download. Filters are the ones the table uses. */
export function exportHref(format: ExportFormat, f: IndicatorFilters): string {
  const p = new URLSearchParams({ format })
  for (const k of ["type", "role", "known", "family", "q"] as const) {
    const v = f[k]
    if (v) p.set(k, v)
  }
  return `${API_BASE}/indicators/export?${p.toString()}`
}
