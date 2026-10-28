/**
 * Mock handlers for the M13 endpoints (indicators, infrastructure graph, export). Only synthetic
 * data: documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), example
 * domains and made-up hashes. Nothing here resolves to a real host.
 */
import { delay, http, HttpResponse } from "msw"
import type { Session } from "@/lib/api"
import type { C2Address } from "@/lib/c2"
import {
  defangIndicator,
  type GraphEdge,
  type GraphNode,
  type IndicatorDetail,
  type IndicatorItem,
  type IndicatorRole,
  type IndicatorType,
  type InfrastructureGraph,
  type IntelAnswer,
} from "@/lib/infrastructure"

const LATENCY_MS = 170
const HOUR = 3_600_000
const iso = (ms: number) => new Date(ms).toISOString().replace(".000Z", "Z")

function hash(s: string | number): number {
  let h = 2166136261
  for (const c of String(s)) h = Math.imul(h ^ c.charCodeAt(0), 16777619)
  return (h >>> 0) / 4294967296
}

function hex(seed: string, length: number): string {
  let out = ""
  for (let i = 0; out.length < length; i++)
    out += Math.floor(hash(`${seed}${i}`) * 0xffffffff)
      .toString(16)
      .padStart(8, "0")
  return out.slice(0, length)
}

type Verdict = "known" | "unlisted" | "unchecked"

interface Spec {
  type: IndicatorType
  value: string
  role: IndicatorRole
  verdict: Verdict
  family: string | null
  ips: number
  sensors: string[]
  host?: string
}

const HOSTS: Spec[] = [
  { type: "ip", value: "203.0.113.66", role: "download_host", verdict: "known", family: "Mirai", ips: 18, sensors: ["ssh", "telnet"] },
  { type: "domain", value: "dl.example.net", role: "download_host", verdict: "known", family: "Gafgyt", ips: 11, sensors: ["telnet", "adb"] },
  { type: "ip", value: "198.51.100.77", role: "download_host", verdict: "known", family: "XMRig", ips: 9, sensors: ["ssh", "docker"] },
  { type: "domain", value: "cdn.example.org", role: "download_host", verdict: "unlisted", family: null, ips: 6, sensors: ["web", "ssh"] },
  { type: "domain", value: "files.example.com", role: "download_host", verdict: "known", family: "Kinsing", ips: 5, sensors: ["docker", "redis"] },
  { type: "ip", value: "203.0.113.141", role: "contacted_host", verdict: "known", family: "Mozi", ips: 4, sensors: ["telnet"] },
  { type: "domain", value: "pool.example.net", role: "contacted_host", verdict: "unlisted", family: null, ips: 3, sensors: ["ssh"] },
  { type: "domain", value: "updates.example.org", role: "download_host", verdict: "unchecked", family: null, ips: 2, sensors: ["web"] },
  { type: "ip", value: "198.51.100.9", role: "contacted_host", verdict: "unchecked", family: null, ips: 1, sensors: ["mssql"] },
  { type: "hash", value: hex("mirai", 64), role: "hash", verdict: "known", family: "trojan.mirai/gafgyt", ips: 8, sensors: ["ssh", "telnet"] },
  { type: "hash", value: hex("xmrig", 64), role: "hash", verdict: "known", family: "coinminer.xmrig", ips: 5, sensors: ["ssh", "docker"] },
  { type: "hash", value: hex("other", 64), role: "hash", verdict: "unlisted", family: null, ips: 2, sensors: ["web"] },
] // prettier-ignore

const URL_PATHS = ["bins/x86", "bins/arm7", "setup.sh", "xmrig.tar.gz", "update.php", "ld.so"]

const COUNTRIES = ["NL", "US", "CN", "RU", "DE", "BR", "IN", "VN", "FR", "ID"]
const ORGS = ["Example Cloud", "Example Hosting", "Example Telecom", "Example ISP", "Example Net"]
const SOURCES = Array.from({ length: 60 }, (_, i) => `192.0.2.${i + 10}`)

interface Built extends IndicatorItem {
  spec: Spec
}

function sourcesFor(spec: Spec, factor: number): string[] {
  const n = Math.max(1, Math.min(SOURCES.length, Math.round(spec.ips * factor)))
  return [...SOURCES]
    .sort((a, b) => hash(`${spec.value}${a}`) - hash(`${spec.value}${b}`))
    .slice(0, n)
}

function build(now: number): Built[] {
  const specs: Spec[] = [...HOSTS]
  // URLs on the payload hosts: fewer addresses than the host itself.
  for (const h of HOSTS.filter((x) => x.role === "download_host" && x.type !== "hash")) {
    URL_PATHS.slice(0, h.ips > 8 ? 3 : h.ips > 3 ? 2 : 1).forEach((path, i) => {
      specs.push({
        type: "url",
        value: `http://${h.value}/${path}`,
        role: "download_host",
        verdict:
          h.verdict === "known" && i === 0
            ? "known"
            : h.verdict === "known"
              ? "unlisted"
              : h.verdict,
        family: h.verdict === "known" && i === 0 ? h.family : null,
        ips: Math.max(1, Math.round(h.ips * (0.8 - i * 0.25))),
        sensors: h.sensors,
        host: h.value,
      })
    })
  }
  return specs
    .map((spec, i): Built => {
      const last = now - Math.floor(hash(`l${spec.value}`) * 5 * 24 * HOUR) - i * 600_000
      const sources = sourcesFor(spec, 1)
      return {
        id: i + 1,
        type: spec.type,
        value: spec.value,
        defanged: defangIndicator(spec.type, spec.value),
        role: spec.role,
        host: spec.host ?? null,
        first_seen: iso(last - Math.floor((2 + hash(`f${spec.value}`) * 18) * 24 * HOUR)),
        last_seen: iso(last),
        sightings: spec.ips * 3 + Math.round(hash(`s${spec.value}`) * 10),
        sensors: spec.sensors,
        sessions: Math.round(spec.ips * 1.6),
        ips: sources.length,
        checked: spec.verdict !== "unchecked",
        known: spec.verdict === "unchecked" ? null : spec.verdict === "known",
        family: spec.family,
        sources:
          spec.verdict === "unchecked"
            ? []
            : spec.type === "hash"
              ? ["virustotal"]
              : ["threatfox", "urlhaus"],
        spec,
      }
    })
    .sort((a, b) => b.last_seen.localeCompare(a.last_seen))
    .map((b, i) => ({ ...b, id: i + 1 }))
}

function intelFor(b: Built, now: number): IntelAnswer[] {
  if (b.spec.verdict === "unchecked") return []
  const checked = iso(now - Math.floor(hash(`c${b.id}`) * 20 * HOUR))
  const known = b.spec.verdict === "known"
  const sources: IntelAnswer["source"][] =
    b.type === "hash" ? ["virustotal"] : known ? ["threatfox", "urlhaus"] : ["urlhaus"]
  return sources.map((source) => ({
    source,
    known,
    family: known ? b.family : null,
    threat_type: known ? (source === "threatfox" ? "payload_delivery" : "malware_download") : null,
    tags: known
      ? [(b.family ?? "").toLowerCase().split(/[./]/)[0] ?? "", "elf"].filter(Boolean)
      : [],
    first_seen_ext: known ? b.first_seen : null,
    reference: known
      ? source === "threatfox"
        ? "https://threatfox.abuse.ch/ioc/1234567/"
        : source === "virustotal"
          ? `https://www.virustotal.com/gui/file/${b.value}`
          : "https://urlhaus.abuse.ch/host/example/"
      : null,
    checked_at: checked,
  }))
}

function graph(items: Built[], hours: number): InfrastructureGraph {
  const factor = hours <= 24 ? 0.45 : hours <= 168 ? 1 : 1.4
  const nodes: GraphNode[] = []
  const edges: GraphEdge[] = []
  const seen = new Set<string>()
  const families = new Map<string, number>()
  const shared: { value: string; type: IndicatorType; ips: number; srcs: string[] }[] = []
  for (const b of items.filter((x) => x.type !== "url")) {
    const srcs = sourcesFor(b.spec, factor)
    if (hours <= 24 && b.spec.ips < 3) continue
    nodes.push({
      id: `i:${b.id}`,
      kind: "indicator",
      label: b.defanged,
      weight: srcs.length,
      type: b.type,
      role: b.role,
      known: b.known,
      indicator_id: b.id,
    })
    for (const ip of srcs) {
      seen.add(ip)
      edges.push({
        source: `s:${ip}`,
        target: `i:${b.id}`,
        weight: 1 + Math.floor(hash(ip + b.value) * 4),
      })
    }
    if (b.family) {
      families.set(b.family, (families.get(b.family) ?? 0) + srcs.length)
      edges.push({
        source: `i:${b.id}`,
        target: `f:${b.family.toLowerCase()}`,
        weight: srcs.length,
      })
    }
    if (b.role === "download_host" && b.type !== "hash" && srcs.length >= 2)
      shared.push({ value: b.defanged, type: b.type, ips: srcs.length, srcs })
  }
  for (const [name, weight] of families)
    nodes.push({ id: `f:${name.toLowerCase()}`, kind: "family", label: name, weight })
  for (const ip of [...seen].sort()) {
    const idx = SOURCES.indexOf(ip)
    nodes.push({
      id: `s:${ip}`,
      kind: "source",
      label: ip,
      weight: edges.filter((e) => e.source === `s:${ip}`).reduce((a, e) => a + e.weight, 0),
      country: COUNTRIES[idx % COUNTRIES.length] ?? null,
    })
  }
  shared.sort((a, b) => b.ips - a.ips)
  return {
    window_hours: hours,
    nodes,
    edges,
    summary: {
      sources: seen.size,
      indicators: nodes.filter((n) => n.kind === "indicator").length,
      families: families.size,
      shared_hosts: shared.length,
      sources_on_shared_hosts: new Set(shared.flatMap((s) => s.srcs)).size,
      top_host: shared[0]?.value ?? null,
      top_host_sources: shared[0]?.ips ?? 0,
    },
    truncated: false,
  }
}

function strip(b: Built): IndicatorItem {
  return {
    id: b.id,
    type: b.type,
    value: b.value,
    defanged: b.defanged,
    role: b.role,
    host: b.host,
    first_seen: b.first_seen,
    last_seen: b.last_seen,
    sightings: b.sightings,
    sensors: b.sensors,
    sessions: b.sessions,
    ips: b.ips,
    checked: b.checked,
    known: b.known,
    family: b.family,
    sources: b.sources,
  }
}

function encodeCursor(offset: number) {
  return btoa(JSON.stringify({ o: offset })).replace(/=+$/, "")
}
function decodeCursor(raw: string | null): number {
  if (!raw) return 0
  try {
    const v = JSON.parse(atob(raw)) as { o?: number }
    return typeof v.o === "number" ? v.o : 0
  } catch {
    return 0
  }
}

const C2_BASE = Date.parse("2026-10-27T09:00:00Z")
const c2 = (
  address: string,
  kind: "ip" | "domain",
  port: number | null,
  confidence: "high" | "medium",
  families: string[],
  seed: string,
  sessions: number,
  ago: number,
): C2Address => {
  const hashes = [0, 1].map((i) => ({
    sha256: hex(`${seed}${i}`, 64),
    family: families[0] ?? null,
  }))
  const vt = `https://www.virustotal.com/gui/file/${hashes[0]?.sha256 ?? ""}`
  return {
    address,
    defanged:
      kind === "ip" ? address.replaceAll(".", "[.]") : address.replace(/\.(?=[^.]+$)/, "[.]"),
    kind,
    port,
    confidence,
    sources: confidence === "high" ? ["threatfox", "virustotal"] : ["virustotal"],
    families,
    hashes,
    hash_count: 2 + sessions,
    sessions,
    first_seen: iso(C2_BASE - (ago + 40) * HOUR),
    last_seen: iso(C2_BASE - ago * HOUR),
    references: confidence === "high" ? [vt, "https://threatfox.abuse.ch/ioc/1234567/"] : [vt],
  }
}

/** Synthetic probable C2 addresses: documentation ranges and example domains only. */
const C2_MOCK: C2Address[] = [
  c2("203.0.113.45", "ip", 4444, "high", ["Mirai"], "c2a", 6, 5),
  c2("c2.example.net", "domain", 443, "high", ["Gafgyt"], "c2b", 3, 14),
  c2("198.51.100.77", "ip", 8080, "medium", ["XMRig"], "c2c", 2, 30),
  c2("192.0.2.9", "ip", null, "medium", [], "c2d", 0, 52),
  c2("update.example.org", "domain", 8443, "medium", ["Mirai"], "c2e", 1, 70),
]

export function intelHandlers(sessions: readonly Session[] = []) {
  const now = Date.now()
  const items = build(now)

  const filtered = (u: URL) => {
    const type = u.searchParams.get("type")
    const role = u.searchParams.get("role")
    const known = u.searchParams.get("known")
    const family = u.searchParams.get("family")?.toLowerCase()
    const q = (u.searchParams.get("q") ?? "").toLowerCase()
    const hours = Number(u.searchParams.get("hours") ?? 0)
    const since = hours > 0 ? now - hours * HOUR : 0
    return items.filter(
      (b) =>
        Date.parse(b.last_seen) >= since &&
        (!type || b.type === type) &&
        (!role || b.role === role) &&
        (known === null || (known === "true" ? b.known === true : b.known !== true)) &&
        (!family || b.family?.toLowerCase() === family) &&
        (!q || b.value.toLowerCase().includes(q)),
    )
  }

  return [
    http.get("/api/v1/indicators/c2", async ({ request }) => {
      await delay(LATENCY_MS)
      const u = new URL(request.url)
      const limit = Math.min(200, Number(u.searchParams.get("limit") ?? 50))
      const offset = decodeCursor(u.searchParams.get("cursor"))
      return HttpResponse.json({
        items: C2_MOCK.slice(offset, offset + limit),
        next_cursor: offset + limit < C2_MOCK.length ? encodeCursor(offset + limit) : null,
      })
    }),

    http.get("/api/v1/indicators/export", ({ request }) => {
      const u = new URL(request.url)
      const rows = filtered(u).map(strip)
      if (u.searchParams.get("format") === "stix") {
        return HttpResponse.json(
          {
            type: "bundle",
            id: "bundle--00000000-0000-4000-8000-000000000000",
            objects: rows.map((r) => ({
              type: "indicator",
              spec_version: "2.1",
              name: r.defanged,
            })),
          },
          {
            headers: { "Content-Disposition": 'attachment; filename="suckerpot-indicators.json"' },
          },
        )
      }
      const csv = [
        "type,value,defanged,role",
        ...rows.map((r) => `${r.type},${r.value},${r.defanged},${r.role}`),
      ]
      return new HttpResponse(csv.join("\n"), {
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": 'attachment; filename="suckerpot.csv"',
        },
      })
    }),

    http.get("/api/v1/indicators/:id", async ({ params }) => {
      await delay(LATENCY_MS)
      const b = items.find((x) => String(x.id) === params.id)
      if (!b) return HttpResponse.json({ detail: "indicator not found" }, { status: 404 })
      const intel = intelFor(b, now)
      const linked = sessions.filter((s) => s.downloads > 0).slice(0, 8)
      const srcs = sourcesFor(b.spec, 1)
      const detail: IndicatorDetail = {
        indicator: strip(b),
        intel,
        not_checked: false,
        sessions: linked.map((s, i) => ({
          session_id: s.session_id,
          sensor: s.sensor,
          src_ip: srcs[i % srcs.length] ?? "192.0.2.10",
          seen_at: s.started_at,
          country: s.country,
          tags: s.tags,
        })),
        source_ips: srcs.slice(0, 12).map((ip, i) => ({
          ip,
          sessions: 1 + Math.floor(hash(ip + b.value) * 5),
          first_seen: iso(now - (3 + i) * 24 * HOUR),
          last_seen: iso(now - Math.floor(hash(ip) * 60) * 3_600_00 - i * 60_000),
          country: COUNTRIES[SOURCES.indexOf(ip) % COUNTRIES.length] ?? null,
          asn: 64500 + (SOURCES.indexOf(ip) % 5),
          org: ORGS[SOURCES.indexOf(ip) % ORGS.length] ?? null,
        })),
        related: items
          .filter(
            (x) =>
              x.id !== b.id &&
              (x.host === b.value || b.host === x.value || x.sensors[0] === b.sensors[0]),
          )
          .slice(0, 5)
          .map((x) => ({
            id: x.id,
            type: x.type,
            defanged: x.defanged,
            role: x.role,
            sessions: x.sessions,
          })),
        links_truncated: srcs.length > 12,
      }
      return HttpResponse.json(detail)
    }),

    http.get("/api/v1/indicators", async ({ request }) => {
      await delay(LATENCY_MS)
      const u = new URL(request.url)
      const limit = Math.min(200, Number(u.searchParams.get("limit") ?? 50))
      const all = filtered(u)
      const offset = decodeCursor(u.searchParams.get("cursor"))
      return HttpResponse.json({
        items: all.slice(offset, offset + limit).map(strip),
        next_cursor: offset + limit < all.length ? encodeCursor(offset + limit) : null,
      })
    }),

    http.get("/api/v1/infrastructure/graph", async ({ request }) => {
      await delay(LATENCY_MS)
      const hours = Number(new URL(request.url).searchParams.get("hours") ?? 168)
      return HttpResponse.json(graph(items, hours))
    }),
  ]
}
