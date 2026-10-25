/**
 * MSW handler for GET /search: the same five groups and the same rules as api/api/search.py
 * (prefix matching, at most five hits per group), over the mock sessions and a few fixed,
 * fictional campaigns, indicators and one CVE.
 */
import { delay, http, HttpResponse } from "msw"
import type { SearchGroup, SearchHit, SearchResponse } from "@/lib/search"
import { buildBenignFixtures } from "./benign"
import { buildFixtures } from "./fixtures"

const LATENCY_MS = 140
const LIMIT = 5

const sessions = [...buildFixtures(), ...buildBenignFixtures()].map((f) => f.session)

const CAMPAIGNS = [
  { id: 41, name: "Mirai loader over Telnet #41", sessions: 37, sources: 9, ageH: 3 },
  { id: 17, name: "Crypto-miner dropper over SSH #17", sessions: 12, sources: 4, ageH: 9 },
  { id: 8, name: "PHP2Shell sweep over Web #8", sessions: 58, sources: 21, ageH: 30 },
]

const INDICATORS = [
  {
    id: 7,
    type: "domain",
    value: "files[.]update-cdn[.]example",
    detail: "Serves downloads",
    count: 14,
  },
  { id: 8, type: "domain", value: "198[.]51[.]100[.]23", detail: "Serves downloads", count: 6 },
  {
    id: 9,
    type: "hash",
    value: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    detail: "File hash",
    count: 3,
  },
]

const CVES = [
  {
    id: "CVE-2099-10001",
    title: "Example PHP: unauthenticated code execution through upload-progress",
  },
]

function ipHits(q: string): SearchHit[] {
  const prefix = /^\d{1,3}(\.\d{1,3}){0,2}\.$/.test(q)
  const full = /^\d{1,3}(\.\d{1,3}){3}$/.test(q)
  if (!prefix && !full) return []
  const byIp = new Map<string, SearchHit>()
  for (const s of sessions) {
    if (full ? s.src_ip !== q : !s.src_ip.startsWith(q)) continue
    const hit = byIp.get(s.src_ip)
    if (hit) {
      hit.count = (hit.count ?? 0) + 1
      if (s.last_event_at > (hit.last_seen ?? "")) hit.last_seen = s.last_event_at
    } else {
      byIp.set(s.src_ip, {
        kind: "ip",
        value: s.src_ip,
        label: s.src_ip,
        detail: [s.country, s.org].filter(Boolean).join(" · ") || null,
        count: 1,
        last_seen: s.last_event_at,
        benign: s.benign === true,
      })
    }
  }
  return [...byIp.values()].sort((a, b) => (b.last_seen ?? "").localeCompare(a.last_seen ?? ""))
}

function group(kind: SearchGroup["kind"], hits: SearchHit[]): SearchGroup[] {
  return hits.length ? [{ kind, hits: hits.slice(0, LIMIT), more: hits.length > LIMIT }] : []
}

export function runSearch(raw: string): SearchResponse {
  const q = raw
    .trim()
    .replace(/\[\.\]/g, ".")
    .slice(0, 128)
  if (q.length < 2) return { q, groups: [] }
  const low = q.toLowerCase()
  const groups: SearchGroup[] = [...group("ip", ipHits(q))]
  if (/^cve-\d{4}-\d{4,7}$/.test(low)) {
    groups.push(
      ...group(
        "cve",
        CVES.filter((c) => c.id.toLowerCase() === low).map((c) => ({
          kind: "cve" as const,
          value: c.id,
          label: c.id,
          detail: c.title,
          count: null,
          last_seen: null,
          benign: false,
        })),
      ),
    )
  }
  const indicator = (i: (typeof INDICATORS)[number], kind: "hash" | "domain"): SearchHit => ({
    kind,
    value: String(i.id),
    label: i.value,
    detail: i.detail,
    count: i.count,
    last_seen: null,
    benign: false,
  })
  if (/^[0-9a-f]{8,128}$/.test(low)) {
    groups.push(
      ...group(
        "hash",
        INDICATORS.filter((i) => i.type === "hash" && i.value.startsWith(low)).map((i) =>
          indicator(i, "hash"),
        ),
      ),
    )
  } else if (low.includes(".") && !/^[\d.]+$/.test(low)) {
    groups.push(
      ...group(
        "domain",
        INDICATORS.filter(
          (i) => i.type === "domain" && i.value.replace(/\[\.\]/g, ".").startsWith(low),
        ).map((i) => indicator(i, "domain")),
      ),
    )
  }
  if (!low.includes(".") && !/^[0-9a-f]{8,128}$/.test(low)) {
    groups.push(
      ...group(
        "campaign",
        CAMPAIGNS.filter((c) => c.name.toLowerCase().startsWith(low) || String(c.id) === low).map(
          (c) => ({
            kind: "campaign" as const,
            value: String(c.id),
            label: c.name,
            detail: `${c.sources} sources, active`,
            count: c.sessions,
            last_seen: new Date(Date.now() - c.ageH * 3_600_000).toISOString(),
            benign: false,
          }),
        ),
      ),
    )
  }
  return { q, groups }
}

export const searchHandlers = [
  http.get("/api/v1/search", async ({ request }) => {
    await delay(LATENCY_MS)
    return HttpResponse.json(runSearch(new URL(request.url).searchParams.get("q") ?? ""))
  }),
]
