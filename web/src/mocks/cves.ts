/**
 * Mock handlers for the CVE watch endpoints. Everything is fictional: ids are in the reserved
 * CVE-2099-* style, products and vendors are made up, links go to example.com.
 */
import { delay, http, HttpResponse } from "msw"
import type { CveDetail, CveItem, CveSync, Relevance } from "@/lib/cves"

const LATENCY_MS = 160
const HOUR = 3_600_000
const DAY = 24 * HOUR

const iso = (ms: number) => new Date(ms).toISOString().replace(".000Z", "Z")

interface Seed {
  id: string
  title: string
  vendor: string
  product: string
  score: number
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  kev?: boolean
  relevance: Relevance
  services: string[]
  tags?: string[]
  seen?: number
  ageH: number
  description: string
}

const SEEDS: Seed[] = [
  {
    id: "CVE-2099-10001",
    title: "Example PHP: unauthenticated code execution through upload-progress",
    vendor: "Example Project",
    product: "PHP",
    score: 9.2,
    severity: "CRITICAL",
    kev: true,
    relevance: "high",
    services: ["web-php"],
    tags: ["php2shell"],
    seen: 38,
    ageH: 30,
    description:
      "A fictional flaw in the session upload-progress feature lets a remote attacker run code on servers using the module build. Used here as demo data.",
  },
  {
    id: "CVE-2099-10002",
    title: "Example Redis: sandbox escape in Lua scripting",
    vendor: "Example Cache",
    product: "Redis",
    score: 9.8,
    severity: "CRITICAL",
    relevance: "high",
    services: ["redis"],
    ageH: 52,
    description: "A fictional use-after-free in the scripting engine of an in-memory data store.",
  },
  {
    id: "CVE-2099-10003",
    title: "Example OpenSSH: pre-authentication race in the login grace timer",
    vendor: "Example BSD",
    product: "OpenSSH",
    score: 8.1,
    severity: "HIGH",
    kev: true,
    relevance: "high",
    services: ["openssh"],
    ageH: 80,
    description: "A fictional signal-handler race that may allow remote code execution as root.",
  },
  {
    id: "CVE-2099-10004",
    title: "Example Remote Desktop Services: pre-auth channel handling flaw",
    vendor: "Example Corp",
    product: "Windows Remote Desktop Services",
    score: 9.8,
    severity: "CRITICAL",
    kev: true,
    relevance: "high",
    services: ["windows-rdp"],
    tags: ["bluekeep"],
    seen: 6,
    ageH: 120,
    description:
      "A fictional wormable flaw in how virtual channels are bound before authentication.",
  },
  {
    id: "CVE-2099-10005",
    title: "Example Docker Engine: container escape through a crafted build context",
    vendor: "Example Containers",
    product: "Docker Engine",
    score: 8.6,
    severity: "HIGH",
    relevance: "high",
    services: ["docker-engine"],
    ageH: 150,
    description:
      "A fictional path handling flaw in the build context that writes outside the sandbox.",
  },
  {
    id: "CVE-2099-10006",
    title: "Example WordPress plugin: SQL injection in the booking form",
    vendor: "Example Plugins",
    product: "Booking Calendar",
    score: 7.5,
    severity: "HIGH",
    relevance: "medium",
    services: ["wordpress"],
    ageH: 40,
    description: "A fictional unauthenticated SQL injection in a WordPress booking plugin.",
  },
  {
    id: "CVE-2099-10007",
    title: "Example Asterisk: SIP INVITE parsing overflow",
    vendor: "Example Telephony",
    product: "Asterisk",
    score: 7.3,
    severity: "HIGH",
    relevance: "high",
    services: ["asterisk-sip"],
    ageH: 200,
    description: "A fictional stack overflow while parsing an oversized header in a SIP INVITE.",
  },
  {
    id: "CVE-2099-10008",
    title: "Example SQL Server: privilege escalation through a linked-server query",
    vendor: "Example Corp",
    product: "SQL Server",
    score: 8.8,
    severity: "HIGH",
    relevance: "high",
    services: ["mssql"],
    ageH: 260,
    description: "A fictional flaw letting a low-privileged login run commands on the host.",
  },
  {
    id: "CVE-2099-10009",
    title: "Example BusyBox telnetd: argument injection in the login helper",
    vendor: "Example Embedded",
    product: "BusyBox",
    score: 6.5,
    severity: "MEDIUM",
    relevance: "high",
    services: ["busybox-telnet"],
    ageH: 300,
    description: "A fictional argument injection reachable before authentication on small routers.",
  },
  {
    id: "CVE-2099-10010",
    title: "Example MySQL: crash on a malformed handshake packet",
    vendor: "Example DB",
    product: "MySQL Server",
    score: 5.3,
    severity: "MEDIUM",
    relevance: "high",
    services: ["mysql"],
    ageH: 340,
    description: "A fictional denial of service reachable from the network before login.",
  },
  {
    id: "CVE-2099-10011",
    title: "Example SMB server: information leak in a compound request",
    vendor: "Example Corp",
    product: "Windows SMB",
    score: 7.5,
    severity: "HIGH",
    kev: true,
    relevance: "high",
    services: ["windows-smb"],
    tags: ["eternalblue"],
    seen: 0,
    ageH: 400,
    description: "A fictional memory disclosure in compound SMB request handling.",
  },
  {
    id: "CVE-2099-10012",
    title: "Example ADB bridge: authentication bypass over the network",
    vendor: "Example Mobile",
    product: "Android Debug Bridge",
    score: 8.2,
    severity: "HIGH",
    relevance: "high",
    services: ["android-adb"],
    ageH: 500,
    description: "A fictional bypass of the host key prompt in a network debug bridge.",
  },
  {
    id: "CVE-2099-10013",
    title: "Example phpMyAdmin clone: stored XSS in the table browser",
    vendor: "Example Tools",
    product: "DB Admin Console",
    score: 5.4,
    severity: "MEDIUM",
    relevance: "medium",
    services: ["phpmyadmin"],
    ageH: 600,
    description: "A fictional stored cross-site scripting issue in a web database console.",
  },
  {
    id: "CVE-2026-13639",
    title: "Synology DSM: session forgery lets an unauthenticated attacker act as an admin",
    vendor: "Synology",
    product: "DiskStation Manager",
    score: 9.8,
    severity: "CRITICAL",
    kev: true,
    relevance: "high",
    services: ["synology-dsm"],
    tags: ["synology-exploit"],
    seen: 11,
    ageH: 38,
    description:
      "A forged session identifier is accepted by the DSM web API without authentication. Fixed on 2026-09-18 in Synology-SA-26:13.",
  },
  {
    id: "CVE-2026-13684",
    title: "Synology DSM: request injection in the web API gateway leads to file write",
    vendor: "Synology",
    product: "DiskStation Manager",
    score: 9.8,
    severity: "CRITICAL",
    relevance: "high",
    services: ["synology-dsm"],
    tags: ["synology-exploit", "c3rb3r"],
    seen: 4,
    ageH: 38,
    description:
      "An injected request reaches the internal gateway and lets an unauthenticated attacker write files on the NAS. Fixed on 2026-09-18 in Synology-SA-26:13.",
  },
]

const FILLER_VENDORS = ["Acme Labs", "Contoso Soft", "Initech", "Globex", "Umbrella Ltd", "Hooli"]
const FILLER_KINDS = [
  "heap overflow in the image decoder",
  "path traversal in the file manager",
  "open redirect in the login page",
  "insecure default credentials",
  "denial of service in the HTTP/2 parser",
  "command injection in the diagnostics page",
]

function hash(s: string | number): number {
  let h = 2166136261
  for (const c of String(s)) h = Math.imul(h ^ c.charCodeAt(0), 16777619)
  return (h >>> 0) / 4294967296
}

function buildItems(now: number): { item: CveItem; seed: Seed | null }[] {
  const hand = SEEDS.map((s): { item: CveItem; seed: Seed | null } => ({
    seed: s,
    item: {
      cve_id: s.id,
      title: s.title,
      description: s.description,
      vendor: s.vendor,
      product: s.product,
      published_at: iso(now - s.ageH * HOUR),
      modified_at: iso(now - s.ageH * HOUR + 6 * HOUR),
      cvss_score: s.score,
      cvss_severity: s.severity,
      in_kev: Boolean(s.kev),
      kev_added_at: s.kev ? iso(now - (s.ageH - 8) * HOUR).slice(0, 10) : null,
      kev_due_date: s.kev ? iso(now + 14 * DAY).slice(0, 10) : null,
      kev_ransomware: s.kev ? s.id.endsWith("4") : null,
      relevance: s.relevance,
      matched_services: s.services,
      tags: s.tags ?? [],
      sources: s.kev ? ["kev", "nvd"] : ["nvd", "github"],
      seen_sessions: s.seen ?? 0,
    },
  }))
  const filler = Array.from({ length: 70 }, (_, i): { item: CveItem; seed: Seed | null } => {
    const score = Math.round((2 + hash(`s${i}`) * 7.4) * 10) / 10
    const severity = score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW"
    const vendor = FILLER_VENDORS[i % FILLER_VENDORS.length] ?? "Acme Labs"
    const kind = FILLER_KINDS[i % FILLER_KINDS.length] ?? "flaw"
    return {
      seed: null,
      item: {
        cve_id: `CVE-2099-${20001 + i}`,
        title: `${vendor} Product ${i + 1}: ${kind}`,
        description: `A fictional ${kind}. Demo data only.`,
        vendor,
        product: `Product ${i + 1}`,
        published_at: iso(now - (60 + i * 11) * HOUR),
        modified_at: null,
        cvss_score: score,
        cvss_severity: severity,
        in_kev: i % 17 === 0,
        kev_added_at: null,
        kev_due_date: null,
        kev_ransomware: null,
        relevance: "none",
        matched_services: [],
        tags: [],
        sources: ["nvd"],
        seen_sessions: 0,
      },
    }
  })
  return [...hand, ...filler]
}

function rank(c: CveItem): number {
  const w = { high: 3, medium: 2, none: 0 }[c.relevance]
  return w * 100_000 + (c.in_kev ? 10_000 : 0) + Math.round((c.cvss_score ?? 0) * 100)
}

function encodeCursor(offset: number) {
  return btoa(JSON.stringify([offset, "x"])).replace(/=+$/, "")
}
function decodeCursor(raw: string | null): number {
  if (!raw) return 0
  try {
    const v = JSON.parse(atob(raw)) as unknown
    return Array.isArray(v) && typeof v[0] === "number" ? v[0] : 0
  } catch {
    return 0
  }
}

export function cveHandlers() {
  const now = Date.now()
  const all = buildItems(now).sort((a, b) => rank(b.item) - rank(a.item))

  return [
    http.get("/api/v1/cves/sync", async () => {
      await delay(LATENCY_MS)
      const body: CveSync = {
        sources: [
          {
            source: "kev",
            last_run_at: iso(now - 3 * HOUR),
            last_success_at: iso(now - 3 * HOUR),
            last_error: null,
            items_last_run: 1_560,
          },
          {
            source: "nvd",
            last_run_at: iso(now - 3 * HOUR),
            last_success_at: iso(now - 3 * HOUR),
            last_error: null,
            items_last_run: 842,
          },
          {
            source: "github",
            last_run_at: iso(now - 3 * HOUR),
            last_success_at: iso(now - 27 * HOUR),
            last_error: "rate_limited",
            items_last_run: 120,
          },
        ],
        total: all.length,
        relevant: all.filter((c) => c.item.relevance !== "none").length,
        kev: all.filter((c) => c.item.in_kev).length,
        nvd_key_configured: false,
        github_key_configured: false,
      }
      return HttpResponse.json(body)
    }),

    http.get("/api/v1/cves/:id", async ({ params }) => {
      await delay(LATENCY_MS)
      const found = all.find((c) => c.item.cve_id === params.id)
      if (!found) return HttpResponse.json({ detail: "CVE not found" }, { status: 404 })
      const { item, seed } = found
      const seen = item.seen_sessions
      const body: CveDetail = {
        item,
        description_full: item.description,
        cwes: ["CWE-94"],
        ghsa_ids: item.sources.includes("github") ? ["GHSA-cfgh-2345-wxvq"] : [],
        refs: [
          `https://example.com/advisories/${item.cve_id.toLowerCase()}`,
          "https://example.com/blog/patch-notes",
        ],
        cpes: [],
        kev_action: item.in_kev ? "Apply the vendor update or stop using the product." : null,
        traffic: {
          sessions: seen,
          ips: Math.max(seen > 0 ? 1 : 0, Math.round(seen * 0.4)),
          first_seen: seen > 0 ? iso(now - 20 * HOUR) : null,
          last_seen: seen > 0 ? iso(now - 25 * 60_000) : null,
          by_tag: seen > 0 && seed?.tags?.[0] ? [{ tag: seed.tags[0], sessions: seen }] : [],
        },
      }
      return HttpResponse.json(body)
    }),

    http.get("/api/v1/cves", async ({ request }) => {
      await delay(LATENCY_MS)
      const u = new URL(request.url)
      const relevance = u.searchParams.get("relevance")
      const severity = u.searchParams.get("severity")
      const kev = u.searchParams.get("kev")
      const since = u.searchParams.get("since")
      const q = (u.searchParams.get("q") ?? "").toLowerCase()
      const limit = Math.min(100, Number(u.searchParams.get("limit") ?? 25))
      const matches = all.filter(({ item }) => {
        if (relevance === "relevant" && item.relevance === "none") return false
        if (relevance && relevance !== "relevant" && item.relevance !== relevance) return false
        if (kev === "true" && !item.in_kev) return false
        if (severity && item.cvss_severity?.toLowerCase() !== severity) return false
        if (since && item.published_at && item.published_at < since) return false
        if (q) {
          const hay = `${item.cve_id} ${item.title ?? ""} ${item.vendor ?? ""} ${item.product ?? ""}`
          if (!hay.toLowerCase().includes(q)) return false
        }
        return true
      })
      const offset = decodeCursor(u.searchParams.get("cursor"))
      return HttpResponse.json({
        items: matches.slice(offset, offset + limit).map((m) => m.item),
        next_cursor: offset + limit < matches.length ? encodeCursor(offset + limit) : null,
        total: matches.length,
      })
    }),
  ]
}
