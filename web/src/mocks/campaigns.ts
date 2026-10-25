/**
 * Mock handlers for the M15 endpoints (campaigns, stories, ATT&CK matrix). Campaigns are
 * derived from the fixture sessions by their tags, the way ingest would group them, and the
 * sessions get `techniques` and `campaign_id` so the Attacks list, the session page and the
 * campaign pages agree. Only synthetic data: documentation addresses and example domains.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type { Page, Session } from "@/lib/api"
import {
  STAGES,
  STAGE_META,
  type Campaign,
  type CampaignIndicator,
  type CampaignStory,
  type CampaignTimeline,
  type ExcerptLine,
  type Matrix,
  type MatrixRow,
  type Stage,
  type StoryStage,
  type TechniqueItem,
} from "@/lib/campaigns"
import { SENSORS } from "@/lib/sensors"
import type { Severity } from "@/lib/severity"
import type { Fixture } from "./fixtures"

const LATENCY_MS = 170
const HOUR = 3_600_000
const DAY = 86_400_000
const iso = (ms: number) => new Date(ms).toISOString().replace(".000Z", "Z")

function hash(s: string | number): number {
  let h = 2166136261
  for (const c of String(s)) h = Math.imul(h ^ c.charCodeAt(0), 16777619)
  return (h >>> 0) / 4294967296
}

// --- the catalogue (a copy of ingest/rules/attack/techniques.yaml, with the API's plain text) ----

interface Tech {
  id: string
  name: string
  tactic: string
  stage: Stage
  plain: string
}

const CATALOGUE: Tech[] = [
  {
    id: "T1595",
    name: "Active Scanning",
    tactic: "reconnaissance",
    stage: "recon",
    plain: "scanned the machine for open services",
  },
  {
    id: "T1595.002",
    name: "Vulnerability Scanning",
    tactic: "reconnaissance",
    stage: "recon",
    plain: "probed for well-known vulnerable pages",
  },
  {
    id: "T1046",
    name: "Network Service Discovery",
    tactic: "discovery",
    stage: "recon",
    plain: "looked for other services to talk to",
  },
  {
    id: "T1082",
    name: "System Information Discovery",
    tactic: "discovery",
    stage: "recon",
    plain: "checked the system's details",
  },
  {
    id: "T1033",
    name: "System Owner/User Discovery",
    tactic: "discovery",
    stage: "recon",
    plain: "checked which user they were",
  },
  {
    id: "T1083",
    name: "File and Directory Discovery",
    tactic: "discovery",
    stage: "recon",
    plain: "browsed files and folders",
  },
  {
    id: "T1057",
    name: "Process Discovery",
    tactic: "discovery",
    stage: "recon",
    plain: "listed the running programs",
  },
  {
    id: "T1016",
    name: "System Network Configuration Discovery",
    tactic: "discovery",
    stage: "recon",
    plain: "looked at the network settings",
  },
  {
    id: "T1087.001",
    name: "Account Discovery: Local Account",
    tactic: "discovery",
    stage: "recon",
    plain: "read the list of local accounts",
  },
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "initial-access",
    stage: "access",
    plain: "exploited a flaw in a public service",
  },
  {
    id: "T1133",
    name: "External Remote Services",
    tactic: "initial-access",
    stage: "access",
    plain: "used a remote-access service that faces the internet",
  },
  {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "initial-access",
    stage: "access",
    plain: "logged in with a password that worked",
  },
  {
    id: "T1210",
    name: "Exploitation of Remote Services",
    tactic: "lateral-movement",
    stage: "access",
    plain: "exploited a flaw in a network service",
  },
  {
    id: "T1110",
    name: "Brute Force",
    tactic: "credential-access",
    stage: "access",
    plain: "guessed passwords",
  },
  {
    id: "T1110.001",
    name: "Brute Force: Password Guessing",
    tactic: "credential-access",
    stage: "access",
    plain: "guessed passwords one by one",
  },
  {
    id: "T1110.003",
    name: "Brute Force: Password Spraying",
    tactic: "credential-access",
    stage: "access",
    plain: "tried a few passwords on many accounts",
  },
  {
    id: "T1110.004",
    name: "Brute Force: Credential Stuffing",
    tactic: "credential-access",
    stage: "access",
    plain: "tried passwords stolen from other sites",
  },
  {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "execution",
    stage: "execution",
    plain: "ran commands",
  },
  {
    id: "T1059.004",
    name: "Command and Scripting Interpreter: Unix Shell",
    tactic: "execution",
    stage: "execution",
    plain: "typed shell commands",
  },
  {
    id: "T1059.006",
    name: "Command and Scripting Interpreter: Python",
    tactic: "execution",
    stage: "execution",
    plain: "ran a Python script",
  },
  {
    id: "T1610",
    name: "Deploy Container",
    tactic: "execution",
    stage: "execution",
    plain: "started a container",
  },
  {
    id: "T1611",
    name: "Escape to Host",
    tactic: "privilege-escalation",
    stage: "persistence",
    plain: "tried to break out of a container",
  },
  {
    id: "T1053.003",
    name: "Scheduled Task/Job: Cron",
    tactic: "persistence",
    stage: "persistence",
    plain: "set up a scheduled job to come back",
  },
  {
    id: "T1098.004",
    name: "Account Manipulation: SSH Authorized Keys",
    tactic: "persistence",
    stage: "persistence",
    plain: "planted their own SSH key",
  },
  {
    id: "T1136.001",
    name: "Create Account: Local Account",
    tactic: "persistence",
    stage: "persistence",
    plain: "created a new account",
  },
  {
    id: "T1505.003",
    name: "Server Software Component: Web Shell",
    tactic: "persistence",
    stage: "persistence",
    plain: "planted a web shell",
  },
  {
    id: "T1105",
    name: "Ingress Tool Transfer",
    tactic: "command-and-control",
    stage: "tool_transfer",
    plain: "downloaded a tool onto the machine",
  },
  {
    id: "T1071.001",
    name: "Application Layer Protocol: Web Protocols",
    tactic: "command-and-control",
    stage: "tool_transfer",
    plain: "talked to a control server over web traffic",
  },
  {
    id: "T1570",
    name: "Lateral Tool Transfer",
    tactic: "lateral-movement",
    stage: "tool_transfer",
    plain: "moved a tool to another machine",
  },
  {
    id: "T1496",
    name: "Resource Hijacking",
    tactic: "impact",
    stage: "objective",
    plain: "used the machine to mine cryptocurrency",
  },
  {
    id: "T1486",
    name: "Data Encrypted for Impact",
    tactic: "impact",
    stage: "objective",
    plain: "locked or ransomed data",
  },
  {
    id: "T1657",
    name: "Financial Theft",
    tactic: "impact",
    stage: "objective",
    plain: "tried to turn the service into a money-making scam",
  },
  {
    id: "T1499",
    name: "Endpoint Denial of Service",
    tactic: "impact",
    stage: "objective",
    plain: "tried to knock the service offline",
  },
]
const TECH = new Map(CATALOGUE.map((t) => [t.id, t]))
const attackUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`

/** What ingest's mapping rules would say about one session. */
export function techniquesOf(s: Session): string[] {
  const out = new Set<string>()
  const shell = ["ssh", "telnet", "adb"].includes(s.sensor)
  if (s.login_attempts > 0) out.add("T1110")
  if (s.login_success) out.add("T1078")
  if (s.commands > 0) out.add(shell ? "T1059.004" : "T1059")
  if (s.downloads > 0) out.add("T1105")
  if (s.http_requests > 0 && s.sensor === "web") out.add("T1595.002")
  if (["smb", "sip"].includes(s.sensor) && s.login_attempts === 0) out.add("T1046")
  const byTag: Record<string, string[]> = {
    recon: ["T1082"],
    php2shell: ["T1190", "T1059", "T1505.003"],
    "crypto-miner": ["T1496"],
    mirai: ["T1059.004", "T1105"],
    "malware-drop": ["T1105"],
    eternalblue: ["T1210"],
    bluekeep: ["T1210"],
    "db-ransom": ["T1486"],
    "sip-fraud": ["T1657"],
    "container-escape": ["T1611", "T1610"],
    "redis-rogue-master": ["T1190", "T1105"],
    persistence: ["T1053.003"],
    "weak-credentials": ["T1110.001"],
  }
  for (const tag of s.tags) for (const id of byTag[tag] ?? []) out.add(id)
  return [...out].sort()
}

// --- campaigns, derived from the fixtures ------------------------------------------------------

interface Def {
  id: number
  name: string
  match: (s: Session) => boolean
  families: string[]
  severity: Severity
  keys: [CampaignIndicator["kind"], string, number][]
}

const has = (tag: string) => (s: Session) => s.tags.includes(tag)

const DEFS: Def[] = [
  {
    id: 1,
    name: "PHP2Shell exploitation over HTTP #1",
    match: has("php2shell"),
    families: [],
    severity: "severe",
    keys: [["exploit", "9f2c4a6e1b8d3f7a0c5e2b4d6f8a1c3e9f2c4a6e1b8d3f7a0c5e2b4d6f8a1c3e", 9]],
  },
  {
    id: 2,
    name: "Xmrig miner drop over SSH #2",
    match: has("crypto-miner"),
    families: ["xmrig"],
    severity: "severe",
    keys: [
      ["payload_host", "198.51.100.77", 12],
      ["family", "xmrig", 12],
      ["script", "c41d7e0a92b35f68e1d0a47b93c26f58d1e0a47b93c26f58c41d7e0a92b35f68", 10],
    ],
  },
  {
    id: 3,
    name: "Mirai-style loader over Telnet #3",
    match: has("mirai"),
    families: ["mirai"],
    severity: "severe",
    keys: [
      ["payload_host", "203.0.113.66", 14],
      ["payload_host", "dl.example.net", 9],
      ["family", "mirai", 14],
      ["script", "7be0f4a9d2c61853e0f4a9d2c61853b7be0f4a9d2c61853e0f4a9d2c61853b7", 11],
    ],
  },
  {
    id: 4,
    name: "Malware dropper over SSH #4",
    match: has("malware-drop"),
    families: [],
    severity: "severe",
    keys: [
      ["payload_host", "cdn.example.org", 6],
      ["hash", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", 6],
    ],
  },
  {
    id: 5,
    name: "EternalBlue exploitation over SMB #5",
    match: has("eternalblue"),
    families: [],
    severity: "severe",
    keys: [["exploit", "3a8d1f6b2c9e4075a8d1f6b2c9e4075b3a8d1f6b2c9e4075a8d1f6b2c9e4075b", 7]],
  },
  {
    id: 6,
    name: "Redis rogue master over Redis #6",
    match: has("redis-rogue-master"),
    families: [],
    severity: "warning",
    keys: [["payload_host", "203.0.113.141", 1]],
  },
  {
    id: 7,
    name: "Database ransom over MySQL #7",
    match: has("db-ransom"),
    families: [],
    severity: "warning",
    keys: [["script", "e19a05c7d3b84f26a05c7d3b84f26e19e19a05c7d3b84f26a05c7d3b84f26e19", 4]],
  },
  {
    id: 8,
    name: "BlueKeep probing over RDP #8",
    match: has("bluekeep"),
    families: [],
    severity: "notice",
    keys: [["exploit", "5c0e8b3a7f1d9264c0e8b3a7f1d92645c0e8b3a7f1d9264c0e8b3a7f1d92645", 8]],
  },
  {
    id: 9,
    name: "Phone fraud over SIP #9",
    match: has("sip-fraud"),
    families: [],
    severity: "warning",
    keys: [["script", "0d6f3b8e5a2c7194d6f3b8e5a2c71940d6f3b8e5a2c7194d6f3b8e5a2c71940", 3]],
  },
]

/** Hand-written campaign whose raw sessions have been pruned: only its counters remain. */
const OLD: Omit<Campaign, "first_seen" | "last_seen"> & { firstAgo: number; lastAgo: number } = {
  id: 10,
  name: "Password-list guessing over SSH #10",
  status: "quiet",
  merged_into: null,
  firstAgo: 26 * DAY,
  lastAgo: 12 * DAY,
  sessions: 1840,
  sources: 31,
  countries: ["CN", "RU", "US", "NL", "BR", "VN"],
  asns: [64498, 64500, 64497, 64496, 64501, 64503],
  sensors: ["ssh"],
  techniques: ["T1110", "T1110.004", "T1078", "T1059.004", "T1082"],
  stages: ["recon", "access", "execution"],
  tags: ["credential-stuffing", "recon"],
  families: [],
  severity: "warning",
  rep_session_id: null,
  demo: false,
}
const MERGED: Omit<Campaign, "first_seen" | "last_seen"> & { firstAgo: number; lastAgo: number } = {
  id: 11,
  name: "Mirai variant over Telnet #11",
  status: "merged",
  merged_into: 3,
  firstAgo: 9 * DAY,
  lastAgo: 3 * DAY,
  sessions: 22,
  sources: 8,
  countries: ["VN", "BR"],
  asns: [64503, 64501],
  sensors: ["telnet"],
  techniques: ["T1110", "T1059.004", "T1105"],
  stages: ["access", "execution", "tool_transfer"],
  tags: ["mirai"],
  families: ["mirai"],
  severity: "severe",
  rep_session_id: null,
  demo: false,
}

function stagesOf(techniques: readonly string[]): Stage[] {
  const present = new Set(techniques.map((t) => TECH.get(t)?.stage))
  return STAGES.filter((s) => present.has(s))
}

function sortedByCount(values: string[]): string[] {
  const counts = new Map<string, number>()
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1)
  return [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([v]) => v)
}

interface Built {
  campaign: Campaign
  members: Fixture[]
  keys: [CampaignIndicator["kind"], string, number][]
}

function buildAll(fixtures: Fixture[], now: number): Built[] {
  const taken = new Set<string>()
  const out: Built[] = []
  for (const def of DEFS) {
    const members = fixtures.filter((f) => !taken.has(f.session.session_id) && def.match(f.session))
    if (members.length < 2) continue
    members.forEach((f) => taken.add(f.session.session_id))
    const sessions = members.map((f) => f.session)
    const techniques = [...new Set(sessions.flatMap((s) => techniquesOf(s)))].sort()
    const rep = [...sessions].sort(
      (a, b) =>
        b.commands + b.downloads - (a.commands + a.downloads) ||
        a.session_id.localeCompare(b.session_id),
    )[0]
    const last = Math.max(...sessions.map((s) => Date.parse(s.last_event_at)))
    out.push({
      members,
      keys: def.keys,
      campaign: {
        id: def.id,
        name: def.name,
        status: now - last < 7 * DAY ? "active" : "quiet",
        merged_into: null,
        first_seen: sessions.map((s) => s.started_at).sort()[0] ?? iso(now),
        last_seen: iso(last),
        sessions: sessions.length,
        sources: new Set(sessions.map((s) => s.src_ip)).size,
        countries: sortedByCount(sessions.flatMap((s) => (s.country ? [s.country] : []))),
        asns: [...new Set(sessions.flatMap((s) => (s.asn ? [s.asn] : [])))],
        sensors: sortedByCount(sessions.map((s) => s.sensor)),
        techniques,
        stages: stagesOf(techniques),
        tags: [...new Set(sessions.flatMap((s) => s.tags))].sort(),
        families: def.families,
        severity: def.severity,
        rep_session_id: rep?.session_id ?? null,
        demo: false,
      },
    })
  }
  for (const spec of [OLD, MERGED]) {
    const { firstAgo, lastAgo, ...rest } = spec
    out.push({
      members: [],
      keys: [],
      campaign: { ...rest, first_seen: iso(now - firstAgo), last_seen: iso(now - lastAgo) },
    })
  }
  return out
}

/** Gives every fixture session its `techniques` and, if it belongs to one, its `campaign_id`. */
function decorate(fixtures: Fixture[], built: Built[]) {
  const owner = new Map<string, number>()
  for (const b of built) for (const m of b.members) owner.set(m.session.session_id, b.campaign.id)
  for (const f of fixtures) {
    f.session.techniques = techniquesOf(f.session)
    const id = owner.get(f.session.session_id)
    f.session.campaign_id = id ?? null
  }
}

// --- story --------------------------------------------------------------------------------------

function joinPhrases(phrases: string[]): string {
  if (phrases.length <= 1) return phrases.join("")
  const shown = phrases.slice(0, 3)
  const rest = phrases.length - shown.length
  if (rest) return `${shown.join(", ")} and ${rest} more`
  return `${shown.slice(0, -1).join(", ")} and ${shown.at(-1)}`
}

function storyStages(techniques: readonly string[]): StoryStage[] {
  const ids = new Set(techniques)
  return STAGES.flatMap((stage) => {
    const items = CATALOGUE.filter(
      (t) => t.stage === stage && ids.has(t.id) && ![...ids].some((o) => o.startsWith(`${t.id}.`)),
    )
    if (items.length === 0) return []
    return [
      {
        stage,
        label: STAGE_META[stage].label,
        summary: `They ${joinPhrases(items.map((t) => t.plain))}.`,
        techniques: items.map((t) => ({
          id: t.id,
          name: t.name,
          url: attackUrl(t.id),
          plain: t.plain,
        })),
      },
    ]
  })
}

function whatToDo(c: Campaign, hosts: string[]): string[] {
  const t = new Set(c.techniques)
  const out: string[] = []
  if (hosts.length)
    out.push(
      `Block ${hosts.slice(0, 2).join(" and ")} at your proxy or firewall, and look for past connections to it.`,
    )
  if (["T1110", "T1110.001", "T1110.004", "T1078"].some((x) => t.has(x)))
    out.push("Turn off password logins on anything exposed, use keys or MFA, and rate-limit.")
  if (["T1190", "T1210", "T1505.003"].some((x) => t.has(x)))
    out.push("Patch public-facing services and check they are not exposed by mistake.")
  if (t.has("T1496")) out.push("Alert on sudden CPU use and on connections to mining pools.")
  if (t.has("T1105")) out.push("Stop servers from downloading and running files from the internet.")
  if (t.has("T1053.003"))
    out.push("Check cron jobs, authorized SSH keys and local accounts on exposed machines.")
  if (out.length === 0)
    out.push("Nothing to block yet: keep watching and check your exposure page.")
  return out.slice(0, 4)
}

const defang = (host: string) => host.replaceAll(".", "[.]")

function excerptOf(f: Fixture | undefined): CampaignStory["excerpt"] {
  if (!f) return null
  const lines: ExcerptLine[] = []
  for (const e of f.events) {
    const d = e.data
    let line: ExcerptLine | null = null
    if (e.type === "command" && typeof d.input === "string")
      line = { kind: "command", text: d.input }
    else if (e.type === "http_request")
      line = {
        kind: "request",
        text: `${typeof d.method === "string" ? d.method : "GET"} ${typeof d.path === "string" ? d.path : "/"}`,
      }
    else if (e.type === "download_attempt" && typeof d.url === "string")
      line = { kind: "download", text: d.url }
    else if (e.type === "login_attempt" && typeof d.username === "string")
      line = { kind: "login", text: `login as ${d.username}` }
    if (!line) continue
    if (line.kind === "login" && lines.at(-1)?.kind === "login") continue
    lines.push({ ...line, text: line.text.slice(0, 200) })
    if (lines.length >= 12) break
  }
  return lines.length ? { session_id: f.session.session_id, sensor: f.session.sensor, lines } : null
}

// --- the matrix -------------------------------------------------------------------------------

/** Sessions per technique and sensor in the fixtures: the weights of the synthetic history. */
function weights(fixtures: Fixture[]): Map<string, Map<string, number>> {
  const out = new Map<string, Map<string, number>>()
  for (const f of fixtures)
    for (const t of f.session.techniques ?? []) {
      const per = out.get(t) ?? new Map<string, number>()
      per.set(f.session.sensor, (per.get(f.session.sensor) ?? 0) + 1)
      out.set(t, per)
    }
  return out
}

function buildMatrix(
  w: Map<string, Map<string, number>>,
  days: number,
  sensors: string[],
  now: number,
): Matrix {
  const today = new Date(now)
  today.setUTCHours(0, 0, 0, 0)
  const dayList = Array.from({ length: days }, (_, i) =>
    iso(today.getTime() - (days - 1 - i) * DAY).slice(0, 10),
  )
  const rows: MatrixRow[] = []
  for (const t of CATALOGUE) {
    const per = w.get(t.id)
    if (!per) continue
    const weight = [...per].reduce(
      (n, [s, c]) => n + (sensors.length && !sensors.includes(s) ? 0 : c),
      0,
    )
    if (weight === 0) continue
    const counts = dayList.map((day, i) => {
      // A rhythm per technique: quiet days, busy days, a slow rise towards today.
      const r = hash(`${t.id}:${day}`)
      const rise = 0.55 + (i / Math.max(1, days - 1)) * 0.9
      const n = Math.round(weight * 0.7 * rise * (r < 0.18 ? 0 : 0.4 + r * 1.6))
      return i === days - 1 ? Math.max(n, 1) : n
    })
    const total = counts.reduce((a, b) => a + b, 0)
    rows.push({
      id: t.id,
      name: t.name,
      tactic: t.tactic,
      stage: t.stage,
      url: attackUrl(t.id),
      plain: t.plain,
      total_sessions: total,
      total_events: total * 4,
      counts,
    })
  }
  rows.sort(
    (a, b) =>
      STAGES.indexOf(a.stage) - STAGES.indexOf(b.stage) || b.total_sessions - a.total_sessions,
  )
  return {
    since: dayList[0] ?? "",
    until: dayList.at(-1) ?? "",
    days: dayList,
    stages: STAGES.map((stage) => ({ stage, label: STAGE_META[stage].label })),
    rows,
  }
}

// --- handlers ---------------------------------------------------------------------------------

function offsetPage(items: readonly unknown[], url: URL, fallback: number) {
  const limit = Number(url.searchParams.get("limit") ?? fallback)
  if (!Number.isInteger(limit) || limit < 1 || limit > 400)
    return HttpResponse.json({ detail: "invalid limit" }, { status: 422 })
  let offset = 0
  const cursor = url.searchParams.get("cursor")
  if (cursor) {
    try {
      const v = JSON.parse(atob(cursor)) as { o?: unknown }
      if (typeof v.o !== "number" || v.o < 0) throw new Error("bad")
      offset = v.o
    } catch {
      return HttpResponse.json({ detail: "invalid cursor" }, { status: 400 })
    }
  }
  const next = offset + limit < items.length ? btoa(JSON.stringify({ o: offset + limit })) : null
  const page: Page<unknown> = { items: items.slice(offset, offset + limit), next_cursor: next }
  return HttpResponse.json(page)
}

function sensorsOf(url: URL): string[] {
  return url.searchParams
    .getAll("sensor")
    .flatMap((v) => v.split(","))
    .filter((v) => (SENSORS as readonly string[]).includes(v))
}

export function campaignsHandlers(fixtures: Fixture[], now = Date.now()): RequestHandler[] {
  const built = buildAll(fixtures, now)
  decorate(fixtures, built)
  const byId = new Map(built.map((b) => [b.campaign.id, b]))
  const weight = weights(fixtures)
  const notFound = () => HttpResponse.json({ detail: "campaign not found" }, { status: 404 })
  const find = (raw: string | readonly string[] | undefined) => byId.get(Number(raw))

  return [
    http.get("/api/v1/campaigns", async ({ request }) => {
      await delay(LATENCY_MS)
      const url = new URL(request.url)
      const q = url.searchParams
      const status = q.get("status")
      const sensors = sensorsOf(url)
      const technique = q.get("technique")
      const family = q.get("family")?.toLowerCase()
      const days = Number(q.get("days") ?? 0)
      const hours = Number(q.get("hours") ?? 0)
      const needle = q.get("q")?.toLowerCase()
      let items = built.map((b) => b.campaign)
      items = items.filter((c) => (status ? c.status === status : c.status !== "merged"))
      if (sensors.length) items = items.filter((c) => c.sensors.some((s) => sensors.includes(s)))
      if (technique) items = items.filter((c) => c.techniques.includes(technique))
      if (family) items = items.filter((c) => c.families.includes(family))
      const window = hours ? hours * HOUR : days ? days * DAY : 0
      if (window) items = items.filter((c) => now - Date.parse(c.last_seen) <= window)
      if (needle) items = items.filter((c) => c.name.toLowerCase().includes(needle))
      items.sort((a, b) => b.last_seen.localeCompare(a.last_seen) || b.id - a.id)
      return offsetPage(items, url, 50)
    }),

    http.get("/api/v1/campaigns/:id", async ({ params }) => {
      await delay(LATENCY_MS)
      return find(params.id) ? HttpResponse.json(find(params.id)?.campaign) : notFound()
    }),

    http.get("/api/v1/campaigns/:id/story", async ({ params }) => {
      await delay(LATENCY_MS)
      const b = find(params.id)
      if (!b) return notFound()
      const c = b.campaign
      const hosts = b.keys.filter(([k]) => k === "payload_host").map(([, v]) => defang(v))
      const rep = b.members.find((m) => m.session.session_id === c.rep_session_id)
      const stages = storyStages(c.techniques)
      const names = stages.map((s) => s.label.toLowerCase())
      const labels =
        names.length > 2
          ? `${names.slice(0, -1).join(", ")}, then ${names.at(-1)}`
          : names.join(" then ")
      const story: CampaignStory = {
        campaign_id: c.id,
        headline: `${c.sessions.toLocaleString("en-US")} sessions from ${c.sources.toLocaleString("en-US")} ${c.sources === 1 ? "address" : "addresses"} followed the same playbook${labels ? `: ${labels}.` : "."}`,
        stages,
        excerpt: excerptOf(rep),
        counts: {
          sessions: c.sessions,
          sources: c.sources,
          countries: c.countries.length,
          networks: c.asns.length,
          sensors: c.sensors.length,
          days_active: Math.max(
            1,
            Math.ceil((Date.parse(c.last_seen) - Date.parse(c.first_seen)) / DAY),
          ),
        },
        what_to_do: whatToDo(c, hosts),
      }
      return HttpResponse.json(story)
    }),

    http.get("/api/v1/campaigns/:id/timeline", async ({ params, request }) => {
      await delay(LATENCY_MS)
      const b = find(params.id)
      if (!b) return notFound()
      const days = Number(new URL(request.url).searchParams.get("days") ?? 7)
      const until = Math.ceil(now / HOUR) * HOUR
      const since = until - days * DAY
      const buckets = new Map<number, number>()
      for (const m of b.members) {
        const t = Math.floor(Date.parse(m.session.last_event_at) / HOUR) * HOUR
        if (t >= since && t < until) buckets.set(t, (buckets.get(t) ?? 0) + 1)
      }
      const points = [...buckets]
        .sort((a, c) => a[0] - c[0])
        .map(([t, n]) => ({ ts: iso(t), sessions: n }))
      const timeline: CampaignTimeline = {
        since: iso(since),
        until: iso(until),
        bucket_seconds: 3600,
        linked: points.reduce((n, p) => n + p.sessions, 0),
        points,
      }
      return HttpResponse.json(timeline)
    }),

    http.get("/api/v1/campaigns/:id/sessions", async ({ params, request }) => {
      await delay(LATENCY_MS)
      const b = find(params.id)
      if (!b) return notFound()
      const sessions = b.members
        .map((m) => m.session)
        .sort((a, c) => c.started_at.localeCompare(a.started_at))
      return offsetPage(sessions, new URL(request.url), 10)
    }),

    http.get("/api/v1/campaigns/:id/indicators", async ({ params }) => {
      await delay(LATENCY_MS)
      const b = find(params.id)
      if (!b) return notFound()
      const c = b.campaign
      const items: CampaignIndicator[] = b.keys.map(([kind, value, sources]) => ({
        kind,
        value,
        defanged: kind === "payload_host" ? defang(value) : value,
        sources,
        confidence: sources < 2 ? "low" : "normal",
        first_seen: c.first_seen,
        last_seen: c.last_seen,
      }))
      return HttpResponse.json({ items })
    }),

    http.get("/api/v1/attack/techniques", async ({ request }) => {
      await delay(LATENCY_MS)
      const url = new URL(request.url)
      const days = Number(url.searchParams.get("days") ?? 30)
      const matrix = buildMatrix(weight, days, sensorsOf(url), now)
      const seen = new Map(matrix.rows.map((r) => [r.id, r]))
      const items: TechniqueItem[] = CATALOGUE.map((t) => {
        const r = seen.get(t.id)
        const lastIdx = r ? r.counts.findLastIndex((n) => n > 0) : -1
        return {
          id: t.id,
          name: t.name,
          tactic: t.tactic,
          stage: t.stage,
          stage_label: STAGE_META[t.stage].label,
          url: attackUrl(t.id),
          plain: t.plain,
          sessions: r?.total_sessions ?? 0,
          events: r?.total_events ?? 0,
          sources: r ? Math.ceil(r.total_sessions / 3) : 0,
          last_day: lastIdx >= 0 ? (matrix.days[lastIdx] ?? null) : null,
        }
      })
      return HttpResponse.json({ days, items, next_cursor: null })
    }),

    http.get("/api/v1/attack/matrix", async ({ request }) => {
      await delay(LATENCY_MS)
      const url = new URL(request.url)
      const days = Number(url.searchParams.get("days") ?? 30)
      if (!Number.isInteger(days) || days < 1 || days > 365)
        return HttpResponse.json({ detail: "invalid days" }, { status: 422 })
      return HttpResponse.json(buildMatrix(weight, days, sensorsOf(url), now))
    }),
  ]
}
