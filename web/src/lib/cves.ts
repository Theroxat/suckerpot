/**
 * CVE watch: shapes of `/api/v1/cves` (api/api/cves.py is the source of truth), the plain-English
 * finding for the page, and the trap-sheet template. Everything here is pure.
 */

import { plural } from "./format"

export type Relevance = "high" | "medium" | "none"
export type CvssSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"

export interface CveItem {
  cve_id: string
  title: string | null
  description: string | null
  vendor: string | null
  product: string | null
  published_at: string | null
  modified_at: string | null
  cvss_score: number | null
  cvss_severity: string | null
  in_kev: boolean
  kev_added_at: string | null
  kev_due_date: string | null
  kev_ransomware: boolean | null
  relevance: Relevance
  matched_services: string[]
  tags: string[]
  sources: string[]
  seen_sessions: number
}

export interface CvePage {
  items: CveItem[]
  next_cursor: string | null
  total: number
}

export interface CveTraffic {
  sessions: number
  ips: number
  first_seen: string | null
  last_seen: string | null
  by_tag: { tag: string; sessions: number }[]
}

export interface CveDetail {
  item: CveItem
  description_full: string | null
  cwes: string[]
  ghsa_ids: string[]
  refs: string[]
  cpes: string[]
  kev_action: string | null
  traffic: CveTraffic
}

export interface CveSourceState {
  source: "kev" | "nvd" | "github"
  last_run_at: string | null
  last_success_at: string | null
  last_error: string | null
  items_last_run: number
}

export interface CveSync {
  sources: CveSourceState[]
  total: number
  relevant: number
  kev: number
  nvd_key_configured: boolean
  github_key_configured: boolean
}

export interface CveFilters {
  relevance?: string | undefined
  kev?: string | undefined
  severity?: string | undefined
  since?: string | undefined
  q?: string | undefined
}

export const RELEVANCE_FILTERS = [
  { value: "relevant", label: "Our services" },
  { value: "all", label: "All" },
] as const

export const SEVERITY_FILTERS = ["critical", "high", "medium", "low"] as const
export const SINCE_OPTIONS = [
  { value: "7", label: "7 days" },
  { value: "30", label: "30 days" },
  { value: "all", label: "Any time" },
] as const

/** Service ids come from ingest/rules/cve/relevance.yaml; unknown ids fall back to the id. */
export const SERVICE_LABELS: Record<string, string> = {
  "web-php": "Apache + PHP",
  wordpress: "WordPress",
  phpmyadmin: "phpMyAdmin",
  openssh: "OpenSSH",
  "busybox-telnet": "BusyBox telnetd",
  "windows-rdp": "Windows RDP",
  redis: "Redis",
  "docker-engine": "Docker Engine",
  mysql: "MySQL",
  mssql: "SQL Server",
  "android-adb": "Android ADB",
  "windows-smb": "Windows SMB",
  "asterisk-sip": "Asterisk / SIP",
}

export function serviceLabel(id: string): string {
  return SERVICE_LABELS[id] ?? id
}

const DAY_MS = 86_400_000

/** ISO timestamp `days` ago, or undefined for "any time". */
export function sinceParam(days: string | null, now = Date.now()): string | undefined {
  if (days === null || days === "all") return undefined
  const n = Number(days)
  if (!Number.isInteger(n) || n < 1 || n > 365) return undefined
  // Rounded to the hour so the query key stays stable between renders.
  const t = Math.floor((now - n * DAY_MS) / 3_600_000) * 3_600_000
  return new Date(t).toISOString()
}

export function severityLevel(sev: string | null): number {
  return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[sev ?? ""] ?? 0
}

export function severityLabel(sev: string | null): string {
  if (!sev) return "Unrated"
  return sev.charAt(0) + sev.slice(1).toLowerCase()
}

export function cveTitle(c: CveItem): string {
  if (c.title) return c.title
  if (c.vendor || c.product) return [c.vendor, c.product].filter(Boolean).join(" ")
  return c.cve_id
}

export interface CveFindingInput {
  /** New critical CVEs this week that match our services. */
  critical: number
  /** New CVEs this week that match our services. */
  relevant: number
  /** Relevant CVEs also in the KEV catalogue (listed anywhere, any age). */
  kevRelevant: number
  /** Relevant CVEs with exploitation seen in our traffic. */
  seen: number
}

/** The sentence at the top of the page. */
export function describeCves(f: CveFindingInput): string {
  if (f.relevant === 0) return "No new CVE this week affects the services we emulate."
  const head =
    f.critical > 0
      ? `${plural(f.critical, "new critical CVE")} this week ${f.critical === 1 ? "affects" : "affect"} services we emulate`
      : `${plural(f.relevant, "new CVE")} this week ${f.relevant === 1 ? "affects" : "affect"} services we emulate`
  const tail: string[] = []
  if (f.kevRelevant > 0) tail.push(`${f.kevRelevant} already exploited in the wild (CISA KEV)`)
  if (f.seen > 0) tail.push(`${f.seen} seen in our traffic`)
  return tail.length > 0 ? `${head}: ${tail.join(", ")}.` : `${head}.`
}

const SENSOR_PORT: Record<string, string> = {
  "web-php": "web sensor (HTTP, 80)",
  wordpress: "web sensor (HTTP, 80)",
  phpmyadmin: "web sensor (HTTP, 80)",
  openssh: "ssh sensor (22)",
  "busybox-telnet": "telnet sensor (23)",
  "windows-rdp": "rdp sensor (3389)",
  redis: "redis sensor (6379)",
  "docker-engine": "docker sensor (2375)",
  mysql: "mysql sensor (3306)",
  mssql: "mssql sensor (1433)",
  "android-adb": "adb sensor (5555)",
  "windows-smb": "smb sensor (445)",
  "asterisk-sip": "sip sensor (5060)",
}

/** A short, safe tag name for a proposed trap: lowercase letters, digits and dashes. */
export function proposedTag(cveId: string): string {
  return cveId
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
}

/**
 * The trap sheet an owner can paste into a ticket or hand to a builder. It is plain text and
 * triggers nothing: SuckerPot never builds or deploys a trap on its own.
 */
export function trapSheet(d: CveDetail): string {
  const c = d.item
  const services = c.matched_services.length
    ? c.matched_services.map((s) => `${serviceLabel(s)} -> ${SENSOR_PORT[s] ?? "to be decided"}`)
    : ["(no emulated service matches; decide where it would run)"]
  const lines = [
    `Trap proposal: ${c.cve_id}`,
    `Summary: ${cveTitle(c)}`,
    `Severity: ${c.cvss_score !== null ? `${c.cvss_score.toFixed(1)} ${severityLabel(c.cvss_severity)}` : "unrated"}${c.in_kev ? ", in the CISA KEV catalogue" : ""}`,
    "",
    "Service to emulate:",
    ...services.map((s) => `  - ${s}`),
    `Version to emulate: <a vulnerable version, from the advisory>`,
    "",
    "URLs / commands to watch (fill in from the advisory and the references):",
    "  - <request path, header or command that triggers the flaw>",
    `Tag name: ${proposedTag(c.cve_id)}`,
    "",
    "References:",
    ...(d.refs.length ? d.refs.slice(0, 6).map((r) => `  - ${r}`) : ["  - (none recorded)"]),
    "",
    "Seen in our traffic: " +
      (d.traffic.sessions > 0
        ? `${plural(d.traffic.sessions, "session")} from ${plural(d.traffic.ips, "address", "addresses")}`
        : "not yet"),
    "",
    "Review with the owner first. Nothing is built or deployed from this sheet.",
  ]
  return lines.join("\n")
}

/** Plain-English state of one source for the status card. */
export function describeSource(s: CveSourceState): string {
  if (s.last_error) return `Last attempt failed (${s.last_error.replace(/_/g, " ")}).`
  if (!s.last_success_at) return "Has not run yet."
  return `${plural(s.items_last_run, "entry", "entries")} on the last run.`
}

export const SOURCE_LABELS: Record<CveSourceState["source"], string> = {
  kev: "CISA KEV",
  nvd: "NVD",
  github: "GitHub advisories",
}
