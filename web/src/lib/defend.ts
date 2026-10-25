/**
 * Defend (M16): blocklists, detection rules, the exposure check and the feed tokens. Everything
 * here is derived from what the honeypot recorded; nothing is scanned or contacted. The sentence
 * builders are pure so they can be unit-tested.
 */
import { ApiError, API_BASE, getJson, sendJson, type Page } from "@/lib/api"
import { formatNumber, plural } from "@/lib/format"
import { sensorMeta } from "@/lib/sensors"

/* --- Blocklists --------------------------------------------------------- */

export const BLOCK_KINDS = ["ip", "domain", "url", "hash"] as const
export type BlockKind = (typeof BLOCK_KINDS)[number]

export function isBlockKind(v: unknown): v is BlockKind {
  return typeof v === "string" && (BLOCK_KINDS as readonly string[]).includes(v)
}

export const KIND_META: Record<BlockKind, { label: string; one: string; many: string }> = {
  ip: { label: "IP addresses", one: "address", many: "addresses" },
  domain: { label: "Domains", one: "domain", many: "domains" },
  url: { label: "URLs", one: "URL", many: "URLs" },
  hash: { label: "File hashes", one: "file hash", many: "file hashes" },
}

/** Scores: "listed" entries go to the firewall, "high" ones are the surest. */
export const LISTED_SCORE = 50
export const HIGH_SCORE = 70
export const DEFAULT_MIN_SCORE = LISTED_SCORE

export interface KindSummary {
  kind: BlockKind
  total: number
  high: number
  listed: number
}

export interface DefendSummary {
  computed_at: string | null
  /** False: the worker is switched off. Null: it has not reported yet. */
  worker_enabled: boolean | null
  feeds_enabled: boolean
  kinds: KindSummary[]
  top_reasons: { reason: string; count: number }[]
  demo_entries: number
  overrides: number
}

export type OverrideAction = "allow" | "block"

export interface BlockEntry {
  kind: BlockKind
  value: string
  score: number
  reasons: string[]
  first_seen: string
  last_seen: string
  sessions: number
  sources: number
  campaign_ids: number[]
  benign: boolean
  demo: boolean
  override: OverrideAction | null
}

export interface OverrideItem {
  id: number
  kind: BlockKind
  value: string
  action: OverrideAction
  note: string | null
  created_by: string
  created_at: string
  expires_at: string | null
}

export interface BlocklistFilters {
  kind?: BlockKind | undefined
  min_score: number
  q?: string | undefined
  reason?: string | undefined
  include_benign?: boolean | undefined
}

/** Plain-English labels for the reason codes the scorer writes. */
export const REASON_LABELS: Record<string, { label: string; sentence: string }> = {
  "brute-force": {
    label: "Guessed passwords",
    sentence: "Tried many passwords against our logins.",
  },
  "login-succeeded": { label: "Got in", sentence: "Logged in to one of our decoys." },
  "ran-commands": { label: "Ran commands", sentence: "Ran commands after logging in." },
  "dropped-malware": { label: "Dropped malware", sentence: "Tried to download or drop malware." },
  "exploit-attempt": { label: "Exploit attempt", sentence: "Sent a known exploit payload." },
  "reported-abusive": {
    label: "Reported abusive",
    sentence: "Other people have reported this address as abusive.",
  },
  "multi-sensor": {
    label: "Hit several decoys",
    sentence: "Attacked more than one kind of decoy.",
  },
  campaign: { label: "Part of a campaign", sentence: "Belongs to a campaign we track." },
  "repeat-visitor": { label: "Came back", sentence: "Returned on several different days." },
  "mass-scanner": {
    label: "Mass scanner",
    sentence: "Scans the whole internet, not just you.",
  },
  "download-source": {
    label: "Serves malware",
    sentence: "Attackers told our decoys to download from here.",
  },
  "contacted-by-attacker": {
    label: "Called by malware",
    sentence: "Attackers made our decoys contact this host.",
  },
  "known-malware": { label: "Known malware", sentence: "Listed by a public malware feed." },
  "malware-family": { label: "Known family", sentence: "Matches a named malware family." },
  "seen-from-many-sources": {
    label: "Many sources",
    sentence: "Used by several different attackers.",
  },
  "file-hash": { label: "File seen", sentence: "A file attackers dropped on our decoys." },
  "manual-block": { label: "Blocked by you", sentence: "You chose to always block this." },
}

export function reasonLabel(code: string): string {
  return REASON_LABELS[code]?.label ?? code.replace(/-/g, " ")
}

export function reasonSentence(code: string): string {
  return REASON_LABELS[code]?.sentence ?? reasonLabel(code)
}

/** The word that goes with a score, so the meter's tone is never the only cue. */
export function scoreBand(score: number): "high" | "listed" | "seen" {
  return score >= HIGH_SCORE ? "high" : score >= LISTED_SCORE ? "listed" : "seen"
}

export const BAND_LABEL = { high: "High", listed: "Listed", seen: "Seen" } as const

/** "12 addresses, 3 domains and 2 URLs scored 50 or higher are ready for your firewall." */
export function blocklistSentence(s: DefendSummary | undefined): string {
  if (!s)
    return "Addresses, domains and files seen attacking you, scored and ready for your firewall."
  const counts: { n: number; text: string }[] = []
  for (const kind of BLOCK_KINDS) {
    const k = s.kinds.find((x) => x.kind === kind)
    if (k && k.listed > 0)
      counts.push({
        n: k.listed,
        text: `${formatNumber(k.listed)} ${k.listed === 1 ? KIND_META[kind].one : KIND_META[kind].many}`,
      })
  }
  if (counts.length === 0)
    return `Nothing has scored ${LISTED_SCORE} or higher yet. Entries appear here as attackers prove themselves.`
  const texts = counts.map((c) => c.text)
  const last = texts.pop()
  const list = texts.length ? `${texts.join(", ")} and ${last}` : String(last)
  const single = counts.length === 1 && counts[0]?.n === 1
  return `${list} scored ${LISTED_SCORE} or higher and ${single ? "is" : "are"} ready for your firewall.`
}

export interface ExportParams {
  kind: BlockKind
  format: "txt" | "alias" | "csv"
  minScore: number
  includeBenign?: boolean
}

/** The download link; a plain anchor, so the browser saves the file. Demo entries are never exported. */
export function exportUrl({ kind, format, minScore, includeBenign = false }: ExportParams): string {
  const qs = new URLSearchParams({
    kind,
    format: format === "alias" && kind !== "ip" ? "txt" : format,
    min_score: String(minScore),
  })
  if (includeBenign) qs.set("include_benign", "true")
  return `${API_BASE}/defend/export?${qs.toString()}`
}

export type Firewall = "opnsense" | "pfsense"

export const FIREWALL_LABEL: Record<Firewall, string> = {
  opnsense: "OPNsense",
  pfsense: "pfSense",
}

/** Step-by-step text for a URL-table alias; the same text is shown and copied. */
export function firewallInstructions(firewall: Firewall, feedUrlText: string): string[] {
  const where =
    firewall === "opnsense" ? "Firewall > Aliases, then Add" : "Firewall > Aliases > URLs, then Add"
  return [
    `Create a feed token in Settings > Feeds. A firewall cannot send headers, so use the token-in-URL form: ${feedUrlText}`,
    `Open ${where}.`,
    `Name it suckerpot_block and set Type to "URL Table (IPs)".`,
    `Paste the feed URL as the content and set the refresh to once a day.`,
    `Save and apply. Then add a Block rule on your WAN interface whose source is the alias suckerpot_block.`,
    `Run the rule in log-only mode for a few days and read the log before you enforce it.`,
  ]
}

export function instructionsText(firewall: Firewall, feedUrlText: string): string {
  return [
    `${FIREWALL_LABEL[firewall]}: use the blocklist as a URL table alias`,
    ...firewallInstructions(firewall, feedUrlText).map((s, i) => `${i + 1}. ${s}`),
  ].join("\n")
}

export const defendKeys = {
  summary: ["defend", "summary"] as const,
  blocklist: (f: object, limit: number) => ["defend", "blocklist", f, limit] as const,
  overrides: ["defend", "overrides"] as const,
  tokens: ["defend", "feed-tokens"] as const,
  detections: (kind: string, days: number) => ["defend", "detections", kind, days] as const,
  guidance: (days: number) => ["defend", "guidance", days] as const,
  inventory: ["defend", "inventory"] as const,
  exposure: (days: number) => ["defend", "exposure", days] as const,
}

/* --- Detections and guidance ------------------------------------------- */

export type RuleKind = "sigma" | "suricata"
export const RULE_KINDS: RuleKind[] = ["sigma", "suricata"]
export const PERIOD_DAYS = [7, 30, 90] as const
export const DEFAULT_DAYS = 30

export function parseDays(raw: string | null): number {
  const n = Number(raw)
  return (PERIOD_DAYS as readonly number[]).includes(n) ? n : DEFAULT_DAYS
}

export const RULE_KIND_META: Record<RuleKind, { label: string; hint: string; ext: string }> = {
  sigma: { label: "Sigma", hint: "Log searches for your SIEM", ext: ".yml" },
  suricata: { label: "Suricata", hint: "Network rules for your IDS", ext: ".rules" },
}

export type RuleSource = "web-paths" | "commands" | "domains" | "urls" | "hashes" | "static"

export const SOURCE_LABELS: Record<RuleSource, string> = {
  "web-paths": "Web requests",
  commands: "Shell commands",
  domains: "Contacted domains",
  urls: "Download URLs",
  hashes: "File hashes",
  static: "Built-in",
}

export interface DetectionRule {
  id: string
  kind: RuleKind
  title: string
  severity: "notice" | "warning" | "severe"
  source: RuleSource
  rationale: string
  sessions: number
  sources: number
  text: string
}

export interface DetectionPage extends Page<DetectionRule> {
  generated_at: string
  days: number
  total: number
}

export interface GuidanceItem {
  tag: string
  title: string
  what: string
  look: string[]
  fix: string[]
  severity: "notice" | "warning" | "severe"
  seen: { sessions: number; sources: number; last_seen: string | null }
}

export function detectionsSentence(total: number | undefined, days: number): string {
  if (total === undefined)
    return "Detection rules written from the attacks the decoys recorded. Review each one before you deploy it."
  if (total === 0)
    return `No detection rules yet: nothing in the last ${plural(days, "day")} came from enough different sources.`
  return `We wrote ${plural(total, "detection rule")} from attacks seen in the last ${plural(days, "day")}. Review each one before you deploy it.`
}

export function evidenceLine(sessions: number, sources: number): string {
  return `${plural(sessions, "session")} from ${plural(sources, "source")}`
}

export function detectionsExportUrl(kind: RuleKind, days: number): string {
  return `${API_BASE}/defend/detections/export?kind=${kind}&days=${days}`
}

/* --- Exposure ----------------------------------------------------------- */

export type Exposure = "internet" | "vpn" | "internal"
export const EXPOSURE_OPTIONS: { value: Exposure; label: string }[] = [
  { value: "internet", label: "Internet" },
  { value: "vpn", label: "VPN" },
  { value: "internal", label: "Internal" },
]
export const EXPOSURE_LABEL: Record<Exposure, string> = {
  internet: "Faces the internet",
  vpn: "Behind a VPN",
  internal: "Internal only",
}

export interface InventoryItem {
  id: number
  name: string
  service: string
  product: string | null
  version: string | null
  exposure: Exposure
  notes: string | null
  created_by: string
  created_at: string
  updated_at: string
}

export interface InventoryInput {
  name: string
  service: string
  product?: string | null
  version?: string | null
  exposure: Exposure
  notes?: string | null
}

export type Verdict = "internet_targeted" | "internet_quiet" | "private_targeted" | "private_quiet"

export const VERDICT_SENTENCE: Record<Verdict, string> = {
  internet_targeted: "Reachable from the internet and attacked",
  internet_quiet: "Reachable from the internet, but no attacks recorded",
  private_targeted: "Kept private, yet attackers go after this kind of service",
  private_quiet: "Kept private, and no attacks recorded on this kind of service",
}

export interface ExposureService {
  item: InventoryItem
  label: string
  verdict: Verdict
  attacks: {
    sessions: number
    sources: number
    deep_sessions: number
    previous_sessions: number
    last_attack_at: string | null
  }
  top_tags: { tag: string; sessions: number }[]
  cves: { cve_id: string; title: string | null; cvss_score: number | null; in_kev: boolean }[]
  checks: string[]
}

export interface UnlistedService {
  service: string
  label: string
  sessions: number
  sources: number
  checks: string[]
}

export interface ExposureReport {
  days: number
  generated_at: string
  services: ExposureService[]
  unlisted: UnlistedService[]
}

/** "You told us you run 6 services; 4 of them face the internet and were targeted 1,204 times ..." */
export function exposureSentence(r: ExposureReport | undefined, days: number): string {
  if (!r) return "How what you run compares with what attackers went after."
  const n = r.services.length
  if (n === 0) {
    const seen = r.unlisted.reduce((sum, u) => sum + u.sessions, 0)
    return `Tell us what you run and we compare it with the ${plural(seen, "attack")} the decoys recorded in the last ${plural(days, "day")}.`
  }
  const facing = r.services.filter((s) => s.item.exposure === "internet")
  const hits = facing.reduce((sum, s) => sum + s.attacks.sessions, 0)
  const verbs = facing.length === 1 ? "faces the internet and was" : "face the internet and were"
  return `You told us you run ${plural(n, "service")}; ${formatNumber(facing.length)} of them ${verbs} targeted ${plural(hits, "time")} in the last ${plural(days, "day")}.`
}

/** "up 20% from 120 before". Neutral words: more attacks are neither good nor bad news here. */
export function previousComparison(current: number, previous: number): string {
  if (previous === 0) return current === 0 ? "none before either" : "none in the period before"
  const change = (current - previous) / previous
  if (Math.abs(change) < 0.05) return `about the same as before (${formatNumber(previous)})`
  return `${change > 0 ? "up" : "down"} ${Math.round(Math.abs(change) * 100)}% from ${formatNumber(previous)} before`
}

export function serviceLabel(service: string): string {
  return sensorMeta(service)?.label ?? service.toUpperCase()
}

export function validateInventory(input: InventoryInput): { name?: string } {
  const name = input.name.trim()
  if (!name) return { name: "Give it a name, for example the host or the app." }
  if (name.length > 80) return { name: "Use at most 80 characters." }
  return {}
}

/* --- Feeds -------------------------------------------------------------- */

export interface FeedToken {
  id: number
  name: string
  hint: string
  kinds: BlockKind[]
  min_score: number
  include_benign: boolean
  created_by: string
  created_at: string
  expires_at: string | null
  revoked_at: string | null
  last_used_at: string | null
  last_used_ip: string | null
  use_count: number
  state: "active" | "revoked" | "expired"
}

export interface FeedTokenList {
  enabled: boolean
  items: FeedToken[]
}

export interface NewFeedToken {
  name: string
  kinds: BlockKind[]
  minScore: number
  includeBenign: boolean
  expiresInDays: number | null
}

export const EXPIRY_OPTIONS = [
  { value: "none", label: "Never", days: null },
  { value: "30", label: "30 days", days: 30 },
  { value: "90", label: "90 days", days: 90 },
  { value: "365", label: "1 year", days: 365 },
] as const

export function feedsSentence(list: FeedTokenList | undefined): string {
  if (!list) return "Let your firewall pull the blocklists on its own."
  if (!list.enabled)
    return "Feeds are off. Turn them on to let your firewall pull the blocklists by itself."
  const active = list.items.filter((t) => t.state === "active").length
  if (active === 0)
    return "Feeds are on, but no token exists yet. Create one so your firewall can pull a list."
  return `${plural(active, "token")} can read your blocklists right now. Revoke any you no longer use.`
}

/** The kinds a token covers, as words: "ip addresses and domains". */
export function kindsPhrase(kinds: readonly BlockKind[]): string {
  const names = BLOCK_KINDS.filter((k) => kinds.includes(k)).map((k) =>
    KIND_META[k].label.toLowerCase(),
  )
  if (names.length <= 1) return names[0] ?? "nothing"
  return `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`
}

/** The URL form works for firewalls that cannot send headers (OPNsense, pfSense URL tables). */
export function feedUrl(origin: string, token: string, kind: BlockKind = "ip"): string {
  return `${origin.replace(/\/+$/, "")}/feeds/${token}/${kind}.txt`
}

export function feedCurl(origin: string, token: string, kind: BlockKind = "ip"): string {
  return `curl -H "Authorization: Bearer ${token}" ${origin.replace(/\/+$/, "")}/feeds/${kind}.txt`
}

/* --- Errors ------------------------------------------------------------- */

export type DefendFailure =
  "wrong-password" | "rate-limited" | "session" | "feeds-disabled" | "limit" | "invalid" | "network"

const FAILURE_MESSAGES: Record<DefendFailure, string> = {
  "wrong-password": "That password is not correct.",
  "rate-limited": "Too many attempts. Wait a minute, then try again.",
  session: "Your session has ended. Sign in again.",
  "feeds-disabled": "Feeds are turned off on this server. Set FEEDS_ENABLED=true in .env first.",
  limit: "You have reached the limit. Remove something you no longer need first.",
  invalid: "That value cannot be used.",
  network: "The server could not be reached. Try again in a moment.",
}

export function classifyFailure(e: unknown): DefendFailure {
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return "wrong-password"
    if (e.code === "session_revoked" || e.status === 401) return "session"
    if (e.code === "feeds_disabled") return "feeds-disabled"
    if (e.code === "limit_reached") return "limit"
    if (e.status === 429) return "rate-limited"
    if (e.status === 422) return "invalid"
  }
  return "network"
}

/** A sentence for the person; for an invalid value the API's own explanation comes first. */
export function describeDefendError(e: unknown): string {
  const kind = classifyFailure(e)
  if (kind === "invalid" && e instanceof ApiError && e.message.length > 0 && e.code)
    return e.message
  return FAILURE_MESSAGES[kind]
}

/* --- Fetchers ------------------------------------------------------------ */

const cursorParams = (cursor: string | null | undefined, limit: number) => ({
  cursor: cursor ?? undefined,
  limit,
})

export const defendApi = {
  summary: () => getJson<DefendSummary>("/defend/summary"),
  blocklist: (f: BlocklistFilters, cursor: string | null | undefined, limit = 50) =>
    getJson<Page<BlockEntry>>("/defend/blocklist", {
      kind: f.kind,
      min_score: f.min_score,
      q: f.q,
      reason: f.reason,
      include_benign: f.include_benign ? "true" : undefined,
      ...cursorParams(cursor, limit),
    }),
  overrides: () => getJson<Page<OverrideItem>>("/defend/overrides", { limit: 200 }),
  feedTokens: () => getJson<FeedTokenList>("/defend/feed-tokens"),
  detections: (kind: RuleKind, days: number, cursor: string | null | undefined, limit = 10) =>
    getJson<DetectionPage>("/defend/detections", { kind, days, ...cursorParams(cursor, limit) }),
  guidance: (days: number) =>
    getJson<{ days: number; items: GuidanceItem[] }>("/defend/guidance", { days }),
  inventory: () => getJson<Page<InventoryItem>>("/defend/inventory", { limit: 200 }),
  exposure: (days: number) => getJson<ExposureReport>("/defend/exposure", { days }),
}

export function createOverride(input: {
  kind: BlockKind
  value: string
  action: OverrideAction
  note?: string
  expiresInDays?: number | null
}): Promise<OverrideItem> {
  const body: Record<string, unknown> = {
    kind: input.kind,
    value: input.value,
    action: input.action,
  }
  if (input.note?.trim()) body.note = input.note.trim()
  if (input.expiresInDays) body.expires_in_days = input.expiresInDays
  return sendJson<OverrideItem>("POST", "/defend/overrides", body)
}

export const deleteOverride = (id: number) => sendJson("DELETE", `/defend/overrides/${id}`)

function inventoryBody(input: Partial<InventoryInput>) {
  const body: Record<string, unknown> = {}
  if (input.name !== undefined) body.name = input.name.trim()
  if (input.service !== undefined) body.service = input.service
  if (input.exposure !== undefined) body.exposure = input.exposure
  for (const key of ["product", "version", "notes"] as const) {
    const v = input[key]
    if (v !== undefined) body[key] = v?.trim() ? v.trim() : null
  }
  return body
}

export const createInventory = (input: InventoryInput) =>
  sendJson<InventoryItem>("POST", "/defend/inventory", inventoryBody(input))
export const updateInventory = (id: number, input: Partial<InventoryInput>) =>
  sendJson<InventoryItem>("PATCH", `/defend/inventory/${id}`, inventoryBody(input))
export const deleteInventory = (id: number) => sendJson("DELETE", `/defend/inventory/${id}`)

/** Creates a token. The secret is in the answer once and is never kept by this module. */
export function createFeedToken(
  input: NewFeedToken,
  password: string,
): Promise<{ token: string; item: FeedToken }> {
  const body: Record<string, unknown> = {
    name: input.name.trim(),
    kinds: input.kinds,
    min_score: input.minScore,
    include_benign: input.includeBenign,
    password,
  }
  if (input.expiresInDays) body.expires_in_days = input.expiresInDays
  return sendJson<{ token: string; item: FeedToken }>("POST", "/defend/feed-tokens", body)
}

export const revokeFeedToken = (id: number) =>
  sendJson<FeedToken>("POST", `/defend/feed-tokens/${id}/revoke`)
