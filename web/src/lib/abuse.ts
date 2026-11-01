/**
 * Abuse reports (M22): shapes of `/api/v1/abuse/*` (docs/design/m22.md section 9.1 is the
 * contract), the plain-English sentences of the pages, and the calls. Nothing here sends mail:
 * the owner copies the draft into his own webmail. The sentences are pure and tested.
 */
import { ApiError, getBlob, getJson, sendJson, type Page } from "./api"
import { plural } from "./format"

// --- Vocabulary -------------------------------------------------------------------

export type ReportKind = "attack_source" | "payload_host" | "c2"
export const KIND_LABEL: Record<ReportKind, string> = {
  attack_source: "Attack source",
  payload_host: "Payload host",
  c2: "C2 server",
}

export type ReportStatus = "draft" | "reviewed" | "sent" | "closed" | "discarded" | "superseded"
/** The tabs of the list, in workflow order. `superseded` is never shown. */
export const LIST_STATUSES = ["draft", "reviewed", "sent", "closed", "discarded"] as const
export type ListStatus = (typeof LIST_STATUSES)[number]
export const STATUS_LABEL: Record<ReportStatus, string> = {
  draft: "Draft",
  reviewed: "Reviewed",
  sent: "Sent",
  closed: "Closed",
  discarded: "Discarded",
  superseded: "Replaced",
}
export const TAB_LABEL: Record<ListStatus, string> = {
  draft: "Drafts",
  reviewed: "Reviewed",
  sent: "Sent",
  closed: "Closed",
  discarded: "Discarded",
}
/** The four steps of the stepper (discarded and replaced are side exits). */
export const STEPS = ["draft", "reviewed", "sent", "closed"] as const

export type MessageFormat = "text" | "xarf" | "eml"
export const FORMAT_OPTIONS = [
  { value: "text", label: "Plain text" },
  { value: "xarf", label: "X-ARF" },
  { value: "eml", label: ".eml" },
] as const

export type Tlp = "clear" | "green" | "amber" | "red"
export const TLP_OPTIONS = [
  { value: "green", label: "TLP:GREEN" },
  { value: "amber", label: "TLP:AMBER" },
  { value: "clear", label: "TLP:CLEAR" },
] as const
export const DEFAULT_TLP: Tlp = "green"

/** Reason codes of the identity check. They never carry the matched value. */
export const GUARD_REASON: Record<string, string> = {
  self_address: "The text contains the public address of the monitored system.",
  self_name: "The text contains a name that belongs to the monitored system.",
  owner_domain: "The text contains a domain that belongs to you.",
  vpn_address: "The text contains the address that outbound traffic leaves from.",
  project_term: "The text contains the name of this project or a word that gives it away.",
  private_address: "The text contains a private or reserved network address.",
  documentation_address: "The text contains an example address that real reports must not use.",
  dashboard_path: "The text contains a link or path into this dashboard.",
  internal_id: "The text contains an internal identifier that links back to the dashboard.",
  default_wording: "The text contains wording shipped with the software.",
  no_self_address:
    "The address of the monitored system is not known yet, so nothing can be checked. Reports stay locked until traffic teaches it, or you add it in Settings.",
  self_terms_unavailable:
    "The list of things that must never appear could not be read, so nothing is released.",
}

export function guardReason(code: string): string {
  return GUARD_REASON[code] ?? "The identity check refused this text."
}

// --- Shapes -----------------------------------------------------------------------

export interface Recipient {
  id: number
  name: string
  /** The mailbox the report goes to; null while no contact was found. */
  mailbox: string | null
  source: "rdap" | "manual"
  muted: boolean
}

export interface AsnRef {
  asn: number
  name: string | null
}

export interface GuardResult {
  ok: boolean
  /** Constant codes only, never the matched text. */
  codes: string[]
}

export interface ReportItem {
  public_id: string
  kind: ReportKind
  status: ReportStatus
  demo: boolean
  recipient: Recipient
  asns: AsnRef[]
  subject_count: number
  window_start: string
  window_end: string
  updated_at: string
  revision: number
  guard: GuardResult
}

export interface ReportSubject {
  subject_type: "ip" | "url" | "domain"
  value: string
  asn: number | null
  network: string | null
  handle: string | null
  sessions: number
  events: number
  first_ts: string
  last_ts: string
  /** The internal dashboard view of this subject. Used by the UI only, never in the text. */
  link: string
}

export interface HistoryEntry {
  ts: string
  actor: string
  from: ReportStatus | null
  to: ReportStatus
}

export interface ReportOptions {
  defang: boolean
  time_precision: "second" | "minute"
  include_usernames: boolean
  include_reply_contact: boolean
  /** The counter line "N values masked, M lines left out". Off unless asked for. */
  show_redaction_counts: boolean
}

export interface ReportDetail extends ReportItem {
  subjects: ReportSubject[]
  /** Counters only: how many values were masked and how many lines left out. */
  redaction: { masked: number; removed: number }
  options: ReportOptions
  notes: string | null
  history: HistoryEntry[]
  /** True when the intro is not the public default wording. Review needs it. */
  custom_intro: boolean
  /** When the same subjects were reported before, if so. */
  previously_reported: string | null
  reviewed_at: string | null
  sent_at: string | null
  closed_at: string | null
}

export interface Attachment {
  name: string
  media_type: string
  content: string
}

export interface RenderedMessage {
  to: string
  subject: string
  body: string
  attachments: Attachment[]
  revision: number
  guard: GuardResult
}

export interface AbuseStatus {
  enabled: boolean
  gate: "open" | "closed"
  rdap_quota: { used: number; limit: number }
  self_address_known: boolean
  /** False when the learned address is stale: reports stay blocked until a fresh one is known. */
  self_address_fresh: boolean
  counts: Record<ReportStatus, number>
  waiting_for_contact: number
}

export interface WaitingRecipient {
  id: number
  name: string
  asns: AsnRef[]
  subject_count: number
}

export interface ReportSettings {
  reply_contact: string | null
  signature: string | null
  /** Null while the public default wording is in use. */
  intro: string | null
  outro: string | null
  xarf_user_agent: string | null
  /** The sentence about the withheld destination and the source ports. */
  note: string | null
  /** The subject line of the message. */
  subject_template: string | null
  /** Round times to the minute (the default). Off sends exact times. */
  round_times: boolean
  default_options: Pick<
    ReportOptions,
    "defang" | "include_usernames" | "include_reply_contact" | "show_redaction_counts"
  >
  default_tlp: Tlp
  revision: number
}

export interface SelfTerm {
  id: number
  kind: "address" | "cidr" | "name" | "text"
  /** Masked unless revealed. */
  value: string
  source: "learned" | "manual" | "sensor"
  confirmed: boolean
  distinct_sources: number
}

export interface ReportFilters {
  status?: ListStatus
  kind?: ReportKind
  recipient?: number
}

// --- Sentences ---------------------------------------------------------------------

/** The sentence above the list. */
export function describeReports(status: AbuseStatus | undefined): string {
  if (!status) return "Reports to the networks that host the attackers, for you to review and send."
  if (!status.enabled)
    return "Abuse reports are switched off on this server, so no drafts are written."
  const ready = status.counts.draft
  const reviewed = status.counts.reviewed
  if (ready === 0 && reviewed === 0)
    return "Nothing to report: no source crossed the thresholds this week."
  const parts: string[] = []
  if (ready > 0)
    parts.push(`${plural(ready, "report")} ${ready === 1 ? "is" : "are"} ready for review`)
  if (reviewed > 0)
    parts.push(
      `${plural(reviewed, "report")} ${reviewed === 1 ? "is" : "are"} reviewed and waiting to be sent`,
    )
  return `${parts.join(", ")}.`
}

/** Why the list cannot be used yet, or null. The message is one sentence. */
export function blockedReason(status: AbuseStatus | undefined): string | null {
  if (!status) return null
  if (!status.enabled)
    return "The reporting worker is off. Set ABUSE_REPORTS_ENABLED=true in .env and restart to get drafts."
  if (!status.self_address_known)
    return "The public address of the monitored system is not known yet, so reports are locked. Traffic teaches it within a day, or you can add it in Settings."
  if (!status.self_address_fresh)
    return "The learned address of the monitored system is out of date, so reports are blocked until a fresh one is known. Traffic refreshes it, or you can enter it by hand in Settings."
  if (status.gate === "closed")
    return "Outbound traffic is closed, so abuse contacts cannot be looked up. Drafts already written still open."
  return null
}

/** "3 addresses in 2 networks" for the first line of a report page. */
export function describeReport(r: ReportItem): string {
  const nets = new Set(r.asns.map((a) => a.asn)).size
  const noun =
    r.kind === "attack_source"
      ? "address"
      : r.kind === "payload_host"
        ? "payload host"
        : "C2 server"
  const where = nets > 0 ? ` in ${plural(nets, "network")}` : ""
  const n = r.subject_count
  const what = noun === "address" ? plural(n, "address", "addresses") : plural(n, noun)
  const name = r.recipient.name
  return `${what}${where}, reported to ${name}${name.endsWith(".") ? "" : "."}`
}

/** The finding of the identity check card. */
export function describeGuard(guard: GuardResult, redaction: { masked: number; removed: number }) {
  if (!guard.ok) {
    return "Blocked: this report would reveal something it must not. It cannot be copied or downloaded."
  }
  const parts: string[] = []
  if (redaction.masked > 0) parts.push(`${plural(redaction.masked, "address", "addresses")} masked`)
  if (redaction.removed > 0) parts.push(`${plural(redaction.removed, "line")} removed`)
  return `Nothing identifying found.${parts.length ? ` ${capitalize(parts.join(", "))}.` : ""}`
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/** What the next step needs, or null when nothing blocks it. */
export function reviewBlocker(r: ReportDetail): string | null {
  if (!r.guard.ok) return "The identity check blocked this report, so it cannot be reviewed."
  if (!r.recipient.mailbox) return "There is no abuse mailbox for this provider yet."
  if (!r.custom_intro)
    return "Write your own introduction in Settings first. The default wording is public, so anyone could recognise it."
  return null
}

/** Allowed next statuses from the current one, per the workflow. */
export function nextActions(
  status: ReportStatus,
): ("reviewed" | "sent" | "closed" | "discarded" | "draft")[] {
  switch (status) {
    case "draft":
      return ["reviewed", "discarded"]
    case "reviewed":
      return ["sent", "draft", "discarded"]
    case "sent":
      return ["closed"]
    default:
      return []
  }
}

export const SETTINGS_INCOMPLETE = "Finish the Reporting settings first"

/** A readable message for a failed call. */
export function describeAbuseError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === "revision_mismatch" || (e.status === 409 && e.code === "stale"))
      return "The draft changed while you were reading it. It was reloaded: read it again, then retry."
    if (e.code === "invalid_transition") return "That step is not possible from the current status."
    if (e.code === "settings_incomplete") return SETTINGS_INCOMPLETE
    if (e.code === "demo_report") return "This is a demo report. It can be reviewed but never sent."
    if (e.code === "no_mailbox") return "There is no abuse mailbox for this provider yet."
    if (e.code === "evidence_invalid") return "The stored evidence for this report is not valid."
    if (e.code === "xarf_reply_contact_required")
      return "X-ARF needs a reply contact, so the abuse desk can answer."
    if (e.code === "xarf_unavailable") return "This report cannot be written as X-ARF."
    if (e.code === "custom_intro_required")
      return "Write your own introduction in Settings before marking a report as reviewed."
    if (e.code === "identity_guard_failed") return "The identity check blocked this text."
    if (e.code === "reauth_failed") return "That password is not right."
    if (e.status === 429) return "Too many requests. Wait a moment and try again."
    if (e.status === 403) return "Only an administrator can do this."
    if (e.status === 422 && e.message) return e.message
  }
  return "That did not work. Check the connection and try again."
}

/** Field names listed by a 409 `settings_incomplete` answer (`missing`), or []. */
export function missingSettingsOf(e: unknown): string[] {
  if (!(e instanceof ApiError) || e.code !== "settings_incomplete") return []
  const m = e.body?.missing
  return Array.isArray(m) ? m.filter((x): x is string => typeof x === "string") : []
}

/** Reason codes of a 409 `identity_guard_failed` answer, or null for any other error. */
export function guardReasonsOf(e: unknown): string[] | null {
  if (!(e instanceof ApiError) || e.code !== "identity_guard_failed") return null
  const reasons = e.body?.reasons
  return Array.isArray(reasons) ? reasons.filter((r): r is string => typeof r === "string") : []
}

export function isStale(e: unknown): boolean {
  return e instanceof ApiError && e.status === 409 && e.code === "revision_mismatch"
}

// --- Calls -------------------------------------------------------------------------

export const abuseKeys = {
  all: ["abuse"] as const,
  status: ["abuse", "status"] as const,
  list: (f: ReportFilters) => ["abuse", "reports", f] as const,
  report: (id: string) => ["abuse", "report", id] as const,
  render: (id: string, format: MessageFormat, revision: number) =>
    ["abuse", "render", id, format, revision] as const,
  waiting: ["abuse", "waiting"] as const,
  settings: ["abuse", "settings"] as const,
  terms: (reveal: boolean) => ["abuse", "terms", reveal] as const,
}

export const abuseApi = {
  status: () => getJson<AbuseStatus>("/abuse/status"),
  list: (f: ReportFilters, cursor?: string | null) =>
    getJson<Page<ReportItem>>("/abuse/reports", {
      status: f.status,
      kind: f.kind,
      recipient: f.recipient,
      cursor: cursor ?? undefined,
      limit: 50,
    }),
  report: (id: string) => getJson<ReportDetail>(`/abuse/reports/${id}`),
  render: (id: string, format: MessageFormat) =>
    getJson<RenderedMessage>(`/abuse/reports/${id}/render`, { format }),
  waiting: () => getJson<WaitingRecipient[]>("/abuse/recipients", { waiting: "true" }),
  setStatus: (id: string, body: { to: ReportStatus; revision: number; sent_at?: string }) =>
    sendJson<ReportDetail>("POST", `/abuse/reports/${id}/status`, body),
  patch: (id: string, body: { notes?: string | null; options?: Partial<ReportOptions> }) =>
    sendJson<ReportDetail>("PATCH", `/abuse/reports/${id}`, body),
  regenerate: (id: string) => sendJson("POST", `/abuse/reports/${id}/regenerate`),
  setMailbox: (recipientId: number, mailbox: string) =>
    sendJson("PATCH", `/abuse/recipients/${recipientId}`, { override_mailbox: mailbox }),
  settings: () => getJson<ReportSettings>("/abuse/settings"),
  saveSettings: (body: ReportSettings) => sendJson<ReportSettings>("PUT", "/abuse/settings", body),
  terms: (reveal: boolean) =>
    getJson<SelfTerm[]>("/abuse/self-terms", { reveal: reveal ? "true" : undefined }),
  addTerm: (kind: SelfTerm["kind"], value: string) =>
    sendJson<SelfTerm>("POST", "/abuse/self-terms", { kind, value }),
  confirmTerm: (id: number) => sendJson("PATCH", `/abuse/self-terms/${id}`, { confirmed: true }),
  deleteTerm: (id: number) => sendJson("DELETE", `/abuse/self-terms/${id}`),
}

export type FileFormat = "txt" | "eml" | "evidence_csv" | "xarf_yaml"

/** A guarded file of one report. A blocked check rejects with the 409 and its reason codes. */
export const downloadFile = (id: string, format: FileFormat) =>
  getBlob(`/abuse/reports/${id}/download`, { format })

/** What a CERT export covers. */
export type ExportScope = { report: string } | { campaign: number } | { since: string }

export const exportFile = (
  kind: "stix" | "misp",
  scope: ExportScope,
  tlp: Tlp,
  description?: string,
) => getBlob(`/abuse/exports/${kind}`, { ...scope, tlp, description })
