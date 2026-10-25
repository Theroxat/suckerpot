/**
 * Alert channels, rules, recent alerts and weekly reports (M18).
 *
 * Nothing secret ever comes back from the API: a channel shows a short hint of where it goes.
 * Creating a channel or changing where it goes asks for the administrator's password again.
 */
import { ApiError, API_BASE, sendJson, type Page } from "@/lib/api"
import { plural } from "@/lib/format"
import type { Severity } from "@/lib/severity"

export type ChannelKind = "discord" | "teams" | "email"
export type RuleKind =
  "new_campaign" | "new_download_host" | "malware_drop" | "watched_cve_seen" | "weekly_report"
export type OutboxState = "pending" | "sent" | "failed" | "suppressed"

export interface LastTest {
  state: "queued" | "done" | "refused" | "failed"
  detail: string | null
  requested_at: string
}

export interface AlertChannel {
  id: number
  kind: ChannelKind
  name: string
  enabled: boolean
  /** Not secret: the host of a webhook, or a partly hidden e-mail address. */
  target_hint: string
  mask_ips: boolean
  created_by: string
  created_at: string
  updated_at: string
  last_test: LastTest | null
}

export interface AlertRule {
  kind: RuleKind
  enabled: boolean
  channel_ids: number[]
  min_severity: Severity
}

export interface WatchedCve {
  cve_id: string
  added_by: string
  added_at: string
}

export interface OutboxItem {
  id: number
  rule_kind: RuleKind
  channel_id: number
  channel_name: string | null
  state: OutboxState
  attempts: number
  created_at: string
  sent_at: string | null
  error_code: string | null
  severity: Severity | null
  title: string | null
  summary: string | null
}

export interface AlertStatus {
  alerts: {
    enabled: boolean
    smtp_configured: boolean
    can_decrypt: boolean
    last_error: string | null
    updated_at: string | null
  }
  reports_enabled: boolean
  editing_enabled: boolean
  editing_reason: string | null
  channels: number
  limits: { per_minute: number; per_day: number; all_channels_per_day: number }
}

export interface ReportItem {
  week_start: string
  week_end: string | null
  headline: string | null
  sessions: number
  sources: number
  malware: number
  change_pct: number | null
  created_at: string
}

/** The stored summary, as ingest writes it (`ingest/reports/build.py`). Every field is optional:
 * older or partial reports still render, with an empty section instead of an error. */
export interface ReportSummary {
  headline?: string
  week_end?: string
  timezone?: string
  actions?: string[]
  totals?: {
    sessions?: number
    sources?: number
    with_commands?: number
    malware?: number
    previous_sessions?: number
    change_pct?: number | null
  }
  by_sensor?: { sensor: string; sessions: number }[]
  countries?: { country: string; sessions: number }[]
  tags?: { tag: string; sessions: number }[]
  campaigns?: { id: number; name: string; severity: string; sessions: number; sources: number }[]
  download_hosts?: { host: string; sightings: number }[]
  watched_cves?: { cve_id: string; sessions: number }[]
}

export interface ReportDetail {
  week_start: string
  created_at: string
  summary: ReportSummary
}

export const KIND_LABEL: Record<ChannelKind, string> = {
  discord: "Discord",
  teams: "Microsoft Teams",
  email: "E-mail",
}

export const KIND_OPTIONS = [
  { value: "discord", label: "Discord" },
  { value: "teams", label: "Teams" },
  { value: "email", label: "E-mail" },
] as const

export const TARGET_LABEL: Record<ChannelKind, { label: string; hint: string; example: string }> = {
  discord: {
    label: "Webhook URL",
    hint: "In Discord: channel settings, Integrations, Webhooks, Copy Webhook URL.",
    example: "https://discord.com/api/webhooks/…",
  },
  teams: {
    label: "Webhook URL",
    hint: "In Teams: the Workflows app, “Post to a channel when a webhook request is received”.",
    example: "https://….logic.azure.com/workflows/…",
  },
  email: {
    label: "E-mail address",
    hint: "One address. The server needs SMTP settings in .env for e-mail to work.",
    example: "security@example.org",
  },
}

export interface RuleInfo {
  kind: RuleKind
  title: string
  /** One plain sentence: when does this fire. */
  when: string
}

/** In the order they are shown. */
export const RULES: readonly RuleInfo[] = [
  {
    kind: "new_campaign",
    title: "A new campaign appears",
    when: "Several addresses start running the same attack against the honeypot.",
  },
  {
    kind: "malware_drop",
    title: "Malware is dropped",
    when: "An attacker downloads or runs a payload in a session.",
  },
  {
    kind: "new_download_host",
    title: "A new malware download host",
    when: "Attackers use a server we have never seen before to deliver payloads.",
  },
  {
    kind: "watched_cve_seen",
    title: "A watched vulnerability is tried",
    when: "A CVE on your watch list is used against the honeypot (at most one alert per CVE and day).",
  },
  {
    kind: "weekly_report",
    title: "The weekly report is ready",
    when: "Every Monday morning: what happened, what changed and what to do next.",
  },
]

export const RULE_TITLE: Record<RuleKind, string> = Object.fromEntries(
  RULES.map((r) => [r.kind, r.title]),
) as Record<RuleKind, string>

export const SEVERITY_OPTIONS = [
  { value: "info", label: "Any" },
  { value: "warning", label: "Warning and up" },
  { value: "severe", label: "Severe only" },
] as const

export const STATE_LABEL: Record<OutboxState, string> = {
  pending: "Waiting",
  sent: "Sent",
  failed: "Failed",
  suppressed: "Not sent",
}

const ERROR_TEXT: Record<string, string> = {
  blocked_target: "The address is not an allowed destination.",
  private_address: "The address points to a private network, so it was refused.",
  dns: "The host name could not be looked up.",
  timeout: "The service did not answer in time.",
  network: "The service could not be reached.",
  tls: "The secure connection failed (certificate check).",
  redirect: "The service answered with a redirect, which is never followed.",
  http_429: "The service asked us to slow down.",
  http_5xx: "The service had a problem on its side.",
  http_400: "The service refused the message.",
  http_401: "The service refused the credentials.",
  http_403: "The service refused the credentials.",
  http_404: "The webhook does not exist any more.",
  smtp_auth: "The mail server refused the user name or password.",
  smtp_recipient: "The mail server refused the recipient.",
  smtp_error: "The mail server returned an error.",
  smtp_not_configured: "E-mail is not set up on the server (SMTP settings in .env).",
  cannot_decrypt: "The stored address cannot be read with the current encryption key.",
  no_encryption_key: "The server has no encryption key for stored addresses.",
  too_large: "The message was too large.",
  digested: "Sent as part of a summary message.",
  daily_limit: "The daily limit was reached.",
  channel_disabled: "The channel was switched off.",
  channel_missing: "The channel no longer exists.",
}

export function describeError(code: string | null | undefined): string {
  if (!code) return ""
  return ERROR_TEXT[code] ?? "Something went wrong."
}

/** What the last test says, in a sentence. */
export function describeTest(test: LastTest | null): string | null {
  if (!test) return null
  if (test.state === "queued") return "Test requested. It is sent within a few seconds."
  if (test.state === "done") return "The last test message arrived."
  return `The last test did not work. ${describeError(test.detail)}`.trim()
}

export function testInFlight(channels: readonly AlertChannel[] | undefined): boolean {
  return (channels ?? []).some((c) => c.last_test?.state === "queued")
}

export function channelsFinding(status: AlertStatus | undefined, channels: AlertChannel[]): string {
  if (status && !status.alerts.enabled)
    return "Alerts are switched off on this server, so nothing is sent."
  if (channels.length === 0) return "No channel yet. Add one to receive alerts."
  const on = channels.filter((c) => c.enabled).length
  const broken = channels.filter(
    (c) => c.last_test && (c.last_test.state === "failed" || c.last_test.state === "refused"),
  ).length
  const base = `${plural(on, "channel")} ${on === 1 ? "is" : "are"} ready to receive alerts.`
  return broken > 0 ? `${base} ${plural(broken, "test")} failed, check the details below.` : base
}

export function rulesFinding(
  rules: readonly AlertRule[],
  channels: readonly AlertChannel[],
): string {
  const on = rules.filter((r) => r.enabled).length
  if (on === 0)
    return channels.length === 0
      ? "Nothing is sent yet: add a channel, then switch on the alerts you care about."
      : "Every alert is off. Switch on the ones you want, and pick where they go."
  return `${plural(on, "alert")} ${on === 1 ? "is" : "are"} on. Everything else stays quiet.`
}

export function outboxFinding(items: readonly OutboxItem[]): string {
  if (items.length === 0) return "No alert has been queued yet."
  const sent = items.filter((i) => i.state === "sent").length
  const failed = items.filter((i) => i.state === "failed").length
  const head = `${plural(sent, "alert")} sent recently`
  return failed > 0 ? `${head}, ${failed} could not be delivered.` : `${head}.`
}

export function reportsFinding(items: readonly ReportItem[]): string {
  const first = items[0]
  if (!first) return "No weekly report yet. The first one is built on the next Monday morning."
  return first.headline ?? `Latest report: week of ${weekLabel(first.week_start)}.`
}

/** "Oct 12 to Oct 18" for a Monday (date-only strings are UTC dates, shown as written). */
export function weekLabel(weekStart: string, weekEnd?: string | null): string {
  const fmt = (iso: string) =>
    new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" }).format(
      new Date(`${iso}T00:00:00Z`),
    )
  const end =
    weekEnd ??
    new Date(Date.parse(`${weekStart}T00:00:00Z`) + 6 * 86_400_000).toISOString().slice(0, 10)
  return `${fmt(weekStart)} to ${fmt(end)}`
}

export const CVE_PATTERN = /^CVE-\d{4}-\d{4,10}$/

/* --- Errors ------------------------------------------------------------------------------- */

export type AlertErrorReason =
  | "wrong-password"
  | "password-required"
  | "invalid-target"
  | "editing-disabled"
  | "alerts-disabled"
  | "rate-limited"
  | "too-many"
  | "no-channel"
  | "not-found"
  | "session"
  | "network"

export const ALERT_MESSAGES: Record<AlertErrorReason, string> = {
  "wrong-password": "That password is not right.",
  "password-required": "Enter your password to confirm.",
  "invalid-target": "This is not an allowed destination.",
  "editing-disabled": "Alert channels cannot be edited: the server has no encryption key.",
  "alerts-disabled": "Alerts are switched off on this server (ALERTS_ENABLED in .env).",
  "rate-limited": "Please wait a moment before trying again.",
  "too-many": "That is the maximum number of items.",
  "no-channel": "Choose at least one channel first.",
  "not-found": "This item no longer exists.",
  session: "Your session has ended. Sign in again.",
  network: "The change could not be saved. Try again.",
}

export class AlertError extends Error {
  constructor(
    readonly reason: AlertErrorReason,
    detail?: string,
  ) {
    super(detail ?? ALERT_MESSAGES[reason])
    this.name = "AlertError"
  }
}

export function toAlertError(e: unknown): AlertError {
  if (e instanceof AlertError) return e
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return new AlertError("wrong-password")
    if (e.code === "password_required") return new AlertError("password-required")
    if (e.code === "invalid_target") return new AlertError("invalid-target", e.message)
    if (e.code === "editing_disabled") return new AlertError("editing-disabled")
    if (e.code === "alerts_disabled") return new AlertError("alerts-disabled")
    if (e.code === "no_channel" || e.code === "bad_channels") return new AlertError("no-channel")
    if (e.code === "too_many") return new AlertError("too-many")
    if (e.code === "not_found") return new AlertError("not-found")
    if (e.status === 429) return new AlertError("rate-limited")
    if (e.status === 401) return new AlertError("session")
  }
  return new AlertError("network")
}

async function run<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    throw toAlertError(e)
  }
}

/* --- Requests ----------------------------------------------------------------------------- */

async function getJson<T>(path: string, params: Record<string, string | undefined> = {}) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v)
  const res = await fetch(`${API_BASE}${path}${qs.size ? `?${qs.toString()}` : ""}`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
  if (!res.ok) throw new ApiError(res.status, res.statusText)
  return (await res.json()) as T
}

export const alertKeys = {
  status: ["alerts", "status"] as const,
  channels: ["alerts", "channels"] as const,
  rules: ["alerts", "rules"] as const,
  watched: ["alerts", "watched"] as const,
  outbox: ["alerts", "outbox"] as const,
  reports: ["reports"] as const,
  report: (week: string) => ["reports", week] as const,
}

export const alertsApi = {
  status: () => getJson<AlertStatus>("/alerts/status"),
  channels: () => getJson<AlertChannel[]>("/alerts/channels"),
  rules: () => getJson<AlertRule[]>("/alerts/rules"),
  watched: () => getJson<WatchedCve[]>("/alerts/watched-cves"),
  outbox: (cursor?: string | null) =>
    getJson<Page<OutboxItem>>("/alerts/outbox", { cursor: cursor ?? undefined, limit: "10" }),
  reports: (cursor?: string | null) =>
    getJson<Page<ReportItem>>("/reports", { cursor: cursor ?? undefined, limit: "12" }),
  report: (week: string) => getJson<ReportDetail>(`/reports/${encodeURIComponent(week)}`),
}

/** The printable page (served by the API under its own strict policy). */
export const reportHtmlUrl = (week: string) =>
  `${API_BASE}/reports/${encodeURIComponent(week)}/html`

export interface NewChannel {
  kind: ChannelKind
  name: string
  target: string
  maskIps: boolean
}

export function createChannel(input: NewChannel, password: string): Promise<AlertChannel> {
  return run(() =>
    sendJson<AlertChannel>("POST", "/alerts/channels", {
      kind: input.kind,
      name: input.name.trim(),
      target: input.target.trim(),
      mask_ips: input.maskIps,
      password,
    }),
  )
}

export function updateChannel(
  id: number,
  changes: { name?: string; enabled?: boolean; mask_ips?: boolean },
): Promise<AlertChannel> {
  return run(() => sendJson<AlertChannel>("PATCH", `/alerts/channels/${id}`, changes))
}

export function changeChannelTarget(
  id: number,
  target: string,
  password: string,
): Promise<AlertChannel> {
  return run(() =>
    sendJson<AlertChannel>("PATCH", `/alerts/channels/${id}`, { target: target.trim(), password }),
  )
}

export function deleteChannel(id: number): Promise<void> {
  return run(() => sendJson("DELETE", `/alerts/channels/${id}`))
}

export function requestChannelTest(id: number): Promise<void> {
  return run(async () => {
    await sendJson("POST", `/alerts/channels/${id}/test`)
  })
}

export function saveRule(
  kind: RuleKind,
  rule: { enabled: boolean; channel_ids: number[]; min_severity: Severity },
): Promise<AlertRule> {
  return run(() => sendJson<AlertRule>("PUT", `/alerts/rules/${kind}`, rule))
}

export function watchCve(id: string): Promise<WatchedCve> {
  return run(() => sendJson<WatchedCve>("PUT", `/alerts/watched-cves/${encodeURIComponent(id)}`))
}

export function unwatchCve(id: string): Promise<void> {
  return run(() => sendJson("DELETE", `/alerts/watched-cves/${encodeURIComponent(id)}`))
}
