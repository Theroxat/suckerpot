/**
 * Sending abuse reports (M25, docs/design/m25.md): shapes of the send queue and the optional SMTP
 * profile, the plain-English sentences for every error code, and the calls. By default nothing is
 * sent: mail leaves only after the owner sets up SMTP and picks a sending mode. The sentences and
 * the `mailto:` builder are pure and tested.
 */
import { ApiError, getJson, sendJson } from "./api"
import { guardReason } from "./abuse"
import { formatClock } from "./format"

// --- Shapes -----------------------------------------------------------------------

export type SendStatus = "pending" | "sent" | "failed" | "cancelled"

export interface SendRequest {
  status: SendStatus
  error_code: string | null
  done_at: string | null
}

export interface QueueItem {
  /** The public id of the report. */
  id: string
  recipient: string
  subject: string
  body_text: string
  /** When the automatic mode will send it, or null. */
  scheduled_at: string | null
  last_request: SendRequest | null
}

export type SendMode = "off" | "click" | "auto"
export type SmtpSecurity = "starttls" | "ssl"

export interface SmtpTest {
  status: SendStatus
  error_code: string | null
  done_at: string | null
}

export interface SmtpConfig {
  configured: boolean
  password_set: boolean
  host: string
  port: number
  security: SmtpSecurity
  username: string
  from_address: string
  from_name: string
  mode: SendMode
  auto_hold_minutes: number
  daily_cap: number
  sent_today: number
  last_test: SmtpTest | null
}

/** What the owner edits. The password is write-only: empty keeps the stored one. */
export interface SmtpForm {
  host: string
  port: number
  security: SmtpSecurity
  username: string
  from_address: string
  from_name: string
  mode: SendMode
  auto_hold_minutes: number
  daily_cap: number
  password: string
}

export const MODE_OPTIONS = [
  { value: "off", label: "Off" },
  { value: "click", label: "Send on click" },
  { value: "auto", label: "Automatic" },
] as const

export const MODE_EXPLANATION: Record<SendMode, string> = {
  off: "Nothing is sent by SuckerPot. You copy each report or open it in your mail app from the To send queue.",
  click:
    "A Send now button appears on a ready report. Nothing leaves until you confirm for that report.",
  auto: "Ready reports are sent after a waiting time, with a Cancel button while they wait.",
}

export const AUTO_WARNING =
  "Reports that pass the identity check are sent without you reading them. Use it only when you trust your wording and your settings."

export const HOLD_RANGE = { min: 10, max: 1440, fallback: 60 } as const
export const CAP_RANGE = { min: 1, max: 200, fallback: 20 } as const

/** The Proton preset: a paid plan with a custom domain. */
export const PROTON_PRESET = {
  host: "smtp.protonmail.ch",
  port: 587,
  security: "starttls",
} as const satisfies Pick<SmtpForm, "host" | "port" | "security">

// --- Sentences ---------------------------------------------------------------------

/** Why a send or a test failed, from the short code the worker records. */
export const SEND_ERROR: Record<string, string> = {
  auth_failed:
    "The mail server refused the username or password. Check them, or create a new SMTP token.",
  tls_failed:
    "The secure connection to the mail server could not be set up. Check the host, the port and the security setting.",
  refused: "The mail server refused the message or the recipient.",
  timeout: "The mail server did not answer in time.",
  egress_closed:
    "Outbound traffic through the VPN is closed, so nothing can leave. It retries when the VPN is back.",
  guard_failed:
    "The identity check blocked the complete message, so nothing was sent. Open the report to see why.",
}

export function describeSendErrorCode(code: string | null | undefined): string {
  return (code ? SEND_ERROR[code] : undefined) ?? "The message could not be sent."
}

/** One sentence about the last request of a report, or null when there is nothing to say. */
export function describeRequest(r: SendRequest | null): string | null {
  if (!r) return null
  switch (r.status) {
    case "pending":
      return "Sending…"
    case "sent":
      return r.done_at ? `Sent at ${formatClock(r.done_at)}.` : "Sent."
    case "failed":
      return `Not sent. ${describeSendErrorCode(r.error_code)}`
    case "cancelled":
      return "Cancelled. It will not be sent."
  }
}

/** Constant words for the 409 answers of the send route. */
export const SEND_CONFLICT: Record<string, string> = {
  smtp_off: "Sending is switched off. Choose a sending mode in Settings, under Reporting.",
  not_ready: "This report is not ready: the identity check, the settings or the status block it.",
  already_pending: "This report is already being sent.",
  cap_reached: "The daily limit of sent reports is reached. Try again tomorrow (UTC).",
}

/** Field and guard codes of a 422 answer on the SMTP profile. */
export const SMTP_PROBLEM: Record<string, string> = {
  bad_host: "The host must be a name such as smtp.example.net, not an address.",
  bad_port: "The port must be a number from 1 to 65535.",
  bad_from: "The from address is not a valid mailbox.",
  bad_username: "The username is missing or too long.",
  bad_hold: `The waiting time must be between ${HOLD_RANGE.min} and ${HOLD_RANGE.max} minutes.`,
  bad_cap: `The daily limit must be between ${CAP_RANGE.min} and ${CAP_RANGE.max}.`,
  password_required: "Enter the SMTP password or token.",
  not_configured: "Set up the SMTP profile first.",
}

export function describeProblem(code: string): string {
  return SMTP_PROBLEM[code] ?? guardReason(code)
}

/** Problem codes of a 422 answer, or []. */
export function problemsOf(e: unknown): string[] {
  if (!(e instanceof ApiError) || e.status !== 422) return []
  const p = e.body?.problems
  return Array.isArray(p) ? p.filter((x): x is string => typeof x === "string") : []
}

/** A readable message for a failed send, SMTP save or test. */
export function describeSendError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return "That password is not right."
    const conflict = e.status === 409 && e.code ? SEND_CONFLICT[e.code] : undefined
    if (conflict) return conflict
    const problems = problemsOf(e)
    if (problems.length > 0) return problems.map(describeProblem).join(" ")
    if (e.status === 422) return "Some of these settings are not valid."
    if (e.status === 429) return "Too many requests. Wait a moment and try again."
    if (e.status === 403) return "Only an administrator can do this."
  }
  return "That did not work. Check the connection and try again."
}

/** The sentence over the queue. */
export function describeQueue(n: number): string {
  if (n === 0) return "Nothing is waiting to be sent."
  return n === 1 ? "1 report is ready to send." : `${n} reports are ready to send.`
}

/** Daily counter shown next to the cap. */
export function describeSentToday(
  c: Pick<SmtpConfig, "sent_today" | "daily_cap" | "mode">,
): string {
  return c.mode === "auto"
    ? `${c.sent_today} of ${c.daily_cap} sent today (UTC day).`
    : `${c.sent_today} sent today (UTC day).`
}

// --- mailto ------------------------------------------------------------------------

export const MAILTO_LIMIT = 1800

/**
 * A `mailto:` link with recipient and subject; the body joins only when the whole link stays under
 * the limit. Returns whether the body made it so the page can say what the clipboard is for.
 */
export function buildMailto(
  to: string,
  subject: string,
  body: string,
): { href: string; bodyIncluded: boolean } {
  const base = `mailto:${encodeURIComponent(to).replace(/%40/g, "@")}?subject=${encodeURIComponent(subject)}`
  const full = `${base}&body=${encodeURIComponent(body.replace(/\r?\n/g, "\r\n"))}`
  return full.length < MAILTO_LIMIT
    ? { href: full, bodyIncluded: true }
    : { href: base, bodyIncluded: false }
}

// --- Calls -------------------------------------------------------------------------

export const sendKeys = {
  queue: ["abuse", "send-queue"] as const,
  smtp: ["abuse", "smtp"] as const,
}

export const sendApi = {
  queue: () => getJson<{ items: QueueItem[] }>("/abuse/send-queue"),
  send: (id: string) => sendJson<{ request_id: number }>("POST", `/abuse/reports/${id}/send`),
  cancel: (id: string) => sendJson("POST", `/abuse/reports/${id}/send/cancel`),
  smtp: () => getJson<SmtpConfig>("/abuse/smtp"),
  saveSmtp: (form: SmtpForm, currentPassword: string) => {
    const { password, ...rest } = form
    return sendJson<SmtpConfig>("PUT", "/abuse/smtp", {
      ...rest,
      ...(password ? { password } : {}),
      current_password: currentPassword,
    })
  },
  removeSmtp: (currentPassword: string) =>
    sendJson("DELETE", "/abuse/smtp", { current_password: currentPassword }),
  testSmtp: (currentPassword: string) =>
    sendJson("POST", "/abuse/smtp/test", { current_password: currentPassword }),
}

/** Refetch interval while something is on its way: a request pending or a send scheduled. */
export function queueRefetch(items: QueueItem[] | undefined): number | false {
  const busy = items?.some((i) => i.last_request?.status === "pending" || i.scheduled_at)
  return busy ? 4000 : false
}
