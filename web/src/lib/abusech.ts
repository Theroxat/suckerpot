/**
 * abuse.ch submission (M27, docs/design/m27.md sections 7 and 11): the optional submission of
 * captured malware URLs to URLhaus (and C2 addresses to ThreatFox). Shapes, vocabulary, sentences
 * and calls. The Auth-Key is write-only: only its last four characters ever come back.
 */
import { ApiError, getJson, sendJson, type Page } from "./api"
import { formatClock, plural } from "./format"

export type SubmitMode = "off" | "review" | "auto"
export type Platform = "urlhaus" | "threatfox"

export const MODE_OPTIONS = [
  { value: "off", label: "Off" },
  { value: "review", label: "Review each" },
  { value: "auto", label: "Automatic" },
] as const satisfies readonly { value: SubmitMode; label: string }[]

export const MODE_EXPLANATION: Record<SubmitMode, string> = {
  off: "Nothing is submitted and no candidate is computed.",
  review: "Candidates are listed in the Submissions tab. You choose which ones to send.",
  auto: "A new candidate is submitted after the waiting time, unless you cancel it.",
}

export const KEY_WARNING = "Use an abuse.ch account whose public name does not identify you."
export const HOLD_RANGE = { min: 10, max: 1440 } as const
export const CAP_RANGE = { min: 1, max: 200 } as const

export interface AbusechSettings {
  mode: SubmitMode
  threatfox_enabled: boolean
  anonymous: boolean
  auto_hold_minutes: number
  daily_cap: number
  key_set: boolean
  key_last4: string | null
  /** False when ABUSECH_SUBMIT_ENABLED is off on the server. */
  server_enabled: boolean
  submitted_today: number
}

export interface AbusechForm {
  mode: SubmitMode
  threatfox_enabled: boolean
  anonymous: boolean
  auto_hold_minutes: number
  daily_cap: number
  key: string
}

export type SubmissionStatus =
  | "candidate"
  | "pending"
  | "submitting"
  | "submitted"
  | "duplicate"
  | "rejected"
  | "failed"
  | "cancelled"
  | "skipped_known"
  | "skipped_never_list"
  | "guard_failed"

/** The tabs of the Submissions page. */
export type SubmissionTab = "review" | "scheduled" | "submitted" | "skipped" | "failed"
export const SUBMISSION_TABS = [
  { value: "review", label: "To review" },
  { value: "scheduled", label: "Scheduled" },
  { value: "submitted", label: "Submitted" },
  { value: "skipped", label: "Skipped" },
  { value: "failed", label: "Failed" },
] as const satisfies readonly { value: SubmissionTab; label: string }[]

export const STATUS_LABEL: Record<SubmissionStatus, string> = {
  candidate: "To review",
  pending: "Scheduled",
  submitting: "Sending",
  submitted: "Submitted",
  duplicate: "Already listed",
  rejected: "Rejected by abuse.ch",
  failed: "Failed",
  cancelled: "Cancelled",
  skipped_known: "Already on URLhaus",
  skipped_never_list: "Not shared (safe list)",
  guard_failed: "Blocked by the identity check",
}

/** The raw statuses behind each tab; the API counts and filters by raw status. */
export const TAB_STATUSES: Record<SubmissionTab, SubmissionStatus[]> = {
  review: ["candidate"],
  scheduled: ["pending", "submitting"],
  submitted: ["submitted", "duplicate"],
  skipped: ["skipped_known", "skipped_never_list", "cancelled"],
  failed: ["failed", "rejected", "guard_failed"],
}

/** Group the API's per-status counts into the tabs. */
export function tabCounts(
  counts: Record<string, number> | undefined,
): Record<SubmissionTab, number> {
  const out = { review: 0, scheduled: 0, submitted: 0, skipped: 0, failed: 0 }
  for (const tab of Object.keys(TAB_STATUSES) as SubmissionTab[])
    out[tab] = TAB_STATUSES[tab].reduce((n, st) => n + (counts?.[st] ?? 0), 0)
  return out
}

/** Result codes are short free-form codes; the common ones read as a sentence. */
export const RESULT_SENTENCE: Record<string, string> = {
  ok: "Accepted by abuse.ch.",
  already_known: "abuse.ch already lists it.",
  guard_failed: "The text would reveal something it must not, so it was not sent.",
  auth_failed: "abuse.ch refused the key.",
  rate_limited: "abuse.ch asked to slow down. It will be tried again.",
  invalid: "abuse.ch did not accept the value.",
  unreachable: "abuse.ch could not be reached. It will be tried again.",
}

export function describeResult(code: string | null): string | null {
  if (!code) return null
  return RESULT_SENTENCE[code] ?? "abuse.ch answered with a result that has no description yet."
}

export interface Submission {
  id: number
  /** Raw value; the UI defangs it. */
  value: string
  platform: Platform
  status: SubmissionStatus
  result_code: string | null
  lookup: "pending" | "unknown" | "known"
  tags: string[]
  scheduled_at: string | null
  submitted_at: string | null
  created_at: string
  /** An abuse.ch link built by the server from a fixed prefix, or null. */
  reference: string | null
  malware: string | null
  demo: boolean
  /** Evidence from recorded sessions that showed the value; 0 and empty when none is linked. */
  session_count: number
  /** Sensor names that saw it. */
  sensors: string[]
  last_seen: string | null
}

export interface SubmissionPage extends Page<Submission> {
  /** Counts by raw status; group them with `tabCounts`. */
  counts: Record<string, number>
}

export interface SubmissionFilters {
  tab: SubmissionTab
  platform?: Platform
  since?: string
}

// --- Sentences ----------------------------------------------------------------------

/** The sentence opening the Submissions tab. */
export function describeSubmissions(s: AbusechSettings | undefined): string {
  if (!s) return "Captured malware URLs can be shared with URLhaus, if you choose."
  if (!s.server_enabled && s.mode !== "off") return "Submission is disabled on this server."
  if (s.mode === "off") return "Submission is off."
  if (s.mode === "review") return "You review each URL before it goes to URLhaus."
  const hold = s.auto_hold_minutes
  return `New URLs go to URLhaus automatically after ${hold} minutes; ${s.submitted_today} of ${s.daily_cap} sent today.`
}

/** "Submitting at 14:05" for a scheduled row. */
export function describeSchedule(s: Submission): string | null {
  if (s.status !== "pending" || !s.scheduled_at) return null
  return `Submitting at ${formatClock(s.scheduled_at)}`
}

export function describeLookup(s: Submission): string {
  if (s.lookup === "pending") return "Lookup pending"
  return s.lookup === "known" ? "Already on URLhaus" : "New to URLhaus"
}

export function describeSelection(n: number): string {
  return `Submit ${plural(n, "URL")}`
}

export function describeAbusechError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return "That password is not right."
    if (e.code === "server_disabled")
      return "Submission is disabled on this server (ABUSECH_SUBMIT_ENABLED)."
    if (e.code === "key_required") return "Add an abuse.ch Auth-Key first."
    if (e.code === "invalid_key") return "That does not look like an abuse.ch Auth-Key."
    if (e.code === "mode_off") return "Submission is off. Turn it on in Settings first."
    if (e.code === "not_a_candidate") return "Only a URL that is still to review can be submitted."
    if (e.code === "lookup_not_ready")
      return "abuse.ch has not been asked yet, or already knows this URL. Try again in a few minutes."
    if (e.code === "demo_submission") return "Demo data is never sent."
    if (e.code === "not_pending") return "It was just sent or cancelled."
    if (e.status === 409) return "That is not possible any more. The list was refreshed."
    if (e.status === 429) return "Too many requests. Wait a moment and try again."
    if (e.status === 403) return "Only an administrator can do this."
    if (e.status === 422 && e.message) return e.message
  }
  return "That did not work. Check the connection and try again."
}

// --- Calls --------------------------------------------------------------------------

export const abusechKeys = {
  settings: ["abusech", "settings"] as const,
  list: (f: SubmissionFilters) => ["abusech", "submissions", f] as const,
  all: ["abusech"] as const,
}

export const abusechApi = {
  settings: () => getJson<AbusechSettings>("/abusech/submission"),
  save: (form: AbusechForm, currentPassword: string) => {
    const { key, ...rest } = form
    return sendJson<AbusechSettings>("PUT", "/abusech/submission", {
      ...rest,
      ...(key ? { key } : {}),
      current_password: currentPassword,
    })
  },
  remove: (currentPassword: string) =>
    sendJson("DELETE", "/abusech/submission", { current_password: currentPassword }),
  list: (f: SubmissionFilters, cursor?: string | null) =>
    getJson<SubmissionPage>("/abusech/submissions", {
      status: TAB_STATUSES[f.tab].join(","),
      platform: f.platform,
      since: f.since,
      cursor: cursor ?? undefined,
      limit: 50,
    }),
  submit: (ids: number[]) => sendJson("POST", "/abusech/submissions/submit", { ids }),
  cancel: (id: number) => sendJson("POST", `/abusech/submissions/${id}/cancel`),
}
