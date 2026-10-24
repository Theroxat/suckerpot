/**
 * Pure helpers for the Trends, Malware and Insights views: API shapes (M7
 * contract), the defanged URL form, the local-time heatmap and the finding
 * sentences. No React in here, so everything is unit-tested.
 */
import type { Session, TopItem, TopResponse } from "./api"
import { SEVERE_TAGS, type Severity } from "./severity"
import { formatNumber, formatPercent, plural } from "./format"

// --- API shapes (M7 contract) -------------------------------------------------

export interface Insight {
  id: string
  kind: "surge" | "new_value" | "campaign" | "exploit" | "success" | "geo_shift"
  severity: Severity
  sentence: string
  evidence: { metric: string; current: number; previous: number; ratio: number }
  /** Relative UI link with filters, e.g. "/attacks?tag=php2shell". */
  link: string
}

export interface InsightsResponse {
  generated_at: string
  items: Insight[]
}

export const NEW_FIELDS = ["username", "password", "command", "url", "asn", "user_agent"] as const
export type NewField = (typeof NEW_FIELDS)[number]

export interface NewItem {
  value: string
  count: number
  first_seen: string
}

export interface NewResponse {
  field: NewField
  items: NewItem[]
}

export interface TagPoint {
  ts: string
  tags: Record<string, number>
}

export interface TagsResponse {
  bucket: string
  since: string
  until: string
  /** Tag names, most frequent first; "other" last. */
  series: string[]
  points: TagPoint[]
}

export interface HeatmapCell {
  /** Day of week in UTC, Monday is 0. */
  dow: number
  /** Hour of day in UTC. */
  hour: number
  events: number
}

export interface HeatmapResponse {
  since: string
  until: string
  cells: HeatmapCell[]
}

export interface MalwareItem {
  url: string
  host: string
  first_seen: string
  last_seen: string
  attempts: number
  sessions: number
  ips: number
  tools: string[]
  sensors: string[]
  sha256: string | null
  size: number | null
  virustotal_url: string | null
}

export interface MalwareDetail {
  item: MalwareItem
  recent_sessions: Session[]
}

export const MALWARE_TOOLS = ["wget", "curl", "tftp", "ftpget"] as const

// --- Defanged URLs ------------------------------------------------------------

/**
 * "http://malware.example.net/x.sh" -> "hxxp://malware[.]example[.]net/x.sh".
 * Safe to paste into a ticket or chat: it can never turn into a live link.
 */
export function defangUrl(raw: string): string {
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/is.exec(raw)
  if (!m) return raw.replace(/^([^/?#]*)/, (h) => h.replaceAll(".", "[.]"))
  const [, proto = "", host = "", rest = ""] = m
  const SCHEMES: Record<string, string> = { http: "hxxp", https: "hxxps", ftp: "fxp" }
  const safeProto = SCHEMES[proto.toLowerCase()] ?? proto
  return `${safeProto}://${host.replaceAll(".", "[.]")}${rest}`
}

// --- Heatmap in the browser's time zone ----------------------------------------

export const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const
export const WEEKDAYS_LONG = [
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
  "Sunday",
] as const

/** A 7 x 24 grid of event counts: grid[dow][hour], Monday first. */
export type HeatGrid = number[][]

/**
 * Shift UTC cells into local time. `offsetHours` is the browser's current UTC
 * offset in whole hours (half-hour zones are rounded; DST is approximated by
 * the offset of the day the page was opened).
 */
export function toLocalGrid(cells: readonly HeatmapCell[], offsetHours: number): HeatGrid {
  const grid: HeatGrid = Array.from({ length: 7 }, () => Array<number>(24).fill(0))
  for (const c of cells) {
    if (c.dow < 0 || c.dow > 6 || c.hour < 0 || c.hour > 23) continue
    const total = c.dow * 24 + c.hour + offsetHours
    const week = 7 * 24
    const idx = ((total % week) + week) % week
    const row = grid[Math.floor(idx / 24)]
    if (row) row[idx % 24] = (row[idx % 24] ?? 0) + c.events
  }
  return grid
}

export function browserOffsetHours(now = new Date()): number {
  return Math.round(-now.getTimezoneOffset() / 60)
}

export function hourLabel(h: number): string {
  return `${String(h).padStart(2, "0")}:00`
}

// --- Findings ----------------------------------------------------------------

export interface Finding {
  finding: string
  detail?: string
}

/** "Attacks peak on Tuesdays, around 14:00 (your time), when 9% of the week's events land." */
export function describeHeatmap(grid: HeatGrid, days: number): Finding {
  const byDay = grid.map((r) => r.reduce((a, b) => a + b, 0))
  const total = byDay.reduce((a, b) => a + b, 0)
  if (total === 0) return { finding: `No activity in the last ${days} days.` }
  const byHour = Array.from({ length: 24 }, (_, h) => grid.reduce((a, r) => a + (r[h] ?? 0), 0))
  const bestDay = byDay.indexOf(Math.max(...byDay))
  const bestHour = byHour.indexOf(Math.max(...byHour))
  return {
    finding: `${WEEKDAYS_LONG[bestDay]} is the busiest day and ${hourLabel(bestHour)} the busiest hour, in your time zone.`,
    detail: `${formatPercent((byDay[bestDay] ?? 0) / total)} of ${formatNumber(total)} events land on ${WEEKDAYS_LONG[bestDay]}; ${formatPercent((byHour[bestHour] ?? 0) / total)} in the ${hourLabel(bestHour)} hour.`,
  }
}

export function tagTotals(points: readonly TagPoint[]): [string, number][] {
  const totals = new Map<string, number>()
  for (const p of points)
    for (const [tag, n] of Object.entries(p.tags)) totals.set(tag, (totals.get(tag) ?? 0) + n)
  return [...totals.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
}

/** Compare the second half of the window with the first for one tag. */
export function tagChange(
  points: readonly TagPoint[],
  tag: string,
): { first: number; second: number } {
  const mid = Math.floor(points.length / 2)
  const sum = (ps: readonly TagPoint[]) => ps.reduce((a, p) => a + (p.tags[tag] ?? 0), 0)
  return { first: sum(points.slice(0, mid)), second: sum(points.slice(mid)) }
}

/** `"php2shell" is the most common tag: 412 events (42%), up from 131 in the first half.` */
export function describeTags(points: readonly TagPoint[], days: number): Finding {
  const named = tagTotals(points).filter(([t]) => t !== "other")
  const all = tagTotals(points).reduce((a, [, n]) => a + n, 0)
  const top = named[0]
  if (!top || all === 0) return { finding: `No tagged activity in the last ${days} days.` }
  const [tag, n] = top
  const { first, second } = tagChange(points, tag)
  let trend = ""
  if (first > 0 && second >= first * 2) trend = `, at least doubling in the second half`
  else if (second > 0 && first >= second * 2) trend = `, less than half as active lately`
  else if (first === 0 && second > 0) trend = `, all of it in the second half of the period`
  return {
    finding: `"${tag}" is the most common tag: ${plural(n, "event")} (${formatPercent(n / all)})${trend}.`,
    detail: `${plural(named.length, "tag")} seen over ${days} days${SEVERE_TAGS.has(tag) ? "; this one marks a payload" : ""}.`,
  }
}

type TopKind = "username" | "password" | "command" | "url"
const KIND_WORD: Record<TopKind, { one: string; many: string; unit: string }> = {
  username: { one: "username", many: "usernames", unit: "login attempts" },
  password: { one: "password", many: "passwords", unit: "login attempts" },
  command: { one: "command", many: "commands", unit: "commands" },
  url: { one: "URL", many: "URLs", unit: "requests and downloads" },
}

/** `"root" was the most tried username in the last 7 days, in 42% of login attempts.` */
export function describeTop(kind: TopKind, top: TopResponse | undefined, days: number): Finding {
  const w = KIND_WORD[kind]
  const [first, second] = top?.items ?? []
  if (!first) return { finding: `No ${w.many} recorded in the last ${days} days.` }
  const shown = first.value.length > 60 ? `${first.value.slice(0, 57)}…` : first.value
  const tail = second
    ? `, ahead of ${second.value.length > 40 ? "the runner-up" : `"${second.value}"`} (${formatPercent(second.share)})`
    : ""
  return {
    finding: `"${shown}" was the most seen ${w.one} in the last ${days} days, in ${formatPercent(first.share)} of ${w.unit}${tail}.`,
    detail: `${formatNumber(top?.total ?? 0)} ${w.unit} in all.`,
  }
}

/** "14 usernames were never seen before this week; the most used was "admin1" (88 times)." */
export function describeNew(field: NewField, items: readonly NewItem[], days: number): Finding {
  const word = field === "asn" ? "networks" : field === "user_agent" ? "user agents" : `${field}s`
  const one = field === "asn" ? "network" : field === "user_agent" ? "user agent" : field
  const period = days === 7 ? "this week" : `in the last ${days} days`
  if (items.length === 0)
    return { finding: `No new ${word} ${period}: every one has been seen before.` }
  const top = [...items].sort((a, b) => b.count - a.count)[0]
  if (!top) return { finding: `No new ${word} ${period}.` }
  const shown = top.value.length > 50 ? `${top.value.slice(0, 47)}…` : top.value
  return {
    finding: `${items.length === 1 ? `1 ${one} was` : `${formatNumber(items.length)} ${word} were`} never seen before ${period}; the most used is "${shown}" (${plural(top.count, "time")}).`,
  }
}

export interface MalwareSummary {
  urls: number
  attempts: number
  hosts: number
  topHost: { host: string; attempts: number } | null
}

export function summariseMalware(items: readonly MalwareItem[]): MalwareSummary {
  const byHost = new Map<string, number>()
  let attempts = 0
  for (const i of items) {
    attempts += i.attempts
    byHost.set(i.host, (byHost.get(i.host) ?? 0) + i.attempts)
  }
  const top = [...byHost.entries()].sort((a, b) => b[1] - a[1])[0]
  return {
    urls: items.length,
    attempts,
    hosts: byHost.size,
    topHost: top ? { host: top[0], attempts: top[1] } : null,
  }
}

export function describeMalware(s: MalwareSummary, more: boolean): Finding {
  if (s.urls === 0) return { finding: "No download attempts recorded yet." }
  const lead = more ? "At least " : ""
  return {
    finding: `${lead}${plural(s.urls, "download URL")} on ${plural(s.hosts, "host")}, tried ${plural(s.attempts, "time")}.`,
    detail: s.topHost
      ? `${s.topHost.host} served the most: ${plural(s.topHost.attempts, "attempt")}.`
      : undefined,
  }
}

/** Is this tag one of the severe ones (gets the red marker)? */
export const isSevereTag = (tag: string) => SEVERE_TAGS.has(tag)

/** Keep the share bar honest: top items only. */
export function topItems(top: TopResponse | undefined): TopItem[] {
  return top?.items ?? []
}

export const HEAT_STEPS = 5

/** 0 for no events, else 1..5 by share of the busiest cell. */
export function gridStep(n: number, max: number): number {
  if (n <= 0 || max <= 0) return 0
  return Math.min(HEAT_STEPS, Math.max(1, Math.ceil((n / max) * HEAT_STEPS)))
}

/**
 * Tags are neutral: lightness steps tell neighbours apart, the legend and the
 * tooltip name them. Payload tags (severe) are the only red.
 */
/**
 * Fill for one tag in the tags-over-time chart. Only the highlighted tag (the
 * leading severe tag, which is what the card's finding sentence is about) is red;
 * every other tag, severe or not, is a neutral lightness step. Severe tags keep
 * their red diamond in the legend, so the signal survives without a wall of red.
 */
export function tagFill(tag: string, index: number, highlight: string | null = null): string {
  if (tag === highlight) return "var(--sev-severe)"
  const mix = Math.max(22, 74 - index * 11)
  return `color-mix(in srgb, var(--fg) ${mix}%, var(--surface))`
}

/** The tag the chart paints red: the most frequent severe tag, if any. */
export function highlightTag(order: readonly string[]): string | null {
  return order.find((t) => isSevereTag(t)) ?? null
}
