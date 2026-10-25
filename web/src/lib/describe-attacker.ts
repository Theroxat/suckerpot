import type { Attacker } from "./api"
import { countryName, formatNumber, plural } from "./format"
import { sensorMeta } from "./sensors"
import { SEVERE_TAGS, WARNING_TAGS, type Severity } from "./severity"

function joinAnd(parts: string[]): string {
  if (parts.length <= 1) return parts.join("")
  return `${parts.slice(0, -1).join(", ")} and ${parts.at(-1) ?? ""}`
}

export function attackerOrigin(a: Pick<Attacker, "country" | "org">): string | null {
  const country = a.country ? (countryName(a.country) ?? a.country) : null
  const parts = [country, a.org].filter((p): p is string => Boolean(p))
  return parts.length ? parts.join(", ") : null
}

/** Whole days between the first and the last sighting. */
export function activeDays(a: Pick<Attacker, "first_seen" | "last_seen">): number {
  const ms = new Date(a.last_seen).getTime() - new Date(a.first_seen).getTime()
  return Math.max(0, Math.round(ms / 86_400_000))
}

function times(n: number): string {
  if (n === 1) return "once"
  if (n === 2) return "twice"
  return `${formatNumber(n)} times`
}

/**
 * The profile predicate: "14 sessions over 6 days on SSH and Telnet, got in
 * twice, tried to download 1 file". The IP and origin are rendered separately.
 */
export function describeAttacker(a: Attacker): string {
  const sensors = joinAnd(a.sensors.map((s) => sensorMeta(s)?.label ?? s.toUpperCase()))
  const days = activeDays(a)
  const span = a.sessions > 1 ? (days >= 1 ? ` over ${plural(days, "day")}` : " within a day") : ""
  const clauses = [`${plural(a.sessions, "session")}${span}${sensors ? ` on ${sensors}` : ""}`]
  if (a.login_success > 0) clauses.push(`got in ${times(a.login_success)}`)
  else if (a.login_attempts > 0) clauses.push("never got in")
  if (a.commands > 0) clauses.push(`ran ${plural(a.commands, "command")}`)
  if (a.downloads > 0) clauses.push(`tried to download ${plural(a.downloads, "file")}`)
  return clauses.join(", ")
}

export function describeAttackerText(a: Attacker): string {
  const origin = attackerOrigin(a)
  return `${a.ip}${origin ? ` · ${origin}` : ""} — ${describeAttacker(a)}`
}

/** Same scale as sessions: a download or payload tag is severe, a shell is a warning. */
export function attackerSeverity(a: Attacker): Severity {
  if (a.downloads > 0 || a.tags.some((t) => SEVERE_TAGS.has(t))) return "severe"
  if (a.login_success > 0 || a.commands > 0 || a.tags.some((t) => WARNING_TAGS.has(t)))
    return "warning"
  if (a.login_attempts > 0 || a.events > 0) return "notice"
  return "info"
}
