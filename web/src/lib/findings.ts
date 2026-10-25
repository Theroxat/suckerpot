/**
 * Plain-English finding sentences for the Overview cards. Every function is
 * pure (data in, text out) so the wording is unit-tested.
 */
import { SENSORS, type Sensor, type TimePoint, type TopItem, type TopResponse } from "./api"
import { countryName, formatNumber, formatPercent, plural } from "./format"
import { FAMILY_META, SENSOR_FAMILIES, SENSOR_META, sumByFamily } from "./sensors"

export interface Finding {
  finding: string
  detail?: string
}

export function sumBySensor(
  points: readonly TimePoint[],
  kind: "events" | "sessions",
): Record<Sensor, number> {
  const out = Object.fromEntries(SENSORS.map((s) => [s, 0])) as Record<Sensor, number>
  for (const p of points) for (const s of SENSORS) out[s] += p[kind][s] ?? 0
  return out
}

export function pointTotal(p: TimePoint, kind: "events" | "sessions" = "events"): number {
  return SENSORS.reduce((n, s) => n + (p[kind][s] ?? 0), 0)
}

/** Split a series in two equal halves: [previous window, current window]. */
export function splitWindows(points: readonly TimePoint[]): [TimePoint[], TimePoint[]] {
  const mid = Math.floor(points.length / 2)
  return [points.slice(0, mid), points.slice(mid)]
}

/** Relative change as a ratio (0.12 = +12%). `null` when there is no baseline. */
export function deltaRatio(current: number, previous: number): number | null {
  if (previous <= 0) return null
  return (current - previous) / previous
}

/**
 * "Remote shells drew 80% of all events in the last 24 hours, led by SSH (65%)."
 * Names the leading family, and its leading sensor; a family with a single
 * active sensor is named by that sensor ("SSH drew 64% of all events…").
 */
export function describeActivity(
  points: readonly TimePoint[],
  formatPeak: (iso: string) => string,
): Finding {
  const totals = sumBySensor(points, "events")
  const total = SENSORS.reduce((n, s) => n + totals[s], 0)
  if (total === 0) return { finding: "No events in the last 24 hours." }

  const families = sumByFamily(totals)
  const family = [...SENSOR_FAMILIES].sort((a, b) => families[b] - families[a])[0] ?? "shell"
  const fam = FAMILY_META[family]
  const leader = [...fam.sensors].sort((a, b) => totals[b] - totals[a])[0] ?? "ssh"
  const label = SENSOR_META[leader].label
  const famShare = families[family] / total
  const share = totals[leader] / total
  const solo = totals[leader] >= families[family] * 0.995

  let finding: string
  if (solo) {
    finding =
      share >= 0.995
        ? `Every event in the last 24 hours hit the ${label} sensor.`
        : `${label} drew ${formatPercent(share)} of all events in the last 24 hours.`
  } else {
    finding =
      famShare >= 0.995
        ? `Every event in the last 24 hours hit the ${fam.noun}, led by ${label} (${formatPercent(share)}).`
        : `${fam.label} drew ${formatPercent(famShare)} of all events in the last 24 hours, led by ${label} (${formatPercent(share)}).`
  }
  const peak = points.reduce<TimePoint | null>(
    (best, p) => (best === null || pointTotal(p) > pointTotal(best) ? p : best),
    null,
  )
  const detail = peak
    ? `${formatNumber(total)} events in all. Busiest hour: ${formatPeak(peak.ts)}, with ${plural(pointTotal(peak), "event")}.`
    : `${formatNumber(total)} events in all.`
  return { finding, detail }
}

function pct(item: TopItem): string {
  return formatPercent(item.share)
}

function named(item: TopItem): string {
  return countryName(item.value) ?? item.value
}

/** "Netherlands led with 23% of events, ahead of United States (14%) and China (11%)." */
export function describeCountries(top: TopResponse | undefined): Finding {
  const items = (top?.items ?? []).filter((i) => i.value)
  const [first, second, third] = items
  if (!first) return { finding: "No country data yet." }
  const rest = [second, third]
    .filter((i): i is TopItem => Boolean(i))
    .map((i) => `${named(i)} (${pct(i)})`)
  const lead = `${named(first)} led with ${pct(first)} of sessions`
  return {
    finding: rest.length ? `${lead}, ahead of ${rest.join(" and ")}.` : `${lead}.`,
    detail: `${formatNumber(top?.total ?? 0)} sessions with a known origin.`,
  }
}

/** `"root" was the most tried username, in 42% of login attempts.` */
export function describeCredential(
  field: "username" | "password",
  top: TopResponse | undefined,
): Finding {
  const [first, second] = top?.items ?? []
  if (!first) return { finding: `No ${field}s tried yet.` }
  const tail = second ? `, ahead of "${second.value}" (${pct(second)})` : ""
  return {
    finding: `"${first.value}" was the most tried ${field}, in ${pct(first)} of login attempts${tail}.`,
    detail: `${formatNumber(top?.total ?? 0)} login attempts.`,
  }
}

/** "Active on 4 of the last 30 days, busiest on Oct 20 with 312 events." */
export function describeTimeline(
  timeline: readonly { day: string; events: number }[],
  formatDay: (day: string) => string,
  window = 30,
): Finding {
  const active = timeline.filter((p) => p.events > 0)
  const peak = active.reduce<{ day: string; events: number } | null>(
    (best, p) => (best === null || p.events > best.events ? p : best),
    null,
  )
  if (!peak) return { finding: `No activity in the last ${window} days.` }
  return {
    finding: `Active on ${active.length} of the last ${window} days, busiest on ${formatDay(peak.day)} with ${plural(peak.events, "event")}.`,
  }
}
