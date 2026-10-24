import { SENSORS, type LiveEvent, type LiveStats, type Sensor } from "@/lib/api"
import { formatNumber, plural } from "@/lib/format"
import { SENSOR_META } from "@/lib/sensors"

/** Counts for the last minute, computed from the buffer when the server sent none (polling). */
export function deriveStats(events: readonly LiveEvent[], now = Date.now()): LiveStats {
  const cutoff = now - 60_000
  const by_sensor: LiveStats["by_sensor"] = {}
  const sessions = new Set<string>()
  const perSensorSessions = new Map<string, Set<string>>()
  let total = 0
  for (const e of events) {
    if (Date.parse(e.ts) < cutoff) continue
    total += 1
    sessions.add(e.session_id)
    const set = perSensorSessions.get(e.sensor) ?? new Set<string>()
    set.add(e.session_id)
    perSensorSessions.set(e.sensor, set)
    const c = by_sensor[e.sensor] ?? { events: 0, sessions: 0 }
    c.events += 1
    by_sensor[e.sensor] = c
  }
  for (const [sensor, set] of perSensorSessions) {
    const c = by_sensor[sensor]
    if (c) c.sessions = set.size
  }
  return {
    window_seconds: 60,
    events_last_minute: total,
    sessions_last_minute: sessions.size,
    by_sensor,
  }
}

export function busiestSensor(stats: LiveStats): { sensor: Sensor; events: number } | null {
  let best: { sensor: Sensor; events: number } | null = null
  for (const sensor of SENSORS) {
    const events = stats.by_sensor[sensor]?.events ?? 0
    if (events > 0 && (!best || events > best.events)) best = { sensor, events }
  }
  return best
}

/** The plain-English sentence that opens the Live page. */
export function liveFinding(stats: LiveStats | null): string {
  if (!stats) return "Waiting for the first events from the sensors."
  const best = busiestSensor(stats)
  if (!best) return "All quiet: no events in the last minute."
  const label = SENSOR_META[best.sensor].label
  const active = SENSORS.filter((s) => (stats.by_sensor[s]?.events ?? 0) > 0).length
  if (active === 1) {
    return `Only ${label} is seeing traffic right now: ${plural(best.events, "event")} in the last minute.`
  }
  return `${label} is the busiest sensor right now: ${plural(best.events, "event")} in the last minute.`
}

export function formatSessions(n: number): string {
  return `${formatNumber(n)} ${n === 1 ? "session" : "sessions"}`
}
