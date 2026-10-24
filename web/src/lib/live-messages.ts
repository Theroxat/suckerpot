/**
 * Pure helpers for the live WebSocket feed: message parsing and the bounded,
 * de-duplicated event buffer. No I/O here, so they are trivial to test.
 */
import type { LiveEvent, LiveStats } from "@/lib/api"

export type LiveMessage =
  | { kind: "backfill"; events: LiveEvent[] }
  | { kind: "event"; event: LiveEvent }
  | { kind: "stats"; stats: LiveStats }
  | { kind: "dropped"; count: number }
  | { kind: "pong" }

/** Most events kept in memory. Older ones fall off the end. */
export const MAX_BUFFER = 500

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v)
}

const isString = (v: unknown): v is string => typeof v === "string"
const isNumber = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v)
const strOrNull = (v: unknown) => (isString(v) ? v : null)
const numOrNull = (v: unknown) => (isNumber(v) ? v : null)

/** Validate one event; anything that does not fit the contract is dropped. */
export function parseLiveEvent(v: unknown): LiveEvent | null {
  if (!isRecord(v)) return null
  const { id, ts, sensor, session_id, type, src_ip, src_port, dst_port, summary } = v
  if (
    !isNumber(id) ||
    !isString(ts) ||
    Number.isNaN(Date.parse(ts)) ||
    !isString(sensor) ||
    !isString(session_id) ||
    !isString(type) ||
    !isString(src_ip)
  ) {
    return null
  }
  return {
    id,
    ts,
    sensor,
    session_id,
    type,
    src_ip,
    src_port: numOrNull(src_port) ?? 0,
    dst_port: numOrNull(dst_port) ?? 0,
    summary: isString(summary) ? summary : type,
    country: strOrNull(v.country),
    city: strOrNull(v.city),
    asn: numOrNull(v.asn),
    org: strOrNull(v.org),
    abuse_score: numOrNull(v.abuse_score),
    known_scanner: typeof v.known_scanner === "boolean" ? v.known_scanner : null,
    tags: Array.isArray(v.tags) ? v.tags.filter(isString) : [],
  }
}

export function parseLiveEvents(v: unknown): LiveEvent[] {
  if (!Array.isArray(v)) return []
  return v.flatMap((e) => {
    const parsed = parseLiveEvent(e)
    return parsed ? [parsed] : []
  })
}

function parseStats(v: unknown): LiveStats | null {
  if (!isRecord(v) || !isNumber(v.events_last_minute) || !isNumber(v.sessions_last_minute)) {
    return null
  }
  const by_sensor: LiveStats["by_sensor"] = {}
  if (isRecord(v.by_sensor)) {
    for (const [name, c] of Object.entries(v.by_sensor)) {
      if (isRecord(c) && isNumber(c.events) && isNumber(c.sessions)) {
        by_sensor[name] = { events: c.events, sessions: c.sessions }
      }
    }
  }
  return {
    window_seconds: isNumber(v.window_seconds) ? v.window_seconds : 60,
    events_last_minute: v.events_last_minute,
    sessions_last_minute: v.sessions_last_minute,
    by_sensor,
  }
}

/**
 * Parse one text frame. Malformed JSON, unknown kinds and invalid payloads
 * return null: the feed must never break on something the server adds later.
 */
export function parseLiveMessage(raw: unknown): LiveMessage | null {
  if (!isString(raw)) return null
  let v: unknown
  try {
    v = JSON.parse(raw)
  } catch {
    return null
  }
  if (!isRecord(v)) return null
  switch (v.kind) {
    case "backfill":
      return { kind: "backfill", events: parseLiveEvents(v.events) }
    case "event": {
      const event = parseLiveEvent(v.event)
      return event ? { kind: "event", event } : null
    }
    case "stats": {
      const stats = parseStats(v.stats)
      return stats ? { kind: "stats", stats } : null
    }
    case "dropped":
      return isNumber(v.count) ? { kind: "dropped", count: v.count } : null
    case "pong":
      return { kind: "pong" }
    default:
      return null
  }
}

/**
 * Merge incoming events into the buffer: de-duplicated by id, newest first
 * (ids grow with time), at most `max` kept. Returns the same array when
 * nothing changed, so subscribers do not re-render for nothing.
 */
export function mergeEvents(
  current: readonly LiveEvent[],
  incoming: readonly LiveEvent[],
  max = MAX_BUFFER,
): readonly LiveEvent[] {
  if (incoming.length === 0) return current
  const known = new Set(current.map((e) => e.id))
  const fresh: LiveEvent[] = []
  for (const e of incoming) {
    if (!known.has(e.id)) {
      known.add(e.id)
      fresh.push(e)
    }
  }
  if (fresh.length === 0) return current
  return [...current, ...fresh].sort((a, b) => b.id - a.id).slice(0, max)
}
