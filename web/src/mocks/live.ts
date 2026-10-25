/**
 * Mock of the live WebSocket (`/api/v1/live`) and of `/events/recent`.
 * Events are cut from the fixtures (documentation addresses only), so a click
 * on a row opens a real fixture session. The wire format mirrors
 * api/api/live.py: backfill, stats, then one event at a time.
 */
import { ws } from "msw"
import { SENSORS, type LiveEvent, type LiveStats, type SensorEvent } from "@/lib/api"
import { buildFixtures } from "./fixtures"

const pool: SensorEvent[] = buildFixtures().flatMap((f) => f.events)
let nextId = 100_000

function clean(v: unknown, limit = 48): string {
  const s = typeof v === "string" ? v : typeof v === "number" ? String(v) : ""
  return s.length <= limit ? s : `${s.slice(0, limit - 1)}…`
}

/** Same sentences as `build_summary` in api/api/live.py. */
function summarise(type: string, d: Record<string, unknown>): string {
  switch (type) {
    case "connect":
      return "connected"
    case "login_attempt":
      return `login ${clean(d.username)}/${clean(d.password)} ${d.success === true ? "succeeded" : "failed"}`
    case "command":
      return `ran \`${clean(d.input, 100)}\``
    case "http_request": {
      const status = d.status != null ? ` → ${clean(d.status, 6)}` : ""
      return `${clean(d.method ?? "GET", 10)} ${clean(d.path ?? "/", 100)}${status}`
    }
    case "download_attempt":
      return `download ${clean(d.url, 100)}${d.tool ? ` via ${clean(d.tool, 16)}` : ""}`
    case "disconnect":
      return typeof d.duration_s === "number"
        ? `disconnected after ${d.duration_s.toFixed(0)}s`
        : "disconnected"
    case "scan":
      return "probe"
    default:
      return clean(type, 24)
  }
}

function toLive(e: SensorEvent, ts: number): LiveEvent {
  const { data, ...rest } = e
  return {
    ...rest,
    id: nextId++,
    ts: new Date(Math.floor(ts / 1000) * 1000).toISOString().replace(".000Z", "Z"),
    summary: summarise(e.type, data),
  }
}

function sample(rand: () => number): SensorEvent {
  const e = pool[Math.floor(rand() * pool.length)]
  if (!e) throw new Error("empty mock pool")
  return e
}

/** Newest first, spread over the last few minutes. */
function backfill(count = 50): LiveEvent[] {
  let seed = 11
  const rand = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0
    return seed / 4294967296
  }
  const now = Date.now()
  const out: LiveEvent[] = []
  for (let i = 0; i < count; i++) {
    out.push(toLive(sample(rand), now - (count - i) * 4_500 - rand() * 2_000))
  }
  return out.reverse()
}

/** A plausible busy minute with a little movement from one frame to the next. */
function stats(rand: () => number): LiveStats {
  const base: Record<string, [number, number]> = {
    ssh: [42, 9],
    telnet: [18, 6],
    adb: [4, 2],
    web: [27, 11],
    docker: [7, 2],
    redis: [15, 5],
    mysql: [9, 3],
    mssql: [5, 2],
    rdp: [6, 3],
    smb: [21, 12],
    sip: [3, 2],
  }
  const by_sensor: LiveStats["by_sensor"] = {}
  let events = 0
  let sessions = 0
  for (const s of SENSORS) {
    const [e, n] = base[s] ?? [0, 0]
    const counts = {
      events: Math.max(0, e + Math.round((rand() - 0.5) * 6)),
      sessions: Math.max(0, n + Math.round((rand() - 0.5) * 2)),
    }
    by_sensor[s] = counts
    events += counts.events
    sessions += counts.sessions
  }
  return {
    window_seconds: 60,
    events_last_minute: events,
    sessions_last_minute: sessions,
    by_sensor,
  }
}

const link = ws.link("*/api/v1/live")

export const liveHandlers = [
  link.addEventListener("connection", ({ client }) => {
    client.send(JSON.stringify({ kind: "backfill", events: backfill() }))
    client.send(JSON.stringify({ kind: "stats", stats: stats(Math.random) }))

    const statsTimer = setInterval(() => {
      client.send(JSON.stringify({ kind: "stats", stats: stats(Math.random) }))
    }, 5_000)

    let stopped = false
    let eventTimer: ReturnType<typeof setTimeout> | undefined
    const tick = () => {
      if (stopped) return
      const event = toLive(sample(Math.random), Date.now())
      client.send(JSON.stringify({ kind: "event", event }))
      eventTimer = setTimeout(tick, 700 + Math.random() * 2_300)
    }
    eventTimer = setTimeout(tick, 1_500)

    client.addEventListener("message", (ev) => {
      if (ev.data === "ping") client.send(JSON.stringify({ kind: "pong" }))
    })
    client.addEventListener("close", () => {
      stopped = true
      clearInterval(statsTimer)
      clearTimeout(eventTimer)
    })
  }),
]

export function recentEvents(limit: number): LiveEvent[] {
  return backfill(Math.min(limit, 200))
}
