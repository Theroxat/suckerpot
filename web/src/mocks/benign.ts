/**
 * Mock research-scanner sessions (Censys-style crawlers). They exist only in the mock data: the
 * sessions list adds them when `include_benign=1` is sent, and `/stats/benign` counts them.
 * Documentation addresses only; the organisation names are made up.
 */
import type { SensorEvent, Session } from "@/lib/api"
import { SENSOR_META, type Sensor } from "@/lib/sensors"
import type { Fixture } from "./fixtures"

const MINUTE = 60_000

const SCANNERS: { name: string; org: string; ip: string; sensor: Sensor; ageMin: number }[] = [
  {
    name: "Atlas Census",
    org: "Atlas Census Research",
    ip: "192.0.2.201",
    sensor: "web",
    ageMin: 14,
  },
  {
    name: "Atlas Census",
    org: "Atlas Census Research",
    ip: "192.0.2.202",
    sensor: "web",
    ageMin: 95,
  },
  {
    name: "Beacon Survey",
    org: "Beacon Survey Project",
    ip: "198.51.100.201",
    sensor: "ssh",
    ageMin: 40,
  },
  {
    name: "Beacon Survey",
    org: "Beacon Survey Project",
    ip: "198.51.100.202",
    sensor: "telnet",
    ageMin: 180,
  },
  {
    name: "Lumen Scan",
    org: "Lumen Scan Foundation",
    ip: "203.0.113.201",
    sensor: "rdp",
    ageMin: 260,
  },
  {
    name: "Lumen Scan",
    org: "Lumen Scan Foundation",
    ip: "203.0.113.202",
    sensor: "smb",
    ageMin: 400,
  },
]

const iso = (ms: number) =>
  new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z")

export function buildBenignFixtures(now = Date.now()): Fixture[] {
  return SCANNERS.map((s, i) => {
    const start = now - s.ageMin * MINUTE
    const id = `Scanner${String(i + 1).padStart(2, "0")}`
    const port = SENSOR_META[s.sensor].port
    const base = {
      country: "US",
      city: null,
      asn: 64510 + i,
      org: s.org,
      abuse_score: 0,
      known_scanner: true,
      tags: ["scanner"],
      sensor: s.sensor,
      session_id: id,
      src_ip: s.ip,
      src_port: 40000 + i,
      dst_port: port,
    }
    const events: SensorEvent[] = [
      { ...base, id: 900_000 + i * 2, ts: iso(start), type: "connect", data: {} },
      {
        ...base,
        id: 900_001 + i * 2,
        ts: iso(start + 1000),
        type: s.sensor === "web" ? "http_request" : "disconnect",
        data: s.sensor === "web" ? { method: "GET", path: "/", user_agent: `${s.name}/1.0` } : {},
      },
    ]
    const session: Session = {
      ...base,
      started_at: iso(start),
      ended_at: iso(start + 1000),
      last_event_at: iso(start + 1000),
      event_count: 2,
      login_attempts: 0,
      login_success: false,
      commands: 0,
      downloads: 0,
      http_requests: s.sensor === "web" ? 1 : 0,
      benign: true,
      scanner_name: s.name,
    }
    return { session, events }
  })
}
