/**
 * Deterministic fake data shaped exactly like the API responses.
 * Documentation addresses only (RFC 5737: 192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24) and private-use ASNs (RFC 5398). Organisation names are
 * made up. Times are relative to when the module loads, so the UI looks live.
 */
import type { SensorEvent, Session, Sensor } from "@/lib/api"

function mulberry32(seed: number) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

type Rand = () => number

function pick<T>(rand: Rand, list: readonly T[]): T {
  const v = list[Math.floor(rand() * list.length)]
  if (v === undefined) throw new Error("empty list")
  return v
}

function int(rand: Rand, min: number, max: number) {
  return Math.floor(rand() * (max - min + 1)) + min
}

const PREFIXES = ["192.0.2", "198.51.100", "203.0.113"] as const

const ORIGINS: readonly { country: string; city: string; asn: number; org: string }[] = [
  { country: "NL", city: "Amsterdam", asn: 64496, org: "Polder Cloud BV" },
  { country: "US", city: "Ashburn", asn: 64497, org: "Example Hosting LLC" },
  { country: "CN", city: "Shenzhen", asn: 64498, org: "Sample Telecom" },
  { country: "DE", city: "Frankfurt", asn: 64499, org: "Rhein Compute GmbH" },
  { country: "RU", city: "Moscow", asn: 64500, org: "Demo Networks" },
  { country: "BR", city: "São Paulo", asn: 64501, org: "Placeholder Fibra" },
  { country: "IN", city: "Mumbai", asn: 64502, org: "Docs Broadband" },
  { country: "VN", city: "Hanoi", asn: 64503, org: "Test Mobile" },
  { country: "SG", city: "Singapore", asn: 64504, org: "Lion VPS Pte" },
  { country: "FR", city: "Roubaix", asn: 64505, org: "Hexagone Serveurs" },
  { country: "KR", city: "Seoul", asn: 64506, org: "Han River Data" },
  { country: "GB", city: "London", asn: 64507, org: "Thames Transit Ltd" },
]

const USERNAMES = ["root", "admin", "ubuntu", "user", "test", "oracle", "pi", "git", "postgres"]
const PASSWORDS = [
  "123456",
  "password",
  "admin",
  "root",
  "12345678",
  "qwerty",
  "P@ssw0rd",
  "raspberry",
  "changeme",
  "letmein",
]
const COMMANDS = [
  "uname -a",
  "cat /proc/cpuinfo | grep name | wc -l",
  "whoami",
  "free -m",
  "ls -la /tmp",
  "crontab -l",
  "cd /tmp; chmod +x .x",
  "nproc",
  "cat /etc/os-release",
]
const PATHS = [
  "/",
  "/.env",
  "/wp-login.php",
  "/phpinfo.php",
  "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
  "/index.php?PHP_SESSION_UPLOAD_PROGRESS=1",
  "/admin/config.php",
  "/.git/config",
]
const AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "curl/8.5.0",
  "python-requests/2.32.3",
  "Go-http-client/1.1",
  "zgrab/0.x",
]

const DST_PORT: Record<Sensor, number> = { ssh: 22, telnet: 23, web: 80, rdp: 3389 }

export interface Fixture {
  session: Session
  events: SensorEvent[]
}

/** Stable small hash of an address (FNV-1a), so fixtures are consistent per IP. */
function ipHash(ip: string): number {
  let h = 0x811c9dc5
  for (let i = 0; i < ip.length; i++) {
    h ^= ip.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h
}

function sessionId(rand: Rand) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
  let out = ""
  for (let i = 0; i < 11; i++) out += chars.charAt(Math.floor(rand() * chars.length))
  return out
}

function iso(ms: number) {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z")
}

export function buildFixtures(count = 420, now = Date.now(), seed = 7): Fixture[] {
  const rand = mulberry32(seed)
  const out: Fixture[] = []
  let eventId = 1000
  // A few repeat visitors so the IP filter has something to show.
  const repeatIps = ["203.0.113.77", "198.51.100.23", "192.0.2.14"]
  let t = now - 40_000

  for (let i = 0; i < count; i++) {
    // Newest first; gaps grow slowly so the last 24 h hold most sessions.
    t -= int(rand, 20, 420) * 1000
    const sensor: Sensor = pick(rand, [
      "ssh",
      "ssh",
      "ssh",
      "ssh",
      "telnet",
      "telnet",
      "web",
      "web",
      "rdp",
    ] as const)
    const src_ip =
      rand() < 0.12 ? pick(rand, repeatIps) : `${pick(rand, PREFIXES)}.${int(rand, 2, 254)}`
    // Origin and enrichment belong to the address, not the session: one IP, one origin.
    rand()
    rand()
    const h = ipHash(src_ip)
    const enriched = h % 100 < 85
    const origin = ORIGINS[h % ORIGINS.length] ?? ORIGINS[0]
    if (!origin) throw new Error("no origins")
    const id = sessionId(rand)
    const src_port = int(rand, 32768, 60999)
    const dst_port = DST_PORT[sensor]

    const tags: string[] = []
    let login_attempts = 0
    let login_success = false
    let commands = 0
    let downloads = 0
    let http_requests = 0

    const roll = rand()
    if (sensor === "web") {
      http_requests = int(rand, 1, roll < 0.2 ? 40 : 6)
      if (roll < 0.25) tags.push("php2shell")
      else if (roll < 0.55) tags.push("recon")
    } else if (sensor === "rdp") {
      login_attempts = roll < 0.3 ? 0 : int(rand, 1, 60)
    } else {
      login_attempts = roll < 0.12 ? 0 : int(rand, 1, roll < 0.5 ? 12 : 140)
      login_success = login_attempts > 0 && rand() < 0.3
      if (login_success) {
        commands = int(rand, 1, 14)
        if (rand() < 0.35) {
          downloads = int(rand, 1, 3)
          tags.push(pick(rand, ["crypto-miner", "mirai", "malware-drop"] as const))
        } else if (rand() < 0.5) tags.push("recon")
      }
    }

    const events: SensorEvent[] = []
    let ts = t
    const base = {
      sensor,
      session_id: id,
      src_ip,
      src_port,
      dst_port,
      country: enriched ? origin.country : null,
      city: enriched ? origin.city : null,
      asn: enriched ? origin.asn : null,
      org: enriched ? origin.org : null,
      abuse_score: enriched ? h % 101 : null,
      known_scanner: enriched ? (h >>> 8) % 5 === 0 : null,
      tags,
    }
    const push = (type: string, data: Record<string, unknown>, stepMs: number) => {
      ts += stepMs
      events.push({ ...base, id: eventId++, ts: iso(ts), type, data })
    }

    push("connect", sensor === "ssh" ? { client_version: "SSH-2.0-libssh_0.9.6" } : {}, 0)
    for (let k = 0; k < login_attempts; k++) {
      const last = k === login_attempts - 1
      push(
        "login_attempt",
        {
          username: pick(rand, USERNAMES),
          password: pick(rand, PASSWORDS),
          success: login_success && last,
          method: "password",
        },
        int(rand, 300, 2500),
      )
    }
    for (let k = 0; k < commands; k++) {
      push("command", { input: pick(rand, COMMANDS) }, int(rand, 800, 6000))
    }
    for (let k = 0; k < downloads; k++) {
      const host = `${pick(rand, PREFIXES)}.${int(rand, 2, 254)}`
      push(
        "download_attempt",
        { url: `http://${host}/bins/x86_64`, tool: pick(rand, ["wget", "curl"]), command: "" },
        int(rand, 500, 3000),
      )
    }
    for (let k = 0; k < http_requests; k++) {
      push(
        "http_request",
        {
          method: rand() < 0.8 ? "GET" : "POST",
          path: pick(rand, PATHS),
          user_agent: pick(rand, AGENTS),
          status: pick(rand, [200, 404, 404, 403]),
        },
        int(rand, 100, 1500),
      )
    }

    // The newest couple of sessions are still open.
    const open = i < 2
    if (!open) push("disconnect", { duration_s: Math.round((ts - t) / 1000), reason: "eof" }, 400)

    const session: Session = {
      ...base,
      started_at: iso(t),
      ended_at: open ? null : iso(ts),
      last_event_at: iso(ts),
      event_count: events.length,
      login_attempts,
      login_success,
      commands,
      downloads,
      http_requests,
    }
    out.push({ session, events })
  }
  return out
}
