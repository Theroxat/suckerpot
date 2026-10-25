import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type {
  AlertChannel,
  AlertRule,
  AlertStatus,
  ChannelKind,
  OutboxItem,
  ReportItem,
  RuleKind,
  WatchedCve,
} from "@/lib/alerts"
import type { Severity } from "@/lib/severity"

/** MSW handlers for the alerts and reports endpoints. State lives for the page load. */
const LATENCY_MS = 160
const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString()
const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000).toISOString()

let nextChannel = 3
const channels: AlertChannel[] = [
  {
    id: 1,
    kind: "discord",
    name: "SecOps channel",
    enabled: true,
    target_hint: "discord.com",
    mask_ips: true,
    created_by: "admin",
    created_at: daysAgo(20),
    updated_at: daysAgo(20),
    last_test: { state: "done", detail: "sent", requested_at: daysAgo(19) },
  },
  {
    id: 2,
    kind: "email",
    name: "Weekly report to the team",
    enabled: true,
    target_hint: "s***@example.org",
    mask_ips: true,
    created_by: "admin",
    created_at: daysAgo(12),
    updated_at: daysAgo(12),
    last_test: { state: "failed", detail: "smtp_not_configured", requested_at: daysAgo(11) },
  },
]

const rules: AlertRule[] = [
  { kind: "new_campaign", enabled: true, channel_ids: [1], min_severity: "warning" },
  { kind: "malware_drop", enabled: true, channel_ids: [1], min_severity: "severe" },
  { kind: "new_download_host", enabled: false, channel_ids: [], min_severity: "warning" },
  { kind: "watched_cve_seen", enabled: true, channel_ids: [1, 2], min_severity: "warning" },
  { kind: "weekly_report", enabled: true, channel_ids: [2], min_severity: "info" },
]

const watched: WatchedCve[] = [
  { cve_id: "CVE-2026-109618", added_by: "admin", added_at: daysAgo(3) },
  { cve_id: "CVE-2026-109619", added_by: "admin", added_at: daysAgo(3) },
]

function alert(
  id: number,
  rule: RuleKind,
  channel: number,
  state: OutboxItem["state"],
  ageMin: number,
  severity: Severity,
  title: string,
  summary: string,
  error: string | null = null,
): OutboxItem {
  return {
    id,
    rule_kind: rule,
    channel_id: channel,
    channel_name: channels.find((c) => c.id === channel)?.name ?? null,
    state,
    attempts: state === "pending" ? 0 : 1,
    created_at: minutesAgo(ageMin),
    sent_at: state === "sent" ? minutesAgo(ageMin) : null,
    error_code: error,
    severity,
    title,
    summary,
  }
}

const outbox: OutboxItem[] = [
  alert(
    12,
    "malware_drop",
    1,
    "sent",
    14,
    "severe",
    "Malware was dropped on the honeypot",
    "An attacker downloaded or ran a payload in a session on the telnet sensor.",
  ),
  alert(
    11,
    "new_campaign",
    1,
    "sent",
    95,
    "warning",
    "New campaign: Mirai loader over Telnet #41",
    "A new coordinated campaign appeared: 9 addresses are running the same attack against the honeypot.",
  ),
  alert(
    10,
    "watched_cve_seen",
    2,
    "failed",
    240,
    "warning",
    "CVE-2026-109618 is being exploited against the honeypot",
    "A vulnerability you watch was tried in 12 sessions today.",
    "smtp_not_configured",
  ),
  alert(
    9,
    "watched_cve_seen",
    1,
    "sent",
    240,
    "warning",
    "CVE-2026-109618 is being exploited against the honeypot",
    "A vulnerability you watch was tried in 12 sessions today.",
  ),
  alert(
    8,
    "new_campaign",
    1,
    "suppressed",
    1500,
    "warning",
    "New campaign: Crypto miner over SSH #38",
    "A new coordinated campaign appeared: 4 addresses are running the same attack against the honeypot.",
    "digested",
  ),
  alert(
    7,
    "new_campaign",
    1,
    "sent",
    1501,
    "warning",
    "14 alerts were waiting",
    "Too many alerts arrived at once, so here is a short list instead of one message each.",
  ),
  alert(
    6,
    "weekly_report",
    2,
    "sent",
    4300,
    "info",
    "Weekly report for the week of 2026-10-12",
    "2,486 attack sessions from 611 addresses, up 18% on the week before, mostly against ssh.",
  ),
]

const status: AlertStatus = {
  alerts: {
    enabled: true,
    smtp_configured: false,
    can_decrypt: true,
    last_error: null,
    updated_at: minutesAgo(1),
  },
  reports_enabled: true,
  editing_enabled: true,
  editing_reason: null,
  channels: channels.length,
  limits: { per_minute: 10, per_day: 100, all_channels_per_day: 300 },
}

const reports: ReportItem[] = [
  {
    week_start: "2026-10-19",
    week_end: "2026-10-25",
    headline:
      "3,104 attack sessions from 702 addresses, up 25% on the week before, mostly against ssh.",
    sessions: 3104,
    sources: 702,
    malware: 41,
    change_pct: 25,
    created_at: minutesAgo(30),
  },
  {
    week_start: "2026-10-12",
    week_end: "2026-10-18",
    headline:
      "2,486 attack sessions from 611 addresses, up 18% on the week before, mostly against ssh.",
    sessions: 2486,
    sources: 611,
    malware: 27,
    change_pct: 18,
    created_at: daysAgo(7),
  },
  {
    week_start: "2026-10-05",
    week_end: "2026-10-11",
    headline: "2,107 attack sessions from 540 addresses, about the same as the week before.",
    sessions: 2107,
    sources: 540,
    malware: 12,
    change_pct: 2,
    created_at: daysAgo(14),
  },
]

const actions = [
  "Block the 3 new malware download hosts listed below on your web proxy or DNS filter.",
  "Review the 2 new campaigns and check that your own services do not expose the same weakness.",
  "Patch or mitigate CVE-2026-109618 on your own systems: it was tried 12 times against the honeypot.",
  "SSH was the most targeted service: allow it only from a VPN, no password logins.",
]

function reportHtml(r: ReportItem): string {
  const li = actions.map((a) => `<li>${a}</li>`).join("")
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Weekly report</title><style>
body{margin:0;background:#fff;color:#16181d;font:14px/1.5 system-ui,sans-serif}main{max-width:800px;margin:0 auto;padding:28px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:#4b5563;margin:24px 0 8px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}
.lead{font-size:16px}.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.kpi{border:1px solid #e5e7eb;border-radius:8px;padding:10px 12px}.kpi b{display:block;font-size:22px}
.kpi span{color:#4b5563;font-size:12px}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:4px 8px 4px 0;border-bottom:1px solid #f0f1f3}td.n,th.n{text-align:right}
@media (max-width:600px){.kpis{grid-template-columns:repeat(2,1fr)}}</style></head><body><main>
<h1>Weekly report, ${r.week_start} to ${r.week_end ?? ""}</h1><p class="lead">${r.headline ?? ""}</p>
<div class="kpis"><div class="kpi"><b>${r.sessions.toLocaleString("en-US")}</b>Attack sessions<br><span>+${r.change_pct ?? 0}% vs previous week</span></div>
<div class="kpi"><b>${r.sources.toLocaleString("en-US")}</b>Different addresses<br><span>unique sources</span></div>
<div class="kpi"><b>312</b>Ran commands<br><span>got past the login</span></div><div class="kpi"><b>${r.malware}</b>Dropped malware<br><span>sessions</span></div></div>
<h2>What to do next</h2><ol>${li}</ol>
<h2>Services attacked</h2><table><tr><th>Service</th><th class="n">Sessions</th></tr><tr><td>ssh</td><td class="n">1,702</td></tr><tr><td>telnet</td><td class="n">702</td></tr><tr><td>web</td><td class="n">480</td></tr></table>
<h2>New malware download hosts (defanged)</h2><table><tr><th>Host</th><th class="n">Times seen</th></tr><tr><td>hxxp[://]198[.]51[.]100[.]23/bins</td><td class="n">18</td></tr><tr><td>cdn-update[.]example</td><td class="n">7</td></tr></table>
<p style="color:#6b7280;font-size:12px;margin-top:24px">IP addresses are not included in this report. Indicators are defanged.</p></main></body></html>`
}

function find(kind: string) {
  return rules.find((r) => r.kind === kind)
}

function demoTest(id: number) {
  const channel = channels.find((c) => c.id === id)
  if (!channel) return
  channel.last_test = { state: "queued", detail: null, requested_at: new Date().toISOString() }
  setTimeout(() => {
    channel.last_test =
      channel.kind === "email"
        ? { state: "failed", detail: "smtp_not_configured", requested_at: new Date().toISOString() }
        : { state: "done", detail: "sent", requested_at: new Date().toISOString() }
  }, 1800)
}

export const alertsHandlers: RequestHandler[] = [
  http.get("/api/v1/alerts/status", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json({ ...status, channels: channels.length })
  }),
  http.get("/api/v1/alerts/channels", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(channels)
  }),
  http.post("/api/v1/alerts/channels", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as {
      kind: ChannelKind
      name: string
      target: string
      mask_ips: boolean
      password: string
    }
    if (body.password === "wrong")
      return HttpResponse.json(
        { detail: "The password is incorrect.", code: "reauth_failed" },
        { status: 403 },
      )
    if (body.kind !== "email" && !body.target.startsWith("https://"))
      return HttpResponse.json(
        { detail: "The webhook URL must use https.", code: "invalid_target" },
        { status: 422 },
      )
    const channel: AlertChannel = {
      id: nextChannel++,
      kind: body.kind,
      name: body.name,
      enabled: true,
      target_hint: body.kind === "email" ? "a***@example.org" : new URL(body.target).hostname,
      mask_ips: body.mask_ips,
      created_by: "admin",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_test: null,
    }
    channels.push(channel)
    return HttpResponse.json(channel, { status: 201 })
  }),
  http.patch("/api/v1/alerts/channels/:id", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const channel = channels.find((c) => c.id === Number(params.id))
    if (!channel)
      return HttpResponse.json({ detail: "Channel not found.", code: "not_found" }, { status: 404 })
    const body = (await request.json()) as Partial<AlertChannel> & {
      target?: string
      password?: string
    }
    if (body.target !== undefined && body.password === "wrong")
      return HttpResponse.json(
        { detail: "The password is incorrect.", code: "reauth_failed" },
        { status: 403 },
      )
    if (body.name !== undefined) channel.name = body.name
    if (body.enabled !== undefined) channel.enabled = body.enabled
    if (body.mask_ips !== undefined) channel.mask_ips = body.mask_ips
    if (body.enabled === false)
      for (const r of rules) {
        r.channel_ids = r.channel_ids.filter((i) => i !== channel.id)
        if (r.channel_ids.length === 0) r.enabled = false
      }
    return HttpResponse.json(channel)
  }),
  http.delete("/api/v1/alerts/channels/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const i = channels.findIndex((c) => c.id === Number(params.id))
    if (i >= 0) channels.splice(i, 1)
    return new HttpResponse(null, { status: 204 })
  }),
  http.post("/api/v1/alerts/channels/:id/test", async ({ params }) => {
    await delay(LATENCY_MS)
    demoTest(Number(params.id))
    return HttpResponse.json(
      { channel_id: Number(params.id), requested_at: new Date().toISOString() },
      { status: 202 },
    )
  }),
  http.get("/api/v1/alerts/rules", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(rules)
  }),
  http.put("/api/v1/alerts/rules/:kind", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const rule = find(String(params.kind))
    if (!rule)
      return HttpResponse.json({ detail: "Rule not found.", code: "not_found" }, { status: 404 })
    const body = (await request.json()) as Omit<AlertRule, "kind">
    if (body.enabled && body.channel_ids.length === 0)
      return HttpResponse.json(
        { detail: "Choose at least one channel before switching a rule on.", code: "no_channel" },
        { status: 422 },
      )
    Object.assign(rule, body)
    return HttpResponse.json(rule)
  }),
  http.get("/api/v1/alerts/watched-cves", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(watched)
  }),
  http.put("/api/v1/alerts/watched-cves/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const id = String(params.id)
    let item = watched.find((w) => w.cve_id === id)
    if (!item) {
      item = { cve_id: id, added_by: "admin", added_at: new Date().toISOString() }
      watched.unshift(item)
    }
    return HttpResponse.json(item)
  }),
  http.delete("/api/v1/alerts/watched-cves/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const i = watched.findIndex((w) => w.cve_id === String(params.id))
    if (i >= 0) watched.splice(i, 1)
    return new HttpResponse(null, { status: 204 })
  }),
  http.get("/api/v1/alerts/outbox", async ({ request }) => {
    await delay(LATENCY_MS)
    const limit = Number(new URL(request.url).searchParams.get("limit") ?? 10)
    const cursor = new URL(request.url).searchParams.get("cursor")
    const offset = cursor ? Number(atob(cursor)) : 0
    const slice = outbox.slice(offset, offset + limit)
    const next = offset + limit < outbox.length ? btoa(String(offset + limit)) : null
    return HttpResponse.json({ items: slice, next_cursor: next })
  }),
  http.get("/api/v1/reports", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json({ items: reports, next_cursor: null })
  }),
  http.get("/api/v1/reports/:week/html", ({ params }) => {
    const r = reports.find((x) => x.week_start === params.week)
    if (!r)
      return HttpResponse.json({ detail: "Report not found.", code: "not_found" }, { status: 404 })
    return new HttpResponse(reportHtml(r), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    })
  }),
  http.get("/api/v1/reports/:week", async ({ params }) => {
    await delay(LATENCY_MS)
    const r = reports.find((x) => x.week_start === params.week)
    if (!r)
      return HttpResponse.json({ detail: "Report not found.", code: "not_found" }, { status: 404 })
    return HttpResponse.json({
      week_start: r.week_start,
      created_at: r.created_at,
      summary: { headline: r.headline, week_end: r.week_end, timezone: "Europe/Zurich", actions },
    })
  }),
]
