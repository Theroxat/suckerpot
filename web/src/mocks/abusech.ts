/**
 * MSW handlers for the M27 abuse.ch endpoints (docs/design/m27.md section 11): the submission
 * settings and the list of candidates. Demo data only: URLs are on documentation ranges and
 * example.net, tags come from the fixed vocabulary. The password "wrong" fails re-authentication.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import { type AbusechSettings, type Submission, type SubmissionStatus } from "@/lib/abusech"

const LATENCY_MS = 150
const HOUR = 3_600_000
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString()

const settings: AbusechSettings = {
  mode: "review",
  threatfox_enabled: false,
  anonymous: true,
  auto_hold_minutes: 60,
  daily_cap: 20,
  key_set: true,
  key_last4: "7f3a",
  server_enabled: true,
  submitted_today: 4,
}

function row(
  id: number,
  value: string,
  status: SubmissionStatus,
  ageH: number,
  tags: string[],
  extra: Partial<Submission> = {},
): Submission {
  return {
    id,
    value,
    platform: "urlhaus",
    status,
    result_code: null,
    lookup: status === "candidate" || status === "pending" ? "unknown" : "known",
    tags,
    scheduled_at: null,
    submitted_at: null,
    created_at: iso(ageH * HOUR),
    reference: null,
    malware: null,
    demo: false,
    // Evidence, varied by id so the rows do not all read the same.
    session_count: (id % 5) + 1,
    sensors: id % 3 === 0 ? ["ssh", "telnet"] : id % 2 === 0 ? ["telnet"] : ["ssh"],
    last_seen: iso((ageH + 1) * HOUR),
    ...extra,
  }
}

const submissions: Submission[] = [
  row(11, "http://203.0.113.140/up.sh", "candidate", 3, ["sh"]),
  row(12, "http://198.51.100.88/i/armv5", "candidate", 5, ["mirai", "elf", "arm"]),
  row(13, "http://example.net/files/z.sh", "candidate", 9, ["sh"]),
  row(14, "http://203.0.113.9/bins/arm7", "pending", 2, ["gafgyt", "elf", "arm"], {
    scheduled_at: iso(-35 * 60_000),
  }),
  row(21, "http://198.51.100.60/m.sh", "submitted", 30, ["sh"], {
    result_code: "ok",
    submitted_at: iso(28 * HOUR),
    reference: "https://urlhaus.example.org/url/1",
  }),
  row(22, "http://198.51.100.60/x86_64", "submitted", 31, ["mirai", "elf", "x86-64"], {
    result_code: "ok",
    submitted_at: iso(29 * HOUR),
    reference: "https://urlhaus.example.org/url/2",
  }),
  row(23, "http://192.0.2.77/k/sora.sh", "submitted", 80, ["sh"], {
    result_code: "ok",
    submitted_at: iso(78 * HOUR),
    reference: "https://urlhaus.example.org/url/3",
  }),
  row(31, "http://203.0.113.31/x.sh", "skipped_known", 40, ["sh"], {
    result_code: "already_known",
    reference: "https://urlhaus.example.org/url/4",
  }),
  row(32, "http://203.0.113.31/a/w.sh", "skipped_known", 41, ["sh"], {
    result_code: "already_known",
    reference: "https://urlhaus.example.org/url/5",
  }),
  row(41, "http://192.0.2.201/z.sh", "failed", 60, ["sh"], {
    result_code: "unreachable",
    session_count: 0,
    sensors: [],
    last_seen: null,
  }),
]

const counts = (): Record<string, number> => {
  const c: Record<string, number> = {}
  for (const s of submissions) c[s.status] = (c[s.status] ?? 0) + 1
  return c
}

const reauthFailed = () =>
  HttpResponse.json({ detail: "wrong password", code: "reauth_failed" }, { status: 403 })

async function body(request: Request): Promise<Record<string, unknown>> {
  return ((await request.json().catch(() => ({}))) ?? {}) as Record<string, unknown>
}
const passwordOk = (b: Record<string, unknown>) =>
  typeof b.current_password === "string" &&
  b.current_password !== "" &&
  b.current_password !== "wrong"

export const abusechHandlers: RequestHandler[] = [
  http.get("/api/v1/abusech/submission", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(settings)
  }),
  http.put("/api/v1/abusech/submission", async ({ request }) => {
    await delay(LATENCY_MS)
    const b = await body(request)
    if (!passwordOk(b)) return reauthFailed()
    if (b.mode === "auto" && !settings.key_set && typeof b.key !== "string")
      return HttpResponse.json({ detail: "key required", code: "key_required" }, { status: 422 })
    Object.assign(settings, {
      mode: b.mode ?? settings.mode,
      threatfox_enabled: Boolean(b.threatfox_enabled),
      anonymous: Boolean(b.anonymous),
      auto_hold_minutes: Number(b.auto_hold_minutes ?? 60),
      daily_cap: Number(b.daily_cap ?? 20),
    })
    if (typeof b.key === "string") {
      settings.key_set = true
      settings.key_last4 = b.key.slice(-4)
    }
    return HttpResponse.json(settings)
  }),
  http.delete("/api/v1/abusech/submission", async ({ request }) => {
    await delay(LATENCY_MS)
    if (!passwordOk(await body(request))) return reauthFailed()
    Object.assign(settings, { mode: "off", key_set: false, key_last4: null })
    return new HttpResponse(null, { status: 204 })
  }),
  http.get("/api/v1/abusech/submissions", async ({ request }) => {
    await delay(LATENCY_MS)
    const q = new URL(request.url).searchParams
    const statuses = (q.get("status") ?? "").split(",").filter(Boolean)
    let items = submissions.filter((s) => !statuses.length || statuses.includes(s.status))
    const platform = q.get("platform")
    if (platform) items = items.filter((s) => s.platform === platform)
    items = [...items].sort((a, b) => b.created_at.localeCompare(a.created_at))
    return HttpResponse.json({ items, next_cursor: null, counts: counts() })
  }),
  http.post("/api/v1/abusech/submissions/submit", async ({ request }) => {
    await delay(LATENCY_MS)
    if (settings.mode === "off")
      return HttpResponse.json({ detail: "off", code: "mode_off" }, { status: 409 })
    const ids = ((await body(request)).ids as number[] | undefined) ?? []
    const picked = submissions.filter((s) => ids.includes(s.id))
    if (picked.some((s) => s.status !== "candidate"))
      return HttpResponse.json({ detail: "no", code: "not_a_candidate" }, { status: 409 })
    for (const s of picked) s.status = "pending"
    return HttpResponse.json({ approved: ids })
  }),
  http.post("/api/v1/abusech/submissions/:id/cancel", async ({ params }) => {
    await delay(LATENCY_MS)
    const s = submissions.find((x) => x.id === Number(params.id))
    if (s?.status === "pending") s.status = "cancelled"
    return new HttpResponse(null, { status: 204 })
  }),
]
