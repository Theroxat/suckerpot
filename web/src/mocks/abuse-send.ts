/**
 * MSW handlers for the M25 sending endpoints (docs/design/m25.md): the send queue, the optional
 * SMTP profile and the send routes. Stateful for the page load. Hosts and mailboxes are on
 * example.* domains; no real address appears. The password "wrong" fails the re-authentication.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type { QueueItem, SendRequest, SmtpConfig, SmtpForm, SmtpTest } from "@/lib/abuse-send"
import { find, missingWording, renderBody, rows, type Row } from "./abuse"

const LATENCY_MS = 140
const MINUTE = 60_000

const smtp: SmtpConfig = {
  configured: true,
  password_set: true,
  host: "smtp.example.net",
  port: 587,
  security: "starttls",
  username: "reports@example.org",
  from_address: "reports@example.org",
  from_name: "",
  mode: "click",
  auto_hold_minutes: 60,
  daily_cap: 20,
  sent_today: 3,
  last_test: {
    status: "sent",
    error_code: null,
    done_at: new Date(Date.now() - 90 * MINUTE).toISOString(),
  },
}

const requests = new Map<string, SendRequest>()
const scheduled = new Map<string, number>()
let requestId = 100

/** The mock report whose send always fails, to show the error sentence. */
const FAILING = "9a8b7c6d-5e4f-4a3b-9c2d-5e6f7a8b9c05"

const ready = (r: Row): boolean =>
  (r.status === "draft" || r.status === "reviewed") &&
  r.guard.ok &&
  !r.demo &&
  Boolean(r.recipient.mailbox) &&
  missingWording().length === 0

function items(): QueueItem[] {
  return rows.filter(ready).map((r) => {
    const m = renderBody(r, "text")
    if (
      smtp.mode === "auto" &&
      !scheduled.has(r.public_id) &&
      requests.get(r.public_id)?.status !== "cancelled"
    )
      scheduled.set(r.public_id, Date.now() + smtp.auto_hold_minutes * MINUTE)
    return {
      id: r.public_id,
      recipient: m.to,
      subject: m.subject,
      body_text: m.body,
      scheduled_at:
        smtp.mode === "auto" && scheduled.has(r.public_id)
          ? new Date(scheduled.get(r.public_id) ?? 0).toISOString()
          : null,
      last_request: requests.get(r.public_id) ?? null,
    }
  })
}

const reauthFailed = () =>
  HttpResponse.json({ detail: "wrong password", code: "reauth_failed" }, { status: 403 })

async function password(request: Request): Promise<{ body: Record<string, unknown>; ok: boolean }> {
  const body = ((await request.json().catch(() => ({}))) ?? {}) as Record<string, unknown>
  const p = body.current_password
  return { body, ok: typeof p === "string" && p !== "" && p !== "wrong" }
}

function settle(id: string) {
  setTimeout(() => {
    const r = find(id)
    const req = requests.get(id)
    if (!r || req?.status !== "pending") return
    const done_at = new Date().toISOString()
    if (id === FAILING) {
      requests.set(id, { status: "failed", error_code: "refused", done_at })
      return
    }
    requests.set(id, { status: "sent", error_code: null, done_at })
    r.status = "sent"
    r.sent_at = done_at
    r.updated_at = done_at
    smtp.sent_today++
  }, 1500)
}

export const abuseSendHandlers: RequestHandler[] = [
  http.get("/api/v1/abuse/send-queue", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json({ items: items() })
  }),
  http.post("/api/v1/abuse/reports/:id/send", async ({ params }) => {
    await delay(LATENCY_MS)
    const id = String(params.id)
    const r = find(id)
    const conflict = (code: string) => HttpResponse.json({ detail: code, code }, { status: 409 })
    if (!r)
      return HttpResponse.json({ detail: "Report not found.", code: "not_found" }, { status: 404 })
    if (smtp.mode === "off" || !smtp.configured) return conflict("smtp_off")
    if (!ready(r)) return conflict("not_ready")
    if (requests.get(id)?.status === "pending") return conflict("already_pending")
    if (smtp.sent_today >= smtp.daily_cap) return conflict("cap_reached")
    requests.set(id, { status: "pending", error_code: null, done_at: null })
    scheduled.delete(id)
    settle(id)
    return HttpResponse.json({ request_id: ++requestId }, { status: 202 })
  }),
  http.post("/api/v1/abuse/reports/:id/send/cancel", async ({ params }) => {
    await delay(LATENCY_MS)
    const id = String(params.id)
    scheduled.delete(id)
    requests.set(id, { status: "cancelled", error_code: null, done_at: new Date().toISOString() })
    return new HttpResponse(null, { status: 204 })
  }),
  http.get("/api/v1/abuse/smtp", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(smtp)
  }),
  http.put("/api/v1/abuse/smtp", async ({ request }) => {
    await delay(LATENCY_MS)
    const { body, ok } = await password(request)
    if (!ok) return reauthFailed()
    const b = body as unknown as Partial<SmtpForm>
    const problems: string[] = []
    if (!b.host || /^[\d.]+$/.test(b.host) || !b.host.includes(".")) problems.push("bad_host")
    if (!Number.isInteger(b.port) || (b.port ?? 0) < 1 || (b.port ?? 0) > 65535)
      problems.push("bad_port")
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(b.from_address ?? "")) problems.push("bad_from")
    if ((b.from_address ?? "").endsWith("@owner.example")) problems.push("owner_domain")
    if (!smtp.password_set && !b.password) problems.push("password_required")
    if (problems.length > 0)
      return HttpResponse.json(
        { detail: "invalid", code: "invalid_smtp", problems },
        { status: 422 },
      )
    Object.assign(smtp, {
      configured: true,
      password_set: true,
      host: b.host,
      port: b.port,
      security: b.security,
      username: b.username ?? "",
      from_address: b.from_address,
      from_name: b.from_name ?? "",
      mode: b.mode ?? "off",
      auto_hold_minutes: b.auto_hold_minutes ?? 60,
      daily_cap: b.daily_cap ?? 20,
    })
    scheduled.clear()
    return HttpResponse.json(smtp)
  }),
  http.delete("/api/v1/abuse/smtp", async ({ request }) => {
    await delay(LATENCY_MS)
    const { ok } = await password(request)
    if (!ok) return reauthFailed()
    Object.assign(smtp, {
      configured: false,
      password_set: false,
      host: "",
      port: 587,
      security: "starttls",
      username: "",
      from_address: "",
      from_name: "",
      mode: "off",
      last_test: null,
    })
    scheduled.clear()
    return new HttpResponse(null, { status: 204 })
  }),
  http.post("/api/v1/abuse/smtp/test", async ({ request }) => {
    await delay(LATENCY_MS)
    const { ok } = await password(request)
    if (!ok) return reauthFailed()
    if (!smtp.configured)
      return HttpResponse.json(
        { detail: "x", code: "not_configured", problems: ["not_configured"] },
        { status: 422 },
      )
    const test: SmtpTest = { status: "sent", error_code: null, done_at: new Date().toISOString() }
    smtp.last_test = test
    return HttpResponse.json({ request_id: ++requestId }, { status: 202 })
  }),
]
