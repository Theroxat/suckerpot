import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { AuthProvider } from "@/app/auth"
import { ThemeProvider } from "@/app/theme"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { AuthUser } from "@/lib/auth-api"
import type { QueueItem, SmtpConfig } from "@/lib/abuse-send"
import { SendQueue } from "./send-queue"

const ADMIN: AuthUser = {
  username: "admin",
  display_name: "Admin",
  role: "admin",
  is_owner: true,
  must_change_password: false,
  read_only: false,
  last_login_at: null,
}

const item = (id: string, over: Partial<QueueItem> = {}): QueueItem => ({
  id,
  recipient: `abuse-${id}@example.net`,
  subject: `Abuse report ${id}`,
  body_text: `Hello from ${id}\nSecond line`,
  scheduled_at: null,
  last_request: null,
  ...over,
})

const smtp = (over: Partial<SmtpConfig> = {}): SmtpConfig => ({
  configured: true,
  password_set: true,
  host: "smtp.example.net",
  port: 587,
  security: "starttls",
  username: "u",
  from_address: "reports@example.org",
  from_name: "",
  mode: "off",
  auto_hold_minutes: 60,
  daily_cap: 20,
  sent_today: 0,
  last_test: null,
  ...over,
})

function stub(items: QueueItem[], config: SmtpConfig = smtp()) {
  const calls: { method: string; url: string; body: unknown }[] = []
  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET"
      const body: unknown = typeof init?.body === "string" ? JSON.parse(init.body) : undefined
      if (url.endsWith("/auth/me")) return Promise.resolve(json(200, ADMIN))
      if (url.endsWith("/auth/csrf")) return Promise.resolve(json(200, { token: "t" }))
      if (method !== "GET") calls.push({ method, url, body })
      if (url.endsWith("/abuse/send-queue")) return Promise.resolve(json(200, { items }))
      if (url.endsWith("/abuse/smtp")) return Promise.resolve(json(200, config))
      if (url.endsWith("/status") && method === "POST")
        return Promise.resolve(json(200, { status: "sent", revision: 8 }))
      if (url.includes("/abuse/reports/"))
        return Promise.resolve(json(200, { status: "reviewed", revision: 7 }))
      return Promise.resolve(json(404, { detail: "nope" }))
    }),
  )
  return calls
}

function renderQueue() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <TooltipProvider>
            <AuthProvider>
              <SendQueue />
            </AuthProvider>
          </TooltipProvider>
        </MemoryRouter>
      </QueryClientProvider>
    </ThemeProvider>,
  )
}

class NoopResizeObserver {
  observe = vi.fn()
  unobserve = vi.fn()
  disconnect = vi.fn()
}

beforeEach(() => vi.stubGlobal("ResizeObserver", NoopResizeObserver))
afterEach(() => vi.unstubAllGlobals())

describe("SendQueue", () => {
  it("shows the reminder, the first report and the progress", async () => {
    stub([item("a"), item("b"), item("c")])
    renderQueue()
    expect(await screen.findByText("3 reports are ready to send.")).toBeInTheDocument()
    expect(screen.getByText(/through your VPN and check the sender address/)).toBeInTheDocument()
    expect(screen.getByLabelText("Progress")).toHaveTextContent("1 of 3")
    expect(screen.getByLabelText("Recipient")).toHaveTextContent("abuse-a@example.net")
  })

  it("opens a mailto link and copies the full message", async () => {
    stub([item("a")])
    const writeText = vi.fn(() => Promise.resolve())
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true })
    renderQueue()
    const link = await screen.findByRole("link", { name: /Open in mail app/ })
    expect(link.getAttribute("href")).toMatch(/^mailto:abuse-a@example\.net\?subject=/)
    // The click would navigate in a browser; jsdom ignores a mailto: navigation.
    await userEvent.click(link)
    expect(writeText).toHaveBeenCalledWith("Hello from a\nSecond line")
    expect(await screen.findByText(/full message was also copied/)).toBeInTheDocument()
  })

  it("skips to the next report and keeps the count", async () => {
    stub([item("a"), item("b")])
    renderQueue()
    await screen.findByText("2 reports are ready to send.")
    await userEvent.click(screen.getByRole("button", { name: /Skip/ }))
    expect(screen.getByLabelText("Recipient")).toHaveTextContent("abuse-b@example.net")
    expect(screen.getByLabelText("Progress")).toHaveTextContent("1 of 2")
  })

  it("marks sent through the existing status route with the shortcut n", async () => {
    const calls = stub([item("a")])
    renderQueue()
    await screen.findByLabelText("Recipient")
    await userEvent.keyboard("n")
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/status"))).toBe(true))
    const call = calls.find((c) => c.url.endsWith("/status"))
    expect(call?.url).toContain("/abuse/reports/a/status")
    expect(call?.body).toEqual({ to: "sent", revision: 7 })
  })

  it("offers Send now only in click mode and names the recipient", async () => {
    stub([item("a")], smtp({ mode: "click" }))
    renderQueue()
    await userEvent.click(await screen.findByRole("button", { name: /Send now/ }))
    expect(await screen.findByText(/goes to abuse-a@example\.net/)).toBeInTheDocument()
  })

  it("shows no Send now when sending is off", async () => {
    stub([item("a")], smtp({ mode: "off" }))
    renderQueue()
    await screen.findByLabelText("Recipient")
    expect(screen.queryByRole("button", { name: /Send now/ })).not.toBeInTheDocument()
  })

  it("shows the failure sentence of the last request", async () => {
    stub(
      [item("a", { last_request: { status: "failed", error_code: "tls_failed", done_at: null } })],
      smtp({ mode: "click" }),
    )
    renderQueue()
    expect(await screen.findByText(/secure connection to the mail server/)).toBeInTheDocument()
  })

  it("shows the planned time and Cancel in automatic mode", async () => {
    stub([item("a", { scheduled_at: "2026-11-01T10:30:00Z" })], smtp({ mode: "auto" }))
    renderQueue()
    expect(await screen.findByText(/Sending at/)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument()
  })
})
