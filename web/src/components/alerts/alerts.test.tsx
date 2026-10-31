import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { AuthProvider } from "@/app/auth"
import { ThemeProvider } from "@/app/theme"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { AuthUser } from "@/lib/auth-api"
import type { AlertChannel, AlertRule } from "@/lib/alerts"
import { ChannelsCard } from "./channels-card"
import { RulesCard } from "./rules-card"

const ADMIN: AuthUser = {
  username: "admin",
  display_name: "Admin",
  role: "admin",
  is_owner: true,
  must_change_password: false,
  read_only: false,
  last_login_at: null,
}
const VIEWER: AuthUser = {
  ...ADMIN,
  username: "viewer",
  role: "viewer",
  is_owner: false,
  read_only: true,
}

const HOOK = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwx"

function channel(over: Partial<AlertChannel> = {}): AlertChannel {
  return {
    id: 1,
    kind: "discord",
    name: "SecOps",
    enabled: true,
    target_hint: "discord.com",
    mask_ips: true,
    created_by: "admin",
    created_at: "2026-10-20T08:00:00Z",
    updated_at: "2026-10-20T08:00:00Z",
    last_test: null,
    ...over,
  }
}

const RULES: AlertRule[] = [
  { kind: "new_campaign", enabled: false, channel_ids: [], min_severity: "warning" },
  { kind: "malware_drop", enabled: false, channel_ids: [], min_severity: "severe" },
  { kind: "new_download_host", enabled: false, channel_ids: [], min_severity: "warning" },
  { kind: "watched_cve_seen", enabled: false, channel_ids: [], min_severity: "warning" },
  { kind: "weekly_report", enabled: false, channel_ids: [], min_severity: "info" },
]

interface Call {
  method: string
  url: string
  body: unknown
}

function stub(opts: { me?: AuthUser; channels?: AlertChannel[]; rules?: AlertRule[] } = {}) {
  const calls: Call[] = []
  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET"
      const body: unknown = typeof init?.body === "string" ? JSON.parse(init.body) : undefined
      if (url.endsWith("/auth/me")) return Promise.resolve(json(200, opts.me ?? ADMIN))
      if (url.endsWith("/auth/csrf")) return Promise.resolve(json(200, { token: "t" }))
      if (method !== "GET") calls.push({ method, url, body })
      if (url.endsWith("/alerts/status"))
        return Promise.resolve(
          json(200, {
            alerts: {
              enabled: true,
              smtp_configured: false,
              can_decrypt: true,
              last_error: null,
              updated_at: null,
            },
            reports_enabled: true,
            editing_enabled: true,
            editing_reason: null,
            channels: 1,
            limits: { per_minute: 10, per_day: 100, all_channels_per_day: 300 },
          }),
        )
      if (url.endsWith("/alerts/channels") && method === "GET")
        return Promise.resolve(json(200, opts.channels ?? [channel()]))
      if (url.endsWith("/alerts/channels") && method === "POST") {
        const b = body as { password: string; target: string }
        if (b.password === "wrong")
          return Promise.resolve(json(403, { detail: "no", code: "reauth_failed" }))
        if (b.target.includes("evil"))
          return Promise.resolve(
            json(422, { detail: "This is not a Discord webhook URL.", code: "invalid_target" }),
          )
        return Promise.resolve(json(201, channel({ id: 2, name: "New" })))
      }
      if (url.endsWith("/test")) return Promise.resolve(json(202, {}))
      if (url.endsWith("/alerts/rules")) return Promise.resolve(json(200, opts.rules ?? RULES))
      if (url.includes("/alerts/rules/")) return Promise.resolve(json(200, body))
      if (method === "PATCH") return Promise.resolve(json(200, channel()))
      return Promise.resolve(json(404, { detail: "nope" }))
    }),
  )
  return calls
}

function renderUi(ui: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <TooltipProvider>
            <AuthProvider>{ui}</AuthProvider>
          </TooltipProvider>
        </MemoryRouter>
      </QueryClientProvider>
    </ThemeProvider>,
  )
}

// Radix switches measure themselves with a ResizeObserver, which jsdom does not have.
class NoopResizeObserver {
  observe = vi.fn()
  unobserve = vi.fn()
  disconnect = vi.fn()
}

beforeEach(() => vi.stubGlobal("ResizeObserver", NoopResizeObserver))
afterEach(() => vi.unstubAllGlobals())

describe("ChannelsCard", () => {
  it("opens with a sentence and shows only a hint of the address", async () => {
    stub()
    renderUi(<ChannelsCard />)
    expect(await screen.findByText("1 channel is ready to receive alerts.")).toBeInTheDocument()
    expect(screen.getByText(/Discord · discord.com/)).toBeInTheDocument()
    expect(screen.getByText(/partly hidden/)).toBeInTheDocument()
  })

  it("sends a test and refreshes", async () => {
    const calls = stub()
    renderUi(<ChannelsCard />)
    await userEvent.click(await screen.findByRole("button", { name: "Send test" }))
    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/channels/1/test"))).toBe(
        true,
      ),
    )
  })

  it("adds a channel with the password, and shows why a bad address is refused", async () => {
    const calls = stub({ channels: [] })
    renderUi(<ChannelsCard />)
    await userEvent.click(await screen.findByRole("button", { name: /Add channel/ }))
    const dialog = await screen.findByRole("dialog")
    await userEvent.type(within(dialog).getByLabelText("Name"), "Ops")
    await userEvent.type(within(dialog).getByLabelText("Webhook URL"), "https://evil.example/x")
    await userEvent.type(within(dialog).getByLabelText("Your password"), "secret-pass")
    await userEvent.click(within(dialog).getByRole("button", { name: "Add channel" }))
    expect(
      await within(dialog).findByText("This is not a Discord webhook URL."),
    ).toBeInTheDocument()

    await userEvent.clear(within(dialog).getByLabelText("Webhook URL"))
    await userEvent.type(within(dialog).getByLabelText("Webhook URL"), HOOK)
    await userEvent.type(within(dialog).getByLabelText("Your password"), "secret-pass")
    await userEvent.click(within(dialog).getByRole("button", { name: "Add channel" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    const post = calls
      .filter((c) => c.method === "POST" && c.url.endsWith("/alerts/channels"))
      .at(-1)
    expect(post?.body).toMatchObject({ kind: "discord", name: "Ops", target: HOOK, mask_ips: true })
    // About 140 typed keys: ~3 s alone, past the 5 s default when the whole suite runs in parallel.
  }, 15_000)

  it("is read-only for a viewer", async () => {
    stub({ me: VIEWER })
    renderUi(<ChannelsCard />)
    await screen.findByText("1 channel is ready to receive alerts.")
    expect(screen.queryByRole("button", { name: /Add channel/ })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Send test" })).not.toBeInTheDocument()
  })
})

describe("RulesCard", () => {
  it("starts with every alert off and switches one on with the ready channels", async () => {
    const calls = stub()
    renderUi(<RulesCard />)
    expect(await screen.findByText(/Every alert is off/)).toBeInTheDocument()
    const switches = await screen.findAllByRole("switch")
    expect(switches).toHaveLength(5)
    expect(switches.every((s) => s.getAttribute("aria-checked") === "false")).toBe(true)
    const second = switches[1]
    if (!second) throw new Error("no second switch")
    await userEvent.click(second)
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true))
    const put = calls.find((c) => c.method === "PUT")
    expect(put?.url).toMatch(/\/alerts\/rules\/malware_drop$/)
    expect(put?.body).toEqual({ enabled: true, channel_ids: [1], min_severity: "severe" })
  })

  it("cannot switch anything on without a channel", async () => {
    stub({ channels: [] })
    renderUi(<RulesCard />)
    const switches = await screen.findAllByRole("switch")
    expect(switches.every((s) => s.hasAttribute("disabled"))).toBe(true)
    expect(screen.getByText(/Add a channel first/)).toBeInTheDocument()
  })
})
