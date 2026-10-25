import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, describe, expect, it, vi } from "vitest"
import { AuthProvider } from "@/app/auth"
import { ThemeProvider } from "@/app/theme"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { AuthUser } from "@/lib/auth-api"
import type { AuditEntry, UserItem } from "@/lib/users"
import { AuditCard } from "./audit-card"
import { UsersCard } from "./users-card"

const ADMIN: AuthUser = {
  username: "admin",
  display_name: "Admin",
  role: "admin",
  is_owner: true,
  must_change_password: false,
  read_only: false,
  last_login_at: null,
}

const TEMP = "kP3mR-4tqXw-nH8yD-aVu6c"

function user(over: Partial<UserItem>): UserItem {
  return {
    id: 1,
    username: "colleague",
    display_name: "A Colleague",
    role: "viewer",
    is_owner: false,
    disabled: false,
    must_change_password: false,
    locked_until: null,
    created_at: "2026-10-20T08:00:00Z",
    created_by: "admin",
    last_login_at: "2026-10-25T09:00:00Z",
    password_changed_at: null,
    ...over,
  }
}

const OWNER = user({
  id: null,
  username: "admin",
  display_name: "Admin",
  role: "admin",
  is_owner: true,
})

interface Backend {
  users: UserItem[]
  calls: { method: string; url: string; body: unknown }[]
  audit: AuditEntry[]
}

function stub(backend: Backend, me: AuthUser = ADMIN) {
  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET"
      const body: unknown = typeof init?.body === "string" ? JSON.parse(init.body) : undefined
      if (url.endsWith("/auth/me")) return Promise.resolve(json(200, me))
      if (url.endsWith("/auth/csrf")) return Promise.resolve(json(200, { token: "t" }))
      if (method !== "GET") backend.calls.push({ method, url, body })
      const password = (body as { password?: string } | undefined)?.password
      if (method !== "GET" && password === "wrong")
        return Promise.resolve(json(403, { detail: "no", code: "reauth_failed" }))
      if (url.startsWith("/api/v1/users") && method === "GET")
        return Promise.resolve(json(200, { owner: OWNER, items: backend.users, next_cursor: null }))
      if (url === "/api/v1/users" && method === "POST")
        return Promise.resolve(json(201, { user: backend.users[0], temporary_password: TEMP }))
      if (url.endsWith("/reset-password"))
        return Promise.resolve(json(200, { temporary_password: TEMP }))
      if (url.startsWith("/api/v1/audit")) backend.calls.push({ method, url, body })
      if (url.startsWith("/api/v1/audit"))
        return Promise.resolve(json(200, { items: backend.audit, next_cursor: null }))
      return Promise.resolve(
        json(method === "DELETE" ? 204 : 200, method === "DELETE" ? undefined : {}),
      )
    }),
  )
}

function mount(node: React.ReactNode, path = "/") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <TooltipProvider>
          <AuthProvider>
            <MemoryRouter initialEntries={[path]}>{node}</MemoryRouter>
          </AuthProvider>
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>,
  )
}

function rowAt(rows: HTMLElement[], i: number): HTMLElement {
  const row = rows[i]
  if (!row) throw new Error(`no row ${i}`)
  return row
}

const backend = (over: Partial<Backend> = {}): Backend => ({
  users: [user({})],
  calls: [],
  audit: [],
  ...over,
})

describe("UsersCard", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("lists the owner without actions and the users with an actions menu", async () => {
    stub(
      backend({
        users: [
          user({}),
          user({ id: 2, username: "jordan", display_name: "Jordan", must_change_password: true }),
          user({ id: 3, username: "riley", display_name: "Riley", disabled: true }),
        ],
      }),
    )
    mount(<UsersCard />)
    const list = await screen.findByRole("list", { name: "Users" })
    const rows = within(list).getAllByRole("listitem")
    expect(rows).toHaveLength(4)
    expect(within(rowAt(rows, 0)).getByText("Owner")).toBeInTheDocument()
    expect(within(rowAt(rows, 0)).queryByRole("button")).toBeNull()
    expect(within(rowAt(rows, 1)).getByText("Active")).toBeInTheDocument()
    expect(within(rowAt(rows, 2)).getByText("Waiting for first sign-in")).toBeInTheDocument()
    expect(within(rowAt(rows, 3)).getByText("Disabled")).toBeInTheDocument()
    expect(screen.getByRole("heading", { level: 3 }).textContent).toMatch(
      /3 people can sign in: 1 administrator and 2 viewers\./,
    )
  })

  it("adds a user and shows the temporary password once, with a warning", async () => {
    const b = backend()
    stub(b)
    const ui = userEvent.setup()
    mount(<UsersCard />)
    await ui.click(await screen.findByRole("button", { name: "Add user" }))
    const dialog = await screen.findByRole("dialog")

    await ui.click(within(dialog).getByRole("button", { name: "Create user" }))
    expect(within(dialog).getByText(/3 to 32 characters/)).toBeInTheDocument()
    expect(b.calls).toHaveLength(0)

    await ui.type(within(dialog).getByLabelText("Username"), "colleague")
    await ui.type(within(dialog).getByLabelText("Name"), "A Colleague")
    await ui.type(within(dialog).getByLabelText("Your password"), "wrong")
    await ui.click(within(dialog).getByRole("button", { name: "Create user" }))
    expect(await within(dialog).findByText("That password is not correct.")).toBeInTheDocument()

    await ui.type(within(dialog).getByLabelText("Your password"), "the admin password")
    await ui.click(within(dialog).getByRole("button", { name: "Create user" }))

    const reveal = await screen.findByRole("dialog", { name: /Account created/ })
    expect(within(reveal).getByTestId("temporary-password")).toHaveTextContent(TEMP)
    expect(within(reveal).getByText(/shown only once/)).toBeInTheDocument()
    expect(b.calls.at(-1)?.body).toMatchObject({
      username: "colleague",
      display_name: "A Colleague",
      role: "viewer",
      password: "the admin password",
    })

    // Escape does not dismiss it before it was copied; the button does.
    await ui.keyboard("{Escape}")
    expect(screen.getByRole("dialog", { name: /Account created/ })).toBeInTheDocument()
    await ui.click(within(reveal).getByRole("button", { name: "I have copied it" }))
    await waitFor(() => expect(screen.queryByTestId("temporary-password")).toBeNull())
    expect(document.body.textContent).not.toContain(TEMP)
  })

  it("asks for the password before resetting one and then reveals the new temporary password", async () => {
    const b = backend()
    stub(b)
    const ui = userEvent.setup()
    mount(<UsersCard />)
    await ui.click(await screen.findByRole("button", { name: "Actions for colleague" }))
    await ui.click(await screen.findByRole("menuitem", { name: "Reset password" }))
    const dialog = await screen.findByRole("dialog")
    await ui.click(within(dialog).getByRole("button", { name: "Reset password" }))
    expect(within(dialog).getByText("Enter your password to confirm.")).toBeInTheDocument()
    await ui.type(within(dialog).getByLabelText("Your password"), "the admin password")
    await ui.click(within(dialog).getByRole("button", { name: "Reset password" }))
    const reveal = await screen.findByRole("dialog", { name: /Password reset/ })
    expect(within(reveal).getByTestId("temporary-password")).toHaveTextContent(TEMP)
    expect(b.calls.at(-1)).toMatchObject({
      method: "POST",
      url: "/api/v1/users/1/reset-password",
      body: { password: "the admin password" },
    })
  })

  it("offers Unlock only for a locked account, and Enable for a disabled one", async () => {
    stub(
      backend({
        users: [
          user({ locked_until: new Date(Date.now() + 600_000).toISOString() }),
          user({ id: 2, username: "riley", display_name: "Riley", disabled: true }),
        ],
      }),
    )
    const ui = userEvent.setup()
    mount(<UsersCard />)
    await ui.click(await screen.findByRole("button", { name: "Actions for colleague" }))
    expect(await screen.findByRole("menuitem", { name: "Unlock" })).toBeInTheDocument()
    expect(screen.getByRole("menuitem", { name: "Disable" })).toBeInTheDocument()
    await ui.keyboard("{Escape}")
    await ui.click(screen.getByRole("button", { name: "Actions for riley" }))
    expect(await screen.findByRole("menuitem", { name: "Enable" })).toBeInTheDocument()
    expect(screen.queryByRole("menuitem", { name: "Unlock" })).toBeNull()
  })

  it("does not let an administrator lock themselves out from the menu", async () => {
    stub(backend({ users: [user({ username: "boss", display_name: "Boss", role: "admin" })] }), {
      ...ADMIN,
      username: "boss",
      is_owner: false,
    })
    const ui = userEvent.setup()
    mount(<UsersCard />)
    await ui.click(await screen.findByRole("button", { name: "Actions for boss" }))
    expect(await screen.findByRole("menuitem", { name: "Delete user" })).toHaveAttribute(
      "aria-disabled",
      "true",
    )
    expect(screen.getByRole("menuitem", { name: "Disable" })).toHaveAttribute(
      "aria-disabled",
      "true",
    )
    expect(screen.getByRole("menuitem", { name: "Sign out everywhere" })).not.toHaveAttribute(
      "aria-disabled",
      "true",
    )
  })
})

describe("AuditCard", () => {
  afterEach(() => vi.unstubAllGlobals())

  const entries: AuditEntry[] = [
    {
      id: 2,
      ts: "2026-10-25T10:00:00Z",
      actor: "admin",
      action: "user.create",
      target: "jordan",
      ip: "203.0.113.20",
      details: { role: "viewer" },
    },
    {
      id: 1,
      ts: "2026-10-25T09:00:00Z",
      actor: "jordan",
      action: "auth.login",
      target: "jordan",
      ip: null,
      details: {},
    },
  ]

  it("writes each entry as a sentence under a finding", async () => {
    stub(backend({ audit: entries }))
    mount(<AuditCard />)
    const list = await screen.findByRole("list", { name: "Audit log" })
    expect(within(list).getByText("created the user jordan (viewer)")).toBeInTheDocument()
    expect(within(list).getByText("signed in")).toBeInTheDocument()
    expect(screen.getByRole("heading", { level: 3 }).textContent).toBe(
      "Latest entry: admin created the user jordan (viewer).",
    )
  })

  it("filters by kind and keeps the filter in the URL", async () => {
    const b = backend({ audit: entries })
    stub(b)
    const ui = userEvent.setup()
    mount(<AuditCard />)
    await screen.findByRole("list", { name: "Audit log" })
    await ui.click(screen.getByRole("radio", { name: "Users" }))
    await waitFor(() => expect(b.calls.some((c) => c.url.includes("action=user."))).toBe(true))
  })
})

describe("read-only access", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("shows the badge to a viewer and to nobody else", async () => {
    const { ReadOnlyBadge } = await import("@/components/read-only-badge")
    stub(backend(), { ...ADMIN, role: "viewer", read_only: true, is_owner: false })
    const view = mount(<ReadOnlyBadge />)
    // Signed in as a viewer once /auth/me answered; the default context is an admin.
    expect(await screen.findByText("Read-only access")).toBeInTheDocument()
    view.unmount()
    vi.unstubAllGlobals()
    stub(backend())
    mount(<ReadOnlyBadge />)
    await waitFor(() => expect(screen.queryByText("Read-only access")).toBeNull())
  })
})

describe("keys for a viewer", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("shows the keys but no control that changes one", async () => {
    const { ProviderKeys } = await import("@/components/provider-keys")
    stub(backend(), { ...ADMIN, role: "viewer", read_only: true, is_owner: false })
    const NO_KEY = {
      configured: true,
      source: "settings" as const,
      last4: "7c2f",
      updated_at: "2026-10-24T10:00:00Z",
      secret_error: null,
      pending_apply: false,
      test: null,
      test_pending: false,
      test_requested_at: null,
    }
    const rep = {
      ...NO_KEY,
      daily_quota: 1000,
      used_today: 3,
      disabled: null,
      paused: false,
      last_error: null,
    }
    mount(
      <ProviderKeys
        e={{
          geoip: {
            provider: "dbip",
            available: true,
            files: {},
            last_error: null,
            refresh_days: 30,
            attribution: null,
          },
          abuseipdb: rep,
          greynoise: rep,
          maxmind: NO_KEY,
          nvd: NO_KEY,
          github: NO_KEY,
          abusech: rep,
          virustotal: rep,
          key_editing: { enabled: true, reason: null },
          reported_at: null,
        }}
      />,
    )
    await screen.findByText(/Only an administrator can change them/)
    expect(screen.queryByRole("button", { name: /Replace|Set the|Remove|Test/ })).toBeNull()
    expect(screen.getAllByText("7c2f").length).toBeGreaterThan(0)
  })
})
