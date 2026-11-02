import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { AuthProvider } from "@/app/auth"
import { ThemeProvider } from "@/app/theme"
import { TooltipProvider } from "@/components/ui/tooltip"
import { ReportingCard } from "./reporting-card"

const ME = {
  username: "admin",
  display_name: "Admin",
  role: "admin",
  is_owner: true,
  must_change_password: false,
  read_only: false,
  last_login_at: null,
}

const BARE = {
  reply_contact: "reports@example.net",
  signature: null,
  intro: null,
  outro: null,
  xarf_user_agent: null,
  note: null,
  subject_template: null,
  round_times: true,
  default_options: {
    defang: true,
    include_usernames: true,
    include_reply_contact: true,
    distinct_sources: 1,
  },
  default_tlp: "green",
  reference_style: "subject",
  revision: 4,
}

function stub(settings: unknown) {
  const puts: unknown[] = []
  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET"
      if (url.endsWith("/auth/me")) return Promise.resolve(json(200, ME))
      if (url.endsWith("/auth/csrf")) return Promise.resolve(json(200, { token: "t" }))
      if (url.endsWith("/abuse/settings")) {
        if (method === "PUT") puts.push(JSON.parse(init?.body as string))
        return Promise.resolve(json(200, settings))
      }
      if (url.includes("/abuse/self-terms")) return Promise.resolve(json(200, []))
      return Promise.resolve(json(404, { detail: "nope" }))
    }),
  )
  return puts
}

function renderCard() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/settings?tab=reporting"]}>
          <TooltipProvider>
            <AuthProvider>
              <ReportingCard />
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

describe("ReportingCard", () => {
  it("marks the wording fields optional and saves them empty", async () => {
    const puts = stub(BARE)
    renderCard()
    await screen.findByRole("textbox", { name: /Reply contact/ })
    // Signature, Introduction, Closing, X-ARF user agent, Note and Subject template.
    expect(screen.getAllByText("Optional")).toHaveLength(6)
    expect(screen.getAllByText(/Leave empty to send only the facts/).length).toBeGreaterThan(0)
    expect(screen.queryByText(/Required: write this/)).toBeNull()
    expect(screen.queryByText(/start empty on purpose/)).toBeNull()
    await userEvent.click(screen.getByRole("button", { name: /^save/i }))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0]).toMatchObject({
      reply_contact: "reports@example.net",
      intro: null,
      outro: null,
      note: null,
      signature: null,
      subject_template: null,
      xarf_user_agent: null,
    })
  })
})
