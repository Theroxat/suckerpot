import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { stubResizeObserver } from "@/test/dom-stubs"
import type { NetworkMember, NetworkStatus } from "@/lib/network"
import { JoinDialog } from "./join-dialog"
import { LeaveDialog } from "./leave-dialog"
import { MemberRow } from "./members-list"
import { NetworkStep } from "../setup/network-step"

const auth = vi.hoisted(() => ({ value: { canWrite: true } }))
vi.mock("@/app/auth", () => ({ useAuth: () => auth.value }))

const OFF: NetworkStatus = {
  enabled_env: true,
  hub_configured: true,
  desired: "off",
  state: "off",
  pseudonym: null,
  country: null,
  show_country: false,
  fingerprint: null,
  enrolled_day: null,
  eligible_from_day: null,
  standing: null,
  last_submit_day: null,
  next_submit_at: null,
  last_error_code: null,
  waiting: null,
}

interface Call {
  url: string
  method: string
  body: Record<string, unknown> | null
}

function stubFetch(
  status: NetworkStatus = OFF,
  mutate: () => Response = () => new Response(null, { status: 204 }),
) {
  const calls: Call[] = []
  const fetchMock = vi.fn((url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET"
    if (url.endsWith("/auth/csrf"))
      return Promise.resolve(new Response(JSON.stringify({ token: "t" }), { status: 200 }))
    calls.push({
      url,
      method,
      body:
        typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : null,
    })
    if (method !== "GET") return Promise.resolve(mutate())
    if (url.includes("/network/status"))
      return Promise.resolve(new Response(JSON.stringify(status), { status: 200 }))
    return Promise.resolve(new Response(JSON.stringify({ items: [] }), { status: 200 }))
  })
  vi.stubGlobal("fetch", fetchMock)
  return calls
}

function wrap(node: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>{node}</QueryClientProvider>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  stubResizeObserver()
  auth.value = { canWrite: true }
})
afterEach(() => vi.unstubAllGlobals())

// Several checkbox clicks through a dialog: slow on a busy machine, so give the tests room.
vi.setConfig({ testTimeout: 30_000 })

describe("JoinDialog", () => {
  it("shows what is shared, has no tick boxes and needs the password", async () => {
    const calls = stubFetch()
    const user = userEvent.setup()
    wrap(<JoinDialog open onOpenChange={() => undefined} />)
    expect(screen.queryAllByRole("checkbox")).toHaveLength(0)
    const list = screen.getByRole("region", { name: "What you share" })
    expect(within(list).getAllByRole("listitem")).toHaveLength(5)
    expect(screen.getByRole("button", { name: /Optional: pseudonym and country/ })).toHaveAttribute(
      "aria-expanded",
      "false",
    )
    await user.click(screen.getByRole("button", { name: "Join the network" }))
    expect(await screen.findByText("Enter your password to confirm.")).toBeInTheDocument()
    expect(calls.filter((c) => c.method !== "GET")).toHaveLength(0)
  })

  it("refuses a bad pseudonym before asking the server, and opens the optional part", async () => {
    const calls = stubFetch()
    const user = userEvent.setup()
    wrap(<JoinDialog open onOpenChange={() => undefined} />)
    await user.click(screen.getByRole("button", { name: /Optional: pseudonym and country/ }))
    await user.type(screen.getByLabelText(/Pseudonym/), "owl@example.org")
    await user.type(screen.getByLabelText("Your password"), "secret-value")
    await user.click(screen.getByRole("button", { name: "Join the network" }))
    expect(await screen.findByText(/cannot contain a link or an @/)).toBeInTheDocument()
    expect(calls.filter((c) => c.method !== "GET")).toHaveLength(0)
  })

  it("joins with all five consents and the password, nothing else needed", async () => {
    const calls = stubFetch()
    const user = userEvent.setup()
    const done = vi.fn()
    wrap(<JoinDialog open onOpenChange={() => undefined} onJoined={done} />)
    await user.type(screen.getByLabelText("Your password"), "secret-value")
    await user.click(screen.getByRole("button", { name: "Join the network" }))
    await waitFor(() => expect(done).toHaveBeenCalled())
    const put = calls.find((c) => c.method === "PUT")
    expect(put?.url).toBe("/api/v1/network/membership")
    expect(put?.body).toMatchObject({
      join: true,
      show_country: false,
      accept: ["sources", "payloads", "c2", "files", "rechecks"],
      password: "secret-value",
    })
    expect(put?.body).not.toHaveProperty("country")
  })

  it("sends the optional pseudonym when given", async () => {
    const calls = stubFetch()
    const user = userEvent.setup()
    const done = vi.fn()
    wrap(<JoinDialog open onOpenChange={() => undefined} onJoined={done} />)
    await user.click(screen.getByRole("button", { name: /Optional: pseudonym and country/ }))
    await user.type(screen.getByLabelText(/Pseudonym/), "gray-heron")
    await user.type(screen.getByLabelText("Your password"), "secret-value")
    await user.click(screen.getByRole("button", { name: "Join the network" }))
    await waitFor(() => expect(done).toHaveBeenCalled())
    expect(calls.find((c) => c.method === "PUT")?.body).toMatchObject({ pseudonym: "gray-heron" })
  })

  it("shows a wrong password on the password field", async () => {
    stubFetch(
      OFF,
      () =>
        new Response(JSON.stringify({ detail: "wrong", code: "reauth_failed" }), { status: 403 }),
    )
    const user = userEvent.setup()
    wrap(<JoinDialog open onOpenChange={() => undefined} />)
    await user.type(screen.getByLabelText("Your password"), "nope")
    await user.click(screen.getByRole("button", { name: "Join the network" }))
    expect(await screen.findByText("That password is not correct.")).toBeInTheDocument()
  })
})

describe("LeaveDialog", () => {
  it("says what is deleted and where, then needs the password", async () => {
    const calls = stubFetch()
    const user = userEvent.setup()
    wrap(<LeaveDialog open onOpenChange={() => undefined} />)
    const here = screen.getByRole("list", { name: "Deleted on this system" })
    expect(within(here).getByText("The node key")).toBeInTheDocument()
    const hub = screen.getByRole("list", { name: "Deleted at the hub" })
    expect(within(hub).getByText("What it sent")).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Leave the network" }))
    expect(await screen.findByText("Enter your password to confirm.")).toBeInTheDocument()
    await user.type(screen.getByLabelText("Your password"), "secret-value")
    await user.click(screen.getByRole("button", { name: "Leave the network" }))
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true))
    expect(calls.find((c) => c.method === "DELETE")?.body).toEqual({ password: "secret-value" })
  })
})

describe("NetworkStep", () => {
  it("makes 'Not now' as easy as joining and sends nothing", async () => {
    const calls = stubFetch()
    const user = userEvent.setup()
    const skip = vi.fn()
    wrap(<NetworkStep onSkip={skip} />)
    expect(await screen.findByText(/You can skip this/)).toBeInTheDocument()
    expect(screen.getByRole("region", { name: "What you share" })).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Not now" }))
    expect(skip).toHaveBeenCalled()
    expect(calls.filter((c) => c.method !== "GET")).toHaveLength(0)
  })

  it("hides itself when sharing is off and no hub is set", async () => {
    stubFetch({ ...OFF, enabled_env: false, hub_configured: false })
    const { container } = wrap(<NetworkStep />)
    await waitFor(() => expect(container).toBeEmptyDOMElement())
  })

  it("says who you are in the network when already a member", async () => {
    stubFetch({ ...OFF, desired: "member", state: "member", pseudonym: "gray-heron" })
    wrap(<NetworkStep />)
    expect(await screen.findByText(/as gray-heron/)).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Settings, Network" })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Join the network" })).toBeNull()
  })
})

describe("MemberRow", () => {
  const named: NetworkMember = {
    fingerprint: "3f9a1c07",
    pseudonym: "night-owl",
    country: "CH",
    member_since: "2026-09",
    active_days: 6,
    tier: 3,
  }
  const anonymous: NetworkMember = {
    fingerprint: "a1b2c3d4",
    pseudonym: null,
    country: null,
    member_since: "2026-10",
    active_days: 0,
    tier: 0,
  }

  it("shows the pseudonym, a text label for the tier and the active days in words", () => {
    render(<MemberRow m={named} />)
    expect(screen.getByText("night-owl")).toBeInTheDocument()
    expect(screen.getAllByText("1,000 to 9,999 items").length).toBeGreaterThan(0)
    expect(
      screen.getAllByRole("img", { name: "Active 6 of 7 days last week" }).length,
    ).toBeGreaterThan(0)
    expect(screen.getAllByRole("meter", { name: "Items sent last week" })[0]).toHaveAttribute(
      "aria-valuetext",
      "1,000 to 9,999 items",
    )
  })

  it("shows the node number and no country for a member who shares none", () => {
    render(<MemberRow m={anonymous} />)
    expect(screen.getByText("Node a1b2c3d4")).toBeInTheDocument()
    expect(screen.getByText("Country not shown")).toBeInTheDocument()
  })
})
