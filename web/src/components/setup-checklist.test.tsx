import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, within } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { SetupChecklistCard } from "./setup-checklist"

const auth = vi.hoisted(() => ({ value: { canWrite: true } }))
vi.mock("@/app/auth", () => ({ useAuth: () => auth.value }))

const ITEMS = [
  { id: "sensors", state: "warning", detail: "2 sensors are silent: SIP, RDP.", href: "/settings" },
  { id: "vpn", state: "ok", detail: "The gate is open.", href: "/settings?tab=vpn" },
  { id: "alerts", state: "off", detail: "No channel yet.", href: "https://example.com/x" },
  {
    id: "self_address",
    state: "todo",
    detail: "Add your address.",
    href: "/settings?tab=reporting",
  },
]

function stub(answer: () => Response) {
  const fetchMock = vi.fn(() => Promise.resolve(answer()))
  vi.stubGlobal("fetch", fetchMock)
  return fetchMock
}

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <SetupChecklistCard />
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe("SetupChecklistCard", () => {
  beforeEach(() => {
    auth.value = { canWrite: true }
  })
  afterEach(() => vi.unstubAllGlobals())

  it("opens with a sentence, then one row per item with a word, a detail and a link", async () => {
    stub(() => new Response(JSON.stringify({ items: ITEMS }), { status: 200 }))
    mount()
    expect(
      await screen.findByText("1 of 4 steps is done, 1 needs attention, 1 is still to do."),
    ).toBeInTheDocument()
    const rows = within(screen.getByRole("list", { name: "Setup checklist" })).getAllByRole(
      "listitem",
    )
    expect(rows).toHaveLength(4)
    const row = (i: number): HTMLElement => {
      const r = rows[i]
      if (!r) throw new Error(`no row ${i}`)
      return r
    }
    // The state is a word, never colour alone.
    expect(within(row(0)).getByText("Needs attention")).toBeInTheDocument()
    expect(within(row(1)).getByText("Done")).toBeInTheDocument()
    expect(within(row(2)).getByText("To do")).toBeInTheDocument()
    expect(within(row(3)).getByText("Off")).toBeInTheDocument()
    expect(within(row(0)).getByText("2 sensors are silent: SIP, RDP.")).toBeInTheDocument()
    expect(within(row(1)).getByRole("link", { name: "Open Outbound gate" })).toHaveAttribute(
      "href",
      "/settings?tab=vpn",
    )
    // An absolute link from the server is not followed.
    expect(within(row(3)).queryByRole("link")).toBeNull()
    expect(
      screen.getByText(/The host firewall can't be seen from inside the stack/),
    ).toBeInTheDocument()
    expect(screen.getByText("just egress-check")).toBeInTheDocument()
  })

  it("accepts a bare list", async () => {
    stub(() => new Response(JSON.stringify(ITEMS.slice(0, 2)), { status: 200 }))
    mount()
    expect(await screen.findByText("1 of 2 steps is done, 1 needs attention.")).toBeInTheDocument()
  })

  it("says so when the status cannot be read", async () => {
    stub(() => new Response(JSON.stringify({ detail: "nope" }), { status: 500 }))
    mount()
    expect(
      await screen.findByText("The setup status is not available right now."),
    ).toBeInTheDocument()
  })

  it("is not shown to a viewer, and never asks", () => {
    auth.value = { canWrite: false }
    const f = stub(() => new Response("{}", { status: 200 }))
    const { container } = mount()
    expect(container).toBeEmptyDOMElement()
    expect(f).not.toHaveBeenCalled()
  })
})
