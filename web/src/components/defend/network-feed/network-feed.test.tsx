import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { buildStatus, type FeedScenario } from "@/mocks/network-feed"
import { stubResizeObserver } from "@/test/dom-stubs"
import { HowToDrawer } from "./how-to-drawer"
import { NetworkFeedTab } from "./network-feed-tab"

const auth = vi.hoisted(() => ({ value: { canWrite: true } }))
vi.mock("@/app/auth", () => ({ useAuth: () => auth.value }))

function stubFetch(scenario: FeedScenario) {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      const body = url.includes("/network/feed/status")
        ? buildStatus(scenario)
        : { items: [], next_cursor: null }
      return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }))
    }),
  )
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
vi.setConfig({ testTimeout: 30_000 })

describe("NetworkFeedTab", () => {
  it("explains the lists and shows the address to copy while the feed is off", async () => {
    stubFetch("off")
    wrap(<NetworkFeedTab />)
    expect(await screen.findByText("The community lists are not fetched here")).toBeInTheDocument()
    expect(screen.getByText(/Using them is optional/)).toBeInTheDocument()
    expect(screen.getByText("https://feeds.example.org/v1/outbound.txt")).toBeInTheDocument()
    expect(screen.getByText("just set NETWORK_FEED_ENABLED=true")).toBeInTheDocument()
  })

  it("says the lists are empty until enough members exist", async () => {
    stubFetch("empty")
    wrap(<NetworkFeedTab />)
    expect(await screen.findByText("Nothing to block yet")).toBeInTheDocument()
    expect(screen.getAllByText(/at least 5 independent sensors/).length).toBeGreaterThan(0)
    expect(screen.queryByRole("heading", { name: "Entries" })).not.toBeInTheDocument()
  })

  it("leads with the finding, one card per list, outbound first to start", async () => {
    stubFetch("ok")
    wrap(<NetworkFeedTab />)
    expect(await screen.findByText(/^The Selfhostr network lists/)).toBeInTheDocument()
    expect(screen.getByRole("group", { name: "Outbound list" })).toBeInTheDocument()
    expect(screen.getByRole("group", { name: "Inbound list" })).toBeInTheDocument()
    expect(screen.getByRole("group", { name: "Outbound domains list" })).toBeInTheDocument()
    expect(screen.getByText("Start here")).toBeInTheDocument()
    expect(screen.getByText("Blocks traffic leaving your network")).toBeInTheDocument()
    expect(screen.getByText("Signature verified")).toBeInTheDocument()
  })

  it("flags an out-of-date feed with words", async () => {
    stubFetch("stale")
    wrap(<NetworkFeedTab />)
    expect(await screen.findByText("Out of date")).toBeInTheDocument()
  })

  it("offers the file formats in the copy menu", async () => {
    stubFetch("ok")
    const user = userEvent.setup()
    wrap(<NetworkFeedTab />)
    const card = await screen.findByRole("group", { name: "Outbound list" })
    await user.click(within(card).getByRole("button", { name: "Copy a outbound list URL" }))
    expect(await screen.findAllByRole("menuitem", { name: "nftables" })).toHaveLength(2)
    expect(screen.getAllByRole("menuitem", { name: "STIX 2.1" })).toHaveLength(2)
  })
})

describe("HowToDrawer", () => {
  it("shows the address and the format to pick for each firewall", async () => {
    const user = userEvent.setup()
    render(<HowToDrawer open onOpenChange={() => undefined} status={buildStatus("ok")} />)
    expect(screen.getByText(/Pick the plain text format \(\.txt\)/)).toBeInTheDocument()
    expect(
      screen.getByText(/Content: https:\/\/feeds\.example\.org\/v1\/outbound\.txt/),
    ).toBeInTheDocument()
    await user.click(screen.getByRole("radio", { name: "nftables" }))
    expect(screen.getByText(/Pick the nftables format/)).toBeInTheDocument()
    expect(screen.getAllByText(/outbound\.nft/).length).toBeGreaterThan(0)
  })
})
