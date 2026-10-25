import { act, render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { LiveFeedProvider } from "@/app/live-feed"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { LiveEvent } from "@/lib/api"
import { liveEvent } from "@/lib/live-messages.test"
import { LivePage } from "./live"

// The map itself (SVG, ResizeObserver) has its own tests: a stub shows what the page hands it.
vi.mock("@/components/map/world-map", () => ({
  WorldMap: (p: { focus: string | null; activity: { sources: unknown[] } }) => (
    <div data-testid="map" data-focus={p.focus ?? ""} data-sources={p.activity.sources.length} />
  ),
}))
vi.mock("@/components/map/use-site", () => ({
  useSiteHome: () => ({ data: { lat: 46.8, lon: 8.2, label: "Switzerland" } }),
}))

class Socket {
  static current: Socket | null = null
  readyState = 1
  onopen: (() => void) | null = null
  onmessage: ((ev: { data: string }) => void) | null = null
  onclose: ((ev: { code: number }) => void) | null = null
  onerror: (() => void) | null = null
  constructor() {
    Socket.current = this
    queueMicrotask(() => this.onopen?.())
  }
  send() {
    return
  }
  close() {
    return
  }
  push(v: unknown) {
    this.onmessage?.({ data: JSON.stringify(v) })
  }
}

function mount(path = "/live") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <TooltipProvider>
        <LiveFeedProvider
          options={{
            createSocket: () => new Socket() as unknown as WebSocket,
            fetchRecent: () => Promise.resolve([]),
          }}
        >
          <LivePage />
        </LiveFeedProvider>
      </TooltipProvider>
    </MemoryRouter>,
  )
}

/** A recent event (inside the 15-minute window). */
function recent(id: number, over: Partial<LiveEvent> = {}): LiveEvent {
  return liveEvent(id, { ts: new Date(Date.now() - (100 - id) * 1_000).toISOString(), ...over })
}

const FR = { country: "FR", asn: 64505, org: "Hexagone Serveurs" }
const DE = { country: "DE", asn: 64499, org: "Rhein Compute GmbH" }

const STATS = {
  kind: "stats",
  stats: {
    window_seconds: 60,
    events_last_minute: 45,
    sessions_last_minute: 9,
    by_sensor: { ssh: { events: 42, sessions: 7 }, web: { events: 3, sessions: 2 } },
  },
}

afterEach(() => vi.restoreAllMocks())
beforeEach(() => {
  Socket.current = null
})

describe("LivePage", () => {
  it("shows a waiting note, then the headline, the ticker and the rankings", async () => {
    mount()
    await act(() => Promise.resolve())
    expect(screen.getByText(/Nothing has arrived yet/)).toBeInTheDocument()

    act(() => {
      Socket.current?.push(STATS)
      Socket.current?.push({
        kind: "backfill",
        events: [
          recent(4, { ...FR, src_ip: "203.0.113.77" }),
          recent(3, { ...FR, src_ip: "203.0.113.77" }),
          recent(2, { ...FR, src_ip: "198.51.100.41" }),
          recent(1, { ...DE, src_ip: "198.51.100.23" }),
        ],
      })
    })
    expect(
      screen.getByText(
        "SSH is the busiest sensor right now: 42 events in the last minute. France sent 75% of the last 15 minutes.",
      ),
    ).toBeInTheDocument()
    expect(
      within(screen.getByRole("list", { name: "Latest events" })).getAllByRole("link"),
    ).toHaveLength(4)

    const addresses = screen.getByRole("list", { name: "Top addresses" })
    expect(within(addresses).getAllByRole("link")[0]).toHaveAttribute(
      "href",
      "/attacks?src_ip=203.0.113.77",
    )
    expect(
      screen.getByText("203.0.113.77 (France) is the busiest address: 2 events, 50% of the total."),
    ).toBeInTheDocument()
    expect(
      screen.getByText("France leads with 75% of events, from 2 addresses."),
    ).toBeInTheDocument()
    expect(
      screen.getByText("Hexagone Serveurs (AS64505) sends the most: 75% of events."),
    ).toBeInTheDocument()
    expect(
      within(screen.getByRole("list", { name: "Top networks" })).getAllByRole("link")[0],
    ).toHaveAttribute("href", "/attacks?asn=64505")
    expect(screen.getByTestId("map")).toHaveAttribute("data-sources", "2")
  })

  it("lights a country on the map while its row is hovered", async () => {
    const user = userEvent.setup()
    mount()
    await act(() => Promise.resolve())
    act(() => {
      Socket.current?.push({
        kind: "backfill",
        events: [recent(2, { ...DE, src_ip: "198.51.100.23" }), recent(1, FR)],
      })
    })
    const countries = screen.getByRole("list", { name: "Top countries" })
    const [first] = within(countries).getAllByRole("link")
    if (!first) throw new Error("no country row")
    await user.hover(first)
    expect(screen.getByTestId("map")).toHaveAttribute("data-focus", "DE")
    await user.unhover(first)
    expect(screen.getByTestId("map")).toHaveAttribute("data-focus", "")
  })

  it("holds new events behind a resume pill while paused", async () => {
    const user = userEvent.setup()
    mount()
    await act(() => Promise.resolve())
    act(() => {
      Socket.current?.push({ kind: "backfill", events: [recent(1)] })
    })
    await user.click(screen.getByRole("button", { name: "Pause" }))
    act(() => {
      Socket.current?.push({ kind: "event", event: recent(2) })
      Socket.current?.push({ kind: "event", event: recent(3) })
    })
    expect(
      within(screen.getByRole("list", { name: "Latest events" })).getAllByRole("link"),
    ).toHaveLength(1)
    await user.click(screen.getByRole("button", { name: "2 new events" }))
    expect(screen.queryByRole("button", { name: "2 new events" })).toBeNull()
    expect(screen.getByRole("button", { name: "Pause" })).toBeInTheDocument()
    expect(
      within(screen.getByRole("list", { name: "Latest events" })).getAllByRole("link"),
    ).toHaveLength(3)
  })

  it("filters by the sensor in the URL", async () => {
    mount("/live?sensor=web")
    await act(() => Promise.resolve())
    act(() => {
      Socket.current?.push({ kind: "backfill", events: [recent(1, { sensor: "ssh" })] })
    })
    expect(screen.getByText("No events from this sensor yet.")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Show all sensors" })).toHaveAttribute("href", "/live")
  })

  it("shows events per minute per family, and a family toggle filters the page", async () => {
    const user = userEvent.setup()
    mount("/live?sensor=redis,mysql,mssql")
    await act(() => Promise.resolve())
    act(() => {
      Socket.current?.push({
        kind: "stats",
        stats: {
          window_seconds: 60,
          events_last_minute: 9,
          sessions_last_minute: 3,
          by_sensor: { redis: { events: 7, sessions: 2 }, smb: { events: 2, sessions: 1 } },
        },
      })
      Socket.current?.push({ kind: "backfill", events: [recent(1, { sensor: "ssh" })] })
    })
    expect(screen.getByText("No events from these sensors yet.")).toBeInTheDocument()
    expect(screen.getByText(/Nothing from the databases is in the live buffer/)).toBeInTheDocument()

    // Two strips are rendered (overlay on wide cards, grid on narrow ones); CSS shows one.
    const [strip] = screen.getAllByRole("region", { name: "Events in the last minute" })
    if (!strip) throw new Error("no strip")
    const databases = within(strip).getByRole("button", { name: /^Databases: 7 events/ })
    expect(databases).toHaveAttribute("aria-pressed", "true")
    await user.click(databases)
    expect(within(strip).getByRole("button", { name: /^Databases: 7 events/ })).toHaveAttribute(
      "aria-pressed",
      "false",
    )
    // Every sensor again: the ssh event is back in the ticker.
    expect(
      within(screen.getByRole("list", { name: "Latest events" })).getAllByRole("link"),
    ).toHaveLength(1)

    await user.click(within(strip).getByRole("button", { name: /^Windows & VoIP: 2 events/ }))
    expect(
      within(strip).getByRole("button", { name: /^Windows & VoIP: 2 events/ }),
    ).toHaveAttribute("aria-pressed", "true")
    expect(screen.getByText("No events from these sensors yet.")).toBeInTheDocument()
  })
})
