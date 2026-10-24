import { act, render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { LiveFeedProvider } from "@/app/live-feed"
import { TooltipProvider } from "@/components/ui/tooltip"
import { liveEvent } from "@/lib/live-messages.test"
import { LivePage } from "./live"

// The globe needs WebGL and a query client: its own tests cover it.
vi.mock("@/components/globe/live-globe", () => ({ LiveGlobe: () => null }))

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

beforeEach(() => {
  // jsdom has no layout: give the virtual list a viewport.
  vi.spyOn(HTMLElement.prototype, "offsetHeight", "get").mockReturnValue(600)
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockReturnValue({
    width: 800,
    height: 600,
    top: 0,
    left: 0,
    right: 800,
    bottom: 600,
    x: 0,
    y: 0,
    toJSON: () => ({}),
  })
})
afterEach(() => vi.restoreAllMocks())

describe("LivePage", () => {
  it("shows an empty state, then the finding sentence and events", async () => {
    mount()
    await act(() => Promise.resolve())
    expect(screen.getByText("Nothing has arrived yet")).toBeInTheDocument()

    act(() => {
      Socket.current?.push({
        kind: "stats",
        stats: {
          window_seconds: 60,
          events_last_minute: 45,
          sessions_last_minute: 9,
          by_sensor: { ssh: { events: 42, sessions: 7 }, web: { events: 3, sessions: 2 } },
        },
      })
      Socket.current?.push({ kind: "backfill", events: [liveEvent(2), liveEvent(1)] })
    })
    expect(
      screen.getByText("SSH is the busiest sensor right now: 42 events in the last minute."),
    ).toBeInTheDocument()
    expect(screen.getByRole("list", { name: "Live events" })).toBeInTheDocument()
  })

  it("holds new events behind a jump pill while paused", async () => {
    const user = userEvent.setup()
    mount()
    await act(() => Promise.resolve())
    act(() => {
      Socket.current?.push({ kind: "backfill", events: [liveEvent(1)] })
    })
    await user.click(screen.getByRole("button", { name: "Pause" }))
    act(() => {
      Socket.current?.push({ kind: "event", event: liveEvent(2) })
      Socket.current?.push({ kind: "event", event: liveEvent(3) })
    })
    expect(screen.getByRole("button", { name: /2 new events — jump to latest/ })).toBeVisible()
    await user.click(screen.getByRole("button", { name: /jump to latest/ }))
    expect(screen.queryByRole("button", { name: /jump to latest/ })).toBeNull()
    expect(screen.getByRole("button", { name: "Pause" })).toBeInTheDocument()
  })

  it("filters by the sensor in the URL", async () => {
    mount("/live?sensor=web")
    await act(() => Promise.resolve())
    act(() => {
      Socket.current?.push({ kind: "backfill", events: [liveEvent(1, { sensor: "ssh" })] })
    })
    expect(screen.getByText("No events from this sensor yet")).toBeInTheDocument()
  })
})
