import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import {
  BACKOFF_MAX_MS,
  HIDDEN_SLEEP_MS,
  LiveClient,
  PING_INTERVAL_MS,
  POLL_INTERVAL_MS,
  backoffDelay,
} from "./live-client"
import { MAX_BUFFER } from "./live-messages"
import { liveEvent } from "./live-messages.test"

class FakeSocket {
  static all: FakeSocket[] = []
  readyState = 0
  sent: string[] = []
  closedWith: number | null = null
  onopen: (() => void) | null = null
  onmessage: ((ev: { data: unknown }) => void) | null = null
  onclose: ((ev: { code: number }) => void) | null = null
  onerror: (() => void) | null = null
  constructor(readonly url: string) {
    FakeSocket.all.push(this)
  }
  send(data: string) {
    this.sent.push(data)
  }
  close(code = 1000) {
    this.closedWith = code
  }
  // Test helpers
  open() {
    this.readyState = 1
    this.onopen?.()
  }
  push(v: unknown) {
    this.onmessage?.({ data: JSON.stringify(v) })
  }
  drop(code = 1006) {
    this.readyState = 3
    this.onclose?.({ code })
  }
}

const last = (): FakeSocket => {
  const s = FakeSocket.all.at(-1)
  if (!s) throw new Error("no socket yet")
  return s
}

const clients: LiveClient[] = []

function make(fetchRecent = vi.fn().mockResolvedValue([])) {
  const client = new LiveClient({
    url: "ws://test/api/v1/live",
    createSocket: (url) => new FakeSocket(url) as unknown as WebSocket,
    fetchRecent,
    random: () => 1, // no jitter reduction: delay equals the ceiling
  })
  clients.push(client)
  client.start()
  return { client, fetchRecent }
}

function setVisibility(state: "hidden" | "visible") {
  Object.defineProperty(document, "visibilityState", { value: state, configurable: true })
  document.dispatchEvent(new Event("visibilitychange"))
}

beforeEach(() => {
  vi.useFakeTimers()
  FakeSocket.all = []
  setVisibility("visible")
})
afterEach(() => {
  clients.splice(0).forEach((c) => c.stop())
  vi.useRealTimers()
})

describe("backoffDelay", () => {
  it("doubles, is capped at 30 s and applies 50-100 % jitter", () => {
    expect(backoffDelay(1, () => 1)).toBe(1_000)
    expect(backoffDelay(2, () => 1)).toBe(2_000)
    expect(backoffDelay(5, () => 1)).toBe(16_000)
    expect(backoffDelay(6, () => 1)).toBe(BACKOFF_MAX_MS)
    expect(backoffDelay(20, () => 1)).toBe(BACKOFF_MAX_MS)
    expect(backoffDelay(3, () => 0)).toBe(2_000)
  })
})

describe("LiveClient", () => {
  it("goes connecting -> live and merges backfill, events and stats", () => {
    const { client } = make()
    expect(client.getSnapshot().status).toBe("connecting")
    last().open()
    expect(client.getSnapshot().status).toBe("live")
    last().push({ kind: "backfill", events: [liveEvent(2), liveEvent(1)] })
    last().push({ kind: "event", event: liveEvent(3) })
    last().push({ kind: "event", event: liveEvent(3) }) // duplicate
    last().push({
      kind: "stats",
      stats: { window_seconds: 60, events_last_minute: 3, sessions_last_minute: 3, by_sensor: {} },
    })
    const s = client.getSnapshot()
    expect(s.events.map((e) => e.id)).toEqual([3, 2, 1])
    expect(s.stats?.events_last_minute).toBe(3)
  })

  it("survives garbage frames and unknown kinds", () => {
    const { client } = make()
    last().open()
    last().onmessage?.({ data: "{broken" })
    last().push({ kind: "from-the-future" })
    last().push({ kind: "event", event: liveEvent(1) })
    expect(client.getSnapshot().events).toHaveLength(1)
    expect(client.getSnapshot().status).toBe("live")
  })

  it("bounds the buffer to 500 events", () => {
    const { client } = make()
    last().open()
    last().push({
      kind: "backfill",
      events: Array.from({ length: 50 }, (_, i) => liveEvent(1000 - i)),
    })
    for (let i = 0; i < MAX_BUFFER + 20; i++) {
      last().push({ kind: "event", event: liveEvent(2000 + i) })
    }
    expect(client.getSnapshot().events).toHaveLength(MAX_BUFFER)
    expect(client.getSnapshot().events[0]?.id).toBe(2000 + MAX_BUFFER + 19)
  })

  it("reconnects with growing delays and keeps events across the gap", () => {
    const { client } = make()
    last().open()
    last().push({ kind: "event", event: liveEvent(1) })
    last().drop(1006)
    expect(client.getSnapshot().status).toBe("reconnecting")
    expect(FakeSocket.all).toHaveLength(1)
    vi.advanceTimersByTime(999)
    expect(FakeSocket.all).toHaveLength(1)
    vi.advanceTimersByTime(1)
    expect(FakeSocket.all).toHaveLength(2)

    last().drop(1006) // second failure: 2 s
    vi.advanceTimersByTime(1_999)
    expect(FakeSocket.all).toHaveLength(2)
    vi.advanceTimersByTime(1)
    expect(FakeSocket.all).toHaveLength(3)

    last().open()
    last().push({ kind: "backfill", events: [liveEvent(2), liveEvent(1)] })
    expect(client.getSnapshot().status).toBe("live")
    expect(client.getSnapshot().events.map((e) => e.id)).toEqual([2, 1])

    // A frame resets the backoff.
    last().drop(1006)
    vi.advanceTimersByTime(1_000)
    expect(FakeSocket.all).toHaveLength(4)
  })

  it("pings every 25 s while open", () => {
    make()
    last().open()
    vi.advanceTimersByTime(PING_INTERVAL_MS * 2)
    expect(last().sent).toEqual(["ping", "ping"])
  })

  it("polls /events/recent when the server is full (1013) and retries the socket later", async () => {
    const fetchRecent = vi.fn().mockResolvedValue([liveEvent(7)])
    const { client } = make(fetchRecent)
    last().drop(1013)
    await vi.advanceTimersByTimeAsync(0)
    expect(fetchRecent).toHaveBeenCalledTimes(1)
    expect(client.getSnapshot()).toMatchObject({ status: "live", transport: "polling" })
    expect(client.getSnapshot().events.map((e) => e.id)).toEqual([7])

    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS)
    expect(fetchRecent).toHaveBeenCalledTimes(2)
    expect(client.getSnapshot().events).toHaveLength(1) // de-duplicated

    await vi.advanceTimersByTimeAsync(60_000)
    expect(FakeSocket.all).toHaveLength(2) // socket retried
    last().open()
    expect(client.getSnapshot().transport).toBe("websocket")
    const calls = fetchRecent.mock.calls.length
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS * 3)
    expect(fetchRecent).toHaveBeenCalledTimes(calls) // polling stopped
  })

  it("polls on 1008 and reports offline when polling fails too", async () => {
    const fetchRecent = vi.fn().mockRejectedValue(new Error("down"))
    const { client } = make(fetchRecent)
    last().drop(1008)
    await vi.advanceTimersByTimeAsync(0)
    expect(client.getSnapshot().status).toBe("offline")
    fetchRecent.mockResolvedValue([liveEvent(1)])
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS)
    expect(client.getSnapshot().status).toBe("live")
  })

  it("starts polling after three failures in a row", async () => {
    const { fetchRecent } = make()
    last().drop(1006)
    vi.advanceTimersByTime(1_000)
    last().drop(1006)
    vi.advanceTimersByTime(2_000)
    expect(fetchRecent).not.toHaveBeenCalled()
    last().drop(1006)
    await vi.advanceTimersByTimeAsync(0)
    expect(fetchRecent).toHaveBeenCalledTimes(1)
  })

  it("sleeps after five minutes hidden and resumes when visible again", () => {
    const { client } = make()
    last().open()
    last().push({ kind: "event", event: liveEvent(1) })
    setVisibility("hidden")
    vi.advanceTimersByTime(HIDDEN_SLEEP_MS - 1)
    expect(last().closedWith).toBeNull()
    vi.advanceTimersByTime(1)
    expect(last().closedWith).toBe(1000)
    expect(client.getSnapshot().status).toBe("offline")
    expect(FakeSocket.all).toHaveLength(1)

    setVisibility("visible")
    expect(FakeSocket.all).toHaveLength(2)
    expect(client.getSnapshot().events).toHaveLength(1)
  })

  it("stays connected for short tab switches", () => {
    make()
    last().open()
    setVisibility("hidden")
    vi.advanceTimersByTime(60_000)
    setVisibility("visible")
    vi.advanceTimersByTime(HIDDEN_SLEEP_MS)
    expect(last().closedWith).toBeNull()
    expect(FakeSocket.all).toHaveLength(1)
  })

  it("stop() closes the socket and cancels timers", () => {
    const { client } = make()
    last().open()
    client.stop()
    expect(last().closedWith).toBe(1000)
    vi.advanceTimersByTime(PING_INTERVAL_MS * 3)
    expect(last().sent).toEqual([])
  })
})
