/**
 * The live feed connection, free of React so it can be tested with fake timers.
 *
 * One WebSocket per tab. It reconnects with exponential backoff and jitter
 * (max 30 s), pings every 25 s, sleeps after the tab has been hidden for five
 * minutes, and falls back to polling `/events/recent` every 10 s when the
 * socket is refused (1013 server full, 1008 origin rejected) or keeps failing.
 */
import { API_BASE, api, getIncludeBenign, type LiveEvent, type LiveStats } from "@/lib/api"
import { mergeEvents, parseLiveMessage } from "@/lib/live-messages"

export type LiveFeedStatus = "connecting" | "live" | "reconnecting" | "offline"
export type LiveTransport = "websocket" | "polling"

export interface LiveFeedState {
  status: LiveFeedStatus
  transport: LiveTransport
  /** Newest first, de-duplicated, at most MAX_BUFFER. */
  events: readonly LiveEvent[]
  /** Server statistics for the last minute. Null until the first frame. */
  stats: LiveStats | null
  /** Messages the server skipped for this client because it was too slow. */
  dropped: number
}

export const PING_INTERVAL_MS = 25_000
export const POLL_INTERVAL_MS = 10_000
export const HIDDEN_SLEEP_MS = 5 * 60_000
export const BACKOFF_BASE_MS = 1_000
export const BACKOFF_MAX_MS = 30_000
/** After this many failed attempts in a row, start polling while retrying. */
export const POLL_AFTER_FAILURES = 3
const RETRY_AFTER_FULL_MS = 60_000
const RETRY_AFTER_ORIGIN_MS = 5 * 60_000
const WS_OPEN = 1

/** Delay before reconnect attempt `attempt` (1-based): 1 s, 2 s, 4 s … capped, with 50-100 % jitter. */
export function backoffDelay(attempt: number, random: () => number = Math.random): number {
  const ceiling = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** Math.max(0, attempt - 1))
  return Math.round(ceiling * (0.5 + 0.5 * random()))
}

export interface LiveClientOptions {
  url?: string
  createSocket?: (url: string) => WebSocket
  fetchRecent?: () => Promise<LiveEvent[]>
  random?: () => number
}

function defaultUrl(): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:"
  // Research scanners are left out of the feed unless the sidebar switch shows them.
  const scanners = getIncludeBenign() ? "?include_benign=1" : ""
  return `${proto}//${window.location.host}${API_BASE}/live${scanners}`
}

const INITIAL: LiveFeedState = {
  status: "connecting",
  transport: "websocket",
  events: [],
  stats: null,
  dropped: 0,
}

export class LiveClient {
  private state: LiveFeedState = INITIAL
  private readonly listeners = new Set<() => void>()
  private readonly createSocket: (url: string) => WebSocket
  private readonly fetchRecent: () => Promise<LiveEvent[]>
  private readonly random: () => number
  private readonly url: string | undefined

  private socket: WebSocket | null = null
  private started = false
  private suspended = false
  private attempts = 0
  private everOpened = false
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private pingTimer: ReturnType<typeof setInterval> | null = null
  private pollTimer: ReturnType<typeof setTimeout> | null = null
  private polling = false
  private hiddenTimer: ReturnType<typeof setTimeout> | null = null

  constructor(options: LiveClientOptions = {}) {
    this.url = options.url
    this.createSocket = options.createSocket ?? ((url) => new WebSocket(url))
    this.fetchRecent = options.fetchRecent ?? (async () => (await api.recentEvents(50)).items)
    this.random = options.random ?? Math.random
  }

  subscribe = (listener: () => void) => {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  getSnapshot = () => this.state

  start() {
    if (this.started) return
    this.started = true
    document.addEventListener("visibilitychange", this.onVisibility)
    window.addEventListener("online", this.onOnline)
    if (document.visibilityState === "hidden") this.armHiddenTimer()
    this.open()
  }

  stop() {
    if (!this.started) return
    this.started = false
    document.removeEventListener("visibilitychange", this.onVisibility)
    window.removeEventListener("online", this.onOnline)
    this.sleep()
    this.clearHiddenTimer()
    this.suspended = false
    this.attempts = 0
    this.everOpened = false
    this.state = { ...INITIAL, events: this.state.events, stats: this.state.stats }
  }

  /** Reconnect from scratch (the feed's filter changed): drops the buffered events. */
  restart() {
    if (!this.started) return
    this.stop()
    this.state = { ...INITIAL }
    this.listeners.forEach((l) => l())
    this.start()
  }

  private update(patch: Partial<LiveFeedState>) {
    const next = { ...this.state, ...patch }
    if ((Object.keys(patch) as (keyof LiveFeedState)[]).every((k) => next[k] === this.state[k])) {
      return
    }
    this.state = next
    this.listeners.forEach((l) => l())
  }

  // --- WebSocket -----------------------------------------------------------

  private open() {
    if (!this.started || this.suspended || this.socket) return
    this.clearReconnectTimer()
    if (this.state.status !== "live") {
      this.update({ status: this.everOpened || this.attempts > 0 ? "reconnecting" : "connecting" })
    }
    let ws: WebSocket
    try {
      ws = this.createSocket(this.url ?? defaultUrl())
    } catch {
      this.onClosed(1006)
      return
    }
    this.socket = ws
    ws.onopen = () => {
      if (this.socket !== ws) return
      this.everOpened = true
      this.stopPolling()
      this.update({ status: "live", transport: "websocket" })
      this.pingTimer = setInterval(() => {
        if (ws.readyState === WS_OPEN) ws.send("ping")
      }, PING_INTERVAL_MS)
    }
    ws.onmessage = (ev: MessageEvent) => {
      if (this.socket !== ws) return
      // A frame proves the link works: only now forget earlier failures.
      this.attempts = 0
      const msg = parseLiveMessage(ev.data)
      if (!msg) return
      switch (msg.kind) {
        case "backfill":
          this.update({ events: mergeEvents(this.state.events, msg.events) })
          break
        case "event":
          this.update({ events: mergeEvents(this.state.events, [msg.event]) })
          break
        case "stats":
          this.update({ stats: msg.stats })
          break
        case "dropped":
          this.update({ dropped: this.state.dropped + msg.count })
          break
        case "pong":
          break
      }
    }
    ws.onerror = () => {
      // A close event always follows; it does the work.
    }
    ws.onclose = (ev: CloseEvent) => {
      if (this.socket !== ws) return
      this.onClosed(ev.code)
    }
  }

  private onClosed(code: number) {
    this.socket = null
    this.clearPing()
    if (!this.started || this.suspended) return
    this.attempts += 1

    let delay: number
    if (code === 1013) {
      this.startPolling()
      delay = RETRY_AFTER_FULL_MS
    } else if (code === 1008) {
      this.startPolling()
      delay = RETRY_AFTER_ORIGIN_MS
    } else {
      delay = backoffDelay(this.attempts, this.random)
      if (this.attempts >= POLL_AFTER_FAILURES) this.startPolling()
    }
    if (!this.isPolling()) {
      this.update({ status: !navigator.onLine ? "offline" : "reconnecting" })
    }
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.open()
    }, delay)
  }

  // --- Polling fallback ----------------------------------------------------

  private isPolling(): boolean {
    return this.polling
  }

  private startPolling() {
    if (this.isPolling()) return
    this.polling = true
    void this.poll()
  }

  private async poll() {
    if (!this.isPolling()) return
    try {
      const items = await this.fetchRecent()
      if (!this.isPolling()) return
      this.update({
        events: mergeEvents(this.state.events, items),
        status: "live",
        transport: "polling",
      })
    } catch {
      if (!this.isPolling()) return
      this.update({ status: "offline", transport: "polling" })
    }
    if (!this.isPolling()) return
    this.pollTimer = setTimeout(() => void this.poll(), POLL_INTERVAL_MS)
  }

  private stopPolling() {
    this.polling = false
    if (this.pollTimer) clearTimeout(this.pollTimer)
    this.pollTimer = null
  }

  // --- Lifecycle -----------------------------------------------------------

  /** Close everything but keep the buffered events. */
  private sleep() {
    this.clearReconnectTimer()
    this.clearPing()
    this.stopPolling()
    const ws = this.socket
    this.socket = null
    if (ws) {
      try {
        ws.close(1000)
      } catch {
        // Already closed.
      }
    }
  }

  private clearReconnectTimer() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
    this.reconnectTimer = null
  }

  private clearPing() {
    if (this.pingTimer) clearInterval(this.pingTimer)
    this.pingTimer = null
  }

  private armHiddenTimer() {
    this.clearHiddenTimer()
    this.hiddenTimer = setTimeout(() => {
      this.hiddenTimer = null
      this.suspended = true
      this.sleep()
      this.update({ status: "offline" })
    }, HIDDEN_SLEEP_MS)
  }

  private clearHiddenTimer() {
    if (this.hiddenTimer) clearTimeout(this.hiddenTimer)
    this.hiddenTimer = null
  }

  private onVisibility = () => {
    if (!this.started) return
    if (document.visibilityState === "hidden") {
      this.armHiddenTimer()
      return
    }
    this.clearHiddenTimer()
    if (this.suspended) {
      this.suspended = false
      this.attempts = 0
      this.open()
    }
  }

  private onOnline = () => {
    if (!this.started || this.suspended || this.socket) return
    this.attempts = 0
    this.open()
  }
}
