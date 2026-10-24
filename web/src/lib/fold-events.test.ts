import type { SensorEvent } from "./api"
import { foldEvents } from "./fold-events"

let id = 0
const ev = (type: string): SensorEvent => ({
  id: ++id,
  ts: "2026-10-24T18:00:00Z",
  sensor: "ssh",
  session_id: "s",
  type,
  src_ip: "192.0.2.1",
  src_port: 1,
  dst_port: 22,
  data: {},
  country: null,
  city: null,
  asn: null,
  org: null,
  abuse_score: null,
  known_scanner: null,
  tags: [],
})

describe("foldEvents", () => {
  it("keeps short runs as is", () => {
    const items = foldEvents([ev("connect"), ev("login_attempt"), ev("disconnect")])
    expect(items.every((i) => i.kind === "event")).toBe(true)
  })

  it("folds long runs, keeping the first three and the last", () => {
    const logins = Array.from({ length: 10 }, () => ev("login_attempt"))
    const items = foldEvents([ev("connect"), ...logins, ev("command")])
    expect(items.map((i) => i.kind)).toEqual([
      "event",
      "event",
      "event",
      "event",
      "fold",
      "event",
      "event",
    ])
    const fold = items[4]
    expect(fold?.kind === "fold" && fold.events.length).toBe(6)
  })

  it("never folds commands", () => {
    const commands = Array.from({ length: 12 }, () => ev("command"))
    expect(foldEvents(commands).every((i) => i.kind === "event")).toBe(true)
  })
})
