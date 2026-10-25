import { describe, expect, it } from "vitest"
import type { LiveStats } from "@/lib/api"
import {
  addressFinding,
  countryFinding,
  liveFinding,
  liveHeadline,
  networkFinding,
} from "./live-stats"

const STATS: LiveStats = {
  window_seconds: 60,
  events_last_minute: 45,
  sessions_last_minute: 9,
  by_sensor: { ssh: { events: 42, sessions: 7 }, web: { events: 3, sessions: 2 } },
}

const leader = {
  key: "203.0.113.77",
  events: 34,
  share: 0.12,
  country: "FR",
  org: "Hexagone Serveurs",
  asn: 64505,
}

describe("Live sentences", () => {
  it("names the busiest sensor, then where the last 15 minutes came from", () => {
    expect(liveFinding(null)).toBe("Waiting for the first events from the sensors.")
    expect(liveHeadline(STATS, undefined, 0)).toBe(liveFinding(STATS))
    expect(liveHeadline(STATS, { country: "FR", events: 38, ips: 9 }, 100)).toBe(
      "SSH is the busiest sensor right now: 42 events in the last minute. France sent 38% of the last 15 minutes.",
    )
  })

  it("describes the busiest address, masked in screenshot mode", () => {
    expect(addressFinding(leader, false)).toBe(
      "203.0.113.77 (France) is the busiest address: 34 events, 12% of the total.",
    )
    expect(addressFinding(leader, true)).toMatch(/^203\.0\.x\.x \(France\)/)
    expect(addressFinding({ ...leader, country: null }, false)).toMatch(/^203\.0\.113\.77 is/)
    expect(addressFinding(undefined, false)).toBe("No attacker in the last 15 minutes.")
  })

  it("describes the leading country and network", () => {
    expect(countryFinding({ country: "DE", events: 1, ips: 1 }, 4)).toBe(
      "Germany leads with 25% of events, from 1 address.",
    )
    expect(countryFinding(undefined, 0)).toBe("No located attacker in the last 15 minutes.")
    expect(networkFinding({ ...leader, key: "64505" })).toBe(
      "Hexagone Serveurs (AS64505) sends the most: 12% of events.",
    )
    expect(networkFinding({ ...leader, key: "64505", org: null })).toBe(
      "AS64505 sends the most: 12% of events.",
    )
  })
})
