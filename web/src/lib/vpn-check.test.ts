import { describe, expect, it } from "vitest"
import { checkAnswered, type VpnStatus } from "./vpn"

const BASE: VpnStatus = {
  source: "env",
  uploaded_at: null,
  uploaded_by: null,
  endpoint_ip: null,
  endpoint_port: null,
  addresses: null,
  peer_key_fingerprint: null,
  gate: {
    state: "closed",
    reason: "ip_not_allowed",
    egress_ip: "198.51.100.20",
    egress_asn: null,
    egress_org: null,
    checked_at: "2026-11-01T10:00:00Z",
  },
  trusted_exits: [],
  trust_candidate: null,
  trust_blocked: null,
  config_writable: true,
}
const ASKED = Date.parse("2026-11-01T10:05:00Z")

describe("checkAnswered", () => {
  it("waits while the gate was last checked before the request", () => {
    expect(checkAnswered(BASE, ASKED)).toBe(false)
    expect(checkAnswered({ ...BASE, gate: { ...BASE.gate, checked_at: null } }, ASKED)).toBe(false)
  })

  it("is answered once the gate was checked after the request", () => {
    const v = { ...BASE, gate: { ...BASE.gate, checked_at: "2026-11-01T10:05:03Z" } }
    expect(checkAnswered(v, ASKED)).toBe(true)
  })

  it("is answered when the request row is marked done", () => {
    const v: VpnStatus = {
      ...BASE,
      last_check_request: { requested_at: "2026-11-01T10:05:00Z", done_at: "2026-11-01T10:05:02Z" },
    }
    expect(checkAnswered(v, ASKED)).toBe(true)
    expect(
      checkAnswered(
        { ...v, last_check_request: { requested_at: "2026-11-01T10:05:00Z", done_at: null } },
        ASKED,
      ),
    ).toBe(false)
  })
})
