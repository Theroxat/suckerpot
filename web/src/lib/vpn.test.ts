import { describe, expect, it } from "vitest"
import { ApiError } from "./api"
import { UserError } from "./users"
import {
  describeNetwork,
  describeProblem,
  describeProblems,
  describeVpn,
  toVpnError,
  type VpnStatus,
} from "./vpn"

const status = (over: Partial<VpnStatus> = {}): VpnStatus => ({
  source: "env",
  uploaded_at: null,
  uploaded_by: null,
  endpoint_ip: null,
  endpoint_port: null,
  addresses: null,
  peer_key_fingerprint: null,
  gate: {
    state: "open",
    reason: null,
    egress_ip: "203.0.113.7",
    egress_asn: 64501,
    egress_org: "Example VPN Provider",
    checked_at: null,
  },
  trusted_exits: [],
  trust_candidate: null,
  trust_blocked: null,
  config_writable: true,
  ...over,
})

describe("describeProblems", () => {
  it("turns known codes into sentences and unknown ones into a generic one", () => {
    expect(describeProblem("not_full_tunnel")).toContain("0.0.0.0/0")
    expect(describeProblem("something_new")).toBe(
      "The file is not a valid WireGuard configuration.",
    )
    expect(describeProblems([])).toBe("The file is not a valid WireGuard configuration.")
  })

  it("lists each problem once", () => {
    const text = describeProblems(["bad_port", "bad_port", "preshared_key_refused"])
    expect(text.match(/Endpoint port/g)).toHaveLength(1)
    expect(text).toContain("PresharedKey")
  })
})

describe("toVpnError", () => {
  const err = (status: number, code?: string, body?: Record<string, unknown>) =>
    toVpnError(new ApiError(status, code ?? "x", code, body))

  it("maps the contract's failures", () => {
    expect(err(403, "reauth_failed").reason).toBe("wrong-password")
    expect(err(413, "too_large").detail).toContain("4 KiB")
    expect(err(409, "no_candidate").detail).toContain("no new exit")
    expect(err(409, "too_many").detail).toContain("Eight exits")
    expect(err(409, "exit_is_self").detail).toContain("itself")
    expect(err(409, "exit_asn_denied").detail).toContain("deny list")
    expect(describeProblem("duplicate_key")).toContain("twice")
    expect(err(503, "vpn_config_unavailable").detail).toContain("vpn-config")
  })

  it("reads the problems of a 422, also when nested in detail", () => {
    expect(
      err(422, "invalid_wireguard_config", { problems: ["not_full_tunnel"] }).detail,
    ).toContain("0.0.0.0/0")
    expect(err(422, undefined, { detail: { problems: ["bad_public_key"] } }).detail).toContain(
      "PublicKey",
    )
  })

  it("keeps other failures generic and never throws away a UserError", () => {
    expect(err(500).detail).toContain("could not be made")
    expect(toVpnError(new TypeError("offline")).reason).toBe("network")
    const own = new UserError("session")
    expect(toVpnError(own)).toBe(own)
  })
})

describe("describeVpn", () => {
  it("opens with a finding for each state", () => {
    expect(describeVpn(status({ source: "upload" }))).toBe(
      "Traffic leaves through 203.0.113.7 (uploaded configuration).",
    )
    expect(
      describeVpn(
        status({
          gate: {
            state: "closed",
            reason: "ip_not_allowed",
            egress_ip: "198.51.100.20",
            egress_asn: 64500,
            egress_org: "Example Networks",
            checked_at: null,
          },
          trust_candidate: "198.51.100.0/24",
        }),
      ),
    ).toBe("The gate is closed: the new exit 198.51.100.20 is not trusted yet.")
    expect(
      describeVpn(
        status({
          gate: {
            state: "open",
            reason: null,
            egress_ip: null,
            egress_asn: null,
            egress_org: null,
            checked_at: null,
          },
        }),
      ),
    ).toBe("Using the settings from .env.")
  })
})

describe("describeNetwork", () => {
  it("joins the AS number and the organisation, and says nothing when unknown", () => {
    expect(describeNetwork({ egress_asn: 64500, egress_org: "Example Networks" })).toBe(
      "AS64500 Example Networks",
    )
    expect(describeNetwork({ egress_asn: 64500, egress_org: null })).toBe("AS64500")
    expect(describeNetwork({ egress_asn: null, egress_org: null })).toBeNull()
  })
})
