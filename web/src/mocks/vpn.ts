/**
 * MSW handlers for the M23 VPN endpoints (docs/design/m23.md section 6). Demo data only:
 * addresses are in the documentation ranges and keys are fake. State lives for the page load.
 *
 * Three starting states: the default (settings from .env, gate open) and `?vpn=upload` (uploaded
 * configuration whose new exit is not trusted yet, so there is a trust candidate). Uploading in
 * the default state moves to the second one; a file whose text contains "invalid" is refused;
 * the password "wrong" is refused.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type { TrustedExit, VpnStatus } from "@/lib/vpn"

const LATENCY_MS = 140
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString()
const MINUTE = 60_000

const envStatus = (): VpnStatus => ({
  source: "env",
  uploaded_at: null,
  uploaded_by: null,
  endpoint_ip: "203.0.113.40",
  endpoint_port: 51820,
  addresses: ["192.0.2.2/32"],
  peer_key_fingerprint: "0badc0de0bad",
  gate: {
    state: "open",
    reason: null,
    egress_ip: "203.0.113.7",
    egress_asn: 64501,
    egress_org: "Example VPN Provider",
    checked_at: iso(MINUTE),
  },
  trusted_exits: [],
  trust_candidate: null,
  trust_blocked: null,
  config_writable: true,
})

const uploadedClosed = (): VpnStatus => ({
  source: "upload",
  uploaded_at: iso(3 * MINUTE),
  uploaded_by: "admin",
  endpoint_ip: "198.51.100.20",
  endpoint_port: 51820,
  addresses: ["192.0.2.8/32", "2001:db8::8/128"],
  peer_key_fingerprint: "0badc0de0bee",
  gate: {
    state: "closed",
    reason: "ip_not_allowed",
    egress_ip: "198.51.100.20",
    egress_asn: 64500,
    egress_org: "Example Networks",
    checked_at: iso(MINUTE),
  },
  trusted_exits: [],
  trust_candidate: "198.51.100.0/24",
  trust_blocked: null,
  config_writable: true,
})

/** `?vpn=self`: the uploaded file leaves through the home connection, which can never be trusted. */
const uploadedSelf = (): VpnStatus => {
  const u = uploadedClosed()
  return {
    ...u,
    gate: {
      ...u.gate,
      reason: "exit_is_self",
      egress_asn: 64502,
      egress_org: "Example Home Internet",
    },
    trust_candidate: null,
    trust_blocked: "exit_is_self",
  }
}

let state: VpnStatus | null = null
let nextId = 1

function current(): VpnStatus {
  if (!state) {
    const wanted =
      typeof window === "undefined" ? null : new URLSearchParams(window.location.search).get("vpn")
    state =
      wanted === "self" ? uploadedSelf() : wanted === "upload" ? uploadedClosed() : envStatus()
    if (wanted === "upload") {
      state.trusted_exits = [
        {
          id: nextId++,
          cidr: "192.0.2.0/24",
          created_at: iso(2 * 86_400_000),
          created_by: "admin",
        },
      ]
    }
  }
  return state
}

const refused = () =>
  HttpResponse.json({ detail: "wrong password", code: "reauth_failed" }, { status: 403 })

export const vpnHandlers: RequestHandler[] = [
  http.get("/api/v1/settings/vpn", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(current())
  }),
  http.put("/api/v1/settings/vpn", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as { conf?: string; password?: string }
    if (!body.password || body.password === "wrong") return refused()
    if ((body.conf ?? "").includes("invalid"))
      return HttpResponse.json(
        {
          detail: "invalid_wireguard_config",
          code: "invalid_wireguard_config",
          problems: ["not_full_tunnel", "bad_private_key"],
        },
        { status: 422 },
      )
    const kept = current().trusted_exits
    state = { ...uploadedClosed(), trusted_exits: kept }
    return HttpResponse.json(state)
  }),
  http.delete("/api/v1/settings/vpn", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as { password?: string }
    if (!body.password || body.password === "wrong") return refused()
    state = { ...envStatus(), trusted_exits: current().trusted_exits }
    return new HttpResponse(null, { status: 204 })
  }),
  http.post("/api/v1/settings/vpn/trusted-exits", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as { password?: string }
    if (!body.password || body.password === "wrong") return refused()
    const s = current()
    if (s.trust_blocked)
      return HttpResponse.json({ detail: s.trust_blocked, code: s.trust_blocked }, { status: 409 })
    if (!s.trust_candidate)
      return HttpResponse.json({ detail: "no_candidate", code: "no_candidate" }, { status: 409 })
    const row: TrustedExit = {
      id: nextId++,
      cidr: s.trust_candidate,
      created_at: new Date().toISOString(),
      created_by: "admin",
    }
    state = {
      ...s,
      trusted_exits: [...s.trusted_exits, row],
      trust_candidate: null,
      gate: { ...s.gate, state: "open", reason: null, checked_at: iso(0) },
    }
    return HttpResponse.json(row, { status: 201 })
  }),
  http.delete("/api/v1/settings/vpn/trusted-exits/:id", async ({ request, params }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as { password?: string }
    if (!body.password || body.password === "wrong") return refused()
    const s = current()
    state = { ...s, trusted_exits: s.trusted_exits.filter((x) => x.id !== Number(params.id)) }
    return new HttpResponse(null, { status: 204 })
  }),
]
