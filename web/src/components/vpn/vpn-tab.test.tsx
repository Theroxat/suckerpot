import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, describe, expect, it, vi } from "vitest"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { VpnStatus } from "@/lib/vpn"
import { VpnTab } from "./vpn-tab"

const FAKE_CONF = [
  "[Interface]",
  "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "Address = 192.0.2.8/32",
  "[Peer]",
  "PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
  "Endpoint = 198.51.100.20:51820",
  "AllowedIPs = 0.0.0.0/0",
].join("\n")

const ENV: VpnStatus = {
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
    checked_at: "2026-11-01T10:00:00Z",
  },
  trusted_exits: [],
  trust_candidate: null,
  trust_blocked: null,
  config_writable: true,
}
const UPLOADED: VpnStatus = {
  ...ENV,
  source: "upload",
  uploaded_at: "2026-11-01T09:55:00Z",
  uploaded_by: "admin",
  gate: {
    state: "closed",
    reason: "ip_not_allowed",
    egress_ip: "198.51.100.20",
    egress_asn: 64500,
    egress_org: "Example Networks",
    checked_at: "2026-11-01T10:00:00Z",
  },
  trusted_exits: [
    { id: 4, cidr: "192.0.2.0/24", created_at: "2026-10-30T10:00:00Z", created_by: "admin" },
  ],
  trust_candidate: "198.51.100.0/24",
}

interface Call {
  method: string
  url: string
  body: Record<string, unknown> | undefined
}

function stub(status: VpnStatus, answer?: (c: Call) => Response | undefined) {
  const calls: Call[] = []
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET"
      const body =
        typeof init?.body === "string"
          ? (JSON.parse(init.body) as Record<string, unknown>)
          : undefined
      if (url.endsWith("/auth/csrf"))
        return Promise.resolve(new Response(JSON.stringify({ token: "t" }), { status: 200 }))
      const call = { method, url, body }
      if (url.startsWith("/api/v1/settings/vpn") && method !== "GET") calls.push(call)
      const custom = answer?.(call)
      if (custom) return Promise.resolve(custom)
      if (url.startsWith("/api/v1/settings/vpn") && method === "GET")
        return Promise.resolve(new Response(JSON.stringify(status), { status: 200 }))
      if (url.startsWith("/api/v1/egress"))
        return Promise.resolve(new Response("{}", { status: 200 }))
      return Promise.resolve(
        new Response(method === "DELETE" ? null : "{}", {
          status: method === "DELETE" ? 204 : 200,
        }),
      )
    }),
  )
  return calls
}

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <VpnTab />
      </TooltipProvider>
    </QueryClientProvider>,
  )
}

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

describe("VpnTab", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("opens with a sentence, then the details, for the .env source", async () => {
    stub(ENV)
    mount()
    expect(
      await screen.findByText("Traffic leaves through 203.0.113.7 (settings from .env)."),
    ).toBeInTheDocument()
    expect(screen.getByText("203.0.113.40:51820")).toBeInTheDocument()
    expect(screen.getByText("0badc0de0bad")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /Use the \.env settings again/ })).toBeNull()
    expect(screen.queryByText(/Trust needed/)).toBeNull()
  })

  it("uploads a file after the warnings and the password, then forgets the text", async () => {
    const calls = stub(ENV)
    const user = userEvent.setup()
    mount()
    await screen.findByText(/Traffic leaves through/)
    await user.upload(
      screen.getByLabelText("WireGuard configuration file"),
      new File([FAKE_CONF], "provider.conf", { type: "text/plain" }),
    )
    await user.click(await screen.findByRole("button", { name: "Review and upload" }))
    const dialog = await screen.findByRole("dialog")
    expect(
      within(dialog).getByText(
        /The VPN endpoint sees your home IP: only upload a file from your own VPN provider\./,
      ),
    ).toBeInTheDocument()
    expect(
      within(dialog).getByText(/The tunnel restarts; outbound lookups pause for a few seconds\./),
    ).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText("Your password"), "pw")
    await user.click(within(dialog).getByRole("button", { name: /Upload and restart/ }))
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0]).toMatchObject({ method: "PUT", url: "/api/v1/settings/vpn" })
    expect(calls[0]?.body).toEqual({ conf: FAKE_CONF, password: "pw" })
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(screen.queryByText("provider.conf")).toBeNull()
    expect(screen.getByText(/The tunnel is restarting/)).toBeInTheDocument()
  })

  it("refuses a big or wrong file before sending anything", async () => {
    const calls = stub(ENV)
    const user = userEvent.setup()
    mount()
    await screen.findByText(/Traffic leaves through/)
    const input = screen.getByLabelText("WireGuard configuration file")
    await user.upload(input, new File(["x".repeat(5000)], "big.conf"))
    expect(await screen.findByRole("alert")).toHaveTextContent("bigger than 4 KiB")
    expect(screen.queryByRole("button", { name: "Review and upload" })).toBeNull()
    expect(calls).toHaveLength(0)
  })

  it("shows the problems of a 422 as sentences and keeps the dialog open", async () => {
    stub(ENV, (c) =>
      c.method === "PUT"
        ? json(422, { code: "invalid_wireguard_config", problems: ["not_full_tunnel", "zzz"] })
        : undefined,
    )
    const user = userEvent.setup()
    mount()
    await screen.findByText(/Traffic leaves through/)
    await user.upload(
      screen.getByLabelText("WireGuard configuration file"),
      new File([FAKE_CONF], "provider.conf"),
    )
    await user.click(await screen.findByRole("button", { name: "Review and upload" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Your password"), "pw")
    await user.click(within(dialog).getByRole("button", { name: /Upload and restart/ }))
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      /AllowedIPs must contain 0\.0\.0\.0\/0.*not a valid WireGuard configuration/,
    )
  })

  it("shows a wrong password on the password field", async () => {
    stub(UPLOADED, (c) =>
      c.method === "POST" ? json(403, { detail: "no", code: "reauth_failed" }) : undefined,
    )
    const user = userEvent.setup()
    mount()
    await user.click(await screen.findByRole("button", { name: "Trust 198.51.100.0/24" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Your password"), "wrong")
    await user.click(within(dialog).getByRole("button", { name: "Trust 198.51.100.0/24" }))
    expect(await within(dialog).findByText("That password is not correct.")).toBeInTheDocument()
  })

  it("trusts the candidate after the password", async () => {
    const calls = stub(UPLOADED)
    const user = userEvent.setup()
    mount()
    expect(
      await screen.findByText("The gate is closed: the new exit 198.51.100.20 is not trusted yet."),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        /is outside the trusted ranges\. Outbound lookups stay paused until you trust it\./,
      ),
    ).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Trust 198.51.100.0/24" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Your password"), "pw")
    await user.click(within(dialog).getByRole("button", { name: "Trust 198.51.100.0/24" }))
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0]).toMatchObject({
      method: "POST",
      url: "/api/v1/settings/vpn/trusted-exits",
      body: { password: "pw" },
    })
  })

  it("explains a 409 with no candidate", async () => {
    stub(UPLOADED, (c) => (c.method === "POST" ? json(409, { code: "no_candidate" }) : undefined))
    const user = userEvent.setup()
    mount()
    await user.click(await screen.findByRole("button", { name: "Trust 198.51.100.0/24" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Your password"), "pw")
    await user.click(within(dialog).getByRole("button", { name: "Trust 198.51.100.0/24" }))
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("no new exit to trust")
  })

  it("removes a trusted exit and goes back to .env, each with the password", async () => {
    const calls = stub(UPLOADED)
    const user = userEvent.setup()
    mount()
    const list = await screen.findByRole("list", { name: "Trusted exits" })
    expect(list).toHaveTextContent("192.0.2.0/24")
    await user.click(within(list).getByRole("button", { name: "Remove 192.0.2.0/24" }))
    let dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Your password"), "pw")
    await user.click(within(dialog).getByRole("button", { name: "Remove" }))
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0]).toMatchObject({
      method: "DELETE",
      url: "/api/v1/settings/vpn/trusted-exits/4",
      body: { password: "pw" },
    })
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())

    await user.click(screen.getByRole("button", { name: "Use the .env settings again" }))
    dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Your password"), "pw2")
    await user.click(within(dialog).getByRole("button", { name: "Use .env settings" }))
    await waitFor(() => expect(calls).toHaveLength(2))
    expect(calls[1]).toMatchObject({
      method: "DELETE",
      url: "/api/v1/settings/vpn",
      body: { password: "pw2" },
    })
  })
  it("shows the exit network and asks to check it before trusting", async () => {
    stub(UPLOADED)
    const user = userEvent.setup()
    mount()
    expect((await screen.findAllByText(/AS64500 Example Networks/)).length).toBeGreaterThan(0)
    await user.click(screen.getByRole("button", { name: "Trust 198.51.100.0/24" }))
    const dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByText(/198\.51\.100\.20/)).toBeInTheDocument()
    expect(within(dialog).getByText(/not your internet provider/)).toBeInTheDocument()
  })

  it("explains a blocked exit, offers no trust, and offers the .env settings", async () => {
    stub({
      ...UPLOADED,
      trust_candidate: null,
      trust_blocked: "exit_is_self",
      gate: { ...UPLOADED.gate, reason: "exit_is_self" },
    })
    mount()
    expect(await screen.findByText("This exit cannot be trusted")).toBeInTheDocument()
    expect(screen.getByText(/looks like your own internet connection/)).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /^Trust / })).toBeNull()
    expect(screen.getAllByRole("button", { name: "Use the .env settings again" })).toHaveLength(1)
  })

  it("turns upload and revert off when the config volume is not writable", async () => {
    stub({ ...UPLOADED, config_writable: false })
    mount()
    expect(
      await screen.findByText(/vpn-config volume is not mounted or not writable/),
    ).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Choose a file" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "Use the .env settings again" })).toBeDisabled()
  })
})
