import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter, Route, Routes } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { TooltipProvider } from "@/components/ui/tooltip"
import { PortsCard } from "@/components/setup/ports-table"
import { SetupPage } from "./setup"

const auth = vi.hoisted(() => ({ value: { canWrite: true } }))
vi.mock("@/app/auth", () => ({ useAuth: () => auth.value }))

const PORTS = {
  dashboard_port: 8443,
  items: [
    {
      sensor: "ssh",
      label: "SSH",
      enabled: true,
      protocols: ["tcp"],
      external_port: 22,
      host_port: 2222,
      env_var: "SSH_HOST_PORT",
      state: "receiving",
      last_event_at: "2026-11-01T08:00:00Z",
    },
    {
      sensor: "telnet",
      label: "Telnet",
      enabled: true,
      protocols: ["tcp"],
      external_port: 23,
      host_port: 2323,
      env_var: "TELNET_HOST_PORT",
      state: "waiting",
      last_event_at: null,
    },
    {
      sensor: "sip",
      label: "SIP",
      enabled: false,
      protocols: ["udp", "tcp"],
      external_port: 5060,
      host_port: 5060,
      env_var: "SIP_HOST_PORT",
      state: "off",
      last_event_at: null,
    },
  ],
}

function stub(progress: unknown) {
  const puts: unknown[] = []
  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      if (url.endsWith("/auth/csrf")) return Promise.resolve(json(200, { token: "t" }))
      if (url.endsWith("/setup/progress")) {
        if (init?.method === "PUT") puts.push(JSON.parse(init.body as string))
        return Promise.resolve(json(200, progress))
      }
      if (url.endsWith("/setup/ports")) return Promise.resolve(json(200, PORTS))
      if (url.includes("/setup/status")) return Promise.resolve(json(200, { items: [] }))
      if (url.includes("/settings/vpn"))
        return Promise.resolve(
          json(200, {
            source: "env",
            gate: { state: "closed", reason: "no_vpn", egress_ip: null },
            trusted_exits: [],
            trust_candidate: null,
            trust_blocked: null,
            config_writable: true,
          }),
        )
      if (url.includes("/abuse/self-terms")) return Promise.resolve(json(200, []))
      if (url.includes("/abuse/settings"))
        return Promise.resolve(json(200, { reply_contact: null }))
      if (url.includes("/alerts/channels")) return Promise.resolve(json(200, []))
      return Promise.resolve(json(404, { detail: "nope" }))
    }),
  )
  return puts
}

function mount(entry = "/setup") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <QueryClientProvider client={client}>
        <TooltipProvider>
          <Routes>
            <Route path="/" element={<p>Today page</p>} />
            <Route path="/setup" element={<SetupPage />} />
          </Routes>
        </TooltipProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

const NEW = { state: "new", steps: {}, show: true }

describe("SetupPage", () => {
  beforeEach(() => {
    auth.value = { canWrite: true }
  })
  afterEach(() => vi.unstubAllGlobals())

  it("opens on the first open step and marks it done on Next", async () => {
    const puts = stub({ state: "in_progress", steps: { welcome: "done" }, show: true })
    mount()
    expect(await screen.findByText(/Each sensor pretends to be one service/)).toBeInTheDocument()
    expect(screen.getByText("Step 2 of 8")).toBeInTheDocument()
    await userEvent.click(screen.getByRole("button", { name: /^Next/ }))
    await waitFor(() => expect(puts).toEqual([{ step: "sensors", status: "done" }]))
    expect(await screen.findByText(/Attackers only reach a sensor/)).toBeInTheDocument()
  })

  it("lists the steps with the current one marked, and jumps on click", async () => {
    stub(NEW)
    mount()
    const nav = await screen.findByRole("navigation", { name: "Setup steps" })
    expect(within(nav).getByRole("button", { name: /Welcome/ })).toHaveAttribute(
      "aria-current",
      "step",
    )
    expect(within(nav).queryByRole("button", { name: /Selfhostr network/ })).toBeNull()
    await userEvent.click(within(nav).getByRole("button", { name: /Open the ports/ }))
    expect(await screen.findByText(/Attackers only reach a sensor/)).toBeInTheDocument()
  })

  it("offers 'Skip for now' on an optional step that is not done, and records it", async () => {
    const puts = stub({ state: "in_progress", steps: {}, show: true })
    mount("/setup?step=vpn")
    await screen.findByRole("heading", { name: /Every lookup and download leaves through a VPN/ })
    await userEvent.click(screen.getByRole("button", { name: /Skip for now/ }))
    await waitFor(() => expect(puts).toEqual([{ step: "vpn", status: "skipped" }]))
  })

  it("builds the copyable sensors command from the switches, never running it", async () => {
    stub(NEW)
    mount("/setup?step=sensors")
    const ssh = await screen.findByRole("switch", { name: /SSH/ })
    expect(screen.queryByLabelText("Command to change the sensors")).toBeNull()
    await userEvent.click(screen.getByRole("switch", { name: /SIP/ }))
    expect(screen.getByLabelText("Command to change the sensors")).toHaveTextContent(
      "just sensors ssh,telnet,sip",
    )
    await userEvent.click(ssh)
    expect(screen.getByLabelText("Command to change the sensors")).toHaveTextContent(
      "just sensors telnet,sip",
    )
  })

  it("skips the whole setup and leaves", async () => {
    const puts = stub(NEW)
    mount()
    await userEvent.click(await screen.findByRole("button", { name: "Skip setup" }))
    await waitFor(() => expect(puts).toEqual([{ skip: true }]))
    expect(await screen.findByText("Today page")).toBeInTheDocument()
  })

  it("finishes from the last step", async () => {
    const puts = stub(NEW)
    mount("/setup?step=done")
    await userEvent.click(await screen.findByRole("button", { name: "Go to Today" }))
    await waitFor(() => expect(puts).toEqual([{ finish: true }]))
    expect(await screen.findByText("Today page")).toBeInTheDocument()
  })

  it("sends a viewer away", () => {
    auth.value = { canWrite: false }
    stub(NEW)
    mount()
    expect(screen.getByText("Today page")).toBeInTheDocument()
  })
})

describe("PortsCard", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("shows router port, machine port and a worded status for each sensor", async () => {
    stub(NEW)
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <TooltipProvider>
          <PortsCard />
        </TooltipProvider>
      </QueryClientProvider>,
    )
    const list = await screen.findByRole("list", { name: "Sensor ports" })
    const rows = within(list).getAllByRole("listitem")
    expect(rows).toHaveLength(3)
    expect(rows[0]).toHaveTextContent("TCP 22")
    expect(rows[0]).toHaveTextContent("2222")
    expect(rows[0]).toHaveTextContent("Receiving")
    expect(rows[1]).toHaveTextContent("Waiting for the first connection")
    expect(rows[2]).toHaveTextContent("UDP + TCP 5060")
    expect(rows[2]).toHaveTextContent("Off")
    expect(screen.getByText(/Never forward port/)).toHaveTextContent("8443")
    expect(
      screen.getByText(
        "1 of 2 enabled sensors are receiving traffic, 1 is still waiting for a first connection.",
      ),
    ).toBeInTheDocument()
  })
})
