import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { describe, expect, it, vi } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { FlowDiagram } from "@/components/infrastructure/flow-diagram"
import { FlowList } from "@/components/infrastructure/flow-list"
import { IndicatorRow } from "@/components/infrastructure/indicator-row"
import { IntelBadge } from "@/components/infrastructure/intel-badge"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { IndicatorItem, InfrastructureGraph } from "@/lib/infrastructure"

const item: IndicatorItem = {
  id: 7,
  type: "url",
  value: "http://203.0.113.66/bins/x86",
  defanged: "hxxp://203[.]0[.]113[.]66/bins/x86",
  role: "download_host",
  host: "203.0.113.66",
  first_seen: "2026-10-20T10:00:00Z",
  last_seen: "2026-10-23T10:00:00Z",
  sightings: 1234,
  sensors: ["ssh"],
  sessions: 900,
  ips: 40,
  checked: true,
  known: true,
  family: "Mirai",
  sources: ["urlhaus"],
}

const graph: InfrastructureGraph = {
  window_hours: 168,
  truncated: false,
  summary: {
    sources: 2,
    indicators: 1,
    families: 1,
    shared_hosts: 1,
    sources_on_shared_hosts: 2,
    top_host: "203[.]0[.]113[.]66",
    top_host_sources: 2,
  },
  nodes: [
    {
      id: "i:7",
      kind: "indicator",
      label: "203[.]0[.]113[.]66",
      weight: 2,
      type: "ip",
      role: "download_host",
      known: true,
      indicator_id: 7,
    },
    { id: "f:mirai", kind: "family", label: "Mirai", weight: 2 },
    { id: "s:192.0.2.10", kind: "source", label: "192.0.2.10", weight: 3, country: "NL" },
    { id: "s:192.0.2.11", kind: "source", label: "192.0.2.11", weight: 1, country: "US" },
  ],
  edges: [
    { source: "i:7", target: "f:mirai", weight: 2 },
    { source: "s:192.0.2.10", target: "i:7", weight: 3 },
    { source: "s:192.0.2.11", target: "i:7", weight: 1 },
  ],
}

function wrap(ui: React.ReactNode) {
  return render(
    <MemoryRouter>
      <IpMaskProvider>
        <TooltipProvider>{ui}</TooltipProvider>
      </IpMaskProvider>
    </MemoryRouter>,
  )
}

describe("IndicatorRow", () => {
  it("shows the defanged value as text and never links to it", () => {
    wrap(<IndicatorRow item={item} onOpen={() => undefined} />)
    expect(screen.getByText(item.defanged)).toBeInTheDocument()
    expect(screen.queryByText(item.value)).toBeNull()
    for (const a of document.querySelectorAll("a")) {
      expect(a.getAttribute("href") ?? "").not.toMatch(/^(https?|ftp):/)
      expect(a.getAttribute("href") ?? "").not.toContain("203.0.113.66")
    }
    expect(screen.getByRole("button", { name: "Copy defanged URL" })).toBeInTheDocument()
    expect(screen.getAllByText("1,234").length).toBeGreaterThan(0)
    expect(screen.getByRole("link", { name: /family Mirai/ })).toHaveAttribute(
      "href",
      "/infrastructure?family=Mirai",
    )
  })

  it("opens the detail panel with the indicator id", async () => {
    const onOpen = vi.fn()
    wrap(<IndicatorRow item={item} onOpen={onOpen} />)
    await userEvent.click(screen.getByRole("button", { name: /^Details for url/ }))
    expect(onOpen).toHaveBeenCalledWith(7)
  })

  it("masks addresses in screenshot mode", () => {
    window.history.pushState({}, "", "/?mask=1")
    wrap(<IndicatorRow item={item} onOpen={() => undefined} />)
    expect(screen.getByText("hxxp://203[.]0[.]x[.]x/bins/x86")).toBeInTheDocument()
    window.history.pushState({}, "", "/?mask=0")
  })
})

describe("IntelBadge", () => {
  it("always carries a word, not only a colour", () => {
    const { rerender } = render(<IntelBadge item={{ checked: true, known: true }} />)
    expect(screen.getByText("Known malicious")).toBeInTheDocument()
    rerender(<IntelBadge item={{ checked: true, known: false }} />)
    expect(screen.getByText("Not listed")).toBeInTheDocument()
    rerender(<IntelBadge item={{ checked: false, known: null }} />)
    expect(screen.getByText("Not checked")).toBeInTheDocument()
  })
})

describe("FlowDiagram", () => {
  it("draws sources, indicators and families, and opens an indicator from the keyboard", async () => {
    const onOpen = vi.fn()
    wrap(<FlowDiagram graph={graph} onOpenIndicator={onOpen} />)
    expect(screen.getByText("192.0.2.10")).toBeInTheDocument()
    expect(screen.getByText("203[.]0[.]113[.]66")).toBeInTheDocument()
    expect(screen.getByText("Mirai")).toBeInTheDocument()
    const node = screen.getByRole("button", {
      name: /203\[\.\]0\[\.\]113\[\.\]66: 2 addresses, known malicious/,
    })
    node.focus()
    await userEvent.keyboard("{Enter}")
    expect(onOpen).toHaveBeenCalledWith(7)
    // nothing in the SVG links out
    expect(document.querySelectorAll("svg a[href]")).toHaveLength(0)
    expect(screen.getByText(/red octagon marks an indicator/)).toBeInTheDocument()
  })
})

describe("FlowList", () => {
  it("lists the indicators used by the most addresses", async () => {
    const onOpen = vi.fn()
    wrap(<FlowList graph={graph} onOpenIndicator={onOpen} />)
    expect(screen.getByText("203[.]0[.]113[.]66")).toBeInTheDocument()
    expect(screen.getByText("Mirai")).toBeInTheDocument()
    expect(screen.getByText("Known malicious")).toBeInTheDocument()
    await userEvent.click(screen.getByRole("button"))
    expect(onOpen).toHaveBeenCalledWith(7)
  })
})
