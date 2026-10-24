import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { TooltipProvider } from "@/components/ui/tooltip"
import { InsightRow } from "@/components/insights/insights-card"
import { Heatmap } from "@/components/trends/heatmap"
import { MalwareRow } from "@/components/trends/malware-row"
import { gridStep, type Insight, type MalwareItem } from "@/lib/trends"

const item: MalwareItem = {
  url: "http://198.51.100.23/bins/x86.sh",
  host: "198.51.100.23",
  first_seen: "2026-10-20T10:00:00Z",
  last_seen: "2026-10-23T10:00:00Z",
  attempts: 1234,
  sessions: 900,
  ips: 40,
  tools: ["wget", "curl"],
  sensors: ["ssh"],
  sha256: null,
  size: null,
  virustotal_url: null,
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

describe("MalwareRow", () => {
  it("shows the URL as text, never as a link, with thousands separators", () => {
    wrap(<MalwareRow item={item} onOpen={() => undefined} showHash={false} />)
    expect(screen.getByText(item.url)).toBeInTheDocument()
    expect(document.querySelectorAll("a")).toHaveLength(0)
    expect(screen.getAllByText("1,234").length).toBeGreaterThan(0)
    expect(screen.getByRole("button", { name: "Copy defanged URL" })).toBeInTheDocument()
  })
})

describe("InsightRow", () => {
  const insight: Insight = {
    id: "x",
    kind: "surge",
    severity: "severe",
    sentence: "Exploit attempts tripled (412 vs 131).",
    evidence: { metric: "tag:php2shell", current: 412, previous: 131, ratio: 3.1 },
    link: "/attacks?tag=php2shell",
  }
  it("links to the filtered view and names its severity", () => {
    wrap(<InsightRow insight={insight} />)
    const link = screen.getByRole("link")
    expect(link).toHaveAttribute("href", "/attacks?tag=php2shell")
    expect(link).toHaveTextContent("Severe")
    expect(link).toHaveTextContent("Exploit attempts tripled")
  })
})

describe("Heatmap", () => {
  it("gives screen readers a full table and a readable scale", () => {
    wrap(<Heatmap cells={[{ dow: 1, hour: 14, events: 1500 }]} offsetHours={0} />)
    expect(screen.getByRole("table", { hidden: true })).toBeInTheDocument()
    expect(screen.getByText("Tuesday")).toBeInTheDocument()
    expect(gridStep(0, 10)).toBe(0)
    expect(gridStep(10, 10)).toBe(5)
    expect(gridStep(1, 1000)).toBe(1)
  })
})
