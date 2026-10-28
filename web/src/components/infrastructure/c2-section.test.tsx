import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { afterEach, describe, expect, it, vi } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { C2Section } from "@/components/infrastructure/c2-section"
import { TooltipProvider } from "@/components/ui/tooltip"
import { api } from "@/lib/api"
import type { C2Address } from "@/lib/c2"

const item: C2Address = {
  address: "203.0.113.45",
  defanged: "203[.]0[.]113[.]45",
  kind: "ip",
  port: 4444,
  confidence: "high",
  sources: ["threatfox"],
  families: ["Mirai"],
  hashes: [{ sha256: "a".repeat(64), family: "Mirai" }],
  hash_count: 1,
  sessions: 6,
  first_seen: "2026-10-20T10:00:00Z",
  last_seen: "2026-10-23T10:00:00Z",
  references: ["https://threatfox.abuse.ch/ioc/1/", "https://evil.example/x"],
}

function show(items: C2Address[]) {
  vi.spyOn(api, "c2").mockResolvedValue({ items, next_cursor: null })
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter>
        <IpMaskProvider>
          <TooltipProvider>
            <C2Section />
          </TooltipProvider>
        </IpMaskProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => vi.restoreAllMocks())

describe("C2Section", () => {
  it("shows the defanged address, safe links only, and never links the address", async () => {
    show([item])
    expect(await screen.findByText(/203\[\.\]0\[\.\]113\[\.\]45/)).toBeInTheDocument()
    expect(screen.getByText("Reported as C2 by ThreatFox")).toBeInTheDocument()
    expect(screen.getByText(/6 sessions dropped this malware/)).toBeInTheDocument()
    const links = screen.getAllByRole("link")
    expect(links).toHaveLength(1)
    expect(links[0]).toHaveAttribute("href", "https://threatfox.abuse.ch/ioc/1/")
    expect(links[0]).toHaveAttribute("rel", "noopener noreferrer")
    expect(screen.queryByText("203.0.113.45")).toBeNull()
  })

  it("explains the empty case", async () => {
    show([])
    expect(await screen.findByText("No C2 address known yet")).toBeInTheDocument()
    expect(screen.getByText(/once VirusTotal or ThreatFox has analysed a file/)).toBeInTheDocument()
  })
})
