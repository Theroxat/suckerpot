import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { ScannerToggle } from "@/components/scanner-toggle"
import { TooltipProvider } from "@/components/ui/tooltip"
import { api, getIncludeBenign, setIncludeBenign } from "@/lib/api"
import { scannerCaption } from "@/lib/scanner-caption"
import { ScannerFilterProvider, useScannerFilter } from "./scanner-filter"

const STORAGE_KEY = "suckerpot.hideScanners"

function urlsCalled(fetchMock: ReturnType<typeof vi.fn>): string[] {
  return fetchMock.mock.calls.map((c) => String(c[0]))
}

function mount(client = new QueryClient()) {
  return {
    client,
    ...render(
      <QueryClientProvider client={client}>
        <TooltipProvider>
          <ScannerFilterProvider>
            <ScannerToggle />
            <State />
          </ScannerFilterProvider>
        </TooltipProvider>
      </QueryClientProvider>,
    ),
  }
}

function State() {
  const { hide } = useScannerFilter()
  return <output aria-label="state">{hide ? "hidden" : "shown"}</output>
}

describe("hide research scanners", () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    localStorage.clear()
    window.history.replaceState(null, "", "/")
    fetchMock.mockReset()
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify({ window_hours: 24, sessions: 1204, sources: 31 }), {
          status: 200,
        }),
      ),
    )
    vi.stubGlobal("fetch", fetchMock)
    setIncludeBenign(false)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    setIncludeBenign(false)
  })

  it("hides scanners by default and says how many it hides", async () => {
    mount()
    expect(screen.getByRole("switch", { name: /Hide research scanners/ })).toBeChecked()
    expect(getIncludeBenign()).toBe(false)
    expect(await screen.findByText("1,204 sessions hidden (last 24 h)")).toBeInTheDocument()
  })

  it("asks the API for scanners only while the switch is off, and refetches on change", async () => {
    const user = userEvent.setup()
    const { client } = mount()
    const invalidate = vi.spyOn(client, "invalidateQueries")
    await screen.findByText(/hidden \(last 24 h\)/)

    await user.click(screen.getByRole("switch", { name: /Hide research scanners/ }))
    expect(screen.getByLabelText("state")).toHaveTextContent("shown")
    expect(getIncludeBenign()).toBe(true)
    expect(invalidate).toHaveBeenCalled()
    expect(localStorage.getItem(STORAGE_KEY)).toBe("0")

    fetchMock.mockClear()
    await api.sessions({})
    await api.summary()
    await api.recentEvents(5)
    await api.top("country")
    await api.attackers({})
    expect(urlsCalled(fetchMock).every((u) => u.includes("include_benign=1"))).toBe(true)
    expect(urlsCalled(fetchMock)).toHaveLength(5)

    await user.click(screen.getByRole("switch", { name: /Hide research scanners/ }))
    fetchMock.mockClear()
    await api.sessions({})
    expect(urlsCalled(fetchMock)[0]).not.toContain("include_benign")
  })

  it("remembers the choice, and ?scanners=show overrides it", () => {
    localStorage.setItem(STORAGE_KEY, "0")
    const first = mount()
    expect(screen.getByLabelText("state")).toHaveTextContent("shown")
    expect(getIncludeBenign()).toBe(true)
    first.unmount()

    localStorage.setItem(STORAGE_KEY, "1")
    window.history.replaceState(null, "", "/?scanners=show")
    mount()
    expect(screen.getByLabelText("state")).toHaveTextContent("shown")
    expect(localStorage.getItem(STORAGE_KEY)).toBe("0")
  })

  it("never sends the flag to endpoints that do not take it", async () => {
    setIncludeBenign(true)
    fetchMock.mockClear()
    await api.enrichmentSettings()
    await api.systemSettings()
    await api.cve("CVE-2099-10001")
    expect(urlsCalled(fetchMock).some((u) => u.includes("include_benign"))).toBe(false)
  })

  it("words the caption for every state", () => {
    expect(scannerCaption(true, undefined)).toBe(" ")
    expect(scannerCaption(true, 0)).toBe("No research scanners in the last 24 h")
    expect(scannerCaption(false, 1)).toBe("Showing 1 session from scanners (last 24 h)")
  })
})
