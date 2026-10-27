import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { TooltipProvider } from "@/components/ui/tooltip"
import { storyApi } from "@/lib/story"
import { todayApi, type TodayResponse } from "@/lib/today"
import { buildStory } from "@/mocks/story"
import { stubResizeObserver } from "@/test/dom-stubs"
import { TodayPage } from "./today"

beforeAll(stubResizeObserver)
afterEach(() => vi.restoreAllMocks())

function mount() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <IpMaskProvider>
          <TooltipProvider>
            <TodayPage />
          </TooltipProvider>
        </IpMaskProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const today: TodayResponse = {
  generated_at: new Date().toISOString(),
  window_hours: 24,
  hidden_benign: 0,
  cards: [
    {
      id: "act",
      sentence: "2 servers hand out malware.",
      items: [],
      action: { label: "Open the blocklist", to: "/defend/blocklists" },
      empty: false,
    },
  ],
}

function stub(story = buildStory(24)) {
  vi.spyOn(storyApi, "story").mockResolvedValue(story)
  vi.spyOn(todayApi, "today").mockResolvedValue(today)
}

describe("TodayPage", () => {
  it("tells the day: headline, numbers, flow, hours, stories and what to do", async () => {
    stub()
    mount()
    expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument()

    expect(await screen.findByText(/machines from 38 countries knocked/)).toBeInTheDocument()
    // jsdom is a narrow screen: the page shows the bar-per-door fallback instead of the Sankey.
    expect(screen.getByRole("heading", { name: "Where they come from" })).toBeInTheDocument()
    expect(screen.getByRole("slider", { name: /hour of the last day/i })).toBeInTheDocument()

    const stories = screen.getByRole("region", { name: "Stories of the day" })
    expect(within(stories).getAllByRole("heading", { level: 3 })).toHaveLength(4)
    expect(await screen.findByRole("link", { name: "Open the blocklist" })).toBeInTheDocument()
  })

  it("keeps the technical lines behind a disclosure", async () => {
    const user = userEvent.setup()
    stub()
    mount()
    const first = (await screen.findAllByRole("button", { name: "Technical details" }))[0]
    if (!first) throw new Error("no story card")
    expect(screen.queryByText(/busybox ECCHI/)).not.toBeInTheDocument()
    await user.click(first)
    expect(screen.getByText(/busybox ECCHI/)).toBeInTheDocument()
    expect(screen.getAllByRole("link", { name: "T1110.001" })[0]).toHaveAttribute(
      "href",
      "/techniques",
    )
    expect(screen.getByRole("link", { name: /Campaign: Mirai loader/ })).toHaveAttribute(
      "href",
      "/campaigns/3",
    )
  })

  it("moves the hour with the arrow keys", async () => {
    const user = userEvent.setup()
    stub()
    mount()
    const slider = await screen.findByRole("slider")
    const before = slider.getAttribute("aria-valuenow")
    slider.focus()
    await user.keyboard("{ArrowLeft}")
    expect(slider.getAttribute("aria-valuenow")).not.toBe(before)
  })

  it("shows an empty state when nothing knocked", async () => {
    const empty = buildStory(24)
    empty.totals = { ...empty.totals, sessions: 0 }
    stub(empty)
    mount()
    expect(await screen.findByText("A quiet day")).toBeInTheDocument()
  })

  it("renders attacker text as text, never as markup", async () => {
    const hostile = buildStory(24)
    const step = hostile.stories[0]?.steps[0]
    if (!step) throw new Error("no step")
    step.technical = '<img src=x onerror="alert(1)">'
    stub(hostile)
    const user = userEvent.setup()
    const { container } = mount()
    const btn = (await screen.findAllByRole("button", { name: "Technical details" }))[0]
    if (!btn) throw new Error("no button")
    await user.click(btn)
    expect(container.querySelector("img[onerror]")).toBeNull()
    expect(screen.getByText(/<img src=x/)).toBeInTheDocument()
  })
})
