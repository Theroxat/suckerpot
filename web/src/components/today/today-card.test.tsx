import { render, screen, within } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { TodayCardData, TodayItem } from "@/lib/today"
import { TodayCard } from "./today-card"

const item = (over: Partial<TodayItem> = {}): TodayItem => ({
  kind: "campaign",
  value: "41",
  label: "Mirai loader over Telnet #41",
  detail: "37 sessions from 9 sources",
  count: 1204,
  to: "/campaigns/41",
  ...over,
})

const card = (over: Partial<TodayCardData> = {}): TodayCardData => ({
  id: "campaigns",
  sentence: "2 new campaigns formed in the last 24 hours.",
  items: [item()],
  action: { label: "See all campaigns", to: "/campaigns" },
  empty: false,
  ...over,
})

function mount(data: TodayCardData) {
  return render(
    <MemoryRouter>
      <IpMaskProvider>
        <TooltipProvider>
          <TodayCard card={data} />
        </TooltipProvider>
      </IpMaskProvider>
    </MemoryRouter>,
  )
}

describe("TodayCard", () => {
  it("is a sentence, its items and one action", () => {
    mount(card())
    const group = screen.getByRole("group")
    expect(within(group).getByRole("heading", { level: 2 })).toHaveTextContent(
      /2 new campaigns.*formed in the last 24 hours\./,
    )
    const link = within(group).getByRole("link", { name: /Mirai loader over Telnet #41/ })
    expect(link).toHaveAttribute("href", "/campaigns/41")
    expect(link).toHaveTextContent("1,204") // thousands separator
    expect(within(group).getByRole("link", { name: /See all campaigns/ })).toHaveAttribute(
      "href",
      "/campaigns",
    )
  })

  it("shows at most three items", () => {
    const items = Array.from({ length: 5 }, (_, i) =>
      item({ value: String(i), label: `Item ${i}` }),
    )
    mount(card({ items }))
    expect(screen.getAllByRole("listitem")).toHaveLength(3)
  })

  it("keeps an empty card readable: the sentence and the action, no list", () => {
    mount(card({ items: [], empty: true, sentence: "No campaign has been spotted yet." }))
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(
      /No campaign.*has been spotted yet\./,
    )
    expect(screen.queryByRole("list")).not.toBeInTheDocument()
    expect(screen.getByRole("link", { name: /See all campaigns/ })).toBeInTheDocument()
  })

  it("names a country instead of showing its code", () => {
    mount(
      card({
        id: "happened",
        items: [
          item({
            kind: "country",
            value: "NL",
            label: "Most active country: NL",
            detail: null,
            to: "/attackers?country=NL",
          }),
        ],
      }),
    )
    expect(screen.getByRole("link", { name: /Netherlands/ })).toHaveAttribute(
      "href",
      "/attackers?country=NL",
    )
  })

  it("explains the word campaign in its heading", () => {
    mount(card())
    expect(screen.getAllByRole("button", { name: /, definition/ }).length).toBeGreaterThan(0)
  })
})
