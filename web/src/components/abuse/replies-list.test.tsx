import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { Reply } from "@/lib/replies"
import { RepliesList } from "./replies-list"

const reply = (over: Partial<Reply> = {}): Reply => ({
  id: 1,
  report: "3c4d5e6f-7a8b-4c9d-8e0f-6f7a8b9c0d06",
  received_at: "2026-10-30T10:00:00Z",
  from_domain: "example.net",
  from_address: "abuse@example.net",
  classification: "ticket_opened",
  classification_source: "rule",
  source: "imap",
  sent_at: null,
  subject: "Re: report",
  auth: "pass",
  rule_id: "ticket_in_subject",
  dsn_status: null,
  truncated: false,
  attachments: { count: 0, types: [], bytes: 0 },
  excerpt_purged: false,
  reviewed_at: null,
  reviewed_by: null,
  match_method: "token",
  verified: true,
  needs_review: false,
  ticket_id: "48213",
  excerpt: "We opened ticket 48213.",
  ...over,
})

function show(replies: Reply[]) {
  return render(
    <MemoryRouter>
      <TooltipProvider>
        <RepliesList replies={replies} />
      </TooltipProvider>
    </MemoryRouter>,
  )
}

describe("RepliesList", () => {
  it("says so when there is no reply", () => {
    show([])
    expect(screen.getByText(/No reply stored/)).toBeTruthy()
  })

  it("shows the verdict, the verification and the rule in words", () => {
    show([reply(), reply({ id: 2, verified: false, classification: "bounce" })])
    expect(screen.getByText("Verified")).toBeTruthy()
    expect(screen.getByText("Check it")).toBeTruthy()
    expect(screen.getByText("Ticket opened")).toBeTruthy()
    expect(screen.getByText("Bounced")).toBeTruthy()
    expect(screen.getAllByText(/Ticket in subject/).length).toBeGreaterThan(0)
  })

  it("renders hostile text as text, never as markup or links", () => {
    const hostile = '<img src=x onerror="alert(1)"> <a href="https://example.org/x">click</a>'
    const { container } = show([reply({ excerpt: hostile })])
    expect(container.querySelector("img")).toBeNull()
    expect(container.querySelector("a")).toBeNull()
    expect(container.querySelector("pre")?.textContent).toBe(hostile)
  })

  it("hides the address and the excerpt when the API leaves them out (viewers)", () => {
    const { container } = show([reply({ from_address: undefined, excerpt: undefined })])
    expect(screen.getByText("example.net")).toBeTruthy()
    expect(container.querySelector("pre")).toBeNull()
  })
})
