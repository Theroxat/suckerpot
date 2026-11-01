import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { TourProvider } from "@/app/tour"
import { TourButton } from "@/components/tour/tour-button"
import { markTourSeen, TOUR_STEPS } from "@/lib/tour"

const auth = vi.hoisted(() => ({
  value: {
    user: { username: "admin", must_change_password: false },
    canWrite: true,
  },
}))
vi.mock("@/app/auth", () => ({ useAuth: () => auth.value }))

const ITEMS = [
  { id: "sensors", state: "ok", detail: "All 12 sensors sent an event.", href: "/settings" },
  { id: "vpn", state: "warning", detail: "The gate is closed.", href: "/settings?tab=vpn" },
]

function stubFetch() {
  const calls: string[] = []
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      calls.push(url)
      if (url.startsWith("/api/v1/setup/status"))
        return Promise.resolve(new Response(JSON.stringify({ items: ITEMS }), { status: 200 }))
      return Promise.resolve(new Response("{}", { status: 200 }))
    }),
  )
  return calls
}

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <TourProvider>
          <TourButton />
        </TourProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

const dialog = () => screen.findByRole("dialog")

describe("guided tour", () => {
  beforeEach(() => {
    window.localStorage.clear()
    auth.value = { user: { username: "admin", must_change_password: false }, canWrite: true }
  })
  afterEach(() => vi.unstubAllGlobals())

  it("opens by itself on the first visit of an account, once", async () => {
    stubFetch()
    const { unmount } = mount()
    const d = await dialog()
    expect(within(d).getByText("Step 1 of 7")).toBeInTheDocument()
    expect(within(d).getByText(TOUR_STEPS[0]?.title ?? "")).toBeInTheDocument()
    unmount()
    mount()
    expect(screen.queryByRole("dialog")).toBeNull()
  })

  it("is per account: another username still gets it", async () => {
    stubFetch()
    markTourSeen("admin")
    auth.value = { user: { username: "colleague", must_change_password: false }, canWrite: false }
    mount()
    expect(await dialog()).toBeInTheDocument()
  })

  it("waits until the first password is chosen", () => {
    stubFetch()
    auth.value = { user: { username: "jordan", must_change_password: true }, canWrite: false }
    mount()
    expect(screen.queryByRole("dialog")).toBeNull()
  })

  it("walks through the seven steps with Next and Back, and ends on Done", async () => {
    stubFetch()
    const user = userEvent.setup()
    mount()
    const d = await dialog()
    expect(within(d).queryByRole("button", { name: "Back" })).toBeNull()
    for (let i = 1; i < TOUR_STEPS.length; i++) {
      await user.click(within(d).getByRole("button", { name: "Next" }))
      expect(within(d).getByText(`Step ${i + 1} of 7`)).toBeInTheDocument()
      expect(within(d).getByText(TOUR_STEPS[i]?.title ?? "")).toBeInTheDocument()
    }
    expect(within(d).queryByRole("button", { name: "Next" })).toBeNull()
    expect(within(d).queryByRole("button", { name: "Skip tour" })).toBeNull()
    await user.click(within(d).getByRole("button", { name: "Back" }))
    expect(within(d).getByText("Step 6 of 7")).toBeInTheDocument()
    await user.keyboard("{ArrowRight}")
    expect(within(d).getByText("Step 7 of 7")).toBeInTheDocument()
    await user.click(within(d).getByRole("button", { name: "Done" }))
    expect(screen.queryByRole("dialog")).toBeNull()
  })

  it("closes with Skip and with Escape, and the ? button plays it again from step one", async () => {
    stubFetch()
    const user = userEvent.setup()
    mount()
    let d = await dialog()
    await user.click(within(d).getByRole("button", { name: "Next" }))
    await user.click(within(d).getByRole("button", { name: "Skip tour" }))
    expect(screen.queryByRole("dialog")).toBeNull()

    await user.click(screen.getByRole("button", { name: "Take the tour" }))
    d = await dialog()
    expect(within(d).getByText("Step 1 of 7")).toBeInTheDocument()
    await user.keyboard("{Escape}")
    expect(screen.queryByRole("dialog")).toBeNull()
  })

  it("shows the setup checklist on the last step for an administrator", async () => {
    const calls = stubFetch()
    const user = userEvent.setup()
    mount()
    const d = await dialog()
    for (let i = 1; i < TOUR_STEPS.length; i++)
      await user.click(within(d).getByRole("button", { name: "Next" }))
    const list = await within(d).findByRole("list", { name: "Setup checklist" })
    expect(within(list).getAllByRole("listitem")).toHaveLength(2)
    expect(within(list).getByText("Needs attention")).toBeInTheDocument()
    expect(
      within(d).getByText(/The host firewall can't be seen from inside the stack/),
    ).toBeInTheDocument()
    expect(calls.filter((u) => u.startsWith("/api/v1/setup/status"))).toHaveLength(1)
    await user.click(within(list).getByRole("link", { name: "Open Outbound gate is open" }))
    expect(screen.queryByRole("dialog")).toBeNull()
  })

  it("does not ask for the checklist, or show it, to a viewer", async () => {
    const calls = stubFetch()
    auth.value = { user: { username: "colleague", must_change_password: false }, canWrite: false }
    const user = userEvent.setup()
    mount()
    const d = await dialog()
    for (let i = 1; i < TOUR_STEPS.length; i++)
      await user.click(within(d).getByRole("button", { name: "Next" }))
    expect(within(d).queryByRole("list", { name: "Setup checklist" })).toBeNull()
    expect(
      within(d).getByText(/An administrator can see what is left to set up/),
    ).toBeInTheDocument()
    expect(calls.some((u) => u.includes("/setup/status"))).toBe(false)
  })
})
