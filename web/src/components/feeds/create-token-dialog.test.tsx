import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import { stubResizeObserver } from "@/test/dom-stubs"
import { CreateTokenDialog, type CreatedToken } from "./create-token-dialog"

const json = (status: number, body?: unknown) =>
  new Response(body === undefined ? null : JSON.stringify(body), { status })

const ITEM = {
  id: 1,
  name: "Edge firewall",
  hint: "abcd",
  kinds: ["ip", "network"],
  min_score: 50,
  include_benign: false,
  created_by: "owner",
  created_at: "2026-11-02T10:00:00Z",
  expires_at: null,
  revoked_at: null,
  last_used_at: null,
  last_used_ip: null,
  use_count: 0,
  state: "active",
}

beforeAll(stubResizeObserver)

describe("create a feed token", () => {
  const bodies: unknown[] = []
  beforeEach(() => {
    bodies.length = 0
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        if (url.endsWith("/auth/csrf")) return json(200, { token: "csrf" })
        if (url.endsWith("/defend/feed-tokens") && init?.method === "POST") {
          bodies.push(JSON.parse(init.body as string))
          return json(200, { token: "t".repeat(43), item: ITEM })
        }
        return json(404)
      }),
    )
  })
  afterEach(() => vi.unstubAllGlobals())

  it("offers every kind the API accepts, the community lists mirror included", async () => {
    const created: CreatedToken[] = []
    render(
      <QueryClientProvider client={new QueryClient()}>
        <CreateTokenDialog open onOpenChange={vi.fn()} onCreated={(c) => created.push(c)} />
      </QueryClientProvider>,
    )
    for (const label of [
      "IP addresses",
      "Domains",
      "URLs",
      "File hashes",
      "Community lists (local mirror)",
    ]) {
      expect(screen.getByRole("checkbox", { name: label })).toBeInTheDocument()
    }
    // The long label spans both columns (a separate class, not glued to the one before it).
    const mirror = screen.getByRole("checkbox", { name: "Community lists (local mirror)" })
    expect(mirror.closest("label")?.classList).toContain("col-span-2")
    const user = userEvent.setup()
    await user.type(screen.getByLabelText("Name"), "Edge firewall")
    await user.click(screen.getByRole("checkbox", { name: "Community lists (local mirror)" }))
    await user.type(screen.getByLabelText("Your password"), "secret-password")
    await user.click(screen.getByRole("button", { name: "Create token" }))
    await vi.waitFor(() => expect(created).toHaveLength(1))
    expect(bodies).toHaveLength(1)
    expect((bodies[0] as { kinds: string[] }).kinds).toEqual(["ip", "network"])
  })
})
