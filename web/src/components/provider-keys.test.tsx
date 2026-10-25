import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, describe, expect, it, vi } from "vitest"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { EnrichmentSettings, KeyInfo, ReputationProvider } from "@/lib/settings"
import { ProviderKeys } from "./provider-keys"

const GOOD = "placeholder-value-for-tests-0001"

const NO_KEY: KeyInfo = {
  configured: false,
  source: null,
  last4: null,
  updated_at: null,
  secret_error: null,
  pending_apply: false,
  test: null,
  test_pending: false,
  test_requested_at: null,
}
const rep = (k: Partial<KeyInfo>): ReputationProvider => ({
  ...NO_KEY,
  daily_quota: 1000,
  used_today: 10,
  disabled: null,
  paused: false,
  last_error: null,
  ...k,
})

function settings(over: Partial<EnrichmentSettings> = {}): EnrichmentSettings {
  return {
    geoip: {
      provider: "dbip",
      available: true,
      files: {},
      last_error: null,
      refresh_days: 30,
      attribution: null,
    },
    abuseipdb: rep({ configured: true, source: "env" }),
    greynoise: rep({
      configured: true,
      source: "settings",
      last4: "7c2f",
      updated_at: "2026-10-24T10:00:00Z",
    }),
    maxmind: NO_KEY,
    key_editing: { enabled: true, reason: null },
    reported_at: null,
    ...over,
  }
}

function mount(e: EnrichmentSettings) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <ProviderKeys e={e} />
      </TooltipProvider>
    </QueryClientProvider>,
  )
}

const row = (name: string) => within(screen.getByText(name).closest("li") as HTMLElement)

function stubFetch(handler: (url: string, init?: RequestInit) => Response) {
  const fetchMock = vi.fn((url: string, init?: RequestInit) =>
    Promise.resolve(
      url.endsWith("/auth/csrf")
        ? new Response(JSON.stringify({ token: "t" }), { status: 200 })
        : handler(url, init),
    ),
  )
  vi.stubGlobal("fetch", fetchMock)
  return fetchMock
}

describe("ProviderKeys", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("shows the source and last four characters, never a key", () => {
    mount(settings())
    expect(row("AbuseIPDB").getByText("From .env")).toBeInTheDocument()
    const gn = row("GreyNoise Community")
    expect(gn.getByText("Set in Settings")).toBeInTheDocument()
    expect(gn.getByText("7c2f")).toBeInTheDocument()
    expect(gn.getByRole("button", { name: "Replace the GreyNoise Community key" })).toBeEnabled()
    expect(gn.getByRole("button", { name: "Remove the GreyNoise Community key" })).toBeEnabled()
    expect(row("MaxMind GeoLite2").getByText("No key")).toBeInTheDocument()
    expect(row("MaxMind GeoLite2").queryByRole("button", { name: /Test/ })).toBeNull()
  })

  it("is disabled, with the reason, when the server has no encryption key", () => {
    mount(
      settings({
        key_editing: {
          enabled: false,
          reason: "Set SETTINGS_ENCRYPTION_KEY in .env to enable it.",
        },
      }),
    )
    expect(
      screen.getByText(
        (_, el) =>
          el?.tagName === "P" &&
          el.textContent.startsWith("Set SETTINGS_ENCRYPTION_KEY in .env to enable it."),
      ),
    ).toBeInTheDocument()
    expect(screen.getByText("SETTINGS_ENCRYPTION_KEY").tagName).toBe("CODE")
    expect(screen.getByRole("button", { name: "Set the AbuseIPDB key" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "Set the MaxMind GeoLite2 key" })).toBeDisabled()
  })

  it("warns about a saved key that cannot be decrypted", () => {
    mount(settings({ greynoise: rep({ configured: false, secret_error: "cannot_decrypt" }) }))
    expect(screen.getByText(/cannot be read/)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Remove the GreyNoise Community key" })).toBeEnabled()
  })

  it("saves a key with the password and clears the typed values", async () => {
    const user = userEvent.setup()
    const fetchMock = stubFetch(() => new Response("{}", { status: 200 }))
    mount(settings())
    await user.click(screen.getByRole("button", { name: "Set the AbuseIPDB key" }))
    const dialog = await screen.findByRole("dialog")
    const key = within(dialog).getByLabelText("API key")
    expect(key).toHaveAttribute("type", "password")
    await user.type(key, GOOD)
    await user.type(within(dialog).getByLabelText("Your password"), "hunter2-hunter2")
    await user.click(within(dialog).getByRole("button", { name: "Save key" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    const put = fetchMock.mock.calls.find(([, init]) => init?.method === "PUT")
    expect(JSON.parse(put?.[1]?.body as string)).toEqual({ key: GOOD, password: "hunter2-hunter2" })
    // The key is not left anywhere in the page.
    expect(document.body.innerHTML).not.toContain(GOOD)
    await user.click(screen.getByRole("button", { name: "Set the AbuseIPDB key" }))
    expect(within(await screen.findByRole("dialog")).getByLabelText("API key")).toHaveValue("")
  })

  it("explains a wrong password and keeps the key field filled", async () => {
    const user = userEvent.setup()
    stubFetch(
      () => new Response(JSON.stringify({ detail: "x", code: "reauth_failed" }), { status: 403 }),
    )
    mount(settings())
    await user.click(screen.getByRole("button", { name: "Set the AbuseIPDB key" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("API key"), GOOD)
    await user.type(within(dialog).getByLabelText("Your password"), "nope-nope-nope")
    await user.click(within(dialog).getByRole("button", { name: "Save key" }))
    const pw = within(dialog).getByLabelText("Your password")
    await waitFor(() => expect(pw).toHaveAttribute("aria-invalid", "true"))
    expect(within(dialog).getByText("That password is not correct.")).toBeInTheDocument()
    expect(pw).toHaveValue("")
    expect(within(dialog).getByLabelText("API key")).toHaveValue(GOOD)
  })

  it("refuses a bad key before sending anything", async () => {
    const user = userEvent.setup()
    const fetchMock = stubFetch(() => new Response("{}", { status: 200 }))
    mount(settings())
    await user.click(screen.getByRole("button", { name: "Set the AbuseIPDB key" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("API key"), "short")
    await user.type(within(dialog).getByLabelText("Your password"), "pw")
    await user.click(within(dialog).getByRole("button", { name: "Save key" }))
    expect(within(dialog).getByText(/16 to 128 characters/)).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("MaxMind asks for the account ID too", async () => {
    const user = userEvent.setup()
    mount(settings())
    await user.click(screen.getByRole("button", { name: "Set the MaxMind GeoLite2 key" }))
    const dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByLabelText("Account ID")).toBeInTheDocument()
    expect(within(dialog).getByLabelText("Licence key")).toBeInTheDocument()
  })

  it("closes with Escape and returns focus to the button", async () => {
    const user = userEvent.setup()
    mount(settings())
    const button = screen.getByRole("button", { name: "Set the AbuseIPDB key" })
    await user.click(button)
    await screen.findByRole("dialog")
    await user.keyboard("{Escape}")
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(button).toHaveFocus()
  })

  it("removes a key after confirming the password", async () => {
    const user = userEvent.setup()
    const fetchMock = stubFetch(() => new Response(null, { status: 204 }))
    mount(settings())
    await user.click(screen.getByRole("button", { name: "Remove the GreyNoise Community key" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Your password"), "pw")
    await user.click(within(dialog).getByRole("button", { name: "Remove key" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    const del = fetchMock.mock.calls.find(([, init]) => init?.method === "DELETE")
    expect(JSON.parse(del?.[1]?.body as string)).toEqual({ password: "pw" })
  })

  it("test button shows pending and the result", async () => {
    const user = userEvent.setup()
    const fetchMock = stubFetch(() => new Response("{}", { status: 202 }))
    const { rerender } = mount(settings())
    await user.click(screen.getByRole("button", { name: "Test the AbuseIPDB key" }))
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([u]) => u.endsWith("/abuseipdb/test"))).toBe(true),
    )
    const pending = settings({
      abuseipdb: rep({
        configured: true,
        source: "env",
        test_pending: true,
        test_requested_at: new Date().toISOString(),
      }),
    })
    const client = new QueryClient()
    rerender(
      <QueryClientProvider client={client}>
        <TooltipProvider>
          <ProviderKeys e={pending} />
        </TooltipProvider>
      </QueryClientProvider>,
    )
    expect(screen.getByRole("button", { name: "Test the AbuseIPDB key" })).toBeDisabled()
    const done = settings({
      abuseipdb: rep({
        configured: true,
        source: "env",
        test: { ok: false, error: "auth", checked_at: new Date().toISOString() },
      }),
    })
    rerender(
      <QueryClientProvider client={client}>
        <TooltipProvider>
          <ProviderKeys e={done} />
        </TooltipProvider>
      </QueryClientProvider>,
    )
    expect(screen.getByText(/The provider rejected the key/)).toBeInTheDocument()
  })
})
