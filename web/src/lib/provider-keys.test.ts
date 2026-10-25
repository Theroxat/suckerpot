import { afterEach, describe, expect, it, vi } from "vitest"
import {
  describeKeyError,
  KeyError,
  removeProviderKey,
  requestKeyTest,
  setProviderKey,
  validateKeyInput,
} from "./provider-keys"

const GOOD = "placeholder-value-for-tests-0001"

describe("validateKeyInput", () => {
  it("accepts a plain key", () => {
    expect(validateKeyInput("abuseipdb", { key: GOOD, accountId: "" })).toEqual({})
  })
  it.each([
    ["", /Enter the key/],
    ["short", /16 to 128/],
    ["x".repeat(129), /16 to 128/],
    [`${GOOD} `, /no spaces/],
    [`${GOOD.slice(0, 8)}\n${GOOD.slice(9)}`, /no spaces/],
    [`${GOOD.slice(0, 8)}é${GOOD.slice(9)}`, /no spaces/],
  ])("refuses %j", (key, message) => {
    expect(validateKeyInput("greynoise", { key, accountId: "" }).key).toMatch(message)
  })
  it("MaxMind also needs a numeric account ID", () => {
    expect(validateKeyInput("maxmind", { key: GOOD, accountId: "" }).accountId).toMatch(/number/)
    expect(validateKeyInput("maxmind", { key: GOOD, accountId: "12ab" }).accountId).toMatch(
      /number/,
    )
    expect(validateKeyInput("maxmind", { key: GOOD, accountId: "424242" })).toEqual({})
  })
})

describe("requests", () => {
  afterEach(() => vi.unstubAllGlobals())

  function stub(status: number, body?: unknown) {
    const fetchMock = vi.fn((url: string) =>
      Promise.resolve(
        url.endsWith("/auth/csrf")
          ? new Response(JSON.stringify({ token: "t" }), { status: 200 })
          : new Response(status === 204 || body === undefined ? null : JSON.stringify(body), {
              status,
            }),
      ),
    )
    vi.stubGlobal("fetch", fetchMock)
    return fetchMock
  }

  const lastCall = (m: ReturnType<typeof stub>) => {
    const calls = m.mock.calls.filter(([u]) => !u.endsWith("/auth/csrf"))
    const call = calls.at(-1) as unknown as [string, RequestInit]
    return { url: call[0], init: call[1] }
  }

  it("PUT sends the key and the password once, with the CSRF header", async () => {
    const m = stub(200, { provider: "abuseipdb" })
    await setProviderKey("abuseipdb", { key: GOOD, accountId: "" }, "pw")
    const { url, init } = lastCall(m)
    expect(url).toBe("/api/v1/settings/providers/abuseipdb")
    expect(init.method).toBe("PUT")
    expect(JSON.parse(init.body as string)).toEqual({ key: GOOD, password: "pw" })
    expect((init.headers as Record<string, string>)["X-CSRF-Token"]).toBeTruthy()
  })

  it("MaxMind includes the account ID", async () => {
    const m = stub(200, {})
    await setProviderKey("maxmind", { key: GOOD, accountId: "42" }, "pw")
    expect(JSON.parse(lastCall(m).init.body as string)).toMatchObject({ account_id: "42" })
  })

  it("DELETE sends only the password", async () => {
    const m = stub(204)
    await removeProviderKey("greynoise", "pw")
    const { url, init } = lastCall(m)
    expect(init.method).toBe("DELETE")
    expect(url).toBe("/api/v1/settings/providers/greynoise")
    expect(JSON.parse(init.body as string)).toEqual({ password: "pw" })
  })

  it("POST test has no body", async () => {
    const m = stub(202, { provider: "abuseipdb" })
    await requestKeyTest("abuseipdb")
    const { url, init } = lastCall(m)
    expect(url).toBe("/api/v1/settings/providers/abuseipdb/test")
    expect(init.body).toBeNull()
  })

  it.each([
    [403, "reauth_failed", "wrong-password"],
    [422, "invalid_key", "invalid-key"],
    [503, "editing_disabled", "editing-disabled"],
    [403, "origin", "origin"],
    [429, "rate_limited", "rate-limited"],
    [500, undefined, "network"],
  ])("maps %i %s to %s", async (status, code, reason) => {
    stub(status, { detail: "Some sentence.", code })
    await expect(
      setProviderKey("abuseipdb", { key: GOOD, accountId: "" }, "pw"),
    ).rejects.toMatchObject({ reason })
  })

  it("test cooldown and missing key get their own sentence", async () => {
    stub(429, { detail: "x", code: "cooldown" })
    await expect(requestKeyTest("abuseipdb")).rejects.toMatchObject({
      reason: "rate-limited",
      detail: expect.stringMatching(/just requested/) as unknown,
    })
    stub(409, { detail: "x", code: "no_key" })
    await expect(requestKeyTest("abuseipdb")).rejects.toMatchObject({
      detail: "There is no key to test.",
    })
  })

  it("never puts the typed values in an error message", () => {
    const text = describeKeyError(new KeyError("wrong-password"))
    expect(text).not.toContain(GOOD)
    expect(describeKeyError(new Error("boom"))).toMatch(/could not be reached/)
  })
})
