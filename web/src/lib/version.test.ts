import { describe, expect, it } from "vitest"
import { describeVersion, hasUpdate, isDevBuild, safeReleaseUrl, type VersionInfo } from "./version"

const base: VersionInfo = {
  version: "v0.8.0",
  build: "image",
  commit: "0badc0d",
  latest: "v0.8.0",
  update_available: false,
  checked_at: "2026-11-01T08:00:00Z",
  check: "ok",
  release_url: "https://example.org/releases/v0.8.0",
}

describe("version", () => {
  it("recognises development builds", () => {
    expect(isDevBuild("dev")).toBe(true)
    expect(isDevBuild("v0.8.0-14-g0badc0d")).toBe(true)
    expect(isDevBuild("v0.8.0-dirty")).toBe(true)
    expect(isDevBuild("v0.8.0")).toBe(false)
  })

  it("never claims an update for a development build", () => {
    const dev = { ...base, version: "v0.8.0-3-gabc1234", latest: "v0.9.0", update_available: true }
    expect(hasUpdate(dev)).toBe(false)
    expect(describeVersion(dev)).toMatch(/development build/)
    expect(hasUpdate({ ...base, latest: "v0.9.0", update_available: true })).toBe(true)
  })

  it("explains each state of the check in one sentence", () => {
    expect(describeVersion(base)).toBe("SuckerPot v0.8.0 is up to date.")
    expect(describeVersion({ ...base, latest: "v0.9.0", update_available: true })).toBe(
      "SuckerPot v0.9.0 is available. You are running v0.8.0.",
    )
    expect(describeVersion({ ...base, check: "off" })).toMatch(/checks are off/)
    expect(describeVersion({ ...base, check: "no_egress" })).toMatch(/gate is closed/)
    expect(describeVersion({ ...base, check: "error" })).toMatch(/failed/)
    expect(describeVersion({ ...base, check: "pending" })).toMatch(/not run yet/)
  })

  it("links only to https release pages", () => {
    expect(safeReleaseUrl("https://example.org/r")).toBe("https://example.org/r")
    expect(safeReleaseUrl("javascript:alert(1)")).toBeNull()
    expect(safeReleaseUrl("http://example.org/r")).toBeNull()
    expect(safeReleaseUrl(null)).toBeNull()
  })
})
