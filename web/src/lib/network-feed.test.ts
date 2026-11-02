import { describe, expect, it } from "vitest"
import { buildStatus, ENTRIES, FEED_BASE_URL, type FeedScenario } from "@/mocks/network-feed"
import {
  FEED_FORMATS,
  FEED_LIST_IDS,
  FEED_STATES,
  describeFeedError,
  feedSentence,
  feedStatusLine,
  fileTier,
  formatsOf,
  isEmptyForNow,
  type FeedEntry,
  type FeedStatus,
} from "./network-feed"

const ISO = /^\d{4}-\d{2}-\d{2}T/
const DAY = /^\d{4}-\d{2}-\d{2}$/
// Documentation ranges and example.org only (RFC 5737, RFC 3849).
const DOC_V4 = /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/
const DOC_V6 = /^2001:db8:/
const DOC_HOST = /\.example\.org$/

const STATUS_KEYS = [
  "enabled_env",
  "configured",
  "state",
  "error_code",
  "serial",
  "generated_at",
  "valid_until",
  "last_ok_at",
  "signature",
  "member",
  "public_base_url",
  "lists",
  "local_mirror",
].sort()
const LIST_KEYS = ["id", "direction", "entries", "high", "seen_here", "helped", "files"].sort()
const FILE_KEYS = ["name", "format", "tier", "url"].sort()
const ENTRY_KEYS = [
  "list",
  "value",
  "family",
  "tier",
  "categories",
  "services",
  "tags",
  "families",
  "ports",
  "first_seen",
  "last_seen",
  "expires",
  "reported",
  "seen_here",
  "helped",
].sort()

const keys = (o: object) => Object.keys(o).sort()
const nullOr = (v: unknown, ok: (x: unknown) => boolean) => v === null || ok(v)
const isStr = (v: unknown) => typeof v === "string"

function checkStatus(s: FeedStatus) {
  expect(keys(s)).toEqual(STATUS_KEYS)
  expect(typeof s.enabled_env).toBe("boolean")
  expect(typeof s.configured).toBe("boolean")
  expect(FEED_STATES).toContain(s.state)
  expect(nullOr(s.error_code, isStr)).toBe(true)
  expect(nullOr(s.serial, Number.isInteger)).toBe(true)
  for (const t of [s.generated_at, s.valid_until, s.last_ok_at])
    expect(nullOr(t, (x) => ISO.test(x as string))).toBe(true)
  expect([null, "verified"]).toContain(s.signature)
  expect(typeof s.member).toBe("boolean")
  expect(nullOr(s.public_base_url, isStr)).toBe(true)
  expect(keys(s.local_mirror)).toEqual(["feeds_enabled"])
  expect(typeof s.local_mirror.feeds_enabled).toBe("boolean")
  expect(s.lists.map((l) => l.id)).toEqual([...FEED_LIST_IDS])
  for (const l of s.lists) {
    expect(keys(l)).toEqual(LIST_KEYS)
    expect(l.direction).toBe(l.id === "inbound" ? "inbound" : "outbound")
    expect(Number.isInteger(l.entries) && l.entries >= 0).toBe(true)
    expect(l.high).toBeLessThanOrEqual(l.entries)
    expect(l.seen_here).toBeLessThanOrEqual(l.entries)
    expect(nullOr(l.helped, Number.isInteger)).toBe(true)
    expect(l.helped === null).toBe(!s.member)
    for (const f of l.files) {
      expect(keys(f)).toEqual(FILE_KEYS)
      expect(FEED_FORMATS).toContain(f.format)
      expect(f.url).toBe(`${FEED_BASE_URL}/${f.name}`)
      expect(f.tier).toBe(f.name.includes("-high") ? "high" : "standard")
    }
  }
}

function checkEntry(e: FeedEntry) {
  expect(keys(e)).toEqual(ENTRY_KEYS)
  expect(FEED_LIST_IDS).toContain(e.list)
  expect([4, 6, null]).toContain(e.family)
  expect(["standard", "high"]).toContain(e.tier)
  for (const a of [e.categories, e.services, e.tags, e.families]) expect(a.every(isStr)).toBe(true)
  expect(e.ports.every(Number.isInteger)).toBe(true)
  for (const d of [e.first_seen, e.last_seen, e.expires]) expect(d).toMatch(DAY)
  expect(e.first_seen <= e.last_seen).toBe(true)
  expect(typeof e.reported).toBe("boolean")
  expect(typeof e.seen_here).toBe("boolean")
  expect(nullOr(e.helped, (x) => typeof x === "boolean")).toBe(true)
  // Documentation values only.
  if (e.family === 4) expect(e.value).toMatch(DOC_V4)
  else if (e.family === 6) expect(e.value).toMatch(DOC_V6)
  else expect(e.value).toMatch(DOC_HOST)
  expect(e.list === "outbound-domains").toBe(e.family === null)
}

const SCENARIOS: FeedScenario[] = ["ok", "off", "unconfigured", "never", "empty", "stale", "error"]

describe("network feed mocks match the contract", () => {
  it.each(SCENARIOS)("status, %s", (scenario) => {
    checkStatus(buildStatus(scenario, false))
    checkStatus(buildStatus(scenario, true))
  })

  it("every entry has the exact fields and only documentation values", () => {
    expect(ENTRIES.length).toBeGreaterThan(100)
    for (const e of ENTRIES) checkEntry(e)
  })

  it("list counts follow the entries", () => {
    for (const l of buildStatus("ok").lists) {
      const rows = ENTRIES.filter((e) => e.list === l.id)
      expect(l.entries).toBe(rows.length)
      expect(l.high).toBe(rows.filter((e) => e.tier === "high").length)
    }
  })
})

describe("sentences and files", () => {
  it("opens with the finding and the confirmation threshold", () => {
    expect(feedSentence(buildStatus("ok"))).toMatch(
      /^The Selfhostr network lists .* attack sources?, each confirmed by at least 5 independent sensors\./,
    )
  })

  it("says plainly that the lists are empty until enough members exist", () => {
    const s = buildStatus("empty")
    expect(isEmptyForNow(s)).toBe(true)
    expect(feedSentence(s)).toContain("empty for now")
  })

  it("warns on a stale or failed feed", () => {
    const fmt = () => "now"
    expect(feedStatusLine(buildStatus("stale"), fmt).tone).toBe("warning")
    expect(feedStatusLine(buildStatus("error"), fmt).detail).toMatch(/signature/)
    expect(feedStatusLine(buildStatus("ok"), fmt).detail).toBe("Signature verified")
  })

  it("splits files by tier from the file name", () => {
    const outbound = buildStatus("ok").lists.find((l) => l.id === "outbound")
    if (!outbound) throw new Error("no outbound list")
    expect(formatsOf(outbound, "high").every((f) => fileTier(f) === "high")).toBe(true)
    expect(formatsOf(outbound, "standard").map((f) => f.format)).toContain("stix")
  })
})

describe("error codes of the feed worker", () => {
  it("has a plain sentence for every code the worker stores", () => {
    for (const code of [
      "not_configured",
      "egress_closed",
      "bad_signature",
      "feed_rollback",
      "feed_expired",
      "feed_invalid",
      "too_large",
      "unreachable",
    ])
      expect(describeFeedError(code)).not.toBe("The last fetch failed.")
    expect(describeFeedError("http_503")).toContain("503")
    expect(describeFeedError(null)).toBeNull()
  })
})
