import { beforeEach, describe, expect, it } from "vitest"
import {
  cleanQuery,
  hitHref,
  loadRecent,
  MAX_QUERY,
  orderedGroups,
  rememberSearch,
  type SearchGroup,
  type SearchHit,
} from "./search"

const hit = (kind: SearchHit["kind"], value: string): SearchHit => ({
  kind,
  value,
  label: value,
  detail: null,
  count: null,
  last_seen: null,
  benign: false,
})
const group = (kind: SearchGroup["kind"], ...values: string[]): SearchGroup => ({
  kind,
  hits: values.map((v) => hit(kind, v)),
  more: false,
})

describe("hitHref", () => {
  it("opens an existing view for every kind, never an outside site", () => {
    expect(hitHref(hit("ip", "203.0.113.7"))).toBe("/attackers/203.0.113.7")
    expect(hitHref(hit("ip", "2001:db8::7"))).toBe("/attackers/2001%3Adb8%3A%3A7")
    expect(hitHref(hit("campaign", "41"))).toBe("/campaigns/41")
    expect(hitHref(hit("cve", "CVE-2099-10001"))).toBe("/cves?cve=CVE-2099-10001")
    expect(hitHref(hit("hash", "12"))).toBe("/infrastructure?indicator=12")
    expect(hitHref(hit("domain", "7"))).toBe("/infrastructure?indicator=7")
  })

  it("escapes what it puts in the URL", () => {
    expect(hitHref(hit("campaign", "a/b?c"))).toBe("/campaigns/a%2Fb%3Fc")
  })
})

describe("orderedGroups", () => {
  it("shows groups in a fixed order and drops empty ones", () => {
    const groups = orderedGroups({
      q: "x",
      groups: [
        group("domain", "7"),
        group("ip", "203.0.113.7"),
        group("cve"),
        group("campaign", "1"),
      ],
    })
    expect(groups.map((g) => g.kind)).toEqual(["ip", "campaign", "domain"])
    expect(orderedGroups(undefined)).toEqual([])
  })
})

describe("cleanQuery", () => {
  it("trims, collapses blanks and caps the length", () => {
    expect(cleanQuery("  mirai \n  loader\t")).toBe("mirai loader")
    expect(cleanQuery("x".repeat(500))).toHaveLength(MAX_QUERY)
  })
})

describe("recent searches", () => {
  beforeEach(() => localStorage.clear())

  it("remembers the last five, newest first, without duplicates", () => {
    for (const q of ["a1", "b2", "c3", "d4", "e5", "f6"]) rememberSearch(q)
    expect(rememberSearch("c3")).toEqual(["c3", "f6", "e5", "d4", "b2"])
    expect(loadRecent()).toEqual(["c3", "f6", "e5", "d4", "b2"])
  })

  it("ignores anything in storage that is not a short string list", () => {
    localStorage.setItem(
      "suckerpot.recentSearches",
      JSON.stringify([1, "ok", "x".repeat(300), null]),
    )
    expect(loadRecent()).toEqual(["ok"])
    localStorage.setItem("suckerpot.recentSearches", "{not json")
    expect(loadRecent()).toEqual([])
    localStorage.setItem("suckerpot.recentSearches", JSON.stringify({ a: 1 }))
    expect(loadRecent()).toEqual([])
  })
})
