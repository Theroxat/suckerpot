import { describe, expect, it } from "vitest"
import type { TodayItem } from "./today"
import { countUnit, isCodeLike, itemLabel, MAX_ITEMS, newField, visibleItems } from "./today-view"

const item = (over: Partial<TodayItem>): TodayItem => ({
  kind: "sensor",
  value: "ssh",
  label: "Most targeted: SSH",
  detail: null,
  count: 10,
  to: "/attacks?sensor=ssh",
  ...over,
})

describe("itemLabel", () => {
  it("spells out a country code", () => {
    const it = item({ kind: "country", value: "NL", label: "Most active country: NL" })
    expect(itemLabel(it, false)).toBe("Most active country: Netherlands")
  })

  it("keeps an unknown code as it is", () => {
    const it = item({ kind: "country", value: "ZZ", label: "Most active country: ZZ" })
    expect(itemLabel(it, false)).toBe("Most active country: ZZ")
  })

  it("masks addresses on request", () => {
    const it = item({ kind: "session", label: "203.0.113.42 on SSH" })
    expect(itemLabel(it, false)).toBe("203.0.113.42 on SSH")
    expect(itemLabel(it, true)).toBe("203.0.x.x on SSH")
  })
})

describe("card items", () => {
  it("never shows more than three", () => {
    const many = Array.from({ length: 6 }, (_, i) => item({ value: String(i) }))
    expect(visibleItems(many)).toHaveLength(MAX_ITEMS)
    expect(MAX_ITEMS).toBe(3)
  })

  it("sets indicators in the monospace face", () => {
    expect(isCodeLike(item({ kind: "host" }))).toBe(true)
    expect(isCodeLike(item({ kind: "campaign" }))).toBe(false)
  })
})

describe("item numbers", () => {
  it("say what they count", () => {
    expect(countUnit(item({ kind: "sensor", count: 82 }))).toBe("sessions")
    expect(countUnit(item({ kind: "host", count: 1 }))).toBe("sighting")
    expect(countUnit(item({ kind: "new", count: 41 }))).toBe("times")
  })

  it("hide a number the detail line already gives", () => {
    expect(countUnit(item({ kind: "campaign", count: 37 }))).toBeNull()
    expect(countUnit(item({ kind: "sensor", count: null }))).toBeNull()
  })

  it("read the field of a first-seen item", () => {
    expect(newField(item({ kind: "new", value: "url:/cgi-bin/luci" }))).toBe("url")
    expect(newField(item({ kind: "sensor", value: "ssh" }))).toBeNull()
  })
})
