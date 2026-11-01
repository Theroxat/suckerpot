import { describe, expect, it } from "vitest"
import { describeSetup, normalizeSetup, safeHref, setupTitle, type SetupItem } from "./setup"

const item = (id: string, state: SetupItem["state"]): SetupItem => ({
  id,
  state,
  detail: "x",
  href: "/settings",
})

describe("setup checklist helpers", () => {
  it("accepts a list or an object with items, drops junk and orders known ids first", () => {
    const raw = [item("alerts", "off"), item("vpn", "ok"), { id: "x", state: "weird" }, null]
    expect(normalizeSetup(raw).map((i) => i.id)).toEqual(["vpn", "alerts"])
    expect(normalizeSetup({ items: [item("sensors", "ok"), item("zzz", "todo")] })).toHaveLength(2)
    expect(normalizeSetup({ items: [item("zzz", "todo"), item("sensors", "ok")] })[0]?.id).toBe(
      "sensors",
    )
    expect(normalizeSetup("nope")).toEqual([])
  })

  it("summarises in one sentence", () => {
    expect(describeSetup([])).toBe("There is nothing to check yet.")
    expect(describeSetup([item("a", "ok"), item("b", "ok")])).toBe("Everything is set up.")
    expect(
      describeSetup([item("a", "ok"), item("b", "warning"), item("c", "todo"), item("d", "todo")]),
    ).toBe("1 of 4 steps is done, 1 needs attention, 2 are still to do.")
  })

  it("only follows in-app links", () => {
    expect(safeHref("/settings?tab=vpn")).toBe("/settings?tab=vpn")
    expect(safeHref("https://example.com/")).toBeNull()
    expect(safeHref("//example.com")).toBeNull()
    expect(safeHref(null)).toBeNull()
  })

  it("titles unknown ids from the id", () => {
    expect(setupTitle("vpn")).toBe("Outbound gate")
    expect(setupTitle("some_new_item")).toBe("some new item")
  })
})
