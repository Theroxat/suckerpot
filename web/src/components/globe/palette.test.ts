import { describe, expect, it } from "vitest"
import { withAlpha } from "./palette"

describe("withAlpha", () => {
  it("converts a hex colour", () => {
    expect(withAlpha("#5ea6f7", 0.5)).toBe("rgba(94,166,247,0.5)")
  })
  it("leaves other formats alone", () => {
    expect(withAlpha("red", 0.5)).toBe("red")
    expect(withAlpha("#fff", 0.5)).toBe("#fff")
  })
})
