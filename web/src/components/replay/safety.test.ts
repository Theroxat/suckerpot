import { describe, expect, it } from "vitest"

/**
 * Guard for the replay safety contract: attacker-controlled terminal data must
 * never be wired to anything. If one of these tests fails, read
 * sanitize.ts and ask for a security review before "fixing" the test.
 */
const sources = import.meta.glob<string>(["./*.ts", "./*.tsx", "!./*.test.ts", "!./*.test.tsx"], {
  query: "?raw",
  import: "default",
  eager: true,
})

const FORBIDDEN: [string, RegExp][] = [
  ["terminal input listener", new RegExp("on" + "Data|on" + "Binary")],
  ["clipboard add-on", new RegExp("addon-" + "clipboard|Clipboard" + "Addon", "i")],
  ["link add-on", new RegExp("addon-web-" + "links|WebLinks" + "Addon", "i")],
  ["image add-on", new RegExp("addon-" + "image|addon-" + "sixel|Image" + "Addon", "i")],
  ["raw html", new RegExp("dangerously" + "SetInnerHTML|inner" + "HTML")],
  ["window.open", new RegExp("window\\.open|location\\.href")],
]

describe("replay safety contract", () => {
  it("found the replay sources", () => {
    expect(Object.keys(sources).length).toBeGreaterThanOrEqual(4)
  })

  for (const [name, pattern] of FORBIDDEN) {
    it(`never uses a ${name}`, () => {
      for (const [file, text] of Object.entries(sources)) {
        expect(pattern.test(text), `${file} matches ${pattern}`).toBe(false)
      }
    })
  }

  it("keeps the terminal read-only", () => {
    expect(sources["./terminal-replay.tsx"]).toMatch(/disableStdin:\s*true/)
  })

  it("never opens links from the terminal", () => {
    expect(sources["./terminal-replay.tsx"]).toMatch(
      /linkHandler:\s*\{\s*activate:\s*\(\)\s*=>\s*undefined/,
    )
  })
})
