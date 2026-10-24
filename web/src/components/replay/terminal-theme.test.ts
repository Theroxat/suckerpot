import { contrastRatio, parseHex } from "@/lib/contrast"
import { TERMINAL_BG, TERMINAL_THEME } from "./terminal-theme"

const TEXT_KEYS = [
  "foreground",
  "black",
  "red",
  "green",
  "yellow",
  "blue",
  "magenta",
  "cyan",
  "white",
  "brightBlack",
  "brightRed",
  "brightGreen",
  "brightYellow",
  "brightBlue",
  "brightMagenta",
  "brightCyan",
  "brightWhite",
] as const

describe("terminal palette", () => {
  it.each(TEXT_KEYS.map((k) => [k] as const))("%s is AA on the terminal background", (k) => {
    const c = TERMINAL_THEME[k]
    expect(c).toBeDefined()
    expect(contrastRatio(parseHex(c ?? ""), parseHex(TERMINAL_BG))).toBeGreaterThanOrEqual(4.5)
  })

  it("never reuses semantic red or sensor hues", () => {
    const semantic = ["#f2555a", "#c8242b", "#5ea6f7", "#3cc6a4", "#d98bcb", "#e0b341", "#4cc38a"]
    const used = (Object.values(TERMINAL_THEME) as unknown[])
      .filter((v): v is string => typeof v === "string")
      .map((v) => v.toLowerCase())
    for (const s of semantic) expect(used).not.toContain(s)
  })
})
