import { describe, expect, it } from "vitest"
import { ReplaySanitizer, sanitizeStream } from "./sanitize"

const ESC = "\x1b"
const BEL = "\x07"
const ST = `${ESC}\\`

describe("ReplaySanitizer", () => {
  it("keeps text, line breaks, SGR colours and cursor movement", () => {
    const input = `${ESC}[01;32mroot@srv-web01${ESC}[0m:${ESC}[1;34m~${ESC}[0m# ls\r\n${ESC}[2K${ESC}[3D${ESC}[H`
    expect(sanitizeStream(input)).toBe(input)
  })

  it("keeps 256-colour and truecolour SGR, including colon sub-parameters", () => {
    const input = `${ESC}[38;5;196mred${ESC}[38;2;10;20;30mrgb${ESC}[4:3mcurly${ESC}[0m`
    expect(sanitizeStream(input)).toBe(input)
  })

  it("drops OSC 52 clipboard writes, with BEL and ST terminators", () => {
    expect(sanitizeStream(`a${ESC}]52;c;ZWNobyBwd25lZA==${BEL}b`)).toBe("ab")
    expect(sanitizeStream(`a${ESC}]52;c;ZWNobyBwd25lZA==${ST}b`)).toBe("ab")
    expect(sanitizeStream(`a${ESC}]52;c;?${BEL}b`)).toBe("ab")
  })

  it("drops OSC 8 hyperlinks but keeps their visible label", () => {
    const input = `${ESC}]8;;https://evil.example/x${ST}click me${ESC}]8;;${ST}`
    expect(sanitizeStream(input)).toBe("click me")
  })

  it("drops title-setting OSC 0, 1 and 2, and every other OSC", () => {
    for (const n of [0, 1, 2, 4, 10, 11, 104, 133, 777, 1337]) {
      expect(sanitizeStream(`x${ESC}]${n};payload${BEL}y`)).toBe("xy")
    }
  })

  it("drops DCS, APC, PM and SOS strings, including sixel and tmux passthrough", () => {
    expect(sanitizeStream(`a${ESC}Pq#0;2;0;0;0~-${ST}b`)).toBe("ab")
    expect(sanitizeStream(`a${ESC}Ptmux;${ESC}${ESC}]52;c;AAAA${BEL}${ST}b`)).toBe("ab")
    expect(sanitizeStream(`a${ESC}_Gf=100;AAAA${ST}b`)).toBe("ab")
    expect(sanitizeStream(`a${ESC}^privacy${ST}b${ESC}Xsos${ST}c`)).toBe("abc")
  })

  it("drops C1 single-character controls", () => {
    expect(sanitizeStream("a\u009d52;c;AAAA\u0007b")).toBe("a52;c;AAAAb")
    expect(sanitizeStream("a\u009b6nb\u0090qc")).toBe("a6nbqc")
  })

  it("drops terminal queries and mode changes", () => {
    for (const seq of [
      `${ESC}[c`,
      `${ESC}[>c`,
      `${ESC}[6n`,
      `${ESC}[?6n`,
      `${ESC}[?1049h`,
      `${ESC}[?2004h`,
      `${ESC}[?1000h`,
      `${ESC}[18t`,
      `${ESC}[21t`,
      `${ESC}[>0q`,
      `${ESC}[0 q`,
      `${ESC}[!p`,
      `${ESC}[=c`,
      `${ESC}[<u`,
      `${ESC}[5;1$p`,
    ]) {
      expect(sanitizeStream(`a${seq}b`), JSON.stringify(seq)).toBe("ab")
    }
  })

  it("drops full reset, charset selection and keypad mode escapes", () => {
    expect(sanitizeStream(`a${ESC}cb${ESC}(Bc${ESC}=d${ESC}>e${ESC}#8f`)).toBe("abcdef")
  })

  it("drops stray control characters but keeps tab, backspace, CR and LF", () => {
    expect(sanitizeStream("a\x00\x05\x07\x0b\x0c\x0e\x0f\x7fb\t\b\r\nc")).toBe("ab\t\b\r\nc")
  })

  it("clamps huge numeric parameters", () => {
    expect(sanitizeStream(`${ESC}[99999999C`)).toBe(`${ESC}[999C`)
  })

  it("handles a sequence split across frames", () => {
    const s = new ReplaySanitizer()
    const out = [`x${ESC}]5`, "2;c;AAAA", `${BEL}y${ESC}`, "[3", "1mz"]
      .map((c) => s.push(c))
      .join("")
    expect(out).toBe(`xy${ESC}[31mz`)
  })

  it("does not hide the rest of the stream after an unterminated string forever", () => {
    const out = sanitizeStream(`${ESC}]0;${"A".repeat(9000)}tail`)
    expect(out.endsWith("tail")).toBe(true)
    expect(out).not.toContain(ESC)
  })

  it("aborts a malformed CSI and keeps going", () => {
    expect(sanitizeStream(`${ESC}[12\nnext`)).toBe("\nnext")
    expect(sanitizeStream(`${ESC}[${"1;".repeat(100)}mok`)).not.toContain(ESC)
  })

  it("a new ESC inside a string restarts parsing (no smuggling through ST confusion)", () => {
    expect(sanitizeStream(`${ESC}]0;t${ESC}[31mred`)).toBe(`${ESC}[31mred`)
  })

  it("never lets an ESC through that is not part of a kept sequence", () => {
    const hostile = [
      `${ESC}]52;c;AAAA${BEL}`,
      `${ESC}]8;;x${ST}`,
      `${ESC}Pdata${ST}`,
      `${ESC}[?1049h`,
      `${ESC}c`,
    ].join("hello")
    const out = sanitizeStream(hostile)
    expect(out).toBe("hellohellohellohello")
  })
})
