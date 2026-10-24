/**
 * Replay safety: the bytes of an attacker's terminal session are hostile data.
 * Before they reach the terminal emulator they go through this allow-list
 * filter. It keeps what is needed to show a session faithfully (printable
 * text, line breaks, SGR colours, cursor movement, line and screen erasing)
 * and drops everything else: OSC (clipboard writes, hyperlinks, title
 * changes, colour queries), DCS/APC/PM/SOS strings, terminal queries and
 * mode changes, C1 controls, and any control character that has no visual
 * meaning.
 *
 * It is a streaming filter: an escape sequence may be split across two
 * frames, so the state survives between calls to `push`.
 */

const ESC = 0x1b
const BEL = 0x07
const CAN = 0x18
const SUB = 0x1a

/** Longest CSI body (parameters + intermediates) we accept before giving up. */
const MAX_CSI_LENGTH = 48
/** Longest OSC/DCS-style string swallowed before the filter gives up on it. */
const MAX_STRING_LENGTH = 8192
/** Numeric CSI parameters above this are clamped (huge counts are never legitimate). */
const MAX_PARAM = 999

/** Visible C0 controls: backspace, tab, line feed, carriage return. */
const ALLOWED_C0 = new Set([0x08, 0x09, 0x0a, 0x0d])
/** Escape sequences without parameters that are kept: save/restore cursor, index, next line, reverse index. */
const KEPT_ESC_FINALS = new Set(["7", "8", "D", "E", "M"])
/** CSI final bytes that are kept: SGR, cursor movement, erase, insert/delete, scroll, save/restore cursor. */
const KEPT_CSI_FINALS = new Set("mABCDEFGHfd`JKLMPX@STsu".split(""))

type State = "ground" | "esc" | "esc-inter" | "csi" | "string" | "string-esc"

export class ReplaySanitizer {
  private state: State = "ground"
  private csi = ""
  private stringLength = 0

  reset(): void {
    this.state = "ground"
    this.csi = ""
    this.stringLength = 0
  }

  /** Filter the next chunk of the stream and return the safe text. */
  push(input: string): string {
    let out = ""
    for (let i = 0; i < input.length; i++) {
      const code = input.charCodeAt(i)
      out += this.step(input.charAt(i), code)
    }
    return out
  }

  private step(ch: string, code: number): string {
    switch (this.state) {
      case "ground":
        return this.ground(ch, code)
      case "esc":
        return this.escape(ch, code)
      case "esc-inter":
        if (code === ESC) this.state = "esc"
        else if (code >= 0x30 && code <= 0x7e) this.state = "ground"
        else if (code < 0x20 || code > 0x2f) this.state = "ground"
        return ""
      case "csi":
        return this.csiByte(ch, code)
      case "string":
        return this.stringByte(code)
      case "string-esc":
        if (code === 0x5c) {
          this.state = "ground"
          return ""
        }
        // ESC followed by anything else starts a new sequence.
        this.state = "esc"
        return this.escape(ch, code)
    }
  }

  private ground(ch: string, code: number): string {
    if (code === ESC) {
      this.state = "esc"
      return ""
    }
    if (code < 0x20) return ALLOWED_C0.has(code) ? ch : ""
    if (code === 0x7f) return ""
    // C1 controls (single-character CSI, OSC, DCS…) are never allowed.
    if (code >= 0x80 && code <= 0x9f) return ""
    return ch
  }

  private escape(ch: string, code: number): string {
    this.state = "ground"
    if (ch === "[") {
      this.state = "csi"
      this.csi = ""
      return ""
    }
    if (ch === "]" || ch === "P" || ch === "X" || ch === "^" || ch === "_") {
      this.state = "string"
      this.stringLength = 0
      return ""
    }
    if (KEPT_ESC_FINALS.has(ch)) return `\x1b${ch}`
    if (code === ESC) {
      this.state = "esc"
      return ""
    }
    if (code >= 0x20 && code <= 0x2f) this.state = "esc-inter"
    return ""
  }

  private stringByte(code: number): string {
    if (code === BEL || code === CAN || code === SUB) {
      this.state = "ground"
    } else if (code === ESC) {
      this.state = "string-esc"
    } else if (++this.stringLength > MAX_STRING_LENGTH) {
      this.state = "ground"
    }
    return ""
  }

  private csiByte(ch: string, code: number): string {
    if (code === ESC) {
      this.state = "esc"
      return ""
    }
    if (code === CAN || code === SUB) {
      this.state = "ground"
      return ""
    }
    if (code >= 0x40 && code <= 0x7e) {
      const body = this.csi
      this.csi = ""
      this.state = "ground"
      return this.finishCsi(body, ch)
    }
    if (code < 0x20 || code > 0x3f || this.csi.length >= MAX_CSI_LENGTH) {
      // Not a valid CSI: abandon it and treat this byte as ordinary input.
      this.csi = ""
      this.state = "ground"
      return this.ground(ch, code)
    }
    this.csi += ch
    return ""
  }

  /** Accept only plain numeric parameters (no ? < = > prefix, no intermediates). */
  private finishCsi(body: string, final: string): string {
    if (!KEPT_CSI_FINALS.has(final)) return ""
    if (!/^[0-9;:]*$/.test(body)) return ""
    const params = body.replace(/\d+/g, (n) => (Number(n) > MAX_PARAM ? String(MAX_PARAM) : n))
    return `\x1b[${params}${final}`
  }
}

/** One-shot helper: filter a complete stream. */
export function sanitizeStream(input: string): string {
  return new ReplaySanitizer().push(input)
}
