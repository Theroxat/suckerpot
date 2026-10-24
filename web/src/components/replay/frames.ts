import type { SensorEvent } from "@/lib/api"
import { ReplaySanitizer, sanitizeStream } from "./sanitize"

/** asciicast-v2-like frame: [seconds since the previous frame, "o" output | "i" typed input, text]. */
export type Frame = readonly [delta: number, kind: "o" | "i", text: string]

/** A replay ready to be played, and where it came from. */
export interface ReplaySource {
  frames: readonly Frame[]
  /** Older frames were dropped by the sensor (12 KiB cap). */
  truncated: boolean
  /** Built from `command` events because the raw stream was not recorded. */
  reconstructed: boolean
}

/** One timed write to the terminal. `at` is seconds since the start of the replay. */
export interface Step {
  at: number
  data: string
}

const MAX_FRAMES = 20_000
const MAX_DELTA_S = 3600
const MAX_FRAME_CHARS = 64 * 1024

/** Seconds per typed character when a replay is rebuilt from commands. */
export const TYPING_SECONDS_PER_CHAR = 0.03

/** Validate untrusted JSON into frames. Anything that is not a well-formed frame is skipped. */
export function parseFrames(raw: unknown): Frame[] | null {
  if (!Array.isArray(raw)) return null
  const out: Frame[] = []
  for (const item of raw) {
    if (out.length >= MAX_FRAMES) break
    if (!Array.isArray(item) || item.length < 3) continue
    const [delta, kind, text] = item as unknown[]
    if (typeof delta !== "number" || !Number.isFinite(delta)) continue
    if ((kind !== "o" && kind !== "i") || typeof text !== "string") continue
    out.push([Math.min(Math.max(delta, 0), MAX_DELTA_S), kind, text.slice(0, MAX_FRAME_CHARS)])
  }
  return out
}

function str(v: unknown, max = 4000): string {
  return typeof v === "string" ? v.slice(0, max) : ""
}

/** Turn an output block into terminal text: LF becomes CR LF, and it ends on a fresh line. */
function toTerminal(output: string): string {
  if (!output) return ""
  const text = output.replace(/\r?\n/g, "\r\n")
  return text.endsWith("\r\n") ? text : `${text}\r\n`
}

/**
 * Rebuild a replay from `command` events: the prompt, the command typed at
 * ~30 ms per character, then its output. Used when no raw stream was kept.
 */
export function reconstructFrames(events: readonly SensorEvent[]): Frame[] {
  const commands = events
    .filter((e) => e.type === "command")
    .sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts) || a.id - b.id)
  const frames: Frame[] = []
  let prev: number | null = null
  for (const e of commands) {
    const input = str(e.data.input, 1000)
    const prompt = str(e.data.prompt, 200) || "$ "
    const ts = Date.parse(e.ts)
    const gap = prev === null || Number.isNaN(ts) ? 0.6 : Math.max(0, (ts - prev) / 1000)
    const typing = input.length * TYPING_SECONDS_PER_CHAR + 0.25
    frames.push([Math.max(0.2, gap - typing), "o", prompt])
    // Typing starts a beat after the prompt, then one frame per character.
    let first = true
    for (const ch of input) {
      frames.push([first ? 0.3 : TYPING_SECONDS_PER_CHAR, "o", ch])
      first = false
    }
    frames.push([0.25, "o", "\r\n"])
    const output = toTerminal(str(e.data.output, 16_000))
    if (output) frames.push([0.1, "o", output])
    if (!Number.isNaN(ts)) prev = ts
  }
  const last = commands.at(-1)
  if (last) frames.push([0.5, "o", str(last.data.prompt, 200) || "$ "])
  return frames
}

/** Pick the best replay for a session: the raw recording, else one rebuilt from commands. */
export function replayFromEvents(events: readonly SensorEvent[]): ReplaySource | null {
  const disconnect = events.findLast((e) => e.type === "disconnect")
  const recorded = parseFrames(disconnect?.data.replay)
  if (recorded?.some(([, kind, text]) => kind === "o" && text.length > 0)) {
    return {
      frames: recorded,
      truncated: disconnect?.data.replay_truncated === true,
      reconstructed: false,
    }
  }
  const rebuilt = reconstructFrames(events)
  if (rebuilt.length > 0) return { frames: rebuilt, truncated: false, reconstructed: true }
  return null
}

const IPV4 = /\b(\d{1,3}\.\d{1,3}\.)(\d{1,3})\.(\d{1,3})\b/g

/**
 * Hide the last two octets of every IPv4 address, keeping the text length so
 * the frame boundaries (and typed-out addresses split over many frames) stay valid.
 */
export function maskPreservingLength(text: string): string {
  return text.replace(
    IPV4,
    (_m, head: string, c: string, d: string) =>
      `${head}${"x".repeat(c.length)}.${"x".repeat(d.length)}`,
  )
}

/**
 * Turn frames into timed, sanitised terminal writes. Only output frames are
 * written (the echo of typed input is part of the output). A typed input
 * with no echo in the stream (an `exec` command) is shown as a prompt line.
 */
export function buildSteps(frames: readonly Frame[], opts: { mask?: boolean } = {}): Step[] {
  const echoed = frames
    .filter(([, kind]) => kind === "o")
    .map(([, , text]) => text)
    .join("")
  const sanitizer = new ReplaySanitizer()
  const steps: Step[] = []
  let at = 0
  for (const [delta, kind, text] of frames) {
    at += delta
    let data = ""
    if (kind === "o") {
      data = sanitizer.push(text)
    } else {
      const typed = sanitizeStream(text).replace(/[\r\n]+$/, "")
      if (typed.trim().length > 1 && !echoed.includes(typed.trim())) {
        data = `\x1b[2m$ \x1b[0m${typed}\r\n`
      }
    }
    if (data) steps.push({ at, data })
  }
  if (!opts.mask) return steps
  const masked = maskPreservingLength(steps.map((s) => s.data).join(""))
  let offset = 0
  return steps.map((s) => {
    const data = masked.slice(offset, offset + s.data.length)
    offset += s.data.length
    return { at: s.at, data }
  })
}

export function formatClockTime(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`
}
