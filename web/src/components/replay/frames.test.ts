import { describe, expect, it } from "vitest"
import type { SensorEvent } from "@/lib/api"
import {
  buildSteps,
  maskPreservingLength,
  parseFrames,
  reconstructFrames,
  replayFromEvents,
  type Frame,
} from "./frames"

let nextId = 1
function ev(type: string, ts: string, data: Record<string, unknown>): SensorEvent {
  return {
    id: nextId++,
    ts,
    sensor: "ssh",
    session_id: "S1",
    type,
    src_ip: "203.0.113.9",
    src_port: 40000,
    dst_port: 22,
    country: null,
    city: null,
    asn: null,
    org: null,
    abuse_score: null,
    known_scanner: null,
    tags: [],
    data,
  }
}

describe("parseFrames", () => {
  it("accepts well-formed frames and skips malformed ones", () => {
    const raw = [
      [0.1, "o", "hi"],
      [1, "x", "no"],
      ["a", "o", "no"],
      [1, "i", 5],
      "str",
      [2, "i", "ls\r"],
    ]
    expect(parseFrames(raw)).toEqual([
      [0.1, "o", "hi"],
      [2, "i", "ls\r"],
    ])
  })
  it("returns null for non-arrays and clamps absurd deltas", () => {
    expect(parseFrames({ nope: 1 })).toBeNull()
    expect(parseFrames(undefined)).toBeNull()
    expect(
      parseFrames([
        [-4, "o", "a"],
        [1e12, "o", "b"],
      ]),
    ).toEqual([
      [0, "o", "a"],
      [3600, "o", "b"],
    ])
  })
})

describe("buildSteps", () => {
  it("accumulates time across input and output frames and writes only output", () => {
    const frames: Frame[] = [
      [0.5, "o", "$ "],
      [1, "i", "l"],
      [0.1, "o", "l"],
      [0.2, "o", "s\r\n"],
    ]
    expect(buildSteps(frames)).toEqual([
      { at: 0.5, data: "$ " },
      { at: 1.6, data: "l" },
      { at: 1.8, data: "s\r\n" },
    ])
  })

  it("sanitises hostile sequences, also when split across frames", () => {
    const frames: Frame[] = [
      [0, "o", "ok\x1b]52;c;QUJD"],
      [0.1, "o", "\x07\x1b[31mred\x1b[6n"],
    ]
    const out = buildSteps(frames)
      .map((s) => s.data)
      .join("")
    expect(out).toBe("ok\x1b[31mred")
  })

  it("shows an exec command that has no echo as a prompt line", () => {
    const frames: Frame[] = [
      [0.2, "i", "uname -a\n"],
      [0.3, "o", "Linux srv-web01\r\n"],
    ]
    const steps = buildSteps(frames)
    expect(steps).toHaveLength(2)
    expect(steps[0]?.data).toContain("uname -a")
  })

  it("does not duplicate typed input that is already echoed", () => {
    const frames: Frame[] = [
      [0.2, "i", "ls"],
      [0.0, "o", "ls"],
    ]
    expect(buildSteps(frames)).toHaveLength(1)
  })

  it("masks IPv4 addresses, even typed one character at a time", () => {
    const text = "ssh 203.0.113.42"
    const frames: Frame[] = Array.from(text, (ch, i): Frame => [i === 0 ? 0 : 0.05, "o", ch])
    const out = buildSteps(frames, { mask: true })
    expect(out.map((s) => s.data).join("")).toBe("ssh 203.0.xxx.xx")
    expect(out).toHaveLength(frames.length)
    expect(out.map((s) => s.at)).toEqual(buildSteps(frames).map((s) => s.at))
  })

  it("leaves non-address text alone when masking", () => {
    expect(maskPreservingLength("Linux 6.8.0-45 x86_64 v1.2.3")).toBe(
      "Linux 6.8.0-45 x86_64 v1.2.3",
    )
  })
})

describe("reconstructFrames", () => {
  const events = [
    ev("connect", "2026-10-24T10:00:00Z", {}),
    ev("command", "2026-10-24T10:00:05Z", {
      input: "uname -a",
      output: "Linux srv-web01 6.8.0",
      prompt: "root@srv-web01:~# ",
      status: 0,
    }),
    ev("command", "2026-10-24T10:00:09Z", { input: "id", output: "uid=0(root)\n", status: 0 }),
  ]

  it("rebuilds prompt, typing at about 30 ms per character, then output", () => {
    const frames = reconstructFrames(events)
    const text = frames.map((f) => f[2]).join("")
    expect(text).toBe(
      "root@srv-web01:~# uname -a\r\nLinux srv-web01 6.8.0\r\n$ id\r\nuid=0(root)\r\n$ ",
    )
    const typed = frames.filter((f) => f[2].length === 1 && f[1] === "o")
    expect(typed.length).toBeGreaterThan(8)
    expect(typed.every((f) => f[0] === 0.03 || f[0] === 0.3)).toBe(true)
  })

  it("keeps the gaps between commands", () => {
    const steps = buildSteps(reconstructFrames(events))
    const total = steps.at(-1)?.at ?? 0
    expect(total).toBeGreaterThan(5)
    expect(total).toBeLessThan(7)
  })

  it("is empty without command events", () => {
    expect(reconstructFrames([ev("connect", "2026-10-24T10:00:00Z", {})])).toEqual([])
  })
})

describe("replayFromEvents", () => {
  const cmd = ev("command", "2026-10-24T10:00:05Z", { input: "id", output: "uid=0(root)" })

  it("prefers the recorded stream and reports truncation", () => {
    const disc = ev("disconnect", "2026-10-24T10:01:00Z", {
      replay: [[0.1, "o", "hello"]],
      replay_truncated: true,
    })
    const r = replayFromEvents([cmd, disc])
    expect(r).toMatchObject({ truncated: true, reconstructed: false })
    expect(r?.frames).toHaveLength(1)
  })

  it("falls back to commands when there is no usable recording", () => {
    for (const data of [{}, { replay: [] }, { replay: "garbage" }, { replay: [[1, "i", "x"]] }]) {
      const r = replayFromEvents([cmd, ev("disconnect", "2026-10-24T10:01:00Z", data)])
      expect(r?.reconstructed).toBe(true)
    }
  })

  it("is null when there is nothing to replay", () => {
    expect(replayFromEvents([ev("connect", "2026-10-24T10:00:00Z", {})])).toBeNull()
  })
})
