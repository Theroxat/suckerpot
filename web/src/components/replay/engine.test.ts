import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { ReplayEngine, type ReplaySink } from "./engine"
import type { Step } from "./frames"

function makeSink() {
  const writes: string[] = []
  let resets = 0
  const sink: ReplaySink = {
    write: (d) => {
      writes.push(d)
    },
    reset: () => {
      resets++
    },
  }
  return { sink, writes, resets: () => resets }
}

// Absolute times: a at 0.5 s, b at 1.5 s, c at 11.5 s (a 10 s idle gap), d at 12 s.
const STEPS: Step[] = [
  { at: 0.5, data: "a" },
  { at: 1.5, data: "b" },
  { at: 11.5, data: "c" },
  { at: 12, data: "d" },
]

describe("ReplayEngine", () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it("writes steps at their recorded times", () => {
    const { sink, writes } = makeSink()
    const e = new ReplayEngine(STEPS, sink)
    e.play()
    vi.advanceTimersByTime(499)
    expect(writes).toEqual([])
    vi.advanceTimersByTime(2)
    expect(writes).toEqual(["a"])
    vi.advanceTimersByTime(1000)
    expect(writes).toEqual(["a", "b"])
    vi.advanceTimersByTime(10_000)
    expect(writes.join("")).toBe("abc")
    vi.advanceTimersByTime(500)
    expect(writes.join("")).toBe("abcd")
    expect(e.playing).toBe(false)
    expect(e.ended).toBe(true)
    expect(e.position()).toBe(12)
  })

  it("pauses and resumes without losing time", () => {
    const { sink, writes } = makeSink()
    const e = new ReplayEngine(STEPS, sink)
    e.play()
    vi.advanceTimersByTime(1000)
    e.pause()
    expect(writes.join("")).toBe("a")
    expect(e.position()).toBeCloseTo(1, 2)
    vi.advanceTimersByTime(60_000)
    expect(writes.join("")).toBe("a")
    e.play()
    vi.advanceTimersByTime(499)
    expect(writes.join("")).toBe("a")
    vi.advanceTimersByTime(2)
    expect(writes.join("")).toBe("ab")
  })

  it.each([
    [0.5, 4000],
    [2, 1000],
    [4, 500],
  ])("speed %sx stretches or shrinks the wait", (speed, ms) => {
    const { sink, writes } = makeSink()
    const e = new ReplayEngine([{ at: 2, data: "x" }], sink, { speed })
    e.play()
    vi.advanceTimersByTime(ms - 5)
    expect(writes).toEqual([])
    vi.advanceTimersByTime(10)
    expect(writes).toEqual(["x"])
  })

  it("re-anchors when the speed changes mid-flight", () => {
    const { sink, writes } = makeSink()
    const e = new ReplayEngine([{ at: 4, data: "x" }], sink)
    e.play()
    vi.advanceTimersByTime(2000) // 2 s of replay played, 2 s left
    e.setSpeed(4) // 0.5 s of wall clock left
    vi.advanceTimersByTime(490)
    expect(writes).toEqual([])
    vi.advanceTimersByTime(20)
    expect(writes).toEqual(["x"])
  })

  it("skip idle caps every gap at one second", () => {
    const { sink, writes } = makeSink()
    const e = new ReplayEngine(STEPS, sink, { skipIdle: true })
    // a 0.5, b 1.5, c capped to 2.5, d 3.0
    expect(e.duration).toBe(3)
    e.play()
    vi.advanceTimersByTime(2600)
    expect(writes.join("")).toBe("abc")
    vi.advanceTimersByTime(500)
    expect(writes.join("")).toBe("abcd")
  })

  it("toggling skip idle keeps the playhead on the same step", () => {
    const { sink, writes } = makeSink()
    const e = new ReplayEngine(STEPS, sink)
    e.play()
    vi.advanceTimersByTime(2000)
    expect(writes.join("")).toBe("ab")
    e.setSkipIdle(true)
    expect(e.position()).toBeCloseTo(1.5, 2)
    vi.advanceTimersByTime(1100)
    expect(writes.join("")).toBe("abc")
  })

  it("seeking forward writes everything due as one batch", () => {
    const { sink, writes, resets } = makeSink()
    const e = new ReplayEngine(STEPS, sink)
    e.seek(2)
    expect(writes).toEqual(["ab"])
    expect(resets()).toBe(0)
    expect(e.position()).toBe(2)
  })

  it("seeking backward resets the terminal and rewrites up to the target", () => {
    const { sink, writes, resets } = makeSink()
    const e = new ReplayEngine(STEPS, sink)
    e.seek(12)
    e.seek(1)
    expect(resets()).toBe(1)
    expect(writes).toEqual(["abcd", "a"])
  })

  it("clamps seeks to the timeline", () => {
    const { sink } = makeSink()
    const e = new ReplayEngine(STEPS, sink)
    e.seek(-5)
    expect(e.position()).toBe(0)
    e.seek(999)
    expect(e.position()).toBe(12)
  })

  it("keeps playing after a seek while playing", () => {
    const { sink, writes } = makeSink()
    const e = new ReplayEngine(STEPS, sink)
    e.play()
    e.seek(1)
    expect(writes.join("")).toBe("a")
    vi.advanceTimersByTime(600)
    expect(writes.join("")).toBe("ab")
  })

  it("restart replays from the beginning, also after the end", () => {
    const { sink, writes, resets } = makeSink()
    const e = new ReplayEngine(STEPS, sink)
    e.seek(12)
    e.restart()
    expect(resets()).toBe(1)
    expect(e.playing).toBe(true)
    vi.advanceTimersByTime(600)
    expect(writes.slice(1).join("")).toBe("a")
  })

  it("play at the end starts over", () => {
    const { sink } = makeSink()
    const e = new ReplayEngine(STEPS, sink)
    e.seek(12)
    e.play()
    expect(e.position()).toBeCloseTo(0, 2)
    expect(e.playing).toBe(true)
  })

  it("notifies subscribers and stops after dispose", () => {
    const { sink, writes } = makeSink()
    const e = new ReplayEngine(STEPS, sink)
    const spy = vi.fn()
    e.subscribe(spy)
    e.play()
    e.pause()
    expect(spy).toHaveBeenCalledTimes(2)
    e.play()
    e.dispose()
    vi.advanceTimersByTime(60_000)
    expect(writes).toEqual([])
  })

  it("handles an empty replay", () => {
    const { sink } = makeSink()
    const e = new ReplayEngine([], sink)
    expect(e.duration).toBe(0)
    e.play()
    expect(e.playing).toBe(false)
  })
})
