import type { Step } from "./frames"

export interface ReplaySink {
  write(data: string): void
  /** Clear the terminal (used before replaying from an earlier point). */
  reset(): void
}

export interface EngineOptions {
  speed?: number
  /** Cap every pause between writes at `idleCap` seconds. */
  skipIdle?: boolean
  idleCap?: number
  /** Clock in milliseconds; injectable for tests. */
  now?: () => number
}

export const SPEEDS = [0.5, 1, 2, 4] as const

/**
 * Plays timed writes into a sink. Pure timing logic, no DOM: one timer is
 * armed for the next step, speed changes and seeks re-anchor the clock, and
 * "skip idle" compresses the timeline so no gap exceeds `idleCap` seconds.
 */
export class ReplayEngine {
  private readonly listeners = new Set<() => void>()
  private readonly now: () => number
  private times: number[] = []
  private cursor = 0
  private base = 0
  private anchor = 0
  private timer: ReturnType<typeof setTimeout> | null = null
  private _playing = false
  private _speed: number
  private _skipIdle: boolean
  private readonly idleCap: number

  constructor(
    private readonly steps: readonly Step[],
    private readonly sink: ReplaySink,
    opts: EngineOptions = {},
  ) {
    this.now = opts.now ?? (() => performance.now())
    this._speed = opts.speed ?? 1
    this._skipIdle = opts.skipIdle ?? false
    this.idleCap = opts.idleCap ?? 1
    this.times = this.computeTimes()
  }

  get playing(): boolean {
    return this._playing
  }
  get speed(): number {
    return this._speed
  }
  get skipIdle(): boolean {
    return this._skipIdle
  }
  /** Total length of the (possibly compressed) timeline, in seconds. */
  get duration(): number {
    return this.times.at(-1) ?? 0
  }
  get ended(): boolean {
    return this.cursor >= this.steps.length
  }

  /** Current position in seconds, advancing smoothly while playing. */
  position(): number {
    if (!this._playing) return this.base
    return Math.min(this.duration, this.base + ((this.now() - this.anchor) / 1000) * this._speed)
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  play(): void {
    if (this._playing) return
    if (this.ended) this.seekTo(0)
    this._playing = true
    this.anchor = this.now()
    this.schedule()
    this.emit()
  }

  pause(): void {
    if (!this._playing) return
    this.base = this.position()
    this._playing = false
    this.clearTimer()
    this.emit()
  }

  toggle(): void {
    if (this._playing) this.pause()
    else this.play()
  }

  restart(): void {
    this.seekTo(0)
    this.play()
  }

  seek(seconds: number): void {
    this.seekTo(seconds)
    this.emit()
  }

  /** Jump relative to the current position. */
  skip(deltaSeconds: number): void {
    this.seek(this.position() + deltaSeconds)
  }

  setSpeed(speed: number): void {
    this.base = this.position()
    this.anchor = this.now()
    this._speed = speed
    if (this._playing) this.schedule()
    this.emit()
  }

  setSkipIdle(on: boolean): void {
    if (on === this._skipIdle) return
    const wasPlaying = this._playing
    this.clearTimer()
    this._skipIdle = on
    this.times = this.computeTimes()
    // Keep the same step; the position follows the new timeline.
    this.base = this.cursor > 0 ? (this.times[this.cursor - 1] ?? 0) : 0
    this.anchor = this.now()
    if (wasPlaying) this.schedule()
    this.emit()
  }

  dispose(): void {
    this.clearTimer()
    this._playing = false
    this.listeners.clear()
  }

  private computeTimes(): number[] {
    const out: number[] = []
    let t = 0
    let prev = 0
    for (const s of this.steps) {
      const gap = Math.max(0, s.at - prev)
      prev = s.at
      t += this._skipIdle ? Math.min(gap, this.idleCap) : gap
      out.push(t)
    }
    return out
  }

  private seekTo(seconds: number): void {
    const target = Math.min(Math.max(seconds, 0), this.duration)
    this.clearTimer()
    let end = this.cursor
    while (end > 0 && (this.times[end - 1] ?? 0) > target) end--
    if (end < this.cursor) {
      this.sink.reset()
      this.cursor = 0
    }
    this.flushUpTo(target)
    this.base = target
    this.anchor = this.now()
    if (this._playing) this.schedule()
  }

  /** Write every pending step that is due at `t`, as one batch. */
  private flushUpTo(t: number): void {
    let data = ""
    while (this.cursor < this.steps.length && (this.times[this.cursor] ?? Infinity) <= t) {
      data += this.steps[this.cursor]?.data ?? ""
      this.cursor++
    }
    if (data) this.sink.write(data)
  }

  private schedule(): void {
    this.clearTimer()
    if (this.ended) {
      this.base = this.duration
      this._playing = false
      return
    }
    const due = this.times[this.cursor] ?? this.duration
    const delay = Math.max(0, ((due - this.position()) / this._speed) * 1000)
    this.timer = setTimeout(() => this.fire(), delay)
  }

  private fire(): void {
    this.timer = null
    if (!this._playing) return
    // A hair of tolerance so a timer that fires a few ms early still writes its step.
    this.flushUpTo(this.position() + 0.005)
    if (this.ended) {
      this.base = this.duration
      this._playing = false
      this.emit()
      return
    }
    this.schedule()
  }

  private clearTimer(): void {
    if (this.timer !== null) clearTimeout(this.timer)
    this.timer = null
  }

  private emit(): void {
    for (const l of [...this.listeners]) l()
  }
}
