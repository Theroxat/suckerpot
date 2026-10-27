import { useRef, useState } from "react"
import { formatNumber } from "@/lib/format"
import { hhmm, bucketMs, bucketSentence, busiestBucket, type TimelineBucket } from "@/lib/story"
import { cn } from "@/lib/utils"

interface TimelineScrubberProps {
  timeline: readonly TimelineBucket[]
  className?: string
}

/**
 * The last day as a strip of bars, one per hour. Click, drag, or use the arrow keys to pick an
 * hour; one sentence says what happened in it. The part of a bar that went as far as an
 * install attempt or an exploit is the only red.
 */
export function TimelineScrubber({ timeline, className }: TimelineScrubberProps) {
  const ms = bucketMs(timeline)
  const [picked, setPicked] = useState<number | null>(null)
  const index = picked !== null && picked < timeline.length ? picked : busiestBucket(timeline)
  const strip = useRef<HTMLDivElement>(null)
  const dragging = useRef(false)
  const bucket = timeline[index]
  const max = Math.max(1, ...timeline.map((b) => b.sessions))
  const last = timeline.length - 1

  const pick = (clientX: number) => {
    const el = strip.current
    if (!el || timeline.length === 0) return
    const r = el.getBoundingClientRect()
    const i = Math.floor(((clientX - r.left) / Math.max(r.width, 1)) * timeline.length)
    setPicked(Math.min(last, Math.max(0, i)))
  }

  const sentence = bucket ? bucketSentence(bucket, ms) : ""
  const first = timeline[0]
  const end = timeline[last]

  return (
    <div className={className}>
      <p className="min-h-10 text-sm text-pretty text-fg tabular-nums" aria-live="polite">
        {sentence}
      </p>
      <div
        ref={strip}
        role="slider"
        tabIndex={0}
        aria-label="Pick an hour of the last day"
        aria-orientation="horizontal"
        aria-valuemin={0}
        aria-valuemax={last}
        aria-valuenow={index}
        aria-valuetext={sentence}
        className="mt-3 flex h-28 touch-none items-end gap-0.5 rounded-md outline-none select-none focus-visible:ring-2 focus-visible:ring-ring"
        onPointerDown={(e) => {
          dragging.current = true
          // jsdom has no pointer capture.
          if (typeof e.currentTarget.setPointerCapture === "function")
            e.currentTarget.setPointerCapture(e.pointerId)
          pick(e.clientX)
        }}
        onPointerMove={(e) => {
          if (dragging.current) pick(e.clientX)
        }}
        onPointerUp={() => {
          dragging.current = false
        }}
        onPointerCancel={() => {
          dragging.current = false
        }}
        onKeyDown={(e) => {
          const step: Record<string, number> = {
            ArrowLeft: -1,
            ArrowDown: -1,
            ArrowRight: 1,
            ArrowUp: 1,
          }
          let next: number | null = null
          if (e.key in step) next = index + (step[e.key] ?? 0)
          else if (e.key === "Home") next = 0
          else if (e.key === "End") next = last
          else if (e.key === "PageDown") next = index - 6
          else if (e.key === "PageUp") next = index + 6
          if (next === null) return
          e.preventDefault()
          setPicked(Math.min(last, Math.max(0, next)))
        }}
      >
        {timeline.map((b, i) => {
          const h = b.sessions === 0 ? 2 : Math.max(6, (b.sessions / max) * 100)
          const severeShare = b.sessions > 0 ? Math.min(1, b.severe / b.sessions) : 0
          return (
            <div key={b.start} className="flex h-full min-w-0 flex-1 items-end" aria-hidden>
              <div
                className={cn(
                  "flex w-full flex-col justify-end overflow-hidden rounded-t-xs transition-opacity duration-150",
                  i === index ? "opacity-100 ring-1 ring-fg" : "opacity-60",
                )}
                style={{ height: `${h}%` }}
                data-selected={i === index || undefined}
              >
                {severeShare > 0 ? (
                  <div className="min-h-0.5 bg-sev-severe" style={{ flexGrow: severeShare }} />
                ) : null}
                <div className="bg-fg-subtle" style={{ flexGrow: 1 - severeShare }} />
              </div>
            </div>
          )
        })}
      </div>
      {first && end ? (
        <div
          className="mt-1.5 flex justify-between text-xs text-fg-subtle tabular-nums"
          aria-hidden
        >
          <span>{hhmm(first.start)}</span>
          <span>peak {formatNumber(max)} visits per bar</span>
          <span>{hhmm(new Date(Date.parse(end.start) + ms))}</span>
        </div>
      ) : null}
    </div>
  )
}
