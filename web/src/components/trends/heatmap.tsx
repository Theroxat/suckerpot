import { useMemo, useState } from "react"
import { Skeleton } from "@/components/ui/skeleton"
import { formatNumber, browserTimeZone } from "@/lib/format"
import {
  gridStep,
  hourLabel,
  toLocalGrid,
  WEEKDAYS,
  WEEKDAYS_LONG,
  type HeatGrid,
  type HeatmapCell,
} from "@/lib/trends"
import { cn } from "@/lib/utils"

/** Neutral sequential scale: the text colour mixed into the card surface, 5 steps. */
function stepColour(step: number): string {
  if (step <= 0) return "var(--surface-hover)"
  const mix = [14, 30, 48, 66, 84][step - 1] ?? 84
  return `color-mix(in srgb, var(--fg) ${mix}%, var(--surface))`
}

interface HeatmapProps {
  cells: readonly HeatmapCell[] | undefined
  /** UTC offset of the browser, in whole hours. */
  offsetHours: number
  loading?: boolean
  className?: string
}

/**
 * Day x hour grid in the browser's time zone. The darkness of a cell is a
 * neutral scale; the exact count is printed in the readout (hover, focus or tap)
 * and in the table that screen readers get.
 */
export function Heatmap({ cells, offsetHours, loading, className }: HeatmapProps) {
  const grid: HeatGrid = useMemo(() => toLocalGrid(cells ?? [], offsetHours), [cells, offsetHours])
  const max = Math.max(0, ...grid.flat())
  const [active, setActive] = useState<{ d: number; h: number } | null>(null)

  if (loading) return <Skeleton className="h-52 w-full" />

  const readout = active
    ? `${WEEKDAYS_LONG[active.d]}, ${hourLabel(active.h)}: ${formatNumber(grid[active.d]?.[active.h] ?? 0)} events`
    : "Hover or tap a cell for the exact count."

  return (
    <div className={className}>
      <div
        role="img"
        aria-label="Heatmap of events by day of the week and hour of the day. The same numbers are in the table below."
        className="grid grid-cols-[2.25rem_repeat(24,minmax(0,1fr))] gap-[2px] sm:gap-[3px]"
        onMouseLeave={() => setActive(null)}
      >
        {WEEKDAYS.map((d, di) => (
          <div key={d} className="contents">
            <span className="flex items-center text-2xs text-fg-subtle">{d}</span>
            {Array.from({ length: 24 }, (_, h) => {
              const n = grid[di]?.[h] ?? 0
              const on = active?.d === di && active.h === h
              return (
                <span
                  key={h}
                  title={`${WEEKDAYS_LONG[di]} ${hourLabel(h)}: ${formatNumber(n)}`}
                  onMouseEnter={() => setActive({ d: di, h })}
                  onClick={() => setActive({ d: di, h })}
                  className={cn(
                    "h-5 rounded-[3px] sm:h-6",
                    on && "ring-2 ring-fg ring-offset-1 ring-offset-surface",
                  )}
                  style={{ background: stepColour(gridStep(n, max)) }}
                />
              )
            })}
          </div>
        ))}
        <span aria-hidden />
        {Array.from({ length: 24 }, (_, h) => (
          <span
            key={h}
            aria-hidden
            className="mt-1 text-center text-2xs text-fg-subtle tabular-nums"
          >
            {h % 6 === 0 ? String(h).padStart(2, "0") : ""}
          </span>
        ))}
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-x-6 gap-y-2 text-xs text-fg-muted">
        <p aria-live="polite" className="min-h-4 tabular-nums">
          {readout}
        </p>
        <div className="flex items-center gap-2">
          <span>Fewer</span>
          <span aria-hidden className="flex gap-[2px]">
            {[0, 1, 2, 3, 4, 5].map((s) => (
              <span
                key={s}
                className="size-3 rounded-[3px]"
                style={{ background: stepColour(s) }}
              />
            ))}
          </span>
          <span>More</span>
        </div>
      </div>
      <p className="mt-1 text-2xs text-fg-subtle">
        Hours are shown in your time zone ({browserTimeZone()}).
      </p>

      <div className="sr-only">
        <table>
          <caption>Events by day of the week and hour, in your time zone</caption>
          <thead>
            <tr>
              <th scope="col">Day</th>
              {Array.from({ length: 24 }, (_, h) => (
                <th key={h} scope="col">
                  {hourLabel(h)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {WEEKDAYS_LONG.map((d, di) => (
              <tr key={d}>
                <th scope="row">{d}</th>
                {Array.from({ length: 24 }, (_, h) => (
                  <td key={h}>{grid[di]?.[h] ?? 0}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
