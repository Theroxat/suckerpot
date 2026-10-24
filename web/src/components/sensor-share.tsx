import { Link } from "react-router"
import type { Sensor } from "@/lib/api"
import { formatNumber, formatPercent } from "@/lib/format"
import { SENSOR_META } from "@/lib/sensors"
import { cn } from "@/lib/utils"

interface SensorShareProps {
  shares: readonly { id: Sensor; value: number }[]
  className?: string
}

/**
 * A single stacked bar plus a labelled legend. The legend carries the numbers,
 * so colour is never the only way to read it. Each row links to the filtered list.
 */
export function SensorShare({ shares, className }: SensorShareProps) {
  const total = shares.reduce((n, s) => n + s.value, 0)
  return (
    <div className={cn("space-y-4", className)}>
      <div
        className="flex h-2.5 w-full gap-0.5 overflow-hidden rounded-full bg-surface-hover"
        role="img"
        aria-label={shares
          .map((s) => `${SENSOR_META[s.id].label} ${formatNumber(s.value)}`)
          .join(", ")}
      >
        {total
          ? shares
              .filter((s) => s.value > 0)
              .map((s) => (
                <span
                  key={s.id}
                  className={cn("h-full transition-[width] duration-250", SENSOR_META[s.id].fill)}
                  style={{ width: `${(s.value / total) * 100}%` }}
                />
              ))
          : null}
      </div>
      <ul className="grid grid-cols-2 gap-x-6 gap-y-1 sm:grid-cols-4">
        {shares.map((s) => {
          const meta = SENSOR_META[s.id]
          return (
            <li key={s.id}>
              <Link
                to={`/attacks?sensor=${s.id}`}
                className="-mx-2 flex flex-col rounded-md px-2 py-1.5 transition-colors hover:bg-surface-hover"
              >
                <span className="flex items-center gap-1.5 text-xs text-fg-muted">
                  <meta.icon aria-hidden className={cn("size-3.5", meta.text)} />
                  {meta.label}
                </span>
                <span className="mt-0.5 flex items-baseline gap-1.5">
                  <span className="text-md font-semibold text-fg">{formatNumber(s.value)}</span>
                  <span className="text-xs text-fg-subtle">
                    {total ? formatPercent(s.value / total) : "–"}
                  </span>
                </span>
              </Link>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
