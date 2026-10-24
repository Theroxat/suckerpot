import { Link } from "react-router"
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { SensorBadge } from "@/components/sensor-badge"
import { Skeleton } from "@/components/ui/skeleton"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { SENSORS, type Sensor, type TimePoint } from "@/lib/api"
import { formatHour } from "@/lib/chart-time"
import { formatCompact, formatNumber, formatPercent } from "@/lib/format"
import { sumBySensor } from "@/lib/findings"
import { SENSOR_META } from "@/lib/sensors"

const full = new Intl.DateTimeFormat("en-US", {
  weekday: "short",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
})

interface Row {
  ts: string
  ssh: number
  telnet: number
  web: number
  rdp: number
}

function toRows(points: readonly TimePoint[]): Row[] {
  return points.map((p) => ({
    ts: p.ts,
    ssh: p.events.ssh ?? 0,
    telnet: p.events.telnet ?? 0,
    web: p.events.web ?? 0,
    rdp: p.events.rdp ?? 0,
  }))
}

interface TipProps {
  active?: boolean
  payload?: readonly { payload?: Row }[]
}

function ChartTooltip({ active, payload }: TipProps) {
  const row = payload?.[0]?.payload
  if (!active || !row) return null
  const total = SENSORS.reduce((n, s) => n + row[s], 0)
  return (
    <div className="min-w-44 rounded-md border bg-surface-raised p-3 text-xs shadow-md">
      <p className="mb-2 font-medium text-fg">{full.format(new Date(row.ts))}</p>
      <ul className="space-y-1">
        {SENSORS.map((s) => {
          const Icon = SENSOR_META[s].icon
          return (
            <li key={s} className="flex items-center justify-between gap-6 text-fg-muted">
              <span className="inline-flex items-center gap-1.5">
                <span aria-hidden className={`size-2 rounded-full ${SENSOR_META[s].fill}`} />
                <Icon aria-hidden className="size-3" />
                {SENSOR_META[s].label}
              </span>
              <span className="text-fg tabular-nums">{formatNumber(row[s])}</span>
            </li>
          )
        })}
      </ul>
      <p className="mt-2 flex justify-between border-t pt-2 font-medium text-fg">
        <span>Total</span>
        <span className="tabular-nums">{formatNumber(total)}</span>
      </p>
    </div>
  )
}

interface SensorActivityChartProps {
  points: readonly TimePoint[] | undefined
  loading?: boolean
  className?: string
}

/**
 * Events per hour, stacked by sensor (fixed order, one hue each). The legend
 * doubles as the key and as links to each sensor's filtered Attacks view; an
 * sr-only table carries the same numbers.
 */
export function SensorActivityChart({ points, loading, className }: SensorActivityChartProps) {
  const reduced = useReducedMotion()
  const rows = toRows(points ?? [])
  const totals = sumBySensor(points ?? [], "events")
  const grand = SENSORS.reduce((n, s) => n + totals[s], 0)

  return (
    <div className={className}>
      <ul aria-label="Sensors" className="mb-3 flex flex-wrap gap-x-5 gap-y-2">
        {SENSORS.map((s: Sensor) => (
          <li key={s}>
            <Link
              to={`/attacks?sensor=${s}`}
              className="inline-flex items-center gap-2 rounded-sm text-xs text-fg-muted transition-colors hover:text-fg"
            >
              <SensorBadge sensor={s} />
              <span className="text-fg tabular-nums">{formatNumber(totals[s])}</span>
              <span className="tabular-nums">
                {grand ? formatPercent(totals[s] / grand) : "0%"}
              </span>
            </Link>
          </li>
        ))}
      </ul>

      {loading ? (
        <Skeleton className="h-56 w-full sm:h-64" />
      ) : (
        <>
          <div
            role="img"
            aria-label="Stacked bar chart of events per hour by sensor. The same numbers are in the table below."
            className="h-56 w-full sm:h-64"
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={rows}
                margin={{ top: 4, right: 4, bottom: 0, left: 0 }}
                barCategoryGap={2}
              >
                <CartesianGrid vertical={false} stroke="var(--border)" />
                <XAxis
                  dataKey="ts"
                  tickFormatter={formatHour}
                  tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: "var(--border-strong)" }}
                  minTickGap={28}
                />
                <YAxis
                  tickFormatter={(v: number) => formatCompact(v)}
                  tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  width={40}
                />
                <Tooltip
                  content={<ChartTooltip />}
                  cursor={{ fill: "var(--surface-hover)" }}
                  isAnimationActive={false}
                />
                {SENSORS.map((s) => (
                  <Bar
                    key={s}
                    dataKey={s}
                    stackId="events"
                    fill={SENSOR_META[s].cssVar}
                    stroke="var(--surface)"
                    strokeWidth={1}
                    isAnimationActive={!reduced}
                    animationDuration={400}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
          <table className="sr-only">
            <caption>Events per hour by sensor</caption>
            <thead>
              <tr>
                <th scope="col">Hour</th>
                {SENSORS.map((s) => (
                  <th key={s} scope="col">
                    {SENSOR_META[s].label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.ts}>
                  <th scope="row">{full.format(new Date(r.ts))}</th>
                  {SENSORS.map((s) => (
                    <td key={s}>{r[s]}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}
