import { Link } from "react-router"
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { SegmentedControl } from "@/components/segmented-control"
import { Skeleton } from "@/components/ui/skeleton"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { useUrlParam } from "@/hooks/use-url-param"
import type { TimePoint } from "@/lib/api"
import { formatHour } from "@/lib/chart-time"
import { formatCompact, formatNumber, formatPercent } from "@/lib/format"
import { sumBySensor } from "@/lib/findings"
import {
  FAMILY_META,
  SENSOR_FAMILIES,
  SENSOR_META,
  SENSORS,
  sensorMeta,
  sensorsHref,
  sumByFamily,
} from "@/lib/sensors"
import { cn } from "@/lib/utils"

const full = new Intl.DateTimeFormat("en-US", {
  weekday: "short",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
})

export type ActivitySplit = "family" | "sensor"

interface Series {
  key: string
  label: string
  fill: string
}

/** Stack order and colours: one hue per family, or one shade per sensor. */
function seriesFor(split: ActivitySplit): Series[] {
  return split === "family"
    ? SENSOR_FAMILIES.map((f) => ({
        key: f,
        label: FAMILY_META[f].label,
        fill: FAMILY_META[f].cssVar,
      }))
    : SENSORS.map((s) => ({ key: s, label: SENSOR_META[s].label, fill: SENSOR_META[s].shadeVar }))
}

type Row = { ts: string } & Record<string, number | string>

function toRows(points: readonly TimePoint[], split: ActivitySplit): Row[] {
  return points.map((p) => {
    const values: Record<string, number> =
      split === "family"
        ? sumByFamily(p.events)
        : Object.fromEntries(SENSORS.map((s) => [s, p.events[s] ?? 0]))
    return { ts: p.ts, ...values }
  })
}

const num = (row: Row, key: string) => {
  const v = row[key]
  return typeof v === "number" ? v : 0
}

interface TipProps {
  active?: boolean
  payload?: readonly { payload?: Row }[]
  split: ActivitySplit
}

function ChartTooltip({ active, payload, split }: TipProps) {
  const row = payload?.[0]?.payload
  if (!active || !row) return null
  const series = seriesFor(split)
  const total = series.reduce((n, s) => n + num(row, s.key), 0)
  // Per sensor, only the sensors that saw something: twelve zero rows say nothing.
  const shown = split === "sensor" ? series.filter((s) => num(row, s.key) > 0) : series
  return (
    <div className="min-w-48 rounded-md border bg-surface-raised p-3 text-xs shadow-md">
      <p className="mb-2 font-medium text-fg">{full.format(new Date(row.ts))}</p>
      <ul className="space-y-1">
        {shown.map((s) => {
          const Icon = split === "sensor" ? sensorMeta(s.key)?.icon : null
          return (
            <li key={s.key} className="flex items-center justify-between gap-6 text-fg-muted">
              <span className="inline-flex items-center gap-1.5">
                <span
                  aria-hidden
                  className="size-2 rounded-[2px]"
                  style={{ backgroundColor: s.fill }}
                />
                {Icon ? <Icon aria-hidden className="size-3" /> : null}
                {s.label}
              </span>
              <span className="text-fg tabular-nums">{formatNumber(num(row, s.key))}</span>
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

/**
 * The key under the chart: one column per family (total, share), its sensors
 * listed below with their own totals. In the per-sensor split each sensor line
 * carries its shade swatch. Every line opens the matching filtered Attacks view.
 */
function ActivityLegend({
  totals,
  split,
}: {
  totals: Record<string, number>
  split: ActivitySplit
}) {
  const families = sumByFamily(totals)
  const grand = SENSORS.reduce((n, s) => n + (totals[s] ?? 0), 0)
  return (
    // Four columns only when the card itself is wide enough (container query, not viewport).
    <ul aria-label="Sensors" className="grid grid-cols-2 gap-x-6 gap-y-4 @3xl:grid-cols-4">
      {SENSOR_FAMILIES.map((f) => {
        const fam = FAMILY_META[f]
        return (
          <li key={f} className="min-w-0">
            <Link
              to={sensorsHref(fam.sensors)}
              className="-mx-1.5 flex items-center gap-2 rounded-sm px-1.5 py-1 text-xs transition-colors hover:bg-surface-hover"
            >
              <span aria-hidden className={cn("size-2 shrink-0 rounded-full", fam.fill)} />
              <span className={cn("min-w-0 flex-1 truncate font-medium", fam.text)}>
                {fam.label}
              </span>
              <span className="font-medium text-fg tabular-nums">{formatNumber(families[f])}</span>
              <span className="w-8 text-right text-fg-subtle tabular-nums">
                {grand ? formatPercent(families[f] / grand) : "0%"}
              </span>
            </Link>
            <ul className="mt-0.5">
              {fam.sensors.map((s) => {
                const m = SENSOR_META[s]
                const n = totals[s] ?? 0
                return (
                  <li key={s}>
                    <Link
                      to={sensorsHref([s])}
                      className="-mx-1.5 flex h-6 items-center gap-2 rounded-sm px-1.5 text-xs text-fg-muted transition-colors hover:bg-surface-hover hover:text-fg"
                    >
                      {split === "sensor" ? (
                        <span
                          aria-hidden
                          className="size-2 shrink-0 rounded-[2px]"
                          style={{ backgroundColor: m.shadeVar }}
                        />
                      ) : (
                        <span aria-hidden className="size-2 shrink-0" />
                      )}
                      <m.icon aria-hidden className={cn("size-3.5 shrink-0", m.text)} />
                      <span className="min-w-0 flex-1 truncate">{m.label}</span>
                      <span className={cn("tabular-nums", n > 0 ? "text-fg" : "text-fg-subtle")}>
                        {formatNumber(n)}
                      </span>
                      <span className="w-8" aria-hidden />
                    </Link>
                  </li>
                )
              })}
            </ul>
          </li>
        )
      })}
    </ul>
  )
}

interface SensorActivityChartProps {
  points: readonly TimePoint[] | undefined
  loading?: boolean
  className?: string
}

/**
 * Events per hour, stacked by sensor family (one hue each) by default; the
 * "Sensors" split drills down to one shade per sensor, grouped by family. The
 * split lives in the URL (`?split=sensor`). An sr-only table carries the numbers.
 */
export function SensorActivityChart({ points, loading, className }: SensorActivityChartProps) {
  const reduced = useReducedMotion()
  const [rawSplit, setSplit] = useUrlParam("split")
  const split: ActivitySplit = rawSplit === "sensor" ? "sensor" : "family"
  const series = seriesFor(split)
  const rows = toRows(points ?? [], split)
  const totals = sumBySensor(points ?? [], "events")
  const what = split === "family" ? "sensor family" : "sensor"

  return (
    <div className={cn("@container", className)}>
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="text-xs text-fg-subtle">Events per hour, by {what}</p>
        <SegmentedControl
          label="Split the chart by"
          value={split}
          onChange={(v) => setSplit(v === "family" ? null : v)}
          options={[
            { value: "family", label: "Families" },
            { value: "sensor", label: "Sensors" },
          ]}
        />
      </div>

      {loading ? (
        <Skeleton className="h-56 w-full sm:h-64" />
      ) : (
        <>
          <div
            role="img"
            aria-label={`Stacked bar chart of events per hour by ${what}. The same numbers are in the table below.`}
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
                  content={<ChartTooltip split={split} />}
                  cursor={{ fill: "var(--surface-hover)" }}
                  isAnimationActive={false}
                />
                {series.map((s) => (
                  <Bar
                    key={s.key}
                    dataKey={s.key}
                    name={s.label}
                    stackId="events"
                    fill={s.fill}
                    stroke="var(--surface)"
                    strokeWidth={1}
                    isAnimationActive={!reduced}
                    animationDuration={400}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
          {/* The wrapper clips: a table ignores the sr-only width and would widen the page. */}
          <div className="sr-only">
            <table>
              <caption>Events per hour by {what}</caption>
              <thead>
                <tr>
                  <th scope="col">Hour</th>
                  {series.map((s) => (
                    <th key={s.key} scope="col">
                      {s.label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.ts}>
                    <th scope="row">{full.format(new Date(r.ts))}</th>
                    {series.map((s) => (
                      <td key={s.key}>{num(r, s.key)}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <div className="mt-4">
        <ActivityLegend totals={totals} split={split} />
      </div>
    </div>
  )
}
