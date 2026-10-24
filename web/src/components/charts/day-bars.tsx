import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis } from "recharts"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { fillDays, type DayPoint } from "@/lib/chart-time"
import { formatNumber } from "@/lib/format"

const dayFmt = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" })
const label = (day: string) => dayFmt.format(new Date(`${day}T00:00:00Z`))

function Tip({
  active,
  payload,
}: {
  active?: boolean
  payload?: readonly { payload?: DayPoint }[]
}) {
  const p = payload?.[0]?.payload
  if (!active || !p) return null
  return (
    <div className="rounded-md border bg-surface-raised px-3 py-2 text-xs shadow-md">
      <span className="text-fg-muted">{label(p.day)}</span>{" "}
      <span className="font-medium text-fg tabular-nums">{formatNumber(p.events)} events</span>
    </div>
  )
}

/** One neutral bar per day (the attacker may span several sensors, so no sensor hue). */
export function DayBars({
  points,
  className,
}: {
  points: readonly DayPoint[]
  className?: string
}) {
  const reduced = useReducedMotion()
  const data = fillDays(points)
  return (
    <div className={className}>
      <div
        role="img"
        aria-label={`Events per day over the last ${data.length} days`}
        className="h-32 w-full"
      >
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            margin={{ top: 4, right: 0, bottom: 0, left: 0 }}
            barCategoryGap={2}
          >
            <XAxis
              dataKey="day"
              tickFormatter={label}
              tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: "var(--border-strong)" }}
              interval="preserveStartEnd"
              minTickGap={48}
            />
            <Tooltip
              content={<Tip />}
              cursor={{ fill: "var(--surface-hover)" }}
              isAnimationActive={false}
            />
            <Bar
              dataKey="events"
              fill="var(--fg-muted)"
              radius={[2, 2, 0, 0]}
              isAnimationActive={!reduced}
              animationDuration={400}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <table className="sr-only">
        <caption>Events per day</caption>
        <thead>
          <tr>
            <th scope="col">Day</th>
            <th scope="col">Events</th>
          </tr>
        </thead>
        <tbody>
          {data.map((p) => (
            <tr key={p.day}>
              <th scope="row">{label(p.day)}</th>
              <td>{p.events}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
