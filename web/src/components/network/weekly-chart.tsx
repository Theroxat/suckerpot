import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { formatNumber } from "@/lib/format"
import { formatDay, type NetworkWeek } from "@/lib/network"

const SERIES = [
  { key: "confirmed", label: "Confirmed", fill: "var(--fg-subtle)" },
  { key: "reported", label: "Reported", fill: "var(--fg-muted)" },
  { key: "taken_down", label: "Taken down", fill: "var(--status-ok)" },
] as const

function Tip({
  active,
  payload,
}: {
  active?: boolean
  payload?: readonly { payload?: NetworkWeek }[]
}) {
  const p = payload?.[0]?.payload
  if (!active || !p) return null
  return (
    <div className="rounded-md border bg-surface-raised px-3 py-2 text-xs shadow-md">
      <p className="mb-1 text-fg-muted">Week of {formatDay(p.week)}</p>
      {SERIES.map((s) => (
        <p key={s.key} className="flex items-center justify-between gap-4">
          <span className="text-fg-muted">{s.label}</span>
          <span className="font-medium text-fg tabular-nums">{formatNumber(p[s.key])}</span>
        </p>
      ))}
    </div>
  )
}

/** Confirmed, reported and taken-down targets per week. Takedowns are the one success colour. */
export function WeeklyChart({ weekly }: { weekly: readonly NetworkWeek[] }) {
  const reduced = useReducedMotion()
  return (
    <div>
      <ul aria-label="Legend" className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-fg-muted">
        {SERIES.map((s) => (
          <li key={s.key} className="inline-flex items-center gap-1.5">
            <span aria-hidden className="size-2.5 rounded-sm" style={{ background: s.fill }} />
            {s.label}
          </li>
        ))}
      </ul>
      <div
        role="img"
        aria-label={`Confirmed, reported and taken down targets per week, last ${weekly.length} weeks`}
        className="h-52 w-full"
      >
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={[...weekly]} margin={{ top: 4, right: 0, bottom: 0, left: 0 }} barGap={2}>
            <XAxis
              dataKey="week"
              tickFormatter={(w: string) => formatDay(w)}
              tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: "var(--border-strong)" }}
              interval="preserveStartEnd"
              minTickGap={32}
            />
            <YAxis
              width={32}
              tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              content={<Tip />}
              cursor={{ fill: "var(--surface-hover)" }}
              isAnimationActive={false}
            />
            {SERIES.map((s) => (
              <Bar
                key={s.key}
                dataKey={s.key}
                name={s.label}
                fill={s.fill}
                radius={[2, 2, 0, 0]}
                isAnimationActive={!reduced}
                animationDuration={400}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <table className="sr-only">
        <caption>Targets per week</caption>
        <thead>
          <tr>
            <th scope="col">Week of</th>
            {SERIES.map((s) => (
              <th key={s.key} scope="col">
                {s.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {weekly.map((w) => (
            <tr key={w.week}>
              <th scope="row">{formatDay(w.week)}</th>
              {SERIES.map((s) => (
                <td key={s.key}>{w[s.key]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
