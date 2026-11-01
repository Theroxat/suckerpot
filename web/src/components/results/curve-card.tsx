import { useQuery } from "@tanstack/react-query"
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import { FindingCard } from "@/components/finding-card"
import { Skeleton } from "@/components/ui/skeleton"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { formatPercent } from "@/lib/format"
import { resultKeys, resultsApi, type ResultFilters, type TakedownSummary } from "@/lib/results"
import { describeCurve, hoursLabel } from "@/lib/results-sentences"

const SERIES = [
  { key: "url", label: "URLs", stroke: "var(--fg)", dash: undefined },
  { key: "host", label: "Hosts", stroke: "var(--fg-muted)", dash: "5 4" },
] as const

interface Row {
  hours: number
  label: string
  url?: number
  host?: number
}

function Tip({ active, payload }: { active?: boolean; payload?: readonly { payload?: Row }[] }) {
  const p = payload?.[0]?.payload
  if (!active || !p) return null
  return (
    <div className="rounded-md border bg-surface-raised px-3 py-2 text-xs shadow-md">
      <p className="mb-1 text-fg-muted">{p.label} after the report</p>
      {SERIES.map((s) => (
        <p key={s.key} className="flex justify-between gap-4">
          <span className="text-fg-muted">{s.label}</span>
          <span className="font-medium text-fg tabular-nums">
            {p[s.key] == null ? "no data" : formatPercent(p[s.key] ?? 0)}
          </span>
        </p>
      ))}
    </div>
  )
}

/** "How fast do things go down?": cumulative share of reported targets that went down. */
export function CurveCard({
  summary,
  filters,
}: {
  summary: TakedownSummary | undefined
  filters: ResultFilters
}) {
  const reduced = useReducedMotion()
  const q = useQuery({
    queryKey: resultKeys.curve(filters),
    queryFn: () => resultsApi.curve(filters),
  })
  const rows: Row[] = []
  for (const s of q.data?.series ?? []) {
    for (const p of s.points) {
      let row = rows.find((r) => r.hours === p.hours)
      if (!row) {
        row = { hours: p.hours, label: hoursLabel(p.hours) }
        rows.push(row)
      }
      row[s.kind] = p.percent ?? undefined
    }
  }
  rows.sort((a, b) => a.hours - b.hours)
  return (
    <FindingCard
      eyebrow="How fast do things go down?"
      finding={describeCurve(summary)}
      detail="Only targets followed for at least that long are counted at each point, so young reports never pull the line down."
    >
      {q.isPending ? (
        <Skeleton className="h-52 w-full" />
      ) : (
        <>
          <ul className="mb-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-fg-muted">
            {SERIES.map((s) => (
              <li key={s.key} className="inline-flex items-center gap-2">
                <svg aria-hidden width="22" height="6" viewBox="0 0 22 6">
                  <line
                    x1="0"
                    y1="3"
                    x2="22"
                    y2="3"
                    stroke={s.stroke}
                    strokeWidth="2"
                    strokeDasharray={s.dash}
                  />
                </svg>
                {s.label}
              </li>
            ))}
          </ul>
          <div
            role="img"
            aria-label="Share of reported targets that went down, by time since the report"
            className="h-52 w-full"
          >
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={rows} margin={{ top: 4, right: 8, bottom: 0, left: -8 }}>
                <CartesianGrid vertical={false} stroke="var(--border)" />
                <XAxis
                  dataKey="label"
                  tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: "var(--border-strong)" }}
                  interval={0}
                  minTickGap={8}
                />
                <YAxis
                  domain={[0, 1]}
                  ticks={[0, 0.25, 0.5, 0.75, 1]}
                  tickFormatter={(v: number) => formatPercent(v)}
                  tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip content={<Tip />} isAnimationActive={false} />
                {SERIES.map((s) => (
                  <Line
                    key={s.key}
                    type="stepAfter"
                    dataKey={s.key}
                    stroke={s.stroke}
                    strokeWidth={2}
                    strokeDasharray={s.dash}
                    dot={{ r: 2.5, fill: s.stroke, strokeWidth: 0 }}
                    connectNulls
                    isAnimationActive={!reduced}
                    animationDuration={400}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
          <table className="sr-only">
            <caption>Share of reported targets that went down, by time since the report</caption>
            <thead>
              <tr>
                <th scope="col">Time after the report</th>
                {SERIES.map((s) => (
                  <th key={s.key} scope="col">
                    {s.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.hours}>
                  <th scope="row">{r.label}</th>
                  {SERIES.map((s) => (
                    <td key={s.key}>
                      {r[s.key] == null ? "no data" : formatPercent(r[s.key] ?? 0)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </FindingCard>
  )
}
