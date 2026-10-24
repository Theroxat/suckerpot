import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { Link } from "react-router"
import { Skeleton } from "@/components/ui/skeleton"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { formatCompact, formatNumber } from "@/lib/format"
import { highlightTag, isSevereTag, tagFill, tagTotals, type TagPoint } from "@/lib/trends"
import { cn } from "@/lib/utils"

const day = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" })
const dayLong = new Intl.DateTimeFormat("en-US", {
  weekday: "short",
  month: "short",
  day: "numeric",
})

interface TagChartProps {
  points: readonly TagPoint[] | undefined
  /** Tag order from the API; falls back to totals. */
  series?: readonly string[] | undefined
  loading?: boolean
  className?: string
}

type Row = { ts: string } & Record<string, number | string>

export function TagChart({ points, series, loading, className }: TagChartProps) {
  const reduced = useReducedMotion()
  const pts = points ?? []
  const totals = tagTotals(pts)
  // "other" always last and quietest.
  const names = series ?? totals.map(([t]) => t)
  const order = [...names.filter((t) => t !== "other"), "other"].filter((t) =>
    totals.some(([x]) => x === t),
  )
  const rows: Row[] = pts.map((p) => ({ ts: p.ts, ...p.tags }))
  const grand = totals.reduce((a, [, n]) => a + n, 0)
  const highlight = highlightTag(order)
  // Neutral steps count only the non-highlighted tags, so the greys stay evenly spaced.
  const neutral = order.filter((t) => t !== highlight)
  const fill = (t: string) => tagFill(t, Math.max(0, neutral.indexOf(t)), highlight)

  return (
    <div className={className}>
      <ul aria-label="Tags" className="mb-3 flex flex-wrap gap-x-5 gap-y-2">
        {order.map((t) => {
          const n = totals.find(([x]) => x === t)?.[1] ?? 0
          const severe = isSevereTag(t)
          const body = (
            <>
              <span
                aria-hidden
                className={cn(
                  "size-2.5 shrink-0 rounded-[2px]",
                  severe && "rotate-45 ring-1 ring-sev-severe",
                )}
                style={{ background: fill(t) }}
              />
              <span className="font-mono">{t}</span>
              {severe ? <span className="sr-only">(severe)</span> : null}
              <span className="text-fg tabular-nums">{formatNumber(n)}</span>
            </>
          )
          return (
            <li key={t}>
              {t === "other" ? (
                <span className="inline-flex items-center gap-2 text-xs text-fg-muted">{body}</span>
              ) : (
                <Link
                  to={`/attacks?tag=${encodeURIComponent(t)}`}
                  className="inline-flex items-center gap-2 rounded-sm text-xs text-fg-muted transition-colors hover:text-fg"
                >
                  {body}
                </Link>
              )}
            </li>
          )
        })}
      </ul>

      {loading ? (
        <Skeleton className="h-56 w-full sm:h-64" />
      ) : grand === 0 ? (
        <p className="py-8 text-center text-sm text-fg-muted">No tagged events in this period.</p>
      ) : (
        <>
          <div
            role="img"
            aria-label="Stacked bar chart of tagged events per day. The same numbers are in the table below."
            className="h-56 w-full sm:h-64"
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={rows}
                margin={{ top: 4, right: 4, bottom: 0, left: 0 }}
                barCategoryGap={4}
              >
                <CartesianGrid vertical={false} stroke="var(--border)" />
                <XAxis
                  dataKey="ts"
                  tickFormatter={(v: string) => day.format(new Date(v))}
                  tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: "var(--border-strong)" }}
                  minTickGap={24}
                />
                <YAxis
                  tickFormatter={(v: number) => formatCompact(v)}
                  tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  width={40}
                />
                <Tooltip
                  content={<TagTooltip order={order} fill={fill} />}
                  cursor={{ fill: "var(--surface-hover)" }}
                  isAnimationActive={false}
                />
                {order.map((t) => (
                  <Bar
                    key={t}
                    dataKey={t}
                    stackId="tags"
                    fill={fill(t)}
                    stroke="var(--surface)"
                    strokeWidth={1}
                    isAnimationActive={!reduced}
                    animationDuration={400}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="sr-only">
            <table>
              <caption>Tagged events per day</caption>
              <thead>
                <tr>
                  <th scope="col">Day</th>
                  {order.map((t) => (
                    <th key={t} scope="col">
                      {t}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pts.map((p) => (
                  <tr key={p.ts}>
                    <th scope="row">{dayLong.format(new Date(p.ts))}</th>
                    {order.map((t) => (
                      <td key={t}>{p.tags[t] ?? 0}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}

interface TipProps {
  active?: boolean
  payload?: readonly { payload?: Row }[]
  order: string[]
  fill: (t: string) => string
}

function TagTooltip({ active, payload, order, fill }: TipProps) {
  const row = payload?.[0]?.payload
  if (!active || !row) return null
  const entries = order.map((t) => [t, Number(row[t] ?? 0)] as const).filter(([, n]) => n > 0)
  const total = entries.reduce((a, [, n]) => a + n, 0)
  return (
    <div className="min-w-44 rounded-md border bg-surface-raised p-3 text-xs shadow-md">
      <p className="mb-2 font-medium text-fg">{dayLong.format(new Date(row.ts))}</p>
      <ul className="space-y-1">
        {entries.map(([t, n]) => (
          <li key={t} className="flex items-center justify-between gap-6 text-fg-muted">
            <span className="inline-flex items-center gap-1.5">
              <span
                aria-hidden
                className={cn(
                  "size-2 rounded-[2px]",
                  isSevereTag(t) && "rotate-45 ring-1 ring-sev-severe",
                )}
                style={{ background: fill(t) }}
              />
              <span className="font-mono">{t}</span>
            </span>
            <span className="text-fg tabular-nums">{formatNumber(n)}</span>
          </li>
        ))}
      </ul>
      <p className="mt-2 flex justify-between border-t pt-2 font-medium text-fg">
        <span>Total</span>
        <span className="tabular-nums">{formatNumber(total)}</span>
      </p>
    </div>
  )
}
