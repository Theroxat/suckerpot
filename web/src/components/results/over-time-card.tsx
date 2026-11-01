import { useQuery } from "@tanstack/react-query"
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { FindingCard } from "@/components/finding-card"
import { SegmentedControl } from "@/components/segmented-control"
import { Skeleton } from "@/components/ui/skeleton"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { useUrlParam } from "@/hooks/use-url-param"
import { KIND_LABEL, type ReportKind } from "@/lib/abuse"
import { formatNumber } from "@/lib/format"
import { resultKeys, resultsApi, type TimelinePoint } from "@/lib/results"
import { describeSentOverTime } from "@/lib/results-sentences"

/** Neutral lightness steps, one per kind: a legend with words tells them apart, not the hue. */
const KINDS: { key: ReportKind; fill: string }[] = [
  { key: "attack_source", fill: "var(--fg)" },
  { key: "payload_host", fill: "var(--fg-muted)" },
  { key: "c2", fill: "var(--fg-subtle)" },
]

const dayFmt = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" })
const monthFmt = new Intl.DateTimeFormat("en-US", { month: "short", year: "2-digit" })

interface Row {
  start: string
  label: string
  attack_source: number
  payload_host: number
  c2: number
}

function Tip({ active, payload }: { active?: boolean; payload?: readonly { payload?: Row }[] }) {
  const p = payload?.[0]?.payload
  if (!active || !p) return null
  return (
    <div className="rounded-md border bg-surface-raised px-3 py-2 text-xs shadow-md">
      <p className="mb-1 text-fg-muted">{p.label}</p>
      {KINDS.map((k) => (
        <p key={k.key} className="flex justify-between gap-4">
          <span className="text-fg-muted">{KIND_LABEL[k.key]}</span>
          <span className="font-medium text-fg tabular-nums">{formatNumber(p[k.key])}</span>
        </p>
      ))}
    </div>
  )
}

export function OverTimeCard() {
  const reduced = useReducedMotion()
  const [bucketParam, setBucket] = useUrlParam("bucket")
  const bucket = bucketParam === "month" ? "month" : "week"
  const q = useQuery({
    queryKey: resultKeys.timeline(bucket),
    queryFn: () => resultsApi.timeline(bucket),
  })
  const points: readonly TimelinePoint[] = q.data?.points ?? []
  const fmt = bucket === "month" ? monthFmt : dayFmt
  const rows: Row[] = points.map((p) => ({
    start: p.start,
    label: fmt.format(new Date(p.start)),
    attack_source: p.sent.attack_source ?? 0,
    payload_host: p.sent.payload_host ?? 0,
    c2: p.sent.c2 ?? 0,
  }))
  return (
    <FindingCard
      eyebrow="Reports over time"
      finding={q.data ? describeSentOverTime(points, new Date()) : "Counting the reports you sent…"}
      action={
        <SegmentedControl
          label="Group by"
          value={bucket}
          onChange={(v) => setBucket(v === "week" ? null : v)}
          options={[
            { value: "week", label: "Weeks" },
            { value: "month", label: "Months" },
          ]}
        />
      }
    >
      {q.isPending ? (
        <Skeleton className="h-48 w-full" />
      ) : (
        <>
          <ul className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-fg-muted">
            {KINDS.map((k) => (
              <li key={k.key} className="inline-flex items-center gap-1.5">
                <span
                  aria-hidden
                  className="size-2.5 rounded-[2px]"
                  style={{ background: k.fill }}
                />
                {KIND_LABEL[k.key]}
              </li>
            ))}
          </ul>
          <div
            role="img"
            aria-label={`Reports sent per ${bucket}, by kind`}
            className="h-48 w-full"
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={rows} margin={{ top: 4, right: 0, bottom: 0, left: -16 }}>
                <CartesianGrid vertical={false} stroke="var(--border)" />
                <XAxis
                  dataKey="label"
                  tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: "var(--border-strong)" }}
                  interval="preserveStartEnd"
                  minTickGap={32}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  content={<Tip />}
                  cursor={{ fill: "var(--surface-hover)" }}
                  isAnimationActive={false}
                />
                {KINDS.map((k) => (
                  <Bar
                    key={k.key}
                    dataKey={k.key}
                    stackId="sent"
                    fill={k.fill}
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
              <caption>Reports sent per {bucket}, by kind</caption>
              <thead>
                <tr>
                  <th scope="col">Start</th>
                  {KINDS.map((k) => (
                    <th key={k.key} scope="col">
                      {KIND_LABEL[k.key]}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.start}>
                    <th scope="row">{r.label}</th>
                    {KINDS.map((k) => (
                      <td key={k.key}>{r[k.key]}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </FindingCard>
  )
}
