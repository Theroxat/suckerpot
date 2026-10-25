import { useQuery } from "@tanstack/react-query"
import { ArrowUpRight, Sparkles } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { SeverityBadge } from "@/components/severity-badge"
import { Skeleton } from "@/components/ui/skeleton"
import { api, queryKeys } from "@/lib/api"
import { maskIpsInText } from "@/lib/format"
import { INSIGHT_KIND_LABEL, type Insight } from "@/lib/trends"
import { cn } from "@/lib/utils"

const HOUR = 3_600_000
const WINDOW_DAYS = 7

/** The auto-written insights: one sentence each, a severity icon, a link to the proof. */
export function InsightsCard({ className }: { className?: string }) {
  const [end] = useState(() => Math.ceil(Date.now() / HOUR) * HOUR)
  const range = {
    since: new Date(end - WINDOW_DAYS * 24 * HOUR).toISOString(),
    until: new Date(end).toISOString(),
  }
  const q = useQuery({ queryKey: queryKeys.insights(range), queryFn: () => api.insights(range) })
  const items = q.data?.items ?? []

  const finding = q.isPending
    ? "Reading the last 7 days…"
    : q.isError
      ? "Insights are not available right now."
      : items.length === 0
        ? "Nothing unusual in the last 7 days."
        : items.length === 1
          ? "One thing stands out in the last 7 days."
          : `${items.length} things stand out in the last 7 days.`

  return (
    <FindingCard
      className={className}
      eyebrow="Insights"
      finding={finding}
      detail={items.length > 0 ? "Each one opens the view that proves it." : undefined}
    >
      {q.isPending ? (
        <div role="status" aria-label="Loading" className="space-y-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : q.isError ? (
        <EmptyState
          variant="bare"
          icon={Sparkles}
          title="Could not load insights"
          description={q.error.message}
          className="py-6"
        />
      ) : items.length === 0 ? (
        <EmptyState
          variant="bare"
          icon={Sparkles}
          title="No insights yet"
          description="Insights appear when something changes: a surge, a new value, or one network dominating."
          className="py-6"
        />
      ) : (
        <ul aria-label="Insights" className="-mx-2 space-y-1">
          {items.map((i) => (
            <li key={i.id}>
              <InsightRow insight={i} />
            </li>
          ))}
        </ul>
      )}
    </FindingCard>
  )
}

export function InsightRow({ insight, className }: { insight: Insight; className?: string }) {
  const { masked } = useIpMask()
  const text = masked ? maskIpsInText(insight.sentence) : insight.sentence
  return (
    <Link
      to={insight.link}
      className={cn(
        "group/insight flex items-start gap-3 rounded-md px-2 py-2.5 transition-colors duration-150 hover:bg-surface-hover",
        className,
      )}
    >
      <SeverityBadge severity={insight.severity} iconOnly className="mt-px" />
      <span className="min-w-0 flex-1 text-sm text-pretty text-fg">
        <span className="sr-only">
          {(INSIGHT_KIND_LABEL as Partial<Record<string, string>>)[insight.kind] ?? "Insight"}:{" "}
        </span>
        {text}
      </span>
      <ArrowUpRight
        aria-hidden
        className="mt-1 size-3.5 shrink-0 text-fg-subtle transition-colors group-hover/insight:text-fg"
      />
    </Link>
  )
}
