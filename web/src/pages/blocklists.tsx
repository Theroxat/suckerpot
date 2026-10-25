import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Download, SearchX, ShieldCheck, ShieldOff } from "lucide-react"
import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { useAuth } from "@/app/auth"
import { BLOCKLIST_GRID, BlocklistRow } from "@/components/defend/blocklist-row"
import { ExportPanel } from "@/components/defend/export-panel"
import { KindTiles } from "@/components/defend/kind-tiles"
import { OverrideDialog, type OverrideTarget } from "@/components/defend/override-dialog"
import { OverridesCard } from "@/components/defend/overrides-card"
import { UrlSearch } from "@/components/defend/url-search"
import { EmptyState } from "@/components/empty-state"
import { FilterBar } from "@/components/filter-bar"
import { PageHeader } from "@/components/page-header"
import { ReadOnlyBadge } from "@/components/read-only-badge"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { useUrlParam } from "@/hooks/use-url-param"
import {
  blocklistSentence,
  DEFAULT_MIN_SCORE,
  defendApi,
  defendKeys,
  deleteOverride,
  HIGH_SCORE,
  isBlockKind,
  KIND_META,
  LISTED_SCORE,
  reasonLabel,
  type BlocklistFilters,
  type BlockEntry,
  type OverrideAction,
} from "@/lib/defend"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50

const SCORE_OPTIONS = [
  { value: "10", label: "Everything seen" },
  { value: String(LISTED_SCORE), label: `Listed (${LISTED_SCORE}+)` },
  { value: String(HIGH_SCORE), label: `High (${HIGH_SCORE}+)` },
]

function parseMinScore(raw: string | null): number {
  const n = Number(raw)
  return SCORE_OPTIONS.some((o) => o.value === raw) ? n : DEFAULT_MIN_SCORE
}

export function BlocklistsPage() {
  const { canWrite } = useAuth()
  const queryClient = useQueryClient()
  const [kindParam, setKindParam] = useUrlParam("kind")
  const [scoreParam, setScoreParam] = useUrlParam("min_score")
  const [q] = useUrlParam("q")
  const [reason, setReason] = useUrlParam("reason")
  const [benignParam, setBenignParam] = useUrlParam("include_benign")
  const kind = isBlockKind(kindParam) ? kindParam : null
  const minScore = parseMinScore(scoreParam)
  const includeBenign = benignParam === "1"
  const benignId = useId()

  const summary = useQuery({
    queryKey: defendKeys.summary,
    queryFn: defendApi.summary,
    staleTime: 30_000,
  })
  const overrides = useQuery({ queryKey: defendKeys.overrides, queryFn: defendApi.overrides })

  const filters: BlocklistFilters = useMemo(
    () => ({
      kind: kind ?? undefined,
      min_score: minScore,
      q: q ?? undefined,
      reason: reason ?? undefined,
      include_benign: includeBenign || undefined,
    }),
    [kind, minScore, q, reason, includeBenign],
  )
  const query = useInfiniteQuery({
    queryKey: defendKeys.blocklist(filters, PAGE_SIZE),
    queryFn: ({ pageParam }) => defendApi.blocklist(filters, pageParam, PAGE_SIZE),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const rows = query.data?.pages.flatMap((p) => p.items) ?? []

  const [dialog, setDialog] = useState<{ target: OverrideTarget; action: OverrideAction } | null>(
    null,
  )
  const removeOverride = useMutation({
    mutationFn: (entry: BlockEntry) => {
      const found = overrides.data?.items.find(
        (o) => o.kind === entry.kind && o.value === entry.value,
      )
      if (!found) return Promise.resolve(undefined)
      return deleteOverride(found.id)
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["defend"] }),
  })

  const listRef = useRef<HTMLDivElement>(null)
  const [scrollMargin, setScrollMargin] = useState(0)
  useLayoutEffect(() => {
    const el = listRef.current
    if (!el) return
    const measure = () => setScrollMargin(el.getBoundingClientRect().top + window.scrollY)
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(document.body)
    return () => ro.disconnect()
  }, [query.isPending])

  const virtualizer = useWindowVirtualizer({
    count: rows.length + (query.hasNextPage ? 1 : 0),
    estimateSize: () => 92,
    overscan: 8,
    scrollMargin,
    getItemKey: (i) => {
      const r = rows[i]
      return r ? `${r.kind}:${r.value}` : `loader-${i}`
    },
  })
  const items = virtualizer.getVirtualItems()
  const lastIndex = items.at(-1)?.index ?? -1
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query
  useEffect(() => {
    if (lastIndex >= rows.length - 6 && hasNextPage && !isFetchingNextPage) void fetchNextPage()
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  const s = summary.data
  const off = s?.worker_enabled === false
  const nothingSeen = s?.kinds.every((k) => k.total === 0) === true
  const filtered = Boolean(kind ?? q ?? reason) || includeBenign || minScore !== DEFAULT_MIN_SCORE

  const header = (
    <PageHeader
      title="Blocklists"
      description={
        off
          ? "Addresses, domains and files seen attacking you, scored and ready for your firewall."
          : blocklistSentence(s)
      }
      actions={
        <>
          <ReadOnlyBadge />
          {!off ? (
            <Button asChild variant="outline" size="sm">
              <a href="#export">
                <Download aria-hidden />
                Export
              </a>
            </Button>
          ) : null}
        </>
      }
    />
  )

  if (off || nothingSeen) {
    return (
      <>
        {header}
        <EmptyState
          icon={off ? ShieldOff : ShieldCheck}
          title={off ? "Blocklists are turned off" : "No entries scored yet"}
          description={
            off ? (
              <>
                Set <code className="font-mono text-fg">BLOCKLIST_ENABLED=true</code> in{" "}
                <code className="font-mono text-fg">.env</code> and restart the stack. The scoring
                worker then reads what the decoys recorded and builds the lists.
              </>
            ) : (
              <>
                The worker scores what the decoys recorded about once an hour. Entries show up here
                as soon as attackers have earned a score. If it stays empty, check that{" "}
                <code className="font-mono text-fg">BLOCKLIST_ENABLED=true</code> is set in{" "}
                <code className="font-mono text-fg">.env</code>.
              </>
            )
          }
        />
      </>
    )
  }

  return (
    <>
      {header}

      <KindTiles summary={s} kind={kind} onSelect={(k) => setKindParam(k)} />

      <FilterBar
        className="mt-6 mb-4"
        chips={[
          {
            param: "kind",
            label: "Type",
            render: (v) => (isBlockKind(v) ? KIND_META[v].label : v),
          },
          { param: "reason", label: "Reason", render: reasonLabel },
        ]}
        alsoClears={["min_score", "q", "include_benign"]}
      >
        <SegmentedControl
          label="Minimum score"
          value={String(minScore)}
          onChange={(v) => setScoreParam(Number(v) === DEFAULT_MIN_SCORE ? null : v)}
          options={SCORE_OPTIONS}
        />
        <UrlSearch label="Search the list" placeholder="Search a value" />
        <label
          htmlFor={benignId}
          className="inline-flex h-8 items-center gap-2 rounded-md border bg-bg px-2.5 text-xs text-fg-muted"
        >
          <Switch
            id={benignId}
            size="sm"
            checked={includeBenign}
            onCheckedChange={(on) => setBenignParam(on ? "1" : null)}
          />
          Show research scanners
        </label>
      </FilterBar>

      {s && s.top_reasons.length > 0 && !reason ? (
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <span className="text-xs text-fg-muted">Common reasons</span>
          {s.top_reasons.map((r) => (
            <button
              key={r.reason}
              type="button"
              onClick={() => setReason(r.reason)}
              className="inline-flex h-6 items-center gap-1.5 rounded-sm border border-border-strong px-2 text-2xs font-medium text-fg-muted transition-colors hover:border-fg-subtle hover:text-fg"
            >
              {reasonLabel(r.reason)}
              <span className="text-fg-subtle">{formatNumber(r.count)}</span>
            </button>
          ))}
        </div>
      ) : null}

      <div className="overflow-hidden rounded-lg border bg-surface shadow-sm">
        <div
          className={cn(
            "hidden border-b px-5 py-2.5 text-2xs font-medium tracking-wide text-fg-subtle uppercase",
            BLOCKLIST_GRID,
          )}
        >
          <span>Value</span>
          <span>Score</span>
          <span>Why it is listed</span>
          <span>Seen</span>
          <span className="sr-only">Actions</span>
        </div>
        {query.isPending ? (
          <SkeletonList rows={8} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title="Could not load the blocklist"
            description={query.error.message}
            action={
              <Button variant="outline" size="sm" onClick={() => void query.refetch()}>
                Try again
              </Button>
            }
          />
        ) : rows.length === 0 ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title={filtered ? "Nothing matches" : "Nothing listed"}
            description={
              filtered
                ? "Lower the minimum score, or clear a filter to see more."
                : "No entry has reached this score yet."
            }
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label="Blocklist entries"
            aria-busy={isFetchingNextPage}
            className="relative w-full"
            style={{ height: virtualizer.getTotalSize() }}
          >
            {items.map((item) => {
              const row = rows[item.index]
              return (
                <div
                  key={item.key}
                  role="listitem"
                  data-index={item.index}
                  ref={virtualizer.measureElement}
                  className={cn("absolute top-0 left-0 w-full", item.index > 0 && "border-t")}
                  style={{
                    transform: `translateY(${item.start - virtualizer.options.scrollMargin}px)`,
                  }}
                >
                  {row ? (
                    <BlocklistRow
                      entry={row}
                      canWrite={canWrite}
                      onOverride={(entry, action) =>
                        setDialog({ target: { kind: entry.kind, value: entry.value }, action })
                      }
                      onRemoveOverride={(entry) => removeOverride.mutate(entry)}
                    />
                  ) : (
                    <SkeletonRow />
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
      {query.isSuccess && rows.length > 0 && !hasNextPage ? (
        <p className="mt-4 text-center text-xs text-fg-subtle">
          End of the list · {formatNumber(rows.length)} {rows.length === 1 ? "entry" : "entries"}
        </p>
      ) : null}
      {s && s.demo_entries > 0 ? (
        <p className="mt-3 text-center text-xs text-fg-subtle">
          {formatNumber(s.demo_entries)} entries are demo data. They are shown here and never
          exported.
        </p>
      ) : null}

      <div className="mt-8 grid grid-cols-1 gap-4 lg:grid-cols-2 lg:items-start">
        <ExportPanel summary={s} initialKind={kind ?? "ip"} />
        <OverridesCard canWrite={canWrite} />
      </div>

      {dialog ? (
        <OverrideDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null)
          }}
          target={dialog.target}
          action={dialog.action}
        />
      ) : null}
    </>
  )
}
