import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleSlash,
  Clock,
  ExternalLink,
  Send,
  type LucideIcon,
} from "lucide-react"
import { useId, useMemo, useState } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { ConfirmDialog } from "@/components/abuse/status-dialogs"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { ReadOnlyBadge } from "@/components/read-only-badge"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonList } from "@/components/skeletons"
import { TagBadge } from "@/components/tag-badge"
import { Button } from "@/components/ui/button"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useUrlParam } from "@/hooks/use-url-param"
import {
  abusechApi,
  abusechKeys,
  describeAbusechError,
  describeLookup,
  describeSchedule,
  describeSelection,
  describeSubmissions,
  describeResult,
  STATUS_LABEL,
  SUBMISSION_TABS,
  tabCounts,
  type Submission,
  type SubmissionStatus,
  type SubmissionTab,
} from "@/lib/abusech"
import { plural } from "@/lib/format"
import { defang } from "@/lib/results-sentences"
import { cn } from "@/lib/utils"

const STATUS_ICON: Record<SubmissionStatus, LucideIcon> = {
  candidate: CircleDashed,
  pending: Clock,
  submitting: Send,
  duplicate: CircleSlash,
  rejected: CircleAlert,
  skipped_never_list: CircleSlash,
  submitted: CircleCheck,
  skipped_known: CircleSlash,
  guard_failed: CircleAlert,
  failed: CircleAlert,
  cancelled: CircleSlash,
}

const MAX_SELECTED = 20

function StatusMark({ s }: { s: Submission }) {
  const Icon = STATUS_ICON[s.status]
  const bad = s.status === "failed" || s.status === "guard_failed" || s.status === "rejected"
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap text-fg">
      <Icon
        aria-hidden
        className={cn(
          "size-3.5",
          s.status === "submitted" ? "text-status-ok" : bad ? "text-sev-warning" : "text-fg-muted",
        )}
      />
      {STATUS_LABEL[s.status]}
    </span>
  )
}

export function SubmissionsPage() {
  const { canWrite } = useAuth()
  const qc = useQueryClient()
  const [param, setParam] = useUrlParam("tab")
  const tab: SubmissionTab = SUBMISSION_TABS.find((t) => t.value === param)?.value ?? "review"
  const [selected, setSelected] = useState<ReadonlySet<number>>(new Set())
  const [confirm, setConfirm] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const checkId = useId()
  const settings = useQuery({
    queryKey: abusechKeys.settings,
    queryFn: abusechApi.settings,
    enabled: canWrite,
    retry: false,
  })
  const filters = { tab }
  const list = useInfiniteQuery({
    queryKey: abusechKeys.list(filters),
    queryFn: ({ pageParam }) => abusechApi.list(filters, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const items = useMemo(() => (list.data?.pages ?? []).flatMap((p) => p.items), [list.data])
  const rawCounts = list.data?.pages[0]?.counts
  const counts = rawCounts ? tabCounts(rawCounts) : undefined
  const refresh = () => void qc.invalidateQueries({ queryKey: abusechKeys.all })
  const cancel = useMutation({
    mutationFn: (id: number) => abusechApi.cancel(id),
    onSuccess: refresh,
    onError: (e) => setError(describeAbusechError(e)),
  })
  const mode = settings.data?.mode
  const submittable = (s: Submission) => s.status === "candidate" && s.lookup === "unknown"
  const chosen = items.filter((s) => selected.has(s.id) && submittable(s))
  const canSubmit = canWrite && mode !== undefined && mode !== "off"
  const total = counts?.[tab] ?? items.length
  const mostTagged = (() => {
    const n = new Map<string, number>()
    for (const s of items) for (const t of s.tags) n.set(t, (n.get(t) ?? 0) + 1)
    return [...n.entries()].sort((a, b) => b[1] - a[1])[0]
  })()
  const finding =
    tab === "review"
      ? `${plural(total, "URL")} ${total === 1 ? "waits" : "wait"} for your review${
          mostTagged
            ? `; ${mostTagged[1]} ${mostTagged[1] === 1 ? "is" : "are"} tagged ${mostTagged[0]}`
            : ""
        }.`
      : `${plural(total, "URL")} in this list.`
  const onePlatform = items.every((s) => s.platform === items[0]?.platform)

  return (
    <>
      <PageHeader
        help="abuse-submissions"
        title="Submissions"
        description={
          <span className="normal-nums">
            {canWrite
              ? describeSubmissions(settings.data)
              : "Captured malware URLs shared with URLhaus, if the administrator chose to."}
          </span>
        }
        actions={
          <>
            <ReadOnlyBadge />
            {canWrite ? (
              <Button asChild variant="outline" size="sm">
                <Link to="/settings?tab=reporting">abuse.ch settings</Link>
              </Button>
            ) : null}
          </>
        }
      />
      <Tabs
        value={tab}
        onValueChange={(v) => {
          setSelected(new Set())
          setParam(v === "review" ? null : v)
        }}
      >
        <TabsList
          variant="line"
          aria-label="Submission status"
          className="mb-4 max-w-full justify-start overflow-x-auto"
        >
          {SUBMISSION_TABS.map((t) => (
            <TabsTrigger key={t.value} value={t.value} className="flex-none px-3">
              {t.label}
              {counts ? (
                <span className="ml-1.5 text-xs text-fg-subtle tabular-nums">
                  {counts[t.value]}
                </span>
              ) : null}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      {list.isPending ? (
        <SkeletonList rows={4} />
      ) : list.isError ? (
        <EmptyState
          icon={Send}
          title="Could not load the submissions"
          action={
            <Button variant="outline" size="sm" onClick={() => void list.refetch()}>
              Try again
            </Button>
          }
        />
      ) : items.length === 0 ? (
        <EmptyState
          icon={Send}
          title="Nothing here"
          description={
            mode === "off"
              ? "Submission is off. Turn it on in Settings, Reporting, abuse.ch."
              : "URLs appear here when a captured sample was served by a host and abuse.ch does not know it yet."
          }
        />
      ) : (
        <FindingCard
          eyebrow={SUBMISSION_TABS.find((t) => t.value === tab)?.label ?? "Submissions"}
          finding={finding}
          detail="URLs are shown defanged and are never links."
          action={
            canSubmit && tab === "review" ? (
              <div className="flex flex-wrap items-center gap-2">
                {chosen.length === 0 ? (
                  <span className="text-xs text-fg-muted">Select URLs to submit</span>
                ) : null}
                <Button
                  size="sm"
                  variant={chosen.length === 0 ? "outline" : "default"}
                  disabled={chosen.length === 0}
                  onClick={() => setConfirm(true)}
                >
                  <Send aria-hidden /> Submit selected
                  {chosen.length > 0 ? ` (${chosen.length})` : ""}
                </Button>
              </div>
            ) : undefined
          }
          bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
          className="normal-nums"
        >
          <ul className="divide-y border-t">
            {items.map((s) => {
              const rowId = `${checkId}-${s.id}`
              const when = describeSchedule(s)
              const canPick = canSubmit && submittable(s)
              return (
                <li
                  key={s.id}
                  className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-1 px-4 py-3 sm:px-5"
                >
                  {canSubmit && tab === "review" ? (
                    <input
                      id={rowId}
                      type="checkbox"
                      disabled={!canPick || (!selected.has(s.id) && chosen.length >= MAX_SELECTED)}
                      checked={selected.has(s.id)}
                      onChange={(e) =>
                        setSelected((prev) => {
                          const next = new Set(prev)
                          if (e.target.checked) next.add(s.id)
                          else next.delete(s.id)
                          return next
                        })
                      }
                      aria-label={`Select ${defang(s.value)}`}
                      className="mt-1 size-4 accent-current"
                    />
                  ) : (
                    <span aria-hidden className="w-0" />
                  )}
                  <div className="min-w-0 space-y-1.5">
                    <p className="font-mono text-xs break-all text-fg">{defang(s.value)}</p>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs text-fg-muted">
                      {tab === "review" ? null : <StatusMark s={s} />}
                      {onePlatform ? null : (
                        <TagBadge
                          tag={s.platform === "urlhaus" ? "URLhaus" : "ThreatFox"}
                          href={null}
                        />
                      )}
                      {s.tags.map((t) => (
                        <TagBadge key={t} tag={t} href={null} />
                      ))}
                      <span>{describeLookup(s)}</span>
                      {when ? <span>{when}</span> : null}
                      {s.submitted_at ? <RelativeTime iso={s.submitted_at} /> : null}
                      {s.reference ? (
                        <a
                          href={s.reference}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="inline-flex items-center gap-1 text-fg underline underline-offset-4"
                        >
                          Open on URLhaus <ExternalLink aria-hidden className="size-3" />
                        </a>
                      ) : null}
                      {canWrite && s.status === "pending" ? (
                        <Button
                          variant="ghost"
                          size="xs"
                          disabled={cancel.isPending}
                          onClick={() => cancel.mutate(s.id)}
                        >
                          Cancel
                        </Button>
                      ) : null}
                    </div>
                    {s.result_code ? (
                      <p className="text-xs text-fg-muted">{describeResult(s.result_code)}</p>
                    ) : null}
                  </div>
                </li>
              )
            })}
          </ul>
        </FindingCard>
      )}
      {list.hasNextPage ? (
        <Button
          className="mt-4"
          variant="outline"
          size="sm"
          disabled={list.isFetchingNextPage}
          onClick={() => void list.fetchNextPage()}
        >
          {list.isFetchingNextPage ? "Loading…" : "Show more"}
        </Button>
      ) : null}
      <p role="alert" className="mt-3 text-sm text-fg empty:hidden">
        {error}
      </p>

      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title={describeSelection(chosen.length)}
        description="These URLs are sent to URLhaus. The text is checked first and never names you."
        confirmLabel="Submit"
        describe={describeAbusechError}
        run={async () => {
          await abusechApi.submit(chosen.map((s) => s.id))
          setSelected(new Set())
          setError(null)
          refresh()
        }}
      >
        <ul className="max-h-48 space-y-1 overflow-y-auto rounded-md border bg-bg p-3 font-mono text-xs break-all">
          {chosen.map((s) => (
            <li key={s.id}>{defang(s.value)}</li>
          ))}
        </ul>
      </ConfirmDialog>
    </>
  )
}
