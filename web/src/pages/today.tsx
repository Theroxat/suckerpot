import { useQuery } from "@tanstack/react-query"
import { SearchX } from "lucide-react"
import { useScannerFilter } from "@/app/scanner-filter"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { Term } from "@/components/term"
import { TodayCard, TodayCardSkeleton } from "@/components/today/today-card"
import { Button } from "@/components/ui/button"
import { plural } from "@/lib/format"
import { todayApi, todayKeys } from "@/lib/today"

/** "17:22": the page refreshes every two minutes, so seconds would be false precision. */
const time = new Intl.DateTimeFormat("en-US", {
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
})
function formatTime(iso: string): string {
  return time.format(new Date(iso))
}

/**
 * Today: the home page. Three to five cards, each one sentence, up to three items and one
 * action, so the first screen answers "what happened, is anything urgent, what should I do".
 */
export function TodayPage() {
  const query = useQuery({
    queryKey: todayKeys.today,
    queryFn: todayApi.today,
    refetchInterval: 120_000,
  })
  const { hide, setHide } = useScannerFilter()
  const data = query.data

  return (
    <>
      <PageHeader
        title="Today"
        description="What happened in the last 24 hours, what is new, and what to do about it."
      />

      {/* One quiet meta line: freshness, and what the scanner switch leaves out. */}
      {data ? (
        <p className="-mt-3 mb-5 text-xs text-fg-muted">
          Updated <time dateTime={data.generated_at}>{formatTime(data.generated_at)}</time>
          {hide && data.hidden_benign > 0 ? (
            <>
              <span aria-hidden className="px-1.5 text-fg-subtle">
                ·
              </span>
              {plural(data.hidden_benign, "session")} from{" "}
              <Term id="research-scanner">research scanners</Term>{" "}
              {data.hidden_benign === 1 ? "is" : "are"} left out.{" "}
              <button
                type="button"
                onClick={() => setHide(false)}
                className="rounded-xs text-fg underline underline-offset-4 hover:text-fg-muted"
              >
                Show them
              </button>
            </>
          ) : null}
        </p>
      ) : null}

      {query.isPending ? (
        <div role="status" aria-label="Loading" className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {Array.from({ length: 4 }, (_, i) => (
            <TodayCardSkeleton key={i} />
          ))}
        </div>
      ) : query.isError ? (
        <EmptyState
          icon={SearchX}
          title="Could not load Today"
          description={query.error.message}
          action={
            <Button variant="outline" size="sm" onClick={() => void query.refetch()}>
              Try again
            </Button>
          }
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {query.data.cards.map((card, i) => (
            <TodayCard
              key={card.id}
              card={card}
              index={i}
              // An odd last card takes the whole row instead of leaving a hole.
              className={
                i === query.data.cards.length - 1 && query.data.cards.length % 2 === 1
                  ? "lg:col-span-2"
                  : undefined
              }
            />
          ))}
        </div>
      )}
    </>
  )
}
