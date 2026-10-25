import { useQuery } from "@tanstack/react-query"
import { ArrowLeft, FileText, Printer } from "lucide-react"
import { Link, useParams } from "react-router"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { Skeleton } from "@/components/ui/skeleton"
import { Button } from "@/components/ui/button"
import { alertKeys, alertsApi, reportHtmlUrl, weekLabel } from "@/lib/alerts"
import { ApiError } from "@/lib/api"

const WEEK = /^\d{4}-\d{2}-\d{2}$/

/**
 * The report page itself, without scripts, in a sandboxed frame. The mock service worker cannot
 * answer a frame navigation, so mock and demo builds fetch the page and hand it over as text.
 */
function ReportFrame({ week }: { week: string }) {
  const mock = import.meta.env.VITE_MOCK === "1"
  const doc = useQuery({
    queryKey: ["reports", week, "html"],
    queryFn: async () => (await fetch(reportHtmlUrl(week))).text(),
    enabled: mock,
  })
  if (mock && doc.isPending) return <Skeleton className="h-[640px] w-full rounded-lg" />
  return (
    <iframe
      title={`Weekly report, week of ${week}`}
      {...(mock ? { srcDoc: doc.data ?? "" } : { src: reportHtmlUrl(week) })}
      sandbox=""
      referrerPolicy="no-referrer"
      className="h-[78vh] min-h-[640px] w-full rounded-lg border bg-white"
    />
  )
}

/**
 * One weekly report. The page itself is plain HTML written by the server with every value
 * escaped; it is shown in a frame without scripts, and the printable version opens on its own
 * so the browser can print it or save it as a PDF.
 */
export function ReportPage() {
  const { week = "" } = useParams()
  const valid = WEEK.test(week)
  const q = useQuery({
    queryKey: alertKeys.report(week),
    queryFn: () => alertsApi.report(week),
    enabled: valid,
    retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 2,
  })
  const back = (
    <Link to="/defend/alerts" className="inline-flex items-center gap-1 hover:text-fg">
      <ArrowLeft aria-hidden className="size-3.5" />
      Alerts and reports
    </Link>
  )
  if (!valid || (q.isError && q.error instanceof ApiError && q.error.status === 404)) {
    return (
      <>
        <PageHeader title="Weekly report" eyebrow={back} />
        <EmptyState
          icon={FileText}
          title="This report does not exist"
          description="Reports are built every Monday morning. Pick one from the list."
          action={
            <Button variant="outline" asChild>
              <Link to="/defend/alerts">Back to the list</Link>
            </Button>
          }
        />
      </>
    )
  }
  const headline = q.data?.summary.headline
  return (
    <>
      <PageHeader
        title={`Week of ${weekLabel(week, q.data?.summary.week_end ?? null)}`}
        eyebrow={back}
        description={headline ?? "Loading the report…"}
        actions={
          <Button variant="outline" size="sm" asChild>
            <a href={reportHtmlUrl(week)} target="_blank" rel="noopener noreferrer">
              <Printer aria-hidden />
              Open printable version
            </a>
          </Button>
        }
      />
      {q.isPending ? (
        <Skeleton className="h-[640px] w-full rounded-lg" />
      ) : q.isError ? (
        <EmptyState
          icon={FileText}
          title="The report could not be loaded"
          description="Try again in a moment."
        />
      ) : (
        <ReportFrame week={week} />
      )}
    </>
  )
}
