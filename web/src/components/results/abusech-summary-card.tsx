import { useQuery } from "@tanstack/react-query"
import { ArrowRight } from "lucide-react"
import { Link } from "react-router"
import { FindingCard } from "@/components/finding-card"
import { Button } from "@/components/ui/button"
import { abusechApi, abusechKeys, tabCounts } from "@/lib/abusech"
import { describeAbusech } from "@/lib/results-sentences"

function monthStart(): string {
  const d = new Date()
  return new Date(d.getFullYear(), d.getMonth(), 1).toISOString()
}

/** The abuse.ch card of the Results page: what went to URLhaus this month. */
export function AbusechSummaryCard() {
  const filters = { tab: "submitted", since: monthStart() } as const
  const q = useQuery({
    queryKey: abusechKeys.list(filters),
    queryFn: () => abusechApi.list(filters),
  })
  const counts = q.data ? tabCounts(q.data.counts) : undefined
  return (
    <FindingCard
      eyebrow="abuse.ch"
      finding={
        counts
          ? describeAbusech({ submitted: counts.submitted, known: counts.skipped })
          : "Counting the submissions to URLhaus…"
      }
      detail="Captured malware URLs can be shared with URLhaus. You decide whether and how."
      action={
        <Button asChild variant="outline" size="sm">
          <Link to="/defend/submissions">
            Open Submissions <ArrowRight aria-hidden />
          </Link>
        </Button>
      }
    />
  )
}
