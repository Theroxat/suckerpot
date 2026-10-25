import { FileText } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"

/** Placeholder until this page is built; the route and nav entry already exist. */
export function ReportPage() {
  return (
    <>
      <PageHeader title="Weekly report" />
      <EmptyState
        icon={FileText}
        badge="Coming soon"
        title="Weekly report is on its way"
        description="One weekly report: what happened, what changed and what to do next."
      />
    </>
  )
}
