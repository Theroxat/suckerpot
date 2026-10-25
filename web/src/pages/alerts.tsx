import { Bell } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"

/** Placeholder until this page is built; the route and nav entry already exist. */
export function AlertsPage() {
  return (
    <>
      <PageHeader title="Alerts and reports" />
      <EmptyState
        icon={Bell}
        badge="Coming soon"
        title="Alerts and reports is on its way"
        description="Where alerts are sent, which events trigger them, and the weekly reports."
      />
    </>
  )
}
