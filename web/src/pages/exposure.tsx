import { Radar } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"

/** Placeholder until this page is built; the route and nav entry already exist. */
export function ExposurePage() {
  return (
    <>
      <PageHeader title="Your exposure" />
      <EmptyState
        icon={Radar}
        badge="Coming soon"
        title="Your exposure is on its way"
        description="How the attacks seen here map onto the services your company runs, and what to patch first."
      />
    </>
  )
}
