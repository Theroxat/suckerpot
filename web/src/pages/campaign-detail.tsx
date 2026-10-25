import { Flag } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"

/** Placeholder until this page is built; the route and nav entry already exist. */
export function CampaignDetailPage() {
  return (
    <>
      <PageHeader title="Campaign" />
      <EmptyState
        icon={Flag}
        badge="Coming soon"
        title="Campaign is on its way"
        description="The timeline, sources, techniques and sessions of one campaign."
      />
    </>
  )
}
