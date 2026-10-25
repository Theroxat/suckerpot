import { Flag } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"

/** Placeholder until this page is built; the route and nav entry already exist. */
export function CampaignsPage() {
  return (
    <>
      <PageHeader title="Campaigns" />
      <EmptyState
        icon={Flag}
        badge="Coming soon"
        title="Campaigns is on its way"
        description="Groups of attacks that share the same tools, scripts or servers, so you see one story instead of hundreds of sessions."
      />
    </>
  )
}
