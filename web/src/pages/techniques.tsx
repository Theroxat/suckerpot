import { Grid3x3 } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"

/** Placeholder until this page is built; the route and nav entry already exist. */
export function TechniquesPage() {
  return (
    <>
      <PageHeader title="Techniques" />
      <EmptyState
        icon={Grid3x3}
        badge="Coming soon"
        title="Techniques is on its way"
        description="A MITRE ATT&CK heatmap of what attackers tried against your sensors, by stage and over time."
      />
    </>
  )
}
