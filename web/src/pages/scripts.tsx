import { FileCode2 } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"

/** Placeholder until this page is built; the route and nav entry already exist. */
export function ScriptsPage() {
  return (
    <>
      <PageHeader title="Scripts" />
      <EmptyState
        icon={FileCode2}
        badge="Coming soon"
        title="Scripts is on its way"
        description="Every distinct command sequence attackers ran, with a plain-language explanation of what it does."
      />
    </>
  )
}
