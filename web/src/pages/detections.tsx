import { ScanSearch } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"

/** Placeholder until this page is built; the route and nav entry already exist. */
export function DetectionsPage() {
  return (
    <>
      <PageHeader title="Detections" />
      <EmptyState
        icon={ScanSearch}
        badge="Coming soon"
        title="Detections is on its way"
        description="Detection rules and indicators you can copy into your own security tools."
      />
    </>
  )
}
