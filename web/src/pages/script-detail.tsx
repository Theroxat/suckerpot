import { FileCode2 } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"

/** Placeholder until this page is built; the route and nav entry already exist. */
export function ScriptDetailPage() {
  return (
    <>
      <PageHeader title="Script" />
      <EmptyState
        icon={FileCode2}
        badge="Coming soon"
        title="Script is on its way"
        description="One recorded script, line by line, with what each line does and who ran it."
      />
    </>
  )
}
