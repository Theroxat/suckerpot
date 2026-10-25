import { ShieldCheck } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"

/** Placeholder until this page is built; the route and nav entry already exist. */
export function BlocklistsPage() {
  return (
    <>
      <PageHeader title="Blocklists" />
      <EmptyState
        icon={ShieldCheck}
        badge="Coming soon"
        title="Blocklists is on its way"
        description="Addresses, domains and URLs seen attacking you, ready to feed a firewall or a proxy."
      />
    </>
  )
}
