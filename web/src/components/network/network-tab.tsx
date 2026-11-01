import { FindingCard } from "@/components/finding-card"
import { SharedExplainer } from "./explainer"
import { JoinCard } from "./join-card"
import { NodeCard } from "./node-card"
import { useNetworkStatus } from "./use-network"
import { isMember } from "@/lib/network"

/**
 * Settings, Network tab: the place to join and to leave. A member sees their node and the two
 * actions; everyone else sees the offer. The full explanation is always one scroll away.
 */
export function NetworkTab() {
  const q = useNetworkStatus()
  const member = isMember(q.data)
  return (
    <>
      {member && q.data ? <NodeCard status={q.data} /> : <JoinCard />}
      <FindingCard
        eyebrow="What is shared"
        finding={
          member
            ? "This is everything your node shares, and everything it never does."
            : "Nothing is shared until you join. This is exactly what would be."
        }
      >
        <SharedExplainer />
      </FindingCard>
    </>
  )
}
