import { LoaderCircle, Share2, TriangleAlert } from "lucide-react"
import { useState } from "react"
import { useAuth } from "@/app/auth"
import { FindingCard } from "@/components/finding-card"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { describeNetworkError, describeStatus, type NetworkStatus } from "@/lib/network"
import { JoinDialog } from "./join-dialog"
import { useNetworkStatus } from "./use-network"

function Notice({ children, busy = false }: { children: React.ReactNode; busy?: boolean }) {
  const Icon = busy ? LoaderCircle : TriangleAlert
  return (
    <p
      role="status"
      className="flex items-start gap-2 rounded-md border bg-bg px-3 py-2 text-sm text-fg-muted"
    >
      <Icon
        aria-hidden
        className={busy ? "mt-0.5 size-4 shrink-0 animate-spin" : "mt-0.5 size-4 shrink-0"}
      />
      <span>{children}</span>
    </p>
  )
}

/** Why joining is not possible right now, or null when it is. */
function blockedBy(s: NetworkStatus): React.ReactNode {
  if (!s.enabled_env)
    return (
      <>
        An administrator must first allow sharing on this system: run{" "}
        <code className="font-mono text-fg">just set NETWORK_ENABLED=true</code> and restart. Until
        then the network stays completely off.
      </>
    )
  if (!s.hub_configured)
    return "This system has no network hub address yet, so there is nothing to join. Nothing is sent."
  return null
}

/**
 * The card shown while this system is NOT a member: it says so, and offers to join. Joining is
 * always an explicit choice; staying out needs no action.
 */
export function JoinCard({ onJoined }: { onJoined?: () => void }) {
  const { canWrite } = useAuth()
  const q = useNetworkStatus()
  const [open, setOpen] = useState(false)
  const s = q.data
  if (q.isPending) {
    return (
      <FindingCard eyebrow="Your membership" finding="Checking the network status…">
        <SkeletonText lines={2} />
      </FindingCard>
    )
  }
  if (!s) {
    return (
      <FindingCard eyebrow="Your membership" finding="The network status is not available.">
        <p className="text-sm text-fg-muted">This status is not available right now.</p>
      </FindingCard>
    )
  }
  const blocked = blockedBy(s)
  const busy = s.state === "enrolling" || s.state === "leaving"
  const error = s.state === "error" ? describeNetworkError(s.last_error_code) : null
  return (
    <FindingCard
      eyebrow="Your membership"
      finding={describeStatus(s)}
      detail={
        s.state === "off"
          ? "The network is optional and off by default. Joining takes one decision; leaving takes one click."
          : undefined
      }
    >
      <div className="space-y-4">
        {blocked ? <Notice>{blocked}</Notice> : null}
        {busy ? (
          <Notice busy>
            {s.state === "enrolling"
              ? "Creating this system's key and registering it. This page updates by itself."
              : "Deleting your data. This page updates by itself."}
          </Notice>
        ) : null}
        {error ? <Notice>{error}</Notice> : null}
        {s.state === "off" || s.state === "error" ? (
          canWrite ? (
            <div className="flex flex-wrap items-center gap-3">
              <Button onClick={() => setOpen(true)} disabled={!!blocked}>
                <Share2 aria-hidden />
                Join the network
              </Button>
              <span className="text-xs text-fg-muted">
                You will be asked to tick what you agree to share, and for your password.
              </span>
            </div>
          ) : (
            <p className="text-sm text-fg-muted">
              Only an administrator can join the network for this system.
            </p>
          )
        ) : null}
      </div>
      <JoinDialog open={open} onOpenChange={setOpen} {...(onJoined ? { onJoined } : {})} />
    </FindingCard>
  )
}
