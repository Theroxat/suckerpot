import { CircleCheck, Share2 } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { JoinDialog } from "@/components/network/join-dialog"
import { SharedExplainer } from "@/components/network/explainer"
import { useNetworkStatus } from "@/components/network/use-network"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { BENEFIT } from "@/lib/network"

/**
 * The optional "Join the Selfhostr network" step of the setup flow. Standalone: the setup flow
 * decides where it goes and what "next" means.
 *
 * Joining is never the default. "Not now" is as prominent as "Join", does nothing and sends
 * nothing, and the step says so. The step hides itself when sharing is switched off in .env and
 * no hub is configured (there is nothing to offer), and shows a done state for a member.
 *
 * - `onDone` is called after joining.
 * - `onSkip` is called when the person chooses "Not now".
 */
export function NetworkStep({ onDone, onSkip }: { onDone?: () => void; onSkip?: () => void }) {
  const { canWrite } = useAuth()
  const q = useNetworkStatus()
  const [open, setOpen] = useState(false)
  const s = q.data
  if (q.isPending) return <SkeletonText lines={4} />
  if (!s || (!s.enabled_env && !s.hub_configured)) return null

  if (s.state === "member" || s.state === "enrolling") {
    return (
      <div className="space-y-3">
        <h3 className="flex items-center gap-2 text-base font-medium text-fg">
          <CircleCheck aria-hidden className="size-4 text-status-ok" strokeWidth={2.25} />
          {s.state === "member"
            ? "You are part of the Selfhostr network."
            : "Joining the Selfhostr network…"}
        </h3>
        <p className="text-sm text-fg-muted">
          You can read everything that was sent, change your pseudonym or leave at any time in{" "}
          <Link to="/settings?tab=network" className="text-fg underline underline-offset-4">
            Settings, Network
          </Link>
          .
        </p>
      </div>
    )
  }

  const blocked = !s.enabled_env
    ? "Sharing is switched off in .env on this system. Run just set NETWORK_ENABLED=true and restart to allow it."
    : !s.hub_configured
      ? "No network hub is configured yet, so there is nothing to join."
      : null

  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <h3 className="text-base font-medium text-fg">
          Join the Selfhostr network <span className="font-normal text-fg-muted">(optional)</span>
        </h3>
        <p className="max-w-3xl text-sm text-fg-muted">{BENEFIT}</p>
        <p className="max-w-3xl text-sm text-fg">
          You can skip this. Until you join, nothing leaves this system, and you can join or leave
          later in Settings.
        </p>
      </div>
      <SharedExplainer compact />
      {blocked ? (
        <p
          role="status"
          className="rounded-md border border-dashed px-3 py-2 text-sm text-fg-muted"
        >
          {blocked}
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-3">
        {canWrite ? (
          <Button variant="outline" onClick={() => setOpen(true)} disabled={!!blocked}>
            <Share2 aria-hidden />
            Join the network
          </Button>
        ) : null}
        <Button variant="outline" onClick={onSkip}>
          Not now
        </Button>
      </div>
      <JoinDialog open={open} onOpenChange={setOpen} {...(onDone ? { onJoined: onDone } : {})} />
    </div>
  )
}
