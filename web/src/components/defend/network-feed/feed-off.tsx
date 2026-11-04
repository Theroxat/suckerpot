import { ListChecks, Rss } from "lucide-react"
import { CodeBlock } from "@/components/defend/code-block"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { Term } from "@/components/term"
import { Button } from "@/components/ui/button"
import type { FeedStatus } from "@/lib/network-feed"

/**
 * The tab when the dashboard does not fetch the lists. Firewalls can still fetch them straight
 * from the public address, so the address is shown to copy. No request is made to the list host
 * until the flag is on.
 */
export function FeedOff({ status, onHowTo }: { status: FeedStatus; onHowTo: () => void }) {
  const outbound = status.lists.find((l) => l.id === "outbound")
  const txt = outbound?.files.find((f) => f.format === "txt" && f.tier === "standard")
  return (
    <div className="space-y-4">
      <EmptyState
        icon={Rss}
        title="The community lists are not fetched here"
        description="The SuckerPot network publishes free lists of malware hosts and attack sources. A host is listed only when at least 5 independent sensors confirmed it, and the lists stay empty until enough members exist. Using them is optional."
        action={
          <Button variant="outline" size="sm" onClick={onHowTo}>
            <ListChecks aria-hidden />
            How to use them in a firewall
          </Button>
        }
      />
      <FindingCard
        eyebrow="Two ways to use the lists"
        finding="Your firewall can fetch them directly, with or without this dashboard."
        detail={
          <>
            An <Term id="outbound-list">outbound list</Term> stops infected devices from calling
            home, and an <Term id="inbound-list">inbound list</Term> blocks known attackers.
          </>
        }
      >
        <div className="space-y-4 text-sm text-fg-muted">
          <div className="space-y-2">
            <p className="font-medium text-fg">1. Directly from the public address</p>
            {txt ? (
              <CodeBlock
                text={txt.url}
                label="Outbound list address"
                caption="Outbound, plain text"
              />
            ) : (
              <p>
                No list address is set on this system yet. The guide shows where the address goes.
              </p>
            )}
          </div>
          <div className="space-y-2">
            <p className="font-medium text-fg">2. Let this dashboard fetch them too</p>
            <p>
              You then see the entries here, and which ones also reached this sensor. On the host,
              run:
            </p>
            <CodeBlock
              text="just set NETWORK_FEED_ENABLED=true"
              label="Command to turn the lists on"
              caption="On the host"
            />
          </div>
        </div>
      </FindingCard>
    </div>
  )
}
