import { useState } from "react"
import { CodeBlock } from "@/components/defend/code-block"
import { SegmentedControl } from "@/components/segmented-control"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { addressFor, usageSteps, type FeedStatus, type FirewallApp } from "@/lib/network-feed"

const APPS = [
  { value: "opnsense", label: "OPNsense" },
  { value: "pfsense", label: "pfSense" },
  { value: "nftables", label: "nftables" },
] as const

const PICK: Record<FirewallApp, string> = {
  opnsense: "Pick the plain text format (.txt). OPNsense reads one address per line.",
  pfsense:
    "Pick the plain text format (.txt). For pfBlockerNG use the IPv4-only and IPv6-only files.",
  nftables: "Pick the nftables format (.nft). It loads in one step with nft -f.",
}

/** The steps to put the lists in a firewall. The lists are optional, and so is every step. */
export function HowToDrawer({
  open,
  onOpenChange,
  status,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  status: FeedStatus | undefined
}) {
  const [app, setApp] = useState<FirewallApp>("opnsense")
  const url = addressFor(app, status)
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full gap-0 overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>Use the lists in your firewall</SheetTitle>
          <SheetDescription>
            Optional. Your firewall fetches the public address itself, so it keeps working without
            this dashboard. Start with the outbound list.
          </SheetDescription>
        </SheetHeader>
        <div className="space-y-4 px-4 pb-6">
          <SegmentedControl label="Firewall" value={app} onChange={setApp} options={APPS} />
          <p className="text-sm text-fg-muted">{PICK[app]}</p>
          <CodeBlock text={url} label={`${app} address`} caption="Address to copy" />
          <ol className="list-decimal space-y-2 pl-5 text-sm text-pretty text-fg-muted marker:text-fg-subtle">
            {usageSteps(app, url).map((step) => (
              <li key={step} className="break-words">
                {step}
              </li>
            ))}
          </ol>
          <p className="text-xs text-fg-muted">
            More firewalls and the full steps are in{" "}
            <code className="font-mono text-fg">docs/feeds.md</code>. Check the menu names against
            your firewall version.
          </p>
        </div>
      </SheetContent>
    </Sheet>
  )
}
