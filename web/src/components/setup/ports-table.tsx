import { useQuery } from "@tanstack/react-query"
import { CircleCheck, CircleOff, Hourglass, type LucideIcon } from "lucide-react"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { SkeletonText } from "@/components/skeletons"
import {
  describePort,
  describePorts,
  PORT_STATE_LABEL,
  wizardApi,
  wizardKeys,
  type PortItem,
  type PortState,
} from "@/lib/setup-wizard"
import { cn } from "@/lib/utils"

const STATE_STYLE: Record<PortState, { icon: LucideIcon; className: string }> = {
  receiving: { icon: CircleCheck, className: "text-status-ok" },
  waiting: { icon: Hourglass, className: "text-sev-warning" },
  off: { icon: CircleOff, className: "text-fg-muted" },
}

export function PortStatus({ item }: { item: PortItem }) {
  const { icon: Icon, className } = STATE_STYLE[item.state]
  return (
    <span className={cn("inline-flex items-start gap-1.5 text-sm", className)}>
      <Icon aria-hidden className="mt-0.5 size-4 shrink-0" strokeWidth={2.25} />
      <span>
        {PORT_STATE_LABEL[item.state]}
        {item.state === "receiving" && item.last_event_at ? (
          <span className="block text-xs text-fg-muted">
            last connection <RelativeTime iso={item.last_event_at} />
          </span>
        ) : null}
      </span>
    </span>
  )
}

const GRID = "grid-cols-[1fr_auto] sm:grid-cols-[8rem_1fr_1fr_1.4fr]"

/** The sensors, the router port to open, the port on this machine, and a live status. */
export function PortsTable({ items }: { items: readonly PortItem[] }) {
  return (
    <div>
      <div
        aria-hidden
        className={cn(
          "hidden gap-x-4 border-t px-4 py-2 text-xs font-medium text-fg-muted sm:grid sm:px-5",
          GRID,
        )}
      >
        <span>Sensor</span>
        <span>Open on your router</span>
        <span>Forward to this machine&apos;s port</span>
        <span>Status</span>
      </div>
      <ul aria-label="Sensor ports" className="divide-y border-t">
        {items.map((i) => (
          <li
            key={i.sensor}
            className={cn(
              "grid items-start gap-x-4 gap-y-1 px-4 py-3 sm:px-5",
              GRID,
              !i.enabled && "text-fg-muted",
            )}
          >
            <SensorBadge sensor={i.sensor} variant="dot" className="text-sm text-fg" />
            <span className="col-start-2 row-start-1 justify-self-end sm:col-start-4 sm:row-start-1 sm:justify-self-start">
              <PortStatus item={i} />
            </span>
            <span className="col-span-2 text-sm sm:col-span-1 sm:col-start-2 sm:row-start-1">
              <span className="text-xs text-fg-muted sm:hidden">Open on your router: </span>
              <span className="font-mono tabular-nums">{describePort(i)}</span>
            </span>
            <span className="col-span-2 text-sm sm:col-span-1 sm:col-start-3 sm:row-start-1">
              <span className="text-xs text-fg-muted sm:hidden">Forward to this machine: </span>
              <span className="font-mono tabular-nums">{i.host_port}</span>
              <span className="ml-2 font-mono text-2xs text-fg-subtle">{i.env_var}</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** The notes that belong under the table: what never to forward, CGNAT and DMZ. */
export function PortsNotes({ dashboardPort }: { dashboardPort: number }) {
  return (
    <ul className="list-disc space-y-1 pl-4 text-xs text-fg-muted">
      <li>
        Never forward port <span className="font-mono tabular-nums">{dashboardPort}</span> (the
        dashboard) or your admin SSH port.
      </li>
      <li>
        If your router&apos;s WAN address is in{" "}
        <span className="font-mono tabular-nums">100.64.0.0/10</span> (CGNAT), forwarding cannot
        work: ask your provider for a public address.
      </li>
      <li>
        A DMZ forwards every port, the dashboard&apos;s included. Forward the ports above one by one
        instead (see <code className="font-mono">docs/deployment.md</code>).
      </li>
      <li>
        Selfhostr never learns your public address. A sensor shows as receiving once a first visitor
        arrives, which usually takes a few minutes.
      </li>
    </ul>
  )
}

/** One card: the finding, the table, the notes. Shared by the setup step and Settings. */
export function PortsCard({ eyebrow = "Sensors and ports" }: { eyebrow?: string }) {
  const q = useQuery({
    queryKey: wizardKeys.ports,
    queryFn: wizardApi.ports,
    refetchInterval: 15_000,
  })
  return (
    <FindingCard
      eyebrow={eyebrow}
      finding={
        q.data
          ? describePorts(q.data.items)
          : q.isError
            ? "The port list is not available right now."
            : "Checking the sensors…"
      }
      detail="The status is live: a sensor turns to receiving as soon as someone connects to it."
      bodyClassName="px-0 sm:px-0 pt-3 pb-0 sm:pb-0"
      footer={q.data ? <PortsNotes dashboardPort={q.data.dashboard_port} /> : null}
    >
      {q.data ? (
        <PortsTable items={q.data.items} />
      ) : q.isPending ? (
        <div className="border-t px-4 py-3 sm:px-5">
          <SkeletonText lines={4} />
        </div>
      ) : null}
    </FindingCard>
  )
}
