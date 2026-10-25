import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { IntelBadge } from "@/components/infrastructure/intel-badge"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { CopyDefanged } from "@/components/trends/copy-defanged"
import { formatNumber, plural } from "@/lib/format"
import { maskDefanged, ROLE_LABELS, TYPE_LABELS, type IndicatorItem } from "@/lib/infrastructure"
import { cn } from "@/lib/utils"

export const INDICATOR_GRID =
  "md:grid-cols-[minmax(0,1fr)_9rem_9rem_5rem_5rem_6rem_2rem] md:gap-x-4"

interface IndicatorRowProps {
  item: IndicatorItem
  onOpen: (id: number) => void
}

/**
 * One indicator. It is text, never a link: the row opens a detail panel, and the copy button
 * hands out the defanged form.
 */
export function IndicatorRow({ item, onOpen }: IndicatorRowProps) {
  const { masked } = useIpMask()
  const shown = masked ? maskDefanged(item.defanged) : item.defanged
  return (
    <div
      className={cn(
        "group/row relative grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1.5 px-4 py-3 transition-colors duration-150 hover:bg-surface-hover/50 sm:px-5",
        INDICATOR_GRID,
      )}
    >
      <button
        type="button"
        onClick={() => onOpen(item.id)}
        aria-label={`Details for ${TYPE_LABELS[item.type].toLowerCase()} ${shown}: ${plural(item.ips, "address", "addresses")}`}
        className="absolute inset-0 rounded-[inherit] focus-visible:outline-offset-[-2px]"
      />
      <div className="min-w-0">
        <p className="truncate font-mono text-xs text-fg" title={shown}>
          {shown}
        </p>
        <p className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-fg-muted">
          <span>{TYPE_LABELS[item.type]}</span>
          <span aria-hidden>·</span>
          <span>{ROLE_LABELS[item.role]}</span>
          {item.sensors.map((s) => (
            <SensorBadge key={s} sensor={s} variant="dot" />
          ))}
        </p>
      </div>

      <div className="relative z-10 md:order-last">
        <CopyDefanged url={item.defanged} />
      </div>

      <div className="col-span-2 flex flex-wrap items-center gap-2 md:contents">
        <IntelBadge item={item} className="md:justify-self-start" />
        {item.family ? (
          <Link
            to={`/infrastructure?family=${encodeURIComponent(item.family)}`}
            className="relative z-10 min-w-0 truncate rounded-sm text-sm text-fg hover:underline hover:decoration-fg-subtle hover:underline-offset-4"
            aria-label={`Show indicators of family ${item.family}`}
          >
            {item.family}
          </Link>
        ) : (
          <span className="text-sm text-fg-subtle">No family</span>
        )}
        <p className="flex items-center gap-4 text-xs text-fg-muted tabular-nums md:hidden">
          <span>
            <span className="text-fg">{formatNumber(item.ips)}</span> addresses
          </span>
          <span>
            <span className="text-fg">{formatNumber(item.sightings)}</span> sightings
          </span>
          <RelativeTime iso={item.last_seen} className="relative z-10 text-xs" />
        </p>
      </div>

      <span className="hidden text-right text-sm text-fg tabular-nums md:block">
        {formatNumber(item.ips)}
      </span>
      <span className="hidden text-right text-sm text-fg tabular-nums md:block">
        {formatNumber(item.sightings)}
      </span>
      <span className="relative z-10 hidden justify-self-end md:block">
        <RelativeTime iso={item.last_seen} className="text-xs" />
      </span>
    </div>
  )
}
