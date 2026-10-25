import { ScanSearch } from "lucide-react"
import { cn } from "@/lib/utils"

/**
 * Marks a session from a known research scanner (shown only while the sidebar switch lets
 * scanners through). Neutral on purpose: it is not a threat, and it never uses red.
 */
export function ScannerBadge({
  name,
  short = false,
  className,
}: {
  name?: string | null
  short?: boolean
  className?: string
}) {
  return (
    <span
      title={name ? `Known research scanner: ${name}` : "Known research scanner"}
      className={cn(
        "inline-flex h-6 shrink-0 items-center gap-1.5 rounded-sm border border-dashed border-border-strong px-2 text-2xs font-medium text-fg-muted",
        className,
      )}
    >
      <ScanSearch aria-hidden className="size-3" strokeWidth={2} />
      {short ? "Scanner" : "Research scanner"}
    </span>
  )
}
