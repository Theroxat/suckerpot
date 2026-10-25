import { useQuery } from "@tanstack/react-query"
import { useId } from "react"
import { useScannerFilter } from "@/app/scanner-filter"
import { Term } from "@/components/term"
import { Switch } from "@/components/ui/switch"
import { scannerCaption } from "@/lib/scanner-caption"
import { todayApi, todayKeys } from "@/lib/today"
import { cn } from "@/lib/utils"

/**
 * "Hide research scanners" switch for the sidebar footer, with the number of sessions it hides.
 * The count is always visible, so hiding never feels like data going missing.
 */
export function ScannerToggle({ className }: { className?: string }) {
  const { hide, setHide } = useScannerFilter()
  const id = useId()
  const captionId = useId()
  const count = useQuery({
    queryKey: todayKeys.benign,
    queryFn: todayApi.benignCount,
    refetchInterval: 60_000,
  })
  return (
    <div className={cn("flex flex-col gap-1", className)}>
      <div className="flex items-center justify-between gap-2">
        <label htmlFor={id} className="text-xs text-fg-muted">
          Hide <Term id="research-scanner">research scanners</Term>
        </label>
        <Switch
          id={id}
          size="sm"
          checked={hide}
          onCheckedChange={setHide}
          aria-describedby={captionId}
        />
      </div>
      <p id={captionId} className="min-h-4 text-2xs text-fg-subtle">
        {scannerCaption(hide, count.data?.sessions)}
      </p>
    </div>
  )
}
