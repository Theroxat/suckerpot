import { useQuery } from "@tanstack/react-query"
import { useId } from "react"
import { useScannerFilter } from "@/app/scanner-filter"
import { Term } from "@/components/term"
import { Switch } from "@/components/ui/switch"
import { scannerCaption } from "@/lib/scanner-caption"
import { todayApi, todayKeys } from "@/lib/today"
import { cn } from "@/lib/utils"

/**
 * "Hide research scanners" switch, with the number of sessions it hides. The count is always
 * visible, so hiding never feels like data going missing. `inline` is the one-row form for the
 * desktop header (count first, then the label and the switch); the stacked form is for the
 * phone navigation drawer.
 */
export function ScannerToggle({
  className,
  inline = false,
}: {
  className?: string
  inline?: boolean
}) {
  const { hide, setHide } = useScannerFilter()
  const id = useId()
  const captionId = useId()
  const count = useQuery({
    queryKey: todayKeys.benign,
    queryFn: todayApi.benignCount,
    refetchInterval: 60_000,
  })
  const caption = scannerCaption(hide, count.data?.sessions)
  if (inline) {
    return (
      <div className={cn("flex items-center gap-2.5", className)}>
        <p id={captionId} className="hidden text-2xs text-fg-subtle xl:block">
          {caption}
        </p>
        <label htmlFor={id} className="text-xs whitespace-nowrap text-fg-muted">
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
    )
  }
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
        {caption}
      </p>
    </div>
  )
}
