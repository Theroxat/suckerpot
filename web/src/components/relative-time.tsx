import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useNow } from "@/hooks/use-now"
import { browserTimeZone, formatAbsolute, formatRelative } from "@/lib/format"
import { cn } from "@/lib/utils"

/** "5 min. ago", with the absolute time in the browser's time zone on hover. */
export function RelativeTime({ iso, className }: { iso: string; className?: string }) {
  const now = useNow()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <time
          dateTime={iso}
          tabIndex={0}
          className={cn("whitespace-nowrap text-fg-muted tabular-nums", className)}
        >
          {formatRelative(iso, now)}
        </time>
      </TooltipTrigger>
      <TooltipContent side="top">
        {formatAbsolute(iso)}
        <span className="ml-1.5 text-fg-subtle">{browserTimeZone()}</span>
      </TooltipContent>
    </Tooltip>
  )
}
