import { Eye } from "lucide-react"
import { useAuth } from "@/app/auth"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"

/** Shown to viewers only: everything can be read, nothing can be changed. */
export function ReadOnlyBadge({
  className,
  short = false,
}: {
  className?: string
  /** "Read-only" alone, for the narrow mobile top bar; the full label stays for screen readers. */
  short?: boolean
}) {
  const { user } = useAuth()
  if (user?.role !== "viewer") return null
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 text-2xs font-medium text-fg-muted",
            className,
          )}
        >
          <Eye aria-hidden className="size-3" />
          Read-only{short ? <span className="sr-only"> access</span> : " access"}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top">
        You can look at everything. Only an administrator can change settings or users.
      </TooltipContent>
    </Tooltip>
  )
}
