import { CircleHelp } from "lucide-react"
import { useTour } from "@/app/tour"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

/** The "?" in the top bar that replays the guided tour. */
export function TourButton({ className }: { className?: string }) {
  const { start } = useTour()
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon-sm"
      aria-label="Take the tour"
      title="Take the tour"
      onClick={start}
      className={cn("text-fg-muted hover:text-fg", className)}
    >
      <CircleHelp aria-hidden className="size-4" strokeWidth={1.85} />
    </Button>
  )
}
