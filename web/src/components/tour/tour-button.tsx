import { Compass } from "lucide-react"
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
      size="sm"
      aria-label="Take the tour"
      title="Take the tour"
      onClick={start}
      className={cn("text-fg-muted hover:text-fg max-lg:px-0", className)}
    >
      <Compass aria-hidden className="size-4" strokeWidth={1.85} />
      <span className="hidden lg:inline">Tour</span>
    </Button>
  )
}
