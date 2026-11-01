import { useQuery } from "@tanstack/react-query"
import { Check, Copy } from "lucide-react"
import { useState } from "react"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { useCopy } from "@/hooks/use-copy"
import { formatNumber } from "@/lib/format"
import { formatDay, networkApi, networkKeys, type NetworkSubmission } from "@/lib/network"
import { cn } from "@/lib/utils"

function countsText(s: NetworkSubmission): string {
  const parts = Object.entries(s.counts)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `${formatNumber(n)} ${k}`)
  return parts.length ? parts.join(", ") : "nothing to send"
}

function droppedText(s: NetworkSubmission): string | null {
  const total = Object.values(s.dropped).reduce((a, b) => a + b, 0)
  return total > 0 ? `${formatNumber(total)} left out by the privacy check or the size cap` : null
}

function Payload({ day }: { day: string }) {
  const q = useQuery({
    queryKey: networkKeys.submission(day),
    queryFn: () => networkApi.submission(day),
  })
  const { copied, copy } = useCopy()
  if (q.isPending) return <SkeletonText lines={6} />
  if (!q.data) return <p className="text-sm text-fg-muted">This batch is no longer stored.</p>
  const text = JSON.stringify(q.data.payload, null, 2)
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-fg-muted">
          The exact data that was sent for {formatDay(day, true)}.
        </p>
        <Button size="sm" variant="outline" onClick={() => void copy(text)}>
          {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      <pre
        tabIndex={0}
        aria-label={`Data sent for ${day}`}
        className="max-h-[60vh] overflow-auto rounded-md border bg-bg p-3 font-mono text-xs leading-5 text-fg focus-visible:ring-2 focus-visible:ring-ring"
      >
        {text}
      </pre>
    </div>
  )
}

/**
 * "See exactly what was sent": the recent batches, and the stored JSON of the one picked.
 * Transparency is the point: whatever left this system can be read here, word for word.
 */
export function SentDrawer({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const q = useQuery({
    queryKey: networkKeys.submissions,
    queryFn: networkApi.submissions,
    enabled: open,
  })
  const [picked, setPicked] = useState<string | null>(null)
  const items = q.data ?? []
  const day = picked ?? items.find((s) => s.status === "sent")?.day ?? null
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full gap-0 overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>What was sent</SheetTitle>
          <SheetDescription>
            One batch a day, kept here for 7 days. Nothing else leaves this system.
          </SheetDescription>
        </SheetHeader>
        <div className="space-y-5 px-4 pb-6">
          {q.isPending ? (
            <SkeletonText lines={4} />
          ) : items.length === 0 ? (
            <p className="text-sm text-fg-muted">
              Nothing has been sent yet. The first batch goes out after a full day has ended.
            </p>
          ) : (
            <ul aria-label="Sent batches" className="divide-y rounded-md border">
              {items.map((s) => (
                <li key={s.day}>
                  <button
                    type="button"
                    onClick={() => setPicked(s.day)}
                    aria-current={day === s.day ? "true" : undefined}
                    className={cn(
                      "flex w-full flex-col gap-0.5 px-3 py-2 text-left text-sm transition-colors outline-none hover:bg-surface-hover focus-visible:ring-2 focus-visible:ring-ring",
                      day === s.day && "bg-surface-hover",
                    )}
                  >
                    <span className="font-medium text-fg">
                      {formatDay(s.day, true)}
                      <span className="ml-2 text-xs font-normal text-fg-muted">
                        {s.status === "sent"
                          ? "Sent"
                          : s.status === "failed"
                            ? "Failed"
                            : "Skipped"}
                      </span>
                    </span>
                    <span className="text-xs text-fg-muted">
                      {countsText(s)}
                      {droppedText(s) ? `; ${droppedText(s)}` : ""}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {day ? <Payload key={day} day={day} /> : null}
        </div>
      </SheetContent>
    </Sheet>
  )
}
