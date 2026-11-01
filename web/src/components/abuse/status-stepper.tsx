import { Check } from "lucide-react"
import { STATUS_LABEL, STEPS, type ReportStatus } from "@/lib/abuse"
import { cn } from "@/lib/utils"

/** Draft, Reviewed, Sent, Closed. A discarded or replaced report shows where it left the path. */
export function StatusStepper({ status }: { status: ReportStatus }) {
  const index = STEPS.indexOf(status as (typeof STEPS)[number])
  const off = index < 0
  return (
    <div className="space-y-2">
      <ol
        aria-label="Report status"
        className="flex flex-wrap items-center gap-x-3.5 gap-y-1 sm:gap-x-2"
      >
        {STEPS.map((s, i) => {
          const done = !off && i < index
          const current = !off && i === index
          return (
            <li
              key={s}
              aria-current={current ? "step" : undefined}
              className={cn(
                "flex items-center gap-2 text-sm",
                current ? "font-medium text-fg" : done ? "text-fg-muted" : "text-fg-subtle",
              )}
            >
              <span
                aria-hidden
                className={cn(
                  "flex size-5 items-center justify-center rounded-full border text-2xs tabular-nums",
                  current && "border-fg bg-fg text-bg",
                  done && "border-border-strong text-fg-muted",
                )}
              >
                {done ? <Check className="size-3" strokeWidth={2.5} /> : i + 1}
              </span>
              {STATUS_LABEL[s]}
              <span className="sr-only">{current ? " (current)" : done ? " (done)" : ""}</span>
              {i < STEPS.length - 1 ? (
                <span aria-hidden className="ml-1 hidden h-px w-8 bg-border-strong sm:block" />
              ) : null}
            </li>
          )
        })}
      </ol>
      {off ? (
        <p className="text-sm text-fg-muted">
          {status === "discarded"
            ? "This report was discarded and will not be sent."
            : "This draft was replaced by a newer one."}
        </p>
      ) : null}
    </div>
  )
}
