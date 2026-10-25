import { STAGES, STAGE_META, stageTrailText } from "@/lib/campaigns"
import { cn } from "@/lib/utils"

interface StageTrailProps {
  /** Stage ids the campaign went through (any order; the trail is always in story order). */
  stages: readonly string[]
  /** Print the stage names under the segments (detail pages), not just the shape. */
  labels?: boolean
  className?: string
}

/**
 * The playbook at a glance: six segments in story order, filled for the stages a campaign went
 * through. The shape carries the meaning (filled or outlined), and the whole trail has a text
 * alternative, so nothing rests on colour. Segments fade in one after the other.
 */
export function StageTrail({ stages, labels = false, className }: StageTrailProps) {
  return (
    <div className={className}>
      <ol
        aria-label={`Stages: ${stageTrailText(stages)}`}
        className={cn("flex items-center", labels ? "gap-1.5" : "gap-1")}
      >
        {STAGES.map((stage, i) => {
          const on = stages.includes(stage)
          return (
            <li
              key={stage}
              title={`${STAGE_META[stage].label}${on ? "" : " (not seen)"}`}
              className={cn("min-w-0", labels ? "flex-1" : "w-5")}
            >
              <span
                aria-hidden
                style={{ animationDelay: `${i * 45}ms` }}
                className={cn(
                  "block h-1.5 animate-fade-in rounded-full border",
                  on ? "border-fg-muted bg-fg-muted" : "border-border-strong bg-transparent",
                )}
              />
              {labels ? (
                <span
                  className={cn(
                    "mt-1.5 block truncate text-2xs",
                    on ? "font-medium text-fg" : "text-fg-subtle",
                  )}
                >
                  {STAGE_META[stage].label}
                  <span className="sr-only">{on ? " (seen)" : " (not seen)"}</span>
                </span>
              ) : (
                <span className="sr-only">
                  {STAGE_META[stage].label}
                  {on ? " (seen)" : " (not seen)"}
                </span>
              )}
            </li>
          )
        })}
      </ol>
    </div>
  )
}
