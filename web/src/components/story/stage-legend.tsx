import { Explain } from "@/components/explain"
import { STAGES, STAGE_META } from "@/lib/story"

/** One plain sentence per stage, in the order the Sankey draws them. Icon + word + colour. */
export function StageLegend() {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-3">
      {STAGES.map((stage) => {
        const meta = STAGE_META[stage]
        const Icon = meta.icon
        return (
          <div key={stage} className="flex gap-2.5">
            <span
              aria-hidden
              className="mt-0.5 inline-flex size-6 shrink-0 items-center justify-center rounded-sm"
              style={{ background: `color-mix(in srgb, ${meta.cssVar} var(--tint), transparent)` }}
            >
              <Icon className="size-3.5 text-fg" strokeWidth={1.85} />
            </span>
            <div className="min-w-0">
              <dt className="flex items-center gap-1.5 text-sm font-medium text-fg">
                <span
                  aria-hidden
                  className="size-2 shrink-0 rounded-full"
                  style={{ background: meta.cssVar }}
                />
                {meta.term ? <Explain term={meta.term}>{meta.label}</Explain> : meta.label}
              </dt>
              <dd className="text-xs text-pretty text-fg-muted">{meta.sentence}</dd>
            </div>
          </div>
        )
      })}
    </dl>
  )
}
