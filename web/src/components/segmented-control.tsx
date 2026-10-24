import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { cn } from "@/lib/utils"

export interface SegmentedOption<T extends string> {
  value: T
  label: React.ReactNode
  /** Accessible name when the label is an icon or abbreviated. */
  ariaLabel?: string
}

interface SegmentedControlProps<T extends string> {
  value: T
  onChange: (value: T) => void
  options: readonly SegmentedOption<T>[]
  /** Accessible name of the whole group, e.g. "Sensor". */
  label: string
  /** `md` for filters and sorts, `icon` for compact icon-only switches. */
  size?: "md" | "icon"
  className?: string
}

const ITEM = {
  md: "h-7 min-w-9 gap-1.5 px-2.5 text-xs font-medium",
  icon: "h-6 w-7 min-w-0 px-0",
} as const

/**
 * One choice among a few, always visible: sensor filter, sort order, playback
 * speed, theme. A track on --bg with the selected segment raised.
 */
export function SegmentedControl<T extends string>({
  value,
  onChange,
  options,
  label,
  size = "md",
  className,
}: SegmentedControlProps<T>) {
  return (
    <ToggleGroup
      type="single"
      value={value}
      onValueChange={(v) => {
        const next = options.find((o) => o.value === v)
        if (next) onChange(next.value)
      }}
      aria-label={label}
      className={cn("rounded-md border bg-bg p-0.5", className)}
    >
      {options.map((o) => (
        <ToggleGroupItem
          key={o.value}
          value={o.value}
          aria-label={o.ariaLabel}
          title={size === "icon" ? o.ariaLabel : undefined}
          className={cn(
            "rounded-sm border-0 text-fg-muted shadow-none hover:bg-transparent hover:text-fg",
            "data-[state=on]:bg-surface-raised data-[state=on]:text-fg data-[state=on]:shadow-sm data-[state=on]:ring-1 data-[state=on]:ring-border",
            ITEM[size],
          )}
        >
          {o.label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  )
}
