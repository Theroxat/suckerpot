import { useTweenedNumber } from "@/hooks/use-tweened-number"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

interface AnimatedNumberProps {
  value: number
  format?: (n: number) => string
  className?: string
}

/** A number that eases to its new value. Screen readers get the final value only. */
export function AnimatedNumber({ value, format = formatNumber, className }: AnimatedNumberProps) {
  const shown = useTweenedNumber(value)
  return (
    <span className={cn("tabular-nums", className)}>
      <span aria-hidden>{format(Math.round(shown))}</span>
      <span className="sr-only">{format(value)}</span>
    </span>
  )
}
