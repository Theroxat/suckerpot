import { cn } from "@/lib/utils"

interface SparklineProps {
  values: number[]
  /** Any CSS colour; defaults to the current text colour. */
  color?: string
  className?: string
  /** Accessible summary, e.g. "Sessions per hour over the last 24 hours". */
  label: string
}

/** A tiny line over a flat 8% area. No axes: the StatTile around it gives the numbers. */
export function Sparkline({ values, color = "currentColor", className, label }: SparklineProps) {
  const w = 120
  const h = 32
  const max = Math.max(1, ...values)
  const step = values.length > 1 ? w / (values.length - 1) : w
  const points = values.map((v, i) => [i * step, h - 2 - (v / max) * (h - 4)] as const)
  const line = points.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("")
  const area = `${line}L${w},${h}L0,${h}Z`

  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={label}
      className={cn("h-8 w-full overflow-visible", className)}
      style={{ color }}
    >
      <path d={area} fill="currentColor" fillOpacity={0.08} />
      <path
        d={line}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}
