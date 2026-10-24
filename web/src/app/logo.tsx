import { cn } from "@/lib/utils"

/** The SuckerPot mark: a honeycomb cell with a drop. Neutral, no brand hue. */
export function Logo({ className, withName = true }: { className?: string; withName?: boolean }) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <svg viewBox="0 0 24 24" aria-hidden className="size-6 shrink-0 text-fg">
        <path
          d="M12 2.5 20.2 7.25v9.5L12 21.5l-8.2-4.75v-9.5Z"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.6"
          strokeLinejoin="round"
        />
        <path
          d="M12 8.2c1.9 2.3 2.85 3.9 2.85 5.05a2.85 2.85 0 0 1-5.7 0c0-1.15.95-2.75 2.85-5.05Z"
          fill="currentColor"
        />
      </svg>
      {withName ? (
        <span className="text-base font-semibold tracking-tight text-fg">SuckerPot</span>
      ) : (
        <span className="sr-only">SuckerPot</span>
      )}
    </span>
  )
}
