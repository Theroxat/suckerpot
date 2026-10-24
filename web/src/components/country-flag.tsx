import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { countryName } from "@/lib/format"
import { cn } from "@/lib/utils"

// Each flag is its own small asset (see vite.config.ts), loaded only when shown.
const FLAGS = import.meta.glob<string>("/node_modules/country-flag-icons/3x2/*.svg", {
  query: "?url",
  import: "default",
  eager: true,
})

function flagUrl(code: string): string | null {
  return FLAGS[`/node_modules/country-flag-icons/3x2/${code.toUpperCase()}.svg`] ?? null
}

interface CountryFlagProps {
  /** ISO 3166-1 alpha-2 code. */
  code: string | null | undefined
  /** Also print the country name next to the flag. */
  showName?: boolean
  className?: string
}

export function CountryFlag({ code, showName = false, className }: CountryFlagProps) {
  const name = countryName(code)
  const url = code ? flagUrl(code) : null
  const label = name ?? (code ? code.toUpperCase() : "Unknown country")

  const flag = url ? (
    <img
      src={url}
      alt=""
      width={18}
      height={12}
      loading="lazy"
      className="h-3 w-[18px] shrink-0 rounded-[2px] object-cover ring-1 ring-fg/10"
    />
  ) : (
    <span
      aria-hidden
      className="inline-flex h-3 w-[18px] shrink-0 items-center justify-center rounded-[2px] bg-surface-hover text-[8px] leading-none font-semibold text-fg-subtle ring-1 ring-border-strong"
    >
      ?
    </span>
  )

  if (showName) {
    return (
      <span className={cn("inline-flex items-center gap-1.5 text-fg-muted", className)}>
        {flag}
        <span className="truncate">{label}</span>
      </span>
    )
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          role="img"
          aria-label={label}
          tabIndex={0}
          className={cn("inline-flex items-center rounded-[2px]", className)}
        >
          {flag}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top">{label}</TooltipContent>
    </Tooltip>
  )
}
