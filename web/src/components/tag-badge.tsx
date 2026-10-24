import { Link } from "react-router"
import { SEVERE_TAGS } from "@/lib/severity"
import { cn } from "@/lib/utils"

interface TagBadgeProps {
  tag: string
  /** Defaults to the Attacks list filtered by this tag. Pass null for a static badge. */
  href?: string | null
  className?: string
}

/**
 * A rules-engine tag. Neutral by default; tags that mean a payload or exploit
 * carry a red marker (shape + colour), keeping red for severe things only.
 */
export function TagBadge({ tag, href, className }: TagBadgeProps) {
  const severe = SEVERE_TAGS.has(tag)
  const to = href === undefined ? `/attacks?tag=${encodeURIComponent(tag)}` : href
  const classes = cn(
    "relative inline-flex h-6 shrink-0 items-center gap-1.5 rounded-sm border px-2 font-mono text-2xs font-medium",
    severe ? "border-sev-severe/40 text-fg" : "border-border-strong text-fg-muted",
    to && "transition-colors duration-150 hover:border-fg-subtle hover:text-fg",
    className,
  )
  const content = (
    <>
      {severe ? (
        <span aria-hidden className="size-1.5 rotate-45 rounded-[1px] bg-sev-severe" />
      ) : null}
      {tag}
      {severe ? <span className="sr-only"> (severe)</span> : null}
    </>
  )
  return to ? (
    <Link to={to} className={classes}>
      {content}
    </Link>
  ) : (
    <span className={classes}>{content}</span>
  )
}
