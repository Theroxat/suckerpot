import { Children, type ReactNode } from "react"
import { cn } from "@/lib/utils"

/**
 * A wrapping line of facts separated by middle dots: "7 sent · 86% answered · median 7 h".
 * Each item carries its own leading dot; the dot of the first item on every visual line sits in a
 * clipped gutter, so a wrapped line never ends or starts with a stray separator.
 * Pass one child per fact; `null` children are skipped.
 */
export function MetaLine({
  children,
  className,
  as: Tag = "div",
}: {
  children: ReactNode
  className?: string
  as?: "div" | "p"
}) {
  const items = Children.toArray(children)
  return (
    <Tag className={cn("overflow-hidden text-xs text-fg-muted", className)}>
      <span className="-ml-4 flex flex-wrap items-center gap-y-0.5">
        {items.map((item, i) => (
          <span
            key={i}
            className="inline-flex min-w-0 items-center before:w-4 before:shrink-0 before:text-center before:text-fg-subtle before:content-['·']"
          >
            {item}
          </span>
        ))}
      </span>
    </Tag>
  )
}
