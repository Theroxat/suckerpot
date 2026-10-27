import { Link } from "react-router"
import { activeTab, type NavItem } from "@/app/nav"
import { cn } from "@/lib/utils"

interface HubTabsProps {
  hub: NavItem
  /** Current pathname: detail routes (/attacks/:id) keep their list tab current. */
  pathname: string
  className?: string
}

/**
 * The tab strip of a hub: links between existing routes, in the segmented-control look.
 * Plain links (not an ARIA tablist), so Tab and Enter work and `aria-current="page"` marks the
 * current one. The row scrolls sideways on a phone.
 */
export function HubTabs({ hub, pathname, className }: HubTabsProps) {
  if (!hub.tabs) return null
  const current = activeTab(hub, pathname)
  return (
    <nav
      aria-label={`${hub.label} pages`}
      className={cn("-mx-1 mb-5 overflow-x-auto px-1 py-0.5", className)}
    >
      <ul className="inline-flex gap-0.5 rounded-md border bg-bg p-0.5">
        {hub.tabs.map((t) => {
          const active = current?.to === t.to
          return (
            <li key={t.to}>
              <Link
                to={t.to}

                aria-current={active ? "page" : undefined}
                className={cn(
                  "flex h-7 items-center rounded-sm px-3 text-xs font-medium whitespace-nowrap transition-colors duration-150 outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  active
                    ? "bg-surface-raised text-fg shadow-sm ring-1 ring-border"
                    : "text-fg-muted hover:text-fg",
                )}
              >
                {t.label}
              </Link>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
