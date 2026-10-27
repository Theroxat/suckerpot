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
 * The tab strip of a hub: links between existing routes, as an underline row.
 * Plain links (not an ARIA tablist), so Tab and Enter work and `aria-current="page"` marks the
 * current one. The row scrolls sideways on a phone.
 */
export function HubTabs({ hub, pathname, className }: HubTabsProps) {
  if (!hub.tabs) return null
  const current = activeTab(hub, pathname)
  return (
    <nav
      aria-label={`${hub.label} pages`}
      className={cn("mb-6 overflow-x-auto border-b", className)}
    >
      <ul className="flex gap-1">
        {hub.tabs.map((t) => {
          const active = current?.to === t.to
          return (
            <li key={t.to}>
              <Link
                to={t.to}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "-mb-px flex h-9 items-center border-b-2 px-3 text-sm whitespace-nowrap transition-colors duration-150 outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  active
                    ? "border-fg font-medium text-fg"
                    : "border-transparent text-fg-muted hover:text-fg",
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
