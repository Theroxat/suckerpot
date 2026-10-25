import {
  Bell,
  Bug,
  Crosshair,
  FileCode2,
  Flag,
  Grid3x3,
  LayoutDashboard,
  Network,
  Radar,
  Radio,
  ScanSearch,
  Settings,
  ShieldAlert,
  ShieldCheck,
  SwatchBook,
  TrendingUp,
  Users,
  type LucideIcon,
} from "lucide-react"

/** The three spaces of the product, plus the footer. */
export type Space = "observe" | "understand" | "defend" | "footer"

export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  space: Space
  /** Small pill after the label, e.g. a count or "New". */
  badge?: string
}

export interface NavGroup {
  space: Space
  label: string
  items: NavItem[]
}

/**
 * Observe: what is happening. Understand: what it means. Defend: what to do about it.
 * "Today" (the future home at "/") joins Observe when it exists; until then "/" redirects to
 * Activity. Settings tabs live in the page itself, not here.
 */
export const NAV_ITEMS: NavItem[] = [
  { space: "observe", to: "/live", label: "Live", icon: Radio },
  { space: "observe", to: "/attacks", label: "Attacks", icon: Crosshair },
  { space: "observe", to: "/attackers", label: "Attackers", icon: Users },
  // The route stays /overview; only the name changed.
  { space: "observe", to: "/overview", label: "Activity", icon: LayoutDashboard },

  { space: "understand", to: "/campaigns", label: "Campaigns", icon: Flag },
  { space: "understand", to: "/techniques", label: "Techniques", icon: Grid3x3 },
  { space: "understand", to: "/scripts", label: "Scripts", icon: FileCode2 },
  { space: "understand", to: "/malware", label: "Malware", icon: Bug },
  { space: "understand", to: "/infrastructure", label: "Infrastructure", icon: Network },
  { space: "understand", to: "/trends", label: "Trends", icon: TrendingUp },
  { space: "understand", to: "/cves", label: "CVE watch", icon: ShieldAlert },

  { space: "defend", to: "/defend/blocklists", label: "Blocklists", icon: ShieldCheck },
  { space: "defend", to: "/defend/detections", label: "Detections", icon: ScanSearch },
  { space: "defend", to: "/defend/exposure", label: "Your exposure", icon: Radar },
  { space: "defend", to: "/defend/alerts", label: "Alerts and reports", icon: Bell },

  { space: "footer", to: "/settings", label: "Settings", icon: Settings },
  { space: "footer", to: "/styleguide", label: "Styleguide", icon: SwatchBook },
]

const SPACE_LABEL: Record<Space, string> = {
  observe: "Observe",
  understand: "Understand",
  defend: "Defend",
  footer: "System",
}

export const NAV: NavGroup[] = (["observe", "understand", "defend", "footer"] as const).map(
  (space) => ({
    space,
    label: SPACE_LABEL[space],
    items: NAV_ITEMS.filter((i) => i.space === space),
  }),
)
