import {
  Bug,
  Crosshair,
  LayoutDashboard,
  Network,
  Radio,
  ShieldAlert,
  Settings,
  SwatchBook,
  TrendingUp,
  Users,
  type LucideIcon,
} from "lucide-react"

export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
}

export interface NavGroup {
  label: string
  items: NavItem[]
}

export const NAV: NavGroup[] = [
  {
    label: "Monitor",
    items: [
      { to: "/live", label: "Live", icon: Radio },
      { to: "/overview", label: "Overview", icon: LayoutDashboard },
      { to: "/attacks", label: "Attacks", icon: Crosshair },
    ],
  },
  {
    label: "Explore",
    items: [
      { to: "/attackers", label: "Attackers", icon: Users },
      { to: "/trends", label: "Trends", icon: TrendingUp },
      { to: "/malware", label: "Malware", icon: Bug },
      { to: "/cves", label: "CVE watch", icon: ShieldAlert },
      { to: "/infrastructure", label: "Infrastructure", icon: Network },
    ],
  },
  {
    label: "System",
    items: [
      { to: "/settings", label: "Settings", icon: Settings },
      { to: "/styleguide", label: "Styleguide", icon: SwatchBook },
    ],
  },
]
