import { Anchor, Download, KeyRound, Search, SquareTerminal, Target } from "lucide-react"
import type { LucideIcon } from "lucide-react"
import type { Stage } from "@/lib/campaigns"

/**
 * One neutral icon per story stage. Stages never get a hue: a hue means a sensor family or a
 * severity, so a stage is told by its icon and its name, always together.
 */
export const STAGE_ICON: Record<Stage, LucideIcon> = {
  recon: Search,
  access: KeyRound,
  execution: SquareTerminal,
  persistence: Anchor,
  tool_transfer: Download,
  objective: Target,
}
