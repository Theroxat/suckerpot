import {
  Download,
  Globe,
  KeyRound,
  LogOut,
  Plug,
  Radar,
  SquareChevronRight,
  type LucideIcon,
} from "lucide-react"

/** Icon, label and severity of an event type, for rows that only have a summary. */
export function eventTypeMeta(type: string): { icon: LucideIcon; label: string; severe: boolean } {
  switch (type) {
    case "connect":
      return { icon: Plug, label: "Connect", severe: false }
    case "login_attempt":
      return { icon: KeyRound, label: "Login attempt", severe: false }
    case "command":
      return { icon: SquareChevronRight, label: "Command", severe: false }
    case "download_attempt":
      return { icon: Download, label: "Download attempt", severe: true }
    case "http_request":
      return { icon: Globe, label: "HTTP request", severe: false }
    case "disconnect":
      return { icon: LogOut, label: "Disconnect", severe: false }
    default:
      return { icon: Radar, label: type === "scan" ? "Probe" : type, severe: false }
  }
}
