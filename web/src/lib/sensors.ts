import { Globe, Monitor, Router, SquareTerminal, type LucideIcon } from "lucide-react"
import { isSensor, type Sensor } from "./api"

export interface SensorMeta {
  id: Sensor
  label: string
  /** Protocol name as written in sentences ("tried 37 SSH passwords"). */
  noun: string
  description: string
  icon: LucideIcon
  /** Tailwind text colour class for the sensor hue. */
  text: string
  /** Tailwind background class for solid marks (dots, bars). */
  fill: string
  /** Tinted badge background. */
  tint: string
  /** Raw CSS variable, for SVG fills and inline styles. */
  cssVar: string
}

export const SENSOR_META: Record<Sensor, SensorMeta> = {
  ssh: {
    id: "ssh",
    label: "SSH",
    noun: "SSH",
    description: "OpenSSH server with a fake shell",
    icon: SquareTerminal,
    text: "text-sensor-ssh",
    fill: "bg-sensor-ssh",
    tint: "tint-ssh",
    cssVar: "var(--sensor-ssh)",
  },
  telnet: {
    id: "telnet",
    label: "Telnet",
    noun: "Telnet",
    description: "BusyBox-style IoT login",
    icon: Router,
    text: "text-sensor-telnet",
    fill: "bg-sensor-telnet",
    tint: "tint-telnet",
    cssVar: "var(--sensor-telnet)",
  },
  web: {
    id: "web",
    label: "Web",
    noun: "HTTP",
    description: "Apache + PHP application",
    icon: Globe,
    text: "text-sensor-web",
    fill: "bg-sensor-web",
    tint: "tint-web",
    cssVar: "var(--sensor-web)",
  },
  rdp: {
    id: "rdp",
    label: "RDP",
    noun: "RDP",
    description: "Windows Remote Desktop",
    icon: Monitor,
    text: "text-sensor-rdp",
    fill: "bg-sensor-rdp",
    tint: "tint-rdp",
    cssVar: "var(--sensor-rdp)",
  },
}

export function sensorMeta(sensor: string): SensorMeta | null {
  return isSensor(sensor) ? SENSOR_META[sensor] : null
}
