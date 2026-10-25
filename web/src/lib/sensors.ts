/**
 * The sensor registry: the ONE place that knows which sensors exist, how they
 * are named, grouped, drawn and on which port they listen. Every list, filter,
 * chart, legend and colour in the UI is derived from it.
 *
 * Colour scales by FAMILY, not by sensor: eleven hues would be neither calm nor
 * colour-blind safe, so each family has one hue (tokens.css `--family-*`) and
 * each sensor is told apart by its icon and its label, which are always shown.
 * Per-sensor shades (`--sensor-*`) exist only for the per-sensor chart split.
 */
import {
  Container,
  Database,
  DatabaseZap,
  FolderOpen,
  Globe,
  Monitor,
  Phone,
  Router,
  Server,
  Smartphone,
  SquareTerminal,
  type LucideIcon,
} from "lucide-react"

/** Registry order: family by family, busiest-first inside a family. Charts stack in this order. */
export const SENSORS = [
  "ssh",
  "telnet",
  "adb",
  "web",
  "docker",
  "redis",
  "mysql",
  "mssql",
  "rdp",
  "smb",
  "sip",
] as const
export type Sensor = (typeof SENSORS)[number]

export const SENSOR_FAMILIES = ["shell", "web", "data", "windows"] as const
export type SensorFamily = (typeof SENSOR_FAMILIES)[number]

export function isSensor(value: unknown): value is Sensor {
  return typeof value === "string" && (SENSORS as readonly string[]).includes(value)
}

export interface FamilyMeta {
  id: SensorFamily
  /** "Remote shells". */
  label: string
  /** Lower-case form for sentences ("the remote shells"). */
  noun: string
  description: string
  /** Tailwind text colour class (AA as text). */
  text: string
  /** Tailwind background class for solid marks. */
  fill: string
  /** Tinted badge background. */
  tint: string
  /** Raw CSS variable, for SVG fills and inline styles. */
  cssVar: string
  /** Members, in registry order. */
  sensors: readonly Sensor[]
}

export interface SensorMeta {
  id: Sensor
  label: string
  /** Protocol name as written in sentences ("tried 37 SSH passwords"). */
  noun: string
  description: string
  icon: LucideIcon
  family: SensorFamily
  /** Default public port, shown in the filter and the styleguide. */
  port: number
  /** "udp" only for SIP; everything else is TCP. */
  transport: "tcp" | "udp"
  /** What a login attempt is called in a story ("password" or "login"). */
  credential: "password" | "login"
  /** Family text colour class (sensors never carry their own text colour). */
  text: string
  /** Family background class for dots and accents. */
  fill: string
  /** Family tint for badges. */
  tint: string
  /** Family CSS variable. */
  cssVar: string
  /** Per-sensor shade, for the per-sensor chart split only (fill, not text). */
  shadeVar: string
}

const FAMILY_STYLE: Record<SensorFamily, Pick<FamilyMeta, "text" | "fill" | "tint" | "cssVar">> = {
  shell: {
    text: "text-family-shell",
    fill: "bg-family-shell",
    tint: "tint-family-shell",
    cssVar: "var(--family-shell)",
  },
  web: {
    text: "text-family-web",
    fill: "bg-family-web",
    tint: "tint-family-web",
    cssVar: "var(--family-web)",
  },
  data: {
    text: "text-family-data",
    fill: "bg-family-data",
    tint: "tint-family-data",
    cssVar: "var(--family-data)",
  },
  windows: {
    text: "text-family-windows",
    fill: "bg-family-windows",
    tint: "tint-family-windows",
    cssVar: "var(--family-windows)",
  },
}

type SensorDef = Omit<SensorMeta, "id" | "text" | "fill" | "tint" | "cssVar" | "shadeVar">

const DEFS: Record<Sensor, SensorDef> = {
  ssh: {
    label: "SSH",
    noun: "SSH",
    description: "OpenSSH server with a fake shell",
    icon: SquareTerminal,
    family: "shell",
    port: 22,
    transport: "tcp",
    credential: "password",
  },
  telnet: {
    label: "Telnet",
    noun: "Telnet",
    description: "BusyBox-style IoT login",
    icon: Router,
    family: "shell",
    port: 23,
    transport: "tcp",
    credential: "password",
  },
  adb: {
    label: "ADB",
    noun: "ADB",
    description: "Android debug bridge of a TV box",
    icon: Smartphone,
    family: "shell",
    port: 5555,
    transport: "tcp",
    credential: "login",
  },
  web: {
    label: "Web",
    noun: "HTTP",
    description: "Apache + PHP application",
    icon: Globe,
    family: "web",
    port: 80,
    transport: "tcp",
    credential: "login",
  },
  docker: {
    label: "Docker",
    noun: "Docker API",
    description: "Unauthenticated Docker Engine API",
    icon: Container,
    family: "web",
    port: 2375,
    transport: "tcp",
    credential: "login",
  },
  redis: {
    label: "Redis",
    noun: "Redis",
    description: "Open Redis server",
    icon: DatabaseZap,
    family: "data",
    port: 6379,
    transport: "tcp",
    credential: "password",
  },
  mysql: {
    label: "MySQL",
    noun: "MySQL",
    description: "MySQL server with a weak root",
    icon: Database,
    family: "data",
    port: 3306,
    transport: "tcp",
    credential: "password",
  },
  mssql: {
    label: "MSSQL",
    noun: "SQL Server",
    description: "Microsoft SQL Server (TDS)",
    icon: Server,
    family: "data",
    port: 1433,
    transport: "tcp",
    credential: "password",
  },
  rdp: {
    label: "RDP",
    noun: "RDP",
    description: "Windows Remote Desktop",
    icon: Monitor,
    family: "windows",
    port: 3389,
    transport: "tcp",
    credential: "login",
  },
  smb: {
    label: "SMB",
    noun: "SMB",
    description: "Windows file sharing (SMB)",
    icon: FolderOpen,
    family: "windows",
    port: 445,
    transport: "tcp",
    credential: "login",
  },
  sip: {
    label: "SIP",
    noun: "SIP",
    description: "VoIP phone system (SIP)",
    icon: Phone,
    family: "windows",
    port: 5060,
    transport: "udp",
    credential: "login",
  },
}

// Literal class names, so Tailwind sees every one of them.
const SHADE_VAR: Record<Sensor, string> = {
  ssh: "var(--sensor-ssh)",
  telnet: "var(--sensor-telnet)",
  adb: "var(--sensor-adb)",
  web: "var(--sensor-web)",
  docker: "var(--sensor-docker)",
  redis: "var(--sensor-redis)",
  mysql: "var(--sensor-mysql)",
  mssql: "var(--sensor-mssql)",
  rdp: "var(--sensor-rdp)",
  smb: "var(--sensor-smb)",
  sip: "var(--sensor-sip)",
}

/** `{ [key]: make(key) }` for a closed list of keys, fully typed. */
function byKey<K extends string, V>(keys: readonly K[], make: (key: K) => V): Record<K, V> {
  const out = {} as Record<K, V>
  for (const k of keys) out[k] = make(k)
  return out
}

export const SENSOR_META: Record<Sensor, SensorMeta> = byKey(SENSORS, (id) => {
  const def = DEFS[id]
  return { id, ...def, ...FAMILY_STYLE[def.family], shadeVar: SHADE_VAR[id] }
})

const FAMILY_TEXT: Record<SensorFamily, Pick<FamilyMeta, "label" | "noun" | "description">> = {
  shell: {
    label: "Remote shells",
    noun: "remote shells",
    description: "Log in, get a prompt, run commands",
  },
  web: {
    label: "Web & APIs",
    noun: "web and API sensors",
    description: "HTTP requests and exposed APIs",
  },
  data: {
    label: "Databases",
    noun: "databases",
    description: "Open data stores and SQL servers",
  },
  windows: {
    label: "Windows & VoIP",
    noun: "Windows and VoIP sensors",
    description: "Desktop, file sharing and phone systems",
  },
}

export const FAMILY_META: Record<SensorFamily, FamilyMeta> = byKey(SENSOR_FAMILIES, (id) => ({
  id,
  ...FAMILY_TEXT[id],
  ...FAMILY_STYLE[id],
  sensors: SENSORS.filter((s) => DEFS[s].family === id),
}))

export function sensorMeta(sensor: string): SensorMeta | null {
  return isSensor(sensor) ? SENSOR_META[sensor] : null
}

export function familyOf(sensor: string): SensorFamily | null {
  return isSensor(sensor) ? SENSOR_META[sensor].family : null
}

// --- The `?sensor=` URL filter: a comma-separated list, e.g. `?sensor=ssh,telnet`.

/** Parse `?sensor=`: known names only, deduplicated, in registry order. */
export function parseSensors(raw: string | null | undefined): Sensor[] {
  if (!raw) return []
  const wanted = new Set(raw.split(",").map((s) => s.trim().toLowerCase()))
  return SENSORS.filter((s) => wanted.has(s))
}

/** The `?sensor=` value for a selection; `null` (no filter) when empty or when every sensor is in. */
export function formatSensors(sensors: readonly Sensor[]): string | null {
  const set = new Set(sensors)
  if (set.size === 0 || set.size === SENSORS.length) return null
  return SENSORS.filter((s) => set.has(s)).join(",")
}

/** `/attacks?sensor=ssh,telnet`, or `/attacks` for no filter. */
export function sensorsHref(sensors: readonly Sensor[], path = "/attacks"): string {
  const v = formatSensors(sensors)
  return v ? `${path}?sensor=${v}` : path
}

/** The family whose members are exactly this selection, if any. */
export function exactFamily(sensors: readonly Sensor[]): SensorFamily | null {
  const set = new Set(sensors)
  for (const f of SENSOR_FAMILIES) {
    const members = FAMILY_META[f].sensors
    if (members.length === set.size && members.every((s) => set.has(s))) return f
  }
  return null
}

function joinAnd(parts: readonly string[]): string {
  if (parts.length <= 1) return parts.join("")
  return `${parts.slice(0, -1).join(", ")} and ${parts.at(-1) ?? ""}`
}

/**
 * Human name of a selection: "All sensors", "SSH", "SSH and Telnet",
 * "Remote shells" (a whole family) or "5 sensors".
 */
export function sensorSetLabel(sensors: readonly Sensor[]): string {
  if (sensors.length === 0 || sensors.length === SENSORS.length) return "All sensors"
  const family = sensors.length > 1 ? exactFamily(sensors) : null
  if (family) return FAMILY_META[family].label
  if (sensors.length <= 3) return joinAnd(sensors.map((s) => SENSOR_META[s].label))
  return `${sensors.length} sensors`
}

/** The same, for the middle of a sentence: "SSH and Telnet", "the remote shells", "5 sensors". */
export function sensorSetPhrase(sensors: readonly Sensor[]): string {
  if (sensors.length === 0 || sensors.length === SENSORS.length) return "every sensor"
  const family = sensors.length > 1 ? exactFamily(sensors) : null
  if (family) return `the ${FAMILY_META[family].noun}`
  return sensorSetLabel(sensors)
}

/** Sum a per-sensor record into per-family totals. */
export function sumByFamily(
  bySensor: Partial<Record<string, number>>,
): Record<SensorFamily, number> {
  const out = { shell: 0, web: 0, data: 0, windows: 0 } satisfies Record<SensorFamily, number>
  for (const s of SENSORS) out[SENSOR_META[s].family] += bySensor[s] ?? 0
  return out
}
