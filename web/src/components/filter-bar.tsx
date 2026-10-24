import { X } from "lucide-react"
import { useSearchParams } from "react-router"
import { useUrlParam } from "@/hooks/use-url-param"
import { Button } from "@/components/ui/button"
import { SegmentedControl } from "@/components/segmented-control"
import { SENSORS, isSensor, type Sensor } from "@/lib/api"
import { SENSOR_META } from "@/lib/sensors"
import { cn } from "@/lib/utils"

export interface FilterChipDef {
  /** URL search param name. */
  param: string
  /** Human label shown before the value, e.g. "IP". */
  label: string
  /** Render the value (mono for IPs, flag for countries…). */
  render?: (value: string) => React.ReactNode
}

/** Sensor switch (All / SSH / Telnet / Web / RDP), synced to `?sensor=`. */
export function SensorFilter({ className }: { className?: string }) {
  const [raw, setSensor] = useUrlParam("sensor")
  const value: Sensor | "all" = isSensor(raw) ? raw : "all"
  return (
    <SegmentedControl
      label="Sensor"
      value={value}
      onChange={(v) => setSensor(v === "all" ? null : v)}
      className={className}
      options={[
        { value: "all", label: "All" },
        ...SENSORS.map((s) => ({
          value: s,
          ariaLabel: SENSOR_META[s].label,
          label: (
            <>
              <span aria-hidden className={cn("size-2 rounded-full", SENSOR_META[s].fill)} />
              {SENSOR_META[s].label}
            </>
          ),
        })),
      ]}
    />
  )
}

interface FilterBarProps {
  /** Controls on the left (e.g. <SensorFilter />). */
  children?: React.ReactNode
  /** Params shown as removable chips when present in the URL. */
  chips: FilterChipDef[]
  /** Extra params cleared by "Clear filters" (besides the chips). */
  alsoClears?: string[]
  className?: string
}

/** Every filter lives in the URL, so any view can be shared as a link. */
export function FilterBar({ children, chips, alsoClears = [], className }: FilterBarProps) {
  const [params, setParams] = useSearchParams()
  const active = chips.flatMap((c) => {
    const v = params.get(c.param)
    return v ? [{ ...c, value: v }] : []
  })
  const anyActive = active.length > 0 || alsoClears.some((p) => params.has(p))

  const remove = (names: string[]) =>
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev)
        names.forEach((n) => p.delete(n))
        return p
      },
      { preventScrollReset: true },
    )

  return (
    <div className={cn("flex flex-wrap items-center gap-2", className)}>
      {children}
      {active.map((c) => (
        <span
          key={c.param}
          className="inline-flex h-8 animate-fade-in items-center gap-1.5 rounded-md border border-border-strong bg-surface pr-1 pl-2.5 text-xs shadow-sm"
        >
          <span className="text-fg-muted">{c.label}</span>
          <span className="font-medium text-fg">{c.render ? c.render(c.value) : c.value}</span>
          <button
            type="button"
            onClick={() => remove([c.param])}
            className="ml-0.5 inline-flex size-6 items-center justify-center rounded-sm text-fg-subtle transition-colors hover:bg-surface-hover hover:text-fg"
            aria-label={`Remove ${c.label} filter`}
          >
            <X aria-hidden className="size-3.5" />
          </button>
        </span>
      ))}
      {anyActive ? (
        <Button
          variant="ghost"
          size="sm"
          className="h-8 text-xs text-fg-muted"
          onClick={() => remove([...chips.map((c) => c.param), ...alsoClears])}
        >
          Clear filters
        </Button>
      ) : null}
    </div>
  )
}
