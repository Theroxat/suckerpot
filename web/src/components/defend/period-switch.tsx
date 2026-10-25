import { SegmentedControl } from "@/components/segmented-control"
import { PERIOD_DAYS } from "@/lib/defend"

export function PeriodSwitch({
  days,
  onChange,
}: {
  days: number
  onChange: (days: number) => void
}) {
  return (
    <SegmentedControl
      label="Period"
      value={String(days)}
      onChange={(v) => onChange(Number(v))}
      options={PERIOD_DAYS.map((d) => ({ value: String(d), label: `${d} days` }))}
    />
  )
}
