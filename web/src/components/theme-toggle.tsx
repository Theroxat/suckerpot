import { Laptop, Moon, Sun } from "lucide-react"
import { useTheme, type ThemePreference } from "@/app/theme"
import { SegmentedControl } from "@/components/segmented-control"

const OPTIONS = [
  { value: "dark", ariaLabel: "Dark theme", label: <Moon aria-hidden className="size-3.5" /> },
  { value: "light", ariaLabel: "Light theme", label: <Sun aria-hidden className="size-3.5" /> },
  {
    value: "system",
    ariaLabel: "Follow system theme",
    label: <Laptop aria-hidden className="size-3.5" />,
  },
] as const satisfies readonly {
  value: ThemePreference
  ariaLabel: string
  label: React.ReactNode
}[]

export function ThemeToggle({ className }: { className?: string }) {
  const { preference, setPreference } = useTheme()
  return (
    <SegmentedControl
      label="Theme"
      size="icon"
      value={preference}
      onChange={setPreference}
      options={OPTIONS}
      className={className}
    />
  )
}
