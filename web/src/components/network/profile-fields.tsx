import { useId, useMemo } from "react"
import { Field } from "@/components/form-parts"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { countryOptions } from "@/lib/network"

const NONE = "none"

export interface Profile {
  pseudonym: string
  country: string
  showCountry: boolean
}

/**
 * The two optional things a member may choose: a pseudonym and a country. Both start empty. The
 * country is never guessed, and showing it next to the pseudonym is a separate switch, off.
 */
export function ProfileFields({
  value,
  onChange,
  pseudonymError,
}: {
  value: Profile
  onChange: (next: Profile) => void
  pseudonymError?: string | undefined
}) {
  const ids = { name: useId(), country: useId(), show: useId() }
  const options = useMemo(() => countryOptions(), [])
  return (
    <div className="flex flex-col gap-4">
      <Field
        id={ids.name}
        label="Pseudonym"
        optional
        hint="Do not use a name you use anywhere else. Left empty, you are listed as a node number."
        error={pseudonymError}
      >
        <Input
          id={ids.name}
          name="pseudonym"
          autoComplete="off"
          maxLength={24}
          value={value.pseudonym}
          onChange={(e) => onChange({ ...value, pseudonym: e.target.value })}
          aria-invalid={pseudonymError ? true : undefined}
          aria-describedby={pseudonymError ? `${ids.name}-error` : `${ids.name}-hint`}
        />
      </Field>
      <Field
        id={ids.country}
        label="Country"
        optional
        hint="Never detected for you. It is shown to members only when at least 3 members share it."
      >
        <Select
          value={value.country || NONE}
          onValueChange={(v) =>
            onChange({
              ...value,
              country: v === NONE ? "" : v,
              showCountry: v === NONE ? false : value.showCountry,
            })
          }
        >
          <SelectTrigger id={ids.country} className="w-full">
            <SelectValue placeholder="No country" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={NONE}>No country</SelectItem>
            {options.map((c) => (
              <SelectItem key={c.code} value={c.code}>
                {c.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Field>
      <div className="flex items-start gap-3">
        <Switch
          id={ids.show}
          checked={value.showCountry}
          disabled={!value.country}
          onCheckedChange={(v) => onChange({ ...value, showCountry: v })}
          className="mt-0.5"
        />
        <label htmlFor={ids.show} className="text-sm text-fg">
          Show my country next to my pseudonym
          <span className="block text-xs text-fg-muted">
            Off by default. Without it, no country is listed for you.
          </span>
        </label>
      </div>
    </div>
  )
}
