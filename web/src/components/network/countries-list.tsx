import { Link } from "react-router"
import { CountryFlag } from "@/components/country-flag"
import { countryName, formatNumber } from "@/lib/format"
import type { NetworkCountry } from "@/lib/network"

/**
 * Where members are, as a ranked list with bars. The hub names a country only when at least 3
 * members share it, so a short list is normal. Each row opens the members of that country.
 */
export function CountriesList({ countries }: { countries: readonly NetworkCountry[] }) {
  const max = Math.max(1, ...countries.map((c) => c.members))
  if (countries.length === 0) {
    return (
      <p className="text-sm text-fg-muted">
        No country is named yet. A country appears here once at least 3 members have chosen to share
        it.
      </p>
    )
  }
  return (
    <ul aria-label="Members per country" className="space-y-2.5">
      {countries.map((c) => (
        <li key={c.cc}>
          <Link
            to={`/network/members?country=${c.cc}`}
            className="group grid grid-cols-[minmax(0,9rem)_1fr_auto] items-center gap-3 rounded-sm text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label={`${countryName(c.cc) ?? c.cc}: ${c.members} members. Show them.`}
          >
            <span className="truncate text-fg group-hover:underline group-hover:underline-offset-4">
              <CountryFlag code={c.cc} showName decorative />
            </span>
            <span aria-hidden className="h-1.5 overflow-hidden rounded-full bg-surface-hover">
              <span
                className="block h-full rounded-full bg-fg-muted"
                style={{ width: `${(c.members / max) * 100}%` }}
              />
            </span>
            <span className="text-xs text-fg-muted tabular-nums">{formatNumber(c.members)}</span>
          </Link>
        </li>
      ))}
    </ul>
  )
}
