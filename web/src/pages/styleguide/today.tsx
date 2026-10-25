/* eslint-disable react-refresh/only-export-components -- a styleguide section exports its registry entry next to its component. */
import { useState } from "react"
import { ScannerBadge } from "@/components/scanner-badge"
import { ScannerToggle } from "@/components/scanner-toggle"
import { SearchTrigger } from "@/components/search/search-palette"
import { Term } from "@/components/term"
import { TodayCard } from "@/components/today/today-card"
import { Button } from "@/components/ui/button"
import { TERM_IDS } from "@/lib/glossary"
import type { TodayCardData } from "@/lib/today"
import { Section, Specimen } from "./parts"
import type { FeatureSection } from "./registry"

const HAPPENED: TodayCardData = {
  id: "happened",
  sentence:
    "1,204 attacks came from 312 addresses in the last 24 hours, 38% more than the day before. 41 sessions ran commands on a fake shell.",
  items: [
    {
      kind: "sensor",
      value: "ssh",
      label: "Most targeted: SSH",
      detail: null,
      count: 702,
      to: "/attacks?sensor=ssh",
    },
    {
      kind: "country",
      value: "NL",
      label: "Most active country: NL",
      detail: null,
      count: 311,
      to: "/attackers?country=NL",
    },
    {
      kind: "tag",
      value: "recon",
      label: "Most common behaviour: Reconnaissance sessions",
      detail: null,
      count: 244,
      to: "/attacks?tag=recon",
    },
  ],
  action: { label: "See all attacks", to: "/attacks" },
  empty: false,
}

const ACT_EMPTY: TodayCardData = {
  id: "act",
  sentence: "Nothing urgent today: no malware downloads and no exploit payloads.",
  items: [],
  action: { label: "Open the blocklists", to: "/defend/blocklists" },
  empty: true,
}

function Motion() {
  const [run, setRun] = useState(0)
  return (
    <Specimen label="animate-card-in · motion-stagger · animate-page-in" className="lg:col-span-2">
      <div className="flex w-full flex-col gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="outline" size="sm" onClick={() => setRun((n) => n + 1)}>
            Replay
          </Button>
          <p className="text-xs text-fg-muted">
            320 ms, 8 px of travel, 60 ms between cards. Pages fade in over 200 ms with 4 px. Off
            under reduced motion, with <code>?motion=off</code>, and in screenshots.
          </p>
        </div>
        <div key={run} className="grid grid-cols-3 gap-3">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              style={{ "--motion-i": i } as React.CSSProperties}
              className="motion-stagger animate-card-in rounded-lg border bg-surface p-4 text-xs text-fg-muted"
            >
              Card {i + 1}
            </div>
          ))}
        </div>
      </div>
    </Specimen>
  )
}

function TodayStyleguide() {
  return (
    <Section
      id="today"
      title="Today, search and glossary"
      description="The home page cards (a sentence, up to three items, one action), the header search, glossary terms, the research-scanner switch and the entrance motion."
    >
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <TodayCard card={HAPPENED} index={0} />
        <TodayCard card={ACT_EMPTY} index={1} />

        <Specimen label="Term: hover, tap, or press Enter">
          <p className="text-base text-fg">
            A <Term id="campaign">campaign</Term> reuses one script; its <Term id="indicator" />s
            can go on a <Term id="blocklist" />. Check the <Term id="asn" /> before you block a
            whole network.
          </p>
        </Specimen>

        <Specimen label="Every glossary term">
          <ul className="flex flex-wrap gap-x-4 gap-y-2 text-sm">
            {TERM_IDS.map((id) => (
              <li key={id}>
                <Term id={id} />
              </li>
            ))}
          </ul>
        </Specimen>

        <Specimen label="ScannerBadge">
          <ScannerBadge name="Atlas Census" />
          <ScannerBadge short />
        </Specimen>

        <Specimen label="ScannerToggle · inline (desktop header) and stacked (phone drawer)">
          <ScannerToggle inline />
          <ScannerToggle className="w-60" />
        </Specimen>

        <Specimen label="SearchTrigger (header) · Ctrl K or Cmd K opens the palette">
          <SearchTrigger className="max-w-md" />
          <SearchTrigger compact />
        </Specimen>

        <Motion />
      </div>
    </Section>
  )
}

export const section: FeatureSection = {
  id: "today",
  label: "Today",
  order: 20,
  Component: TodayStyleguide,
}
