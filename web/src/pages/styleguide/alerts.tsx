/* eslint-disable react-refresh/only-export-components -- a section module exports its descriptor (see registry.ts) */
import { useState } from "react"
import { OutboxRow } from "@/components/alerts/outbox-card"
import { ChannelPicker } from "@/components/alerts/rules-card"
import { SegmentedControl } from "@/components/segmented-control"
import { SEVERITY_OPTIONS, type AlertChannel, type OutboxItem } from "@/lib/alerts"
import type { Severity } from "@/lib/severity"
import type { FeatureSection } from "./registry"
import { Section, Specimen } from "./parts"

const NOW = "2026-10-25T08:00:00Z"

function channel(id: number, name: string, enabled = true): AlertChannel {
  return {
    id,
    kind: "discord",
    name,
    enabled,
    target_hint: "discord.com",
    mask_ips: true,
    created_by: "admin",
    created_at: NOW,
    updated_at: NOW,
    last_test: null,
  }
}

const CHANNELS = [
  channel(1, "SecOps channel"),
  channel(2, "Weekly report to the team"),
  channel(3, "Paused", false),
]

function outbox(id: number, over: Partial<OutboxItem>): OutboxItem {
  return {
    id,
    rule_kind: "malware_drop",
    channel_id: 1,
    channel_name: "SecOps channel",
    state: "sent",
    attempts: 1,
    created_at: NOW,
    sent_at: NOW,
    error_code: null,
    severity: "severe",
    title: "Malware was dropped on the honeypot",
    summary: "An attacker downloaded or ran a payload in a session on the telnet sensor.",
    ...over,
  }
}

function Demo() {
  const [ids, setIds] = useState([1])
  const [sev, setSev] = useState<Severity>("warning")
  return (
    <Section
      id="alerts"
      title="Alerts and reports"
      description="Rules read as sentences, a channel toggle shows a check when on and a dashed plus when off, and delivery states pair an icon with a word. A failed delivery is orange, never red: red stays for severe events."
    >
      <div className="grid gap-4 lg:grid-cols-2">
        <Specimen label="ChannelPicker + severity">
          <ChannelPicker channels={CHANNELS} selected={ids} disabled={false} onChange={setIds} />
          <SegmentedControl
            label="Severity"
            value={sev}
            onChange={setSev}
            options={SEVERITY_OPTIONS}
          />
        </Specimen>
        <Specimen label="OutboxRow: sent, failed, held back" className="[&>div]:block [&>div]:p-0">
          <ul className="divide-y">
            <OutboxRow item={outbox(1, {})} />
            <OutboxRow
              item={outbox(2, {
                state: "failed",
                severity: "warning",
                rule_kind: "watched_cve_seen",
                title: "CVE-2026-109618 is being exploited against the honeypot",
                summary: "A vulnerability you watch was tried in 12 sessions today.",
                error_code: "smtp_not_configured",
              })}
            />
            <OutboxRow
              item={outbox(3, {
                state: "suppressed",
                severity: "warning",
                rule_kind: "new_campaign",
                title: "New campaign: Crypto miner over SSH #38",
                summary: null,
                error_code: "digested",
              })}
            />
          </ul>
        </Specimen>
      </div>
    </Section>
  )
}

export const section: FeatureSection = { id: "alerts", label: "Alerts", order: 60, Component: Demo }
