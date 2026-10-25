import { Download } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
import { CopyButton } from "@/components/defend/copy-button"
import { FindingCard } from "@/components/finding-card"
import { SegmentedControl } from "@/components/segmented-control"
import { Button } from "@/components/ui/button"
import {
  BLOCK_KINDS,
  exportUrl,
  firewallInstructions,
  FIREWALL_LABEL,
  instructionsText,
  KIND_META,
  LISTED_SCORE,
  type BlockKind,
  type DefendSummary,
  type Firewall,
} from "@/lib/defend"
import { formatNumber } from "@/lib/format"

const SCORES = [LISTED_SCORE, 70, 90] as const
type Format = "txt" | "alias" | "csv"

/** Download a list, or read how to point a firewall at it. */
export function ExportPanel({
  summary,
  initialKind,
}: {
  summary: DefendSummary | undefined
  initialKind: BlockKind
}) {
  const [kind, setKind] = useState<BlockKind>(initialKind)
  const [format, setFormat] = useState<Format>("txt")
  const [minScore, setMinScore] = useState<number>(LISTED_SCORE)
  const [firewall, setFirewall] = useState<Firewall>("opnsense")

  const effectiveFormat: Format = kind === "ip" ? format : format === "alias" ? "txt" : format
  const href = exportUrl({ kind, format: effectiveFormat, minScore })
  const count =
    summary?.kinds.find((k) => k.kind === kind)?.[minScore >= 70 ? "high" : "listed"] ?? null
  const feed = `${window.location.origin}/feeds/<your-token>/${kind}.txt`
  const steps = firewallInstructions(firewall, feed)

  const formatOptions: { value: Format; label: string }[] = [
    { value: "txt", label: "Plain list" },
    ...(kind === "ip" ? [{ value: "alias" as const, label: "Firewall alias" }] : []),
    { value: "csv", label: "CSV" },
  ]

  return (
    <div id="export" className="scroll-mt-20">
      <FindingCard
        eyebrow="Export"
        finding="Download a list, or point your firewall at it so it stays current."
        detail="Entries you always allow and research scanners are left out. Demo entries are never exported."
      >
        <div className="space-y-5">
          <div className="flex flex-wrap items-end gap-x-5 gap-y-3">
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-fg-muted">What</p>
              <SegmentedControl
                label="What to export"
                value={kind}
                onChange={setKind}
                options={BLOCK_KINDS.map((k) => ({ value: k, label: KIND_META[k].label }))}
                className="flex-wrap"
              />
            </div>
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-fg-muted">Format</p>
              <SegmentedControl
                label="File format"
                value={effectiveFormat}
                onChange={setFormat}
                options={formatOptions}
              />
            </div>
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-fg-muted">Minimum score</p>
              <SegmentedControl
                label="Minimum score"
                value={String(minScore)}
                onChange={(v) => setMinScore(Number(v))}
                options={SCORES.map((s) => ({ value: String(s), label: `${s}+` }))}
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Button asChild>
              <a href={href} download>
                <Download aria-hidden />
                Download {KIND_META[kind].label}
              </a>
            </Button>
            {count !== null ? (
              <p className="text-sm text-fg-muted">
                About {formatNumber(count)}{" "}
                {count === 1 ? KIND_META[kind].one : KIND_META[kind].many} at this score.
              </p>
            ) : null}
          </div>

          <div className="space-y-3 border-t pt-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h4 className="text-sm font-medium text-fg">Keep a firewall up to date</h4>
              <SegmentedControl
                label="Firewall"
                value={firewall}
                onChange={setFirewall}
                options={(["opnsense", "pfsense"] as const).map((f) => ({
                  value: f,
                  label: FIREWALL_LABEL[f],
                }))}
              />
            </div>
            <ol className="list-decimal space-y-1.5 pl-5 text-sm text-fg-muted marker:text-fg-subtle">
              {steps.map((s) => (
                <li key={s} className="pl-1 break-words">
                  {s}
                </li>
              ))}
            </ol>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              <CopyButton
                variant="outline"
                text={instructionsText(firewall, feed)}
                label="Copy firewall instructions"
              >
                Copy firewall instructions
              </CopyButton>
              <Link
                to="/settings?tab=feeds"
                className="text-sm text-fg underline underline-offset-4 hover:text-fg-muted"
              >
                Create a feed token in Settings
              </Link>
            </div>
          </div>
        </div>
      </FindingCard>
    </div>
  )
}
