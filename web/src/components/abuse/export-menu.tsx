import { Download, Share2 } from "lucide-react"
import { useId, useState } from "react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  abuseKeys,
  abuseApi,
  DEFAULT_TLP,
  describeAbuseError,
  exportFile,
  guardReason,
  guardReasonsOf,
  TLP_OPTIONS,
  type ExportScope,
  type Tlp,
} from "@/lib/abuse"
import { saveBlob } from "@/lib/samples"
import { useQuery } from "@tanstack/react-query"
import { useAuth } from "@/app/auth"

/**
 * "Export for CERT": STIX 2.1 or MISP JSON of one report or one campaign, with a TLP choice. The
 * files are guarded by the server; a blocked check is explained here in plain words.
 */
export function ExportMenu({ scope, className }: { scope: ExportScope; className?: string }) {
  const { canWrite } = useAuth()
  // The default TLP is a setting only an administrator can read; everyone else gets GREEN.
  const settings = useQuery({
    queryKey: abuseKeys.settings,
    queryFn: abuseApi.settings,
    enabled: canWrite,
  })
  const [chosen, setChosen] = useState<Tlp | null>(null)
  const tlp = chosen ?? settings.data?.default_tlp ?? DEFAULT_TLP
  const [busy, setBusy] = useState(false)
  const [description, setDescription] = useState("")
  const descId = useId()
  const [message, setMessage] = useState<string | null>(null)

  async function run(kind: "stix" | "misp") {
    if (kind === "misp" && !description.trim()) {
      setMessage("Write a description for the MISP event first.")
      return
    }
    setBusy(true)
    setMessage(null)
    try {
      const { blob, filename } = await exportFile(
        kind,
        scope,
        tlp,
        kind === "misp" ? description.trim() : undefined,
      )
      saveBlob(blob, filename ?? `indicators.${kind}.json`)
    } catch (e) {
      const reasons = guardReasonsOf(e)
      setMessage(
        reasons
          ? `Blocked by the identity check. ${reasons.map(guardReason).join(" ")}`
          : describeAbuseError(e),
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={className}>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" disabled={busy}>
            <Share2 aria-hidden />
            {busy ? "Preparing…" : "Export for CERT"}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel>Sharing level</DropdownMenuLabel>
          <DropdownMenuRadioGroup value={tlp} onValueChange={(v) => setChosen(v as Tlp)}>
            {TLP_OPTIONS.map((o) => (
              <DropdownMenuRadioItem key={o.value} value={o.value}>
                {o.label}
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => void run("stix")}>
            <Download aria-hidden /> STIX 2.1 bundle
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => void run("misp")}>
            <Download aria-hidden /> MISP event (JSON)
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <div className="mt-2 flex max-w-sm flex-col gap-1">
        <label htmlFor={descId} className="text-xs font-medium text-fg-muted">
          Description (required for MISP)
        </label>
        <Input
          id={descId}
          value={description}
          maxLength={500}
          autoComplete="off"
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>
      <p
        role="status"
        aria-live="polite"
        className="mt-2 max-w-sm text-xs text-fg-muted empty:hidden"
      >
        {message}
      </p>
    </div>
  )
}
