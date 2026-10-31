import { Download } from "lucide-react"
import { useState } from "react"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { Button } from "@/components/ui/button"
import { saveBlob, samplesApi } from "@/lib/samples"

/**
 * Admin-only download of a sample as an encrypted zip. The dialog says what the file is and what
 * the archive password is, and asks for the administrator's own password again.
 */
export function ArchiveButton({ sha256 }: { sha256: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        <Download aria-hidden className="size-4" />
        Download as archive
      </Button>
      <AdminActionDialog
        open={open}
        onOpenChange={setOpen}
        title="Download this sample"
        description={
          <>
            This is live malware. It comes in an encrypted zip with the password{" "}
            <code className="font-mono text-fg">infected</code>, so antivirus tools do not open it
            by accident. Never run it outside an isolated machine. The download is recorded in the
            audit log.
          </>
        }
        hint="Downloads ask for your own dashboard password again."
        confirmLabel="Download"
        pendingLabel="Preparing…"
        run={async (password) => {
          const blob = await samplesApi.archive(sha256, password)
          saveBlob(blob, `${sha256}.zip`)
        }}
        onDone={() => undefined}
      />
    </>
  )
}
