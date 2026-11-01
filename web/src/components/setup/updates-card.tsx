import { useAuth } from "@/app/auth"
import { useVersion } from "@/hooks/use-version"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonText } from "@/components/skeletons"
import { describeVersion, hasUpdate, safeReleaseUrl, type VersionInfo } from "@/lib/version"
import { setCommand } from "@/lib/setup-wizard"
import { CommandBox } from "./command-box"

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 space-y-1">
      <dt className="text-xs text-fg-muted">{label}</dt>
      <dd className="text-sm text-fg tabular-nums">{children}</dd>
    </div>
  )
}

function Details({ v }: { v: VersionInfo }) {
  const url = safeReleaseUrl(v.release_url)
  return (
    <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-4">
      <Row label="Running">
        <span className="font-mono text-xs">{v.version}</span>
        <span className="ml-2 text-xs text-fg-muted">
          {v.build === "image" ? "release image" : "built from source"}
        </span>
      </Row>
      <Row label="Latest release">
        {v.latest ? <span className="font-mono text-xs">{v.latest}</span> : "Not known"}
      </Row>
      <Row label="Last checked">{v.checked_at ? <RelativeTime iso={v.checked_at} /> : "Never"}</Row>
      <Row label="Release notes">
        {url && hasUpdate(v) ? (
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-sm underline underline-offset-4 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
          >
            Open the release page
          </a>
        ) : (
          "Nothing new"
        )}
      </Row>
    </dl>
  )
}

/** Settings, General tab: the running version and the update check. Viewers do not get the command. */
export function UpdatesCard() {
  const { canWrite } = useAuth()
  const q = useVersion()
  const v = q.data
  return (
    <FindingCard
      eyebrow="Updates"
      finding={
        v
          ? describeVersion(v)
          : q.isError
            ? "The version is not available right now."
            : "Checking the version…"
      }
      detail="The check asks only whether a newer release exists. It sends no version, no identifier and nothing about your system, and it runs through the VPN."
    >
      {v ? (
        <div className="space-y-4">
          <Details v={v} />
          {canWrite && hasUpdate(v) ? (
            <CommandBox
              command="just update"
              label="Command to update"
              hint="Run it on the machine that hosts Selfhostr. It takes a database backup first and can be rolled back."
            />
          ) : null}
          {canWrite && v.check === "off" ? (
            <CommandBox
              command={setCommand("UPDATE_CHECK_ENABLED", "true")}
              label="Command to switch the update check on"
            />
          ) : null}
        </div>
      ) : q.isPending ? (
        <SkeletonText lines={2} />
      ) : null}
    </FindingCard>
  )
}
