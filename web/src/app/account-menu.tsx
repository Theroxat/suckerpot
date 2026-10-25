import { ChevronsUpDown, KeyRound, LogOut } from "lucide-react"
import { useState } from "react"
import { useNavigate } from "react-router"
import { ChangePasswordDialog } from "@/components/change-password-dialog"
import { RelativeTime } from "@/components/relative-time"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { ROLE_LABEL } from "@/lib/users"
import { useAuth } from "./auth"

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  const letters = parts.length > 1 ? [parts[0], parts[parts.length - 1]] : [parts[0] ?? "?"]
  return letters
    .map((p) => (p ?? "?").charAt(0))
    .join("")
    .toUpperCase()
    .slice(0, 2)
}

/** Who is signed in, with the last sign-in, "Change password" and "Sign out". */
export function AccountMenu() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [changing, setChanging] = useState(false)
  if (!user) return null
  const role = user.is_owner ? "Owner" : ROLE_LABEL[user.role]

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            aria-label={`Account menu for ${user.display_name}`}
            className="flex w-full items-center gap-2.5 rounded-md px-1 py-1 text-left transition-colors duration-150 hover:bg-surface-hover/60 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
          >
            <span
              aria-hidden
              className="grid size-7 shrink-0 place-items-center rounded-full border bg-surface text-2xs font-semibold text-fg-muted"
            >
              {initials(user.display_name)}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-xs font-medium text-fg">
                {user.display_name}
              </span>
              <span className="block truncate text-2xs text-fg-subtle">{role}</span>
            </span>
            <ChevronsUpDown aria-hidden className="size-3.5 shrink-0 text-fg-subtle" />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" side="top" className="w-60">
          <DropdownMenuLabel className="space-y-0.5 font-normal">
            <span className="block truncate text-sm font-medium text-fg">{user.display_name}</span>
            <span className="block truncate font-mono text-xs text-fg-muted">{user.username}</span>
            {user.last_login_at ? (
              <span className="block pt-1 text-xs text-fg-muted">
                Last sign-in <RelativeTime iso={user.last_login_at} className="text-xs" />
              </span>
            ) : null}
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          {user.is_owner ? (
            <DropdownMenuItem disabled>
              <KeyRound aria-hidden />
              Password is set in .env
            </DropdownMenuItem>
          ) : (
            <DropdownMenuItem onSelect={() => setChanging(true)}>
              <KeyRound aria-hidden />
              Change password
            </DropdownMenuItem>
          )}
          <DropdownMenuItem
            onSelect={() => {
              void logout().finally(() => navigate("/login", { replace: true }))
            }}
          >
            <LogOut aria-hidden />
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <ChangePasswordDialog open={changing} onOpenChange={setChanging} username={user.username} />
    </>
  )
}
