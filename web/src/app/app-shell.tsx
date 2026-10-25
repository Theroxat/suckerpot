import { Menu } from "lucide-react"
import { useState } from "react"
import { NavLink, Outlet, ScrollRestoration, useLocation } from "react-router"
import { LiveIndicator } from "@/components/live-indicator"
import { MaskToggle } from "@/components/mask-toggle"
import { ReadOnlyBadge } from "@/components/read-only-badge"
import { ThemeToggle } from "@/components/theme-toggle"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { cn } from "@/lib/utils"
import { AccountMenu } from "./account-menu"
import { Logo } from "./logo"
import { NAV } from "./nav"
import { useLiveStatus } from "./use-live-status"

const MOCK = import.meta.env.VITE_MOCK === "1"

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav aria-label="Main" className="flex flex-col gap-6">
      {NAV.map((group) => (
        <div key={group.label} className="flex flex-col gap-0.5">
          <div className="px-2.5 pb-1.5 text-2xs font-medium tracking-wide text-fg-subtle uppercase">
            {group.label}
          </div>
          {group.items.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              onClick={onNavigate}
              className={({ isActive }) =>
                cn(
                  "group flex h-8 items-center gap-2.5 rounded-md px-2.5 text-sm font-medium transition-colors duration-150",
                  isActive
                    ? "bg-surface-hover text-fg"
                    : "text-fg-muted hover:bg-surface-hover/60 hover:text-fg",
                )
              }
            >
              {({ isActive }) => (
                <>
                  <Icon
                    aria-hidden
                    className={cn(
                      "size-4",
                      isActive ? "text-fg" : "text-fg-subtle group-hover:text-fg-muted",
                    )}
                    strokeWidth={1.85}
                  />
                  {label}
                </>
              )}
            </NavLink>
          ))}
        </div>
      ))}
    </nav>
  )
}

function StatusFooter() {
  const { status, detail } = useLiveStatus()
  return (
    <div className="flex flex-col gap-3 border-t px-3 pt-4">
      <div className="flex items-center justify-between gap-2 px-1">
        <LiveIndicator status={status} detail={detail} />
        {MOCK ? (
          <span className="rounded-sm border px-1.5 py-0.5 text-2xs font-medium text-fg-muted">
            Mock data
          </span>
        ) : null}
      </div>
      <div className="flex items-center justify-between gap-2 px-1">
        <span className="text-xs text-fg-muted">Theme</span>
        <ThemeToggle />
      </div>
      <MaskToggle className="px-1" />
      <div className="flex flex-col gap-2 border-t pt-3">
        <ReadOnlyBadge className="mx-1 self-start" />
        <AccountMenu />
      </div>
    </div>
  )
}

function currentLabel(pathname: string): string {
  for (const g of NAV) for (const i of g.items) if (pathname.startsWith(i.to)) return i.label
  return ""
}

export function AppShell() {
  const [open, setOpen] = useState(false)
  const { pathname } = useLocation()
  const { status } = useLiveStatus()

  return (
    <div className="min-h-dvh bg-bg">
      <a
        href="#main"
        className="sr-only z-50 rounded-md bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
      >
        Skip to content
      </a>

      {/* Desktop sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r bg-bg py-4 lg:flex">
        <div className="px-5 pt-1 pb-6">
          <Logo />
        </div>
        <div className="flex-1 overflow-y-auto px-3">
          <NavList />
        </div>
        <StatusFooter />
      </aside>

      {/* Mobile top bar */}
      <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-bg/85 px-2 backdrop-blur-md lg:hidden">
        <Sheet open={open} onOpenChange={setOpen}>
          <SheetTrigger asChild>
            <Button variant="ghost" size="icon" aria-label="Open navigation" className="size-10">
              <Menu aria-hidden className="size-5" />
            </Button>
          </SheetTrigger>
          <SheetContent side="left" className="w-72 gap-0 border-r bg-bg p-0 py-4">
            <SheetTitle className="px-5 pt-1 pb-6">
              <Logo />
            </SheetTitle>
            <SheetDescription className="sr-only">Main navigation</SheetDescription>
            <div className="flex-1 overflow-y-auto px-3">
              <NavList onNavigate={() => setOpen(false)} />
            </div>
            <StatusFooter />
          </SheetContent>
        </Sheet>
        <Logo />
        <span className="sr-only">{currentLabel(pathname)}</span>
        <ReadOnlyBadge className="ml-auto" />
        <LiveIndicator status={status} className="mr-2 ml-2" />
      </header>

      <main id="main" className="lg:pl-60">
        <div
          className={cn(
            "mx-auto w-full px-4 pt-6 pb-16 sm:px-6 lg:px-10 lg:pt-10",
            // Live is the wall screen: its map uses the whole width. Other pages stay readable.
            pathname.startsWith("/live") ? "max-w-[2400px]" : "max-w-[1200px]",
          )}
        >
          <Outlet />
        </div>
      </main>
      <ScrollRestoration />
    </div>
  )
}
