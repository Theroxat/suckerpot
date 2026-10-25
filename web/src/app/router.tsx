/* eslint-disable react-refresh/only-export-components -- route table: lazy page components live next to the router on purpose. */
import { Suspense, lazy } from "react"
import { Navigate, createBrowserRouter, type RouteObject } from "react-router"
import { PageSkeleton } from "@/components/skeletons"
import { AttacksPage } from "@/pages/attacks"
import { NotFoundPage, RouteError } from "@/pages/not-found"
import { LoginPage } from "@/pages/login"
import { SetPasswordPage } from "@/pages/set-password"
import { AppShell } from "./app-shell"
import { RequireAuth } from "./auth"

// Heavy pages (charts, terminal emulator, virtualised feeds) load on demand.
const OverviewPage = lazy(() =>
  import("@/pages/overview").then((m) => ({ default: m.OverviewPage })),
)
const LivePage = lazy(() => import("@/pages/live").then((m) => ({ default: m.LivePage })))
const SessionDetailPage = lazy(() =>
  import("@/pages/session-detail").then((m) => ({ default: m.SessionDetailPage })),
)
const AttackersPage = lazy(() =>
  import("@/pages/attackers").then((m) => ({ default: m.AttackersPage })),
)
const AttackerDetailPage = lazy(() =>
  import("@/pages/attacker-detail").then((m) => ({ default: m.AttackerDetailPage })),
)
const TrendsPage = lazy(() => import("@/pages/trends").then((m) => ({ default: m.TrendsPage })))
const CvesPage = lazy(() => import("@/pages/cves").then((m) => ({ default: m.CvesPage })))
const MalwarePage = lazy(() => import("@/pages/malware").then((m) => ({ default: m.MalwarePage })))
const InfrastructurePage = lazy(() =>
  import("@/pages/infrastructure").then((m) => ({ default: m.InfrastructurePage })),
)
const SettingsPage = lazy(() =>
  import("@/pages/settings").then((m) => ({ default: m.SettingsPage })),
)
const StyleguidePage = lazy(() =>
  import("@/pages/styleguide").then((m) => ({ default: m.StyleguidePage })),
)

/** Suspense with a skeleton in the final layout, so nothing jumps when the chunk lands. */
function Lazy({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<PageSkeleton />}>{children}</Suspense>
}

export const router = createBrowserRouter(
  [
    { path: "login", element: <LoginPage /> },
    { path: "set-password", element: <SetPasswordPage /> },
    {
      element: <RequireAuth />,
      errorElement: <RouteError />,
      children: [appRoutes()],
    },
  ],
  // "/" in a normal build, "/suckerpot/demo/" in the GitHub Pages demo.
  { basename: import.meta.env.BASE_URL.replace(/\/$/, "") || undefined },
)

function appRoutes(): RouteObject {
  return {
    element: <AppShell />,
    errorElement: <RouteError />,
    children: [
      { index: true, element: <Navigate to="/overview" replace /> },
      {
        path: "live",
        element: (
          <Lazy>
            <LivePage />
          </Lazy>
        ),
      },
      {
        path: "overview",
        element: (
          <Lazy>
            <OverviewPage />
          </Lazy>
        ),
      },
      { path: "attacks", element: <AttacksPage /> },
      {
        path: "attacks/:sessionId",
        element: (
          <Lazy>
            <SessionDetailPage />
          </Lazy>
        ),
      },
      {
        path: "attackers",
        element: (
          <Lazy>
            <AttackersPage />
          </Lazy>
        ),
      },
      {
        path: "attackers/:ip",
        element: (
          <Lazy>
            <AttackerDetailPage />
          </Lazy>
        ),
      },
      {
        path: "trends",
        element: (
          <Lazy>
            <TrendsPage />
          </Lazy>
        ),
      },
      {
        path: "malware",
        element: (
          <Lazy>
            <MalwarePage />
          </Lazy>
        ),
      },
      {
        path: "cves",
        element: (
          <Lazy>
            <CvesPage />
          </Lazy>
        ),
      },
      {
        path: "infrastructure",
        element: (
          <Lazy>
            <InfrastructurePage />
          </Lazy>
        ),
      },
      {
        path: "settings",
        element: (
          <Lazy>
            <SettingsPage />
          </Lazy>
        ),
      },
      {
        path: "styleguide",
        element: (
          <Lazy>
            <StyleguidePage />
          </Lazy>
        ),
      },
      { path: "*", element: <NotFoundPage /> },
    ],
  }
}
