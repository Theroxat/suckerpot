/* eslint-disable react-refresh/only-export-components -- the provider and its hook belong together. */
import { useQueryClient } from "@tanstack/react-query"
import { createContext, use, useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Navigate, Outlet, useLocation } from "react-router"
import { PageSkeleton } from "@/components/skeletons"
import { setUnauthorizedHandler } from "@/lib/api"
import { demoMode } from "./demo-role"
import { fetchMe, loginRequest, logoutRequest, safeNext, type AuthUser } from "@/lib/auth-api"

/** Mock and demo builds have no backend: the visitor is always signed in. */
export const AUTH_BYPASS = import.meta.env.VITE_MOCK === "1"

export type AuthStatus = "loading" | "authenticated" | "anonymous"

export interface AuthState {
  status: AuthStatus
  user: AuthUser | null
  /** True after an explicit sign-out, so the login page does not bounce back to the old page. */
  signedOut: boolean
  /** True for an administrator: every write control is available. A viewer reads only. */
  canWrite: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  /** Loads the account again (after the first password was chosen, say). */
  refresh: () => Promise<void>
}

function demoUser(): AuthUser {
  const mode = demoMode()
  return {
    username: mode === "viewer" ? "colleague" : "demo",
    display_name: mode === "viewer" ? "A Colleague" : "Demo admin",
    role: mode === "viewer" ? "viewer" : "admin",
    is_owner: mode === "admin",
    must_change_password: mode === "first-login",
    read_only: mode === "viewer",
    last_login_at: new Date(Date.now() - 26 * 3_600_000).toISOString(),
  }
}

const DEMO_USER: AuthUser = demoUser()

// Without a provider (isolated component tests) everything behaves as signed in.
const AuthContext = createContext<AuthState>({
  status: "authenticated",
  user: DEMO_USER,
  signedOut: false,
  canWrite: true,
  login: () => Promise.resolve(),
  logout: () => Promise.resolve(),
  refresh: () => Promise.resolve(),
})

export function useAuth(): AuthState {
  return use(AuthContext)
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient()
  const [status, setStatus] = useState<AuthStatus>(AUTH_BYPASS ? "authenticated" : "loading")
  const [user, setUser] = useState<AuthUser | null>(AUTH_BYPASS ? DEMO_USER : null)
  const [signedOut, setSignedOut] = useState(false)
  const generation = useRef(0)

  const apply = useCallback((next: AuthUser | null) => {
    setUser(next)
    setStatus(next ? "authenticated" : "anonymous")
  }, [])

  useEffect(() => {
    if (AUTH_BYPASS) return
    const run = ++generation.current
    fetchMe()
      .then((me) => run === generation.current && apply(me))
      // A server that cannot be reached must not look like "signed in".
      .catch(() => run === generation.current && apply(null))
  }, [apply])

  useEffect(() => {
    if (AUTH_BYPASS) return
    setUnauthorizedHandler(() => {
      generation.current++
      apply(null)
    })
    return () => setUnauthorizedHandler(null)
  }, [apply])

  const login = useCallback(
    async (username: string, password: string) => {
      await loginRequest(username, password)
      generation.current++
      setSignedOut(false)
      queryClient.clear()
      apply(await fetchMe())
    },
    [apply, queryClient],
  )

  const refresh = useCallback(async () => {
    if (AUTH_BYPASS) {
      apply(await fetchMe().catch(() => demoUser()))
      return
    }
    apply(await fetchMe())
  }, [apply])

  const logout = useCallback(async () => {
    if (!AUTH_BYPASS) await logoutRequest()
    generation.current++
    setSignedOut(true)
    queryClient.clear()
    if (!AUTH_BYPASS) apply(null)
  }, [apply, queryClient])

  const canWrite = user?.role === "admin" && !user.must_change_password
  const value = useMemo(
    () => ({ status, user, signedOut, canWrite, login, logout, refresh }),
    [status, user, signedOut, canWrite, login, logout, refresh],
  )
  return <AuthContext value={value}>{children}</AuthContext>
}

/** Route wrapper: renders the nested routes for a signed-in user, else goes to /login?next=…
 * (or to /set-password while the account still has a temporary password). */
export function RequireAuth() {
  const { status, signedOut, user } = useAuth()
  const location = useLocation()
  if (status === "loading") return <PageSkeleton />
  if (status === "anonymous") {
    const here = `${location.pathname}${location.search}${location.hash}`
    const target = signedOut ? "/login" : `/login?next=${encodeURIComponent(safeNext(here))}`
    return <Navigate to={target} replace />
  }
  // A new account (or one whose password an administrator reset) must choose its own first.
  if (user?.must_change_password) return <Navigate to="/set-password" replace />
  return <Outlet />
}
