/** Client for /api/v1/auth/*. Cookies are httpOnly: the UI only ever learns the username. */
import { ApiError, API_BASE, sendJson } from "@/lib/api"

export interface AuthUser {
  username: string
}

/** Resolves to the signed-in user, or null when there is no valid session. */
export async function fetchMe(): Promise<AuthUser | null> {
  const res = await fetch(`${API_BASE}/auth/me`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
  if (res.status === 401) return null
  if (!res.ok) throw new ApiError(res.status, res.statusText)
  return (await res.json()) as AuthUser
}

export type LoginFailure = "invalid" | "rate-limited" | "origin" | "network"

export class LoginError extends Error {
  constructor(
    readonly reason: LoginFailure,
    readonly retryAfterSeconds?: number,
  ) {
    super(reason)
    this.name = "LoginError"
  }
}

/** Never reveals which of the two fields was wrong. */
export async function loginRequest(username: string, password: string): Promise<void> {
  try {
    await sendJson(
      "POST",
      "/auth/login",
      { username, password },
      { csrf: false, notifyUnauthorized: false },
    )
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.status === 429) throw new LoginError("rate-limited")
      if (e.status === 401) throw new LoginError("invalid")
      if (e.status === 403) throw new LoginError("origin")
    }
    throw new LoginError("network")
  }
}

export async function logoutRequest(): Promise<void> {
  try {
    await sendJson("POST", "/auth/logout", undefined, { notifyUnauthorized: false })
  } catch (e) {
    // 401: already signed out. Anything else: the cookie may live on, but the UI still leaves.
    if (!(e instanceof ApiError)) throw e
  }
}

/** Only same-app paths are valid redirect targets (no open redirect, no loop through /login). */
export function safeNext(raw: string | null | undefined): string {
  const fallback = "/overview"
  // eslint-disable-next-line no-control-regex -- control characters and whitespace are the point
  if (!raw || /[\x00-\x20\x7f]/.test(raw) || !raw.startsWith("/") || raw.startsWith("//")) {
    return fallback
  }
  if (raw.includes("\\")) return fallback
  let url: URL
  try {
    url = new URL(raw, window.location.origin)
  } catch {
    return fallback
  }
  if (url.origin !== window.location.origin || url.pathname.startsWith("//")) return fallback
  if (url.pathname === "/login") return fallback
  return raw
}
