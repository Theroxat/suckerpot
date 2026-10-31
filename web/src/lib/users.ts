/**
 * Users and the audit log (administrators only). Every change asks for the administrator's own
 * password again; the temporary password of a new or reset account is returned once and is never
 * kept: callers hold it in component state until the dialog closes.
 */
import { ApiError, API_BASE, sendJson, type Page } from "@/lib/api"
import type { Role } from "@/lib/auth-api"
import { PROVIDER_NAMES } from "@/lib/provider-keys"
import type { ProviderId } from "@/lib/settings"

export interface UserItem {
  /** Null for the owner account, which lives in `.env` and has no row. */
  id: number | null
  username: string
  display_name: string
  role: Role
  is_owner: boolean
  disabled: boolean
  must_change_password: boolean
  /** Set while the account is locked after repeated wrong passwords. */
  locked_until: string | null
  created_at: string | null
  created_by: string | null
  last_login_at: string | null
  password_changed_at: string | null
}

export interface UserList {
  owner: UserItem
  items: UserItem[]
  next_cursor: string | null
}

export interface AuditEntry {
  id: number
  ts: string
  actor: string
  action: string
  target: string | null
  ip: string | null
  details: Record<string, unknown>
}

export const ROLE_LABEL: Record<Role, string> = { admin: "Administrator", viewer: "Viewer" }

export const ROLE_OPTIONS = [
  { value: "viewer", label: "Viewer" },
  { value: "admin", label: "Administrator" },
] as const

export const ROLE_HINT: Record<Role, string> = {
  viewer: "Can look at everything, can change nothing.",
  admin: "Can also change settings and manage users.",
}

export type UserState = "active" | "disabled" | "locked" | "pending"

/** One state per account, the most limiting first. */
export function userState(u: UserItem, now: number = Date.now()): UserState {
  if (u.disabled) return "disabled"
  if (u.locked_until && Date.parse(u.locked_until) > now) return "locked"
  if (u.must_change_password) return "pending"
  return "active"
}

export const STATE_LABEL: Record<UserState, string> = {
  active: "Active",
  disabled: "Disabled",
  locked: "Locked",
  pending: "Waiting for first sign-in",
}

function count(n: number, one: string, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`
}

/** The finding sentence of the Users card. */
export function usersFinding(list: UserList, now: number = Date.now()): string {
  const all = [list.owner, ...list.items]
  const admins = all.filter((u) => u.role === "admin" && !u.disabled).length
  const viewers = all.filter((u) => u.role === "viewer" && !u.disabled).length
  const people = admins + viewers
  let text =
    people === 1
      ? "One person can sign in: the owner."
      : `${count(people, "person", "people")} can sign in: ${count(admins, "administrator")} and ${count(viewers, "viewer")}.`
  const locked = all.filter((u) => userState(u, now) === "locked").length
  if (locked > 0) text += ` ${count(locked, "account is", "accounts are")} locked.`
  const waiting = all.filter((u) => userState(u, now) === "pending").length
  if (waiting > 0) text += ` ${count(waiting, "person has", "people have")} not signed in yet.`
  return text
}

const text = (value: unknown) => (typeof value === "string" ? value : "?")

/** "admin" reads as "administrator" in a sentence, like the role badges. */
const roleWord = (value: unknown) => (value === "admin" ? "administrator" : text(value))

/** "abuseipdb" reads as "AbuseIPDB", as on the Settings page. */
const providerName = (id: string) => (id in PROVIDER_NAMES ? PROVIDER_NAMES[id as ProviderId] : id)

/** Entries written by SuckerPot itself (the automatic lockout), not by a person. */
export function isSystemActor(e: AuditEntry): boolean {
  const id = e.details.actor_id
  return id === undefined ? e.actor === "system" : id === "system"
}

/** The name that opens an audit sentence: the actor's username, or "System". */
export function auditActorLabel(e: AuditEntry): string {
  return isSystemActor(e) ? "System" : e.actor
}

/** What the actor did, to follow their name: "created the user colleague (viewer)". */
export function describeAudit(e: AuditEntry): string {
  const who = e.target ?? "an account"
  const d = e.details
  switch (e.action) {
    case "auth.login":
      return "signed in"
    case "password.change":
      return "changed their own password"
    case "user.create":
      return `created the user ${who}${typeof d.role === "string" ? ` (${roleWord(d.role)})` : ""}`
    case "user.role":
      return `changed the role of ${who} from ${roleWord(d.from)} to ${roleWord(d.to)}`
    case "user.disable":
      return `disabled ${who}`
    case "user.enable":
      return `enabled ${who}`
    case "user.rename":
      return `renamed ${who}`
    case "user.reset_password":
      return `reset the password of ${who}`
    case "user.unlock":
      return `unlocked ${who}`
    case "user.locked":
      // Older entries name the locked user as the actor; newer ones are written by the system.
      return e.target && (isSystemActor(e) || e.actor !== e.target)
        ? `locked ${e.target} after too many wrong passwords`
        : "was locked after too many wrong passwords"
    case "user.revoke_sessions":
      return `signed ${who} out everywhere`
    case "user.delete":
      return `deleted the user ${who}`
    case "provider_key.set":
      return `saved the ${providerName(who)} key`
    case "provider_key.remove":
      return `removed the ${providerName(who)} key`
    case "provider_key.test":
      return `tested the ${providerName(who)} key`
    default:
      return e.target ? `${e.action} on ${e.target}` : e.action
  }
}

/** Action filters of the audit log: the server matches them as prefixes. */
export const AUDIT_GROUPS = [
  { value: "", label: "All" },
  { value: "auth.", label: "Sign-ins" },
  { value: "user.", label: "Users" },
  { value: "provider_key.", label: "Keys" },
] as const

export type UserFailure =
  | "wrong-password"
  | "taken"
  | "self"
  | "not-found"
  | "rate-limited"
  | "session"
  | "invalid"
  | "network"
  | "unavailable"

export class UserError extends Error {
  constructor(
    readonly reason: UserFailure,
    readonly detail?: string,
  ) {
    super(reason)
    this.name = "UserError"
  }
}

export const USER_MESSAGES: Record<UserFailure, string> = {
  "wrong-password": "That password is not correct.",
  taken: "That username is already taken.",
  self: "You cannot do this to your own account.",
  "not-found": "That user no longer exists. The list has been refreshed.",
  "rate-limited": "Too many attempts. Wait a minute, then try again.",
  session: "Your session has ended. Sign in again.",
  invalid: "Some of the details are not valid.",
  network: "The server could not be reached. Try again in a moment.",
  unavailable: "This file is no longer stored, so there is nothing to download.",
}

export function describeUserError(e: unknown): string {
  return USER_MESSAGES[e instanceof UserError ? e.reason : "network"]
}

function toUserError(e: unknown): UserError {
  if (e instanceof UserError) return e
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return new UserError("wrong-password")
    if (e.code === "session_revoked") return new UserError("session")
    if (e.code === "username_taken") return new UserError("taken")
    if (e.code === "self_action") return new UserError("self")
    if (e.code === "not_found") return new UserError("not-found")
    if (e.status === 429) return new UserError("rate-limited")
    if (e.status === 422) return new UserError("invalid")
    if (e.status === 401) return new UserError("session")
  }
  return new UserError("network")
}

async function run<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    throw toUserError(e)
  }
}

export const USERNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$/

export type NewUserField = "username" | "displayName"

export function validateNewUser(
  username: string,
  displayName: string,
): Partial<Record<NewUserField, string>> {
  const errors: Partial<Record<NewUserField, string>> = {}
  if (!USERNAME_PATTERN.test(username))
    errors.username =
      "3 to 32 characters: letters, digits, dots, dashes and underscores, starting with a letter or digit."
  if (!displayName.trim()) errors.displayName = "Enter a name."
  else if (displayName.trim().length > 64) errors.displayName = "Use at most 64 characters."
  return errors
}

async function getJson<T>(path: string, params: Record<string, string | undefined>) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v)
  const res = await fetch(`${API_BASE}${path}${qs.size ? `?${qs.toString()}` : ""}`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
  if (!res.ok) throw new ApiError(res.status, res.statusText)
  return (await res.json()) as T
}

export const usersApi = {
  list: (cursor?: string | null) =>
    getJson<UserList>("/users", { cursor: cursor ?? undefined, limit: "50" }),
  audit: (
    filters: { actor?: string | undefined; action?: string | undefined },
    cursor?: string | null,
  ) =>
    getJson<Page<AuditEntry>>("/audit", {
      actor: filters.actor,
      action: filters.action,
      cursor: cursor ?? undefined,
      limit: "25",
    }),
}

export interface NewUser {
  username: string
  displayName: string
  role: Role
}

/** Creates the account and resolves to the one-time temporary password. */
export function createUser(input: NewUser, password: string): Promise<{ temporary: string }> {
  return run(async () => {
    const res = await sendJson<{ temporary_password: string }>("POST", "/users", {
      username: input.username,
      display_name: input.displayName.trim(),
      role: input.role,
      password,
    })
    return { temporary: res.temporary_password }
  })
}

export function updateUser(
  id: number,
  changes: { role?: Role; disabled?: boolean; display_name?: string },
  password: string,
): Promise<void> {
  return run(async () => {
    await sendJson("PATCH", `/users/${id}`, { ...changes, password })
  })
}

export function resetUserPassword(id: number, password: string): Promise<{ temporary: string }> {
  return run(async () => {
    const res = await sendJson<{ temporary_password: string }>(
      "POST",
      `/users/${id}/reset-password`,
      { password },
    )
    return { temporary: res.temporary_password }
  })
}

export function unlockUser(id: number, password: string): Promise<void> {
  return run(async () => {
    await sendJson("POST", `/users/${id}/unlock`, { password })
  })
}

export function revokeUserSessions(id: number, password: string): Promise<void> {
  return run(async () => {
    await sendJson("POST", `/users/${id}/revoke-sessions`, { password })
  })
}

export function deleteUser(id: number, password: string): Promise<void> {
  return run(async () => {
    await sendJson("DELETE", `/users/${id}`, { password })
  })
}
