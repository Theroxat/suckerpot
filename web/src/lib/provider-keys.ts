/**
 * Enrichment API keys entered on the Settings page. Keys are write-only: they go to the API in
 * one request and are never kept in the browser, and nothing here ever reads one back.
 */
import { ApiError, sendJson } from "@/lib/api"
import type { ProviderId } from "@/lib/settings"

export const PROVIDER_NAMES: Record<ProviderId, string> = {
  abuseipdb: "AbuseIPDB",
  greynoise: "GreyNoise Community",
  maxmind: "MaxMind GeoLite2",
}

export const MIN_KEY_LENGTH = 16
export const MAX_KEY_LENGTH = 128

export interface KeyInput {
  key: string
  accountId: string
}

export type KeyField = "key" | "accountId"

/** Same rules as the API (it checks again): printable ASCII, no spaces, 16 to 128 characters. */
export function validateKeyInput(
  provider: ProviderId,
  { key, accountId }: KeyInput,
): Partial<Record<KeyField, string>> {
  const errors: Partial<Record<KeyField, string>> = {}
  if (!key) errors.key = "Enter the key."
  else if (!/^[\x21-\x7e]+$/.test(key))
    errors.key = "The key may only contain letters, digits and symbols, with no spaces."
  else if (key.length < MIN_KEY_LENGTH || key.length > MAX_KEY_LENGTH)
    errors.key = `The key must be ${MIN_KEY_LENGTH} to ${MAX_KEY_LENGTH} characters long.`
  if (provider === "maxmind" && !/^[0-9]{1,16}$/.test(accountId))
    errors.accountId = "The account ID is a number of up to 16 digits."
  return errors
}

export type KeyFailure =
  | "wrong-password"
  | "invalid-key"
  | "rate-limited"
  | "editing-disabled"
  | "origin"
  | "session"
  | "network"

export class KeyError extends Error {
  constructor(
    readonly reason: KeyFailure,
    /** The API's own sentence, shown for `invalid-key`. */
    readonly detail?: string,
  ) {
    super(reason)
    this.name = "KeyError"
  }
}

export const KEY_MESSAGES: Record<Exclude<KeyFailure, "invalid-key">, string> = {
  "wrong-password": "That password is not correct.",
  "rate-limited": "Too many attempts. Wait a minute, then try again.",
  "editing-disabled": "Editing keys here is turned off on this server.",
  origin:
    "This address is not allowed to change settings. Open the dashboard at its usual address.",
  session: "Your session has expired. Sign in again.",
  network: "The server could not be reached. Try again in a moment.",
}

/** Explains a failure in plain words; never repeats what was typed. */
export function describeKeyError(e: unknown): string {
  if (e instanceof KeyError) {
    if (e.detail) return e.detail
    if (e.reason !== "invalid-key") return KEY_MESSAGES[e.reason]
    return "The key is not valid."
  }
  return KEY_MESSAGES.network
}

function toKeyError(e: unknown): KeyError {
  if (e instanceof KeyError) return e
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return new KeyError("wrong-password")
    if (e.code === "invalid_key") return new KeyError("invalid-key", e.message)
    if (e.code === "editing_disabled") return new KeyError("editing-disabled")
    if (e.code === "origin") return new KeyError("origin")
    if (e.status === 429) return new KeyError("rate-limited")
    if (e.status === 401) return new KeyError("session")
  }
  return new KeyError("network")
}

const path = (provider: ProviderId) => `/settings/providers/${provider}`

/** Saves or replaces a key. `password` is the admin password (re-authentication). */
export async function setProviderKey(
  provider: ProviderId,
  input: KeyInput,
  password: string,
): Promise<void> {
  const body: Record<string, string> = { key: input.key, password }
  if (provider === "maxmind") body.account_id = input.accountId
  try {
    await sendJson("PUT", path(provider), body)
  } catch (e) {
    throw toKeyError(e)
  }
}

export async function removeProviderKey(provider: ProviderId, password: string): Promise<void> {
  try {
    await sendJson("DELETE", path(provider), { password })
  } catch (e) {
    throw toKeyError(e)
  }
}

/** Asks ingest to spend one quota call on the current key. The result shows up in the status. */
export async function requestKeyTest(provider: ProviderId): Promise<void> {
  try {
    await sendJson("POST", `${path(provider)}/test`, undefined)
  } catch (e) {
    if (e instanceof ApiError && e.code === "cooldown")
      throw new KeyError("rate-limited", "A test was just requested. Wait a few seconds.")
    if (e instanceof ApiError && e.code === "no_key")
      throw new KeyError("invalid-key", "There is no key to test.")
    throw toKeyError(e)
  }
}
