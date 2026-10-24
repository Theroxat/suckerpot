import type { Session } from "./api"

export const SEVERITIES = ["info", "notice", "warning", "severe"] as const
export type Severity = (typeof SEVERITIES)[number]

/** Tags that mean a payload was delivered or an exploit was sent. */
export const SEVERE_TAGS = new Set(["malware-drop", "php2shell", "crypto-miner", "mirai"])

/**
 * How serious a session is, from what the attacker actually did:
 * - severe: malware download or exploit payload (red is reserved for this);
 * - warning: got a shell or ran commands;
 * - notice: tried credentials or sent requests;
 * - info: connected or probed only.
 */
export function sessionSeverity(s: Session): Severity {
  if (s.downloads > 0 || s.tags.some((t) => SEVERE_TAGS.has(t))) return "severe"
  if (s.login_success || s.commands > 0) return "warning"
  if (s.login_attempts > 0 || s.http_requests > 0) return "notice"
  return "info"
}

/** Tags that mean the request itself carried an exploit payload. */
export const EXPLOIT_TAGS = new Set(["php2shell"])

/**
 * Whether one event (not its whole session) is severe, i.e. gets a red icon:
 * a download attempt, or an HTTP request tagged as an exploit. A failed login
 * inside a session later tagged "malware-drop" is not severe by itself; the
 * tag badge already carries that signal.
 */
export function isSevereEvent(type: string, tags: readonly string[]): boolean {
  if (type === "download_attempt") return true
  return type === "http_request" && tags.some((t) => EXPLOIT_TAGS.has(t))
}
