import type { Session } from "./api"

export const SEVERITIES = ["info", "notice", "warning", "severe"] as const
export type Severity = (typeof SEVERITIES)[number]

/** Tags that mean a payload was delivered or an exploit was sent (red, diamond marker). */
export const SEVERE_TAGS = new Set([
  "malware-drop",
  "php2shell",
  "crypto-miner",
  "mirai",
  "container-escape",
  "sql-rce",
  "eternalblue",
])

/**
 * Tags that mean real harm short of a payload: data held to ransom, a rogue
 * replication master, phone fraud, persistence (orange, triangle marker).
 */
export const WARNING_TAGS = new Set([
  "db-ransom",
  "redis-rogue-master",
  "sip-fraud",
  "persistence",
  // A BlueKeep probe sends no payload (unlike eternalblue); a weak-credentials tag means a
  // decoy password was guessed, the RDP counterpart of a successful login.
  "bluekeep",
  "weak-credentials",
])

/** "severe", "warning" or null (neutral) for one tag. */
export function tagSeverity(tag: string): "severe" | "warning" | null {
  if (SEVERE_TAGS.has(tag)) return "severe"
  if (WARNING_TAGS.has(tag)) return "warning"
  return null
}

/**
 * How serious a session is, from what the attacker actually did:
 * - severe: malware download or exploit payload (red is reserved for this);
 * - warning: got a shell or ran commands;
 * - notice: tried credentials or sent requests;
 * - info: connected or probed only.
 */
export function sessionSeverity(s: Session): Severity {
  if (s.downloads > 0 || s.tags.some((t) => SEVERE_TAGS.has(t))) return "severe"
  if (s.login_success || s.commands > 0 || s.tags.some((t) => WARNING_TAGS.has(t))) return "warning"
  if (s.login_attempts > 0 || s.http_requests > 0) return "notice"
  return "info"
}

/** Exploit tags, and the event type that carries the payload for each. */
export const EXPLOIT_TAGS: ReadonlyMap<string, string> = new Map([
  ["php2shell", "http_request"],
  ["container-escape", "http_request"],
  ["eternalblue", "scan"],
  ["sql-rce", "command"],
])

/**
 * Whether one event (not its whole session) is severe, i.e. gets a red icon:
 * a download attempt, or the event that carries a tagged exploit (an HTTP
 * request for php2shell or container-escape, an SMB probe for eternalblue, a
 * SQL command for sql-rce). A failed login
 * inside a session later tagged "malware-drop" is not severe by itself; the
 * tag badge already carries that signal.
 */
export function isSevereEvent(type: string, tags: readonly string[]): boolean {
  if (type === "download_attempt") return true
  return tags.some((t) => EXPLOIT_TAGS.get(t) === type)
}
