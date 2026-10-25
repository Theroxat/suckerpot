import { describe, expect, it } from "vitest"
import {
  describeAudit,
  userState,
  usersFinding,
  validateNewUser,
  type AuditEntry,
  type UserItem,
  type UserList,
} from "./users"
import { validateNewPassword } from "./auth-api"

const NOW = Date.parse("2026-10-25T12:00:00Z")

function user(over: Partial<UserItem> = {}): UserItem {
  return {
    id: 1,
    username: "colleague",
    display_name: "A Colleague",
    role: "viewer",
    is_owner: false,
    disabled: false,
    must_change_password: false,
    locked_until: null,
    created_at: "2026-10-20T08:00:00Z",
    created_by: "admin",
    last_login_at: null,
    password_changed_at: null,
    ...over,
  }
}

const OWNER = user({ id: null, username: "admin", role: "admin", is_owner: true })

describe("userState", () => {
  it("picks the most limiting state first", () => {
    expect(userState(user(), NOW)).toBe("active")
    expect(userState(user({ must_change_password: true }), NOW)).toBe("pending")
    expect(
      userState(user({ locked_until: "2026-10-25T12:10:00Z", must_change_password: true }), NOW),
    ).toBe("locked")
    expect(userState(user({ locked_until: "2026-10-25T11:50:00Z" }), NOW)).toBe("active")
    expect(userState(user({ disabled: true, locked_until: "2026-10-25T12:10:00Z" }), NOW)).toBe(
      "disabled",
    )
  })
})

describe("usersFinding", () => {
  const list = (items: UserItem[]): UserList => ({ owner: OWNER, items, next_cursor: null })

  it("says who can sign in", () => {
    expect(usersFinding(list([]), NOW)).toBe("One person can sign in: the owner.")
    expect(usersFinding(list([user()]), NOW)).toBe(
      "2 people can sign in: 1 administrator and 1 viewer.",
    )
  })

  it("leaves disabled accounts out and flags locked and waiting ones", () => {
    const text = usersFinding(
      list([
        user({ id: 2, disabled: true }),
        user({ id: 3, locked_until: "2026-10-25T12:10:00Z" }),
        user({ id: 4, must_change_password: true }),
      ]),
      NOW,
    )
    expect(text).toBe(
      "3 people can sign in: 1 administrator and 2 viewers. 1 account is locked. 1 person has not signed in yet.",
    )
  })
})

describe("describeAudit", () => {
  const entry = (action: string, over: Partial<AuditEntry> = {}): AuditEntry => ({
    id: 1,
    ts: "2026-10-25T12:00:00Z",
    actor: "admin",
    action,
    target: "colleague",
    ip: null,
    details: {},
    ...over,
  })

  it("writes plain English", () => {
    expect(describeAudit(entry("user.create", { details: { role: "viewer" } }))).toBe(
      "created the user colleague (viewer)",
    )
    expect(describeAudit(entry("user.role", { details: { from: "viewer", to: "admin" } }))).toBe(
      "changed the role of colleague from viewer to administrator",
    )
    expect(describeAudit(entry("user.revoke_sessions"))).toBe("signed colleague out everywhere")
    expect(describeAudit(entry("provider_key.set", { target: "abuseipdb" }))).toBe(
      "saved the AbuseIPDB key",
    )
    expect(describeAudit(entry("auth.login"))).toBe("signed in")
    expect(describeAudit(entry("user.locked"))).toBe("was locked after too many wrong passwords")
  })

  it("never fails on an action it does not know", () => {
    expect(describeAudit(entry("thing.happened"))).toBe("thing.happened on colleague")
    expect(describeAudit(entry("thing.happened", { target: null }))).toBe("thing.happened")
  })
})

describe("validateNewUser", () => {
  it("applies the server's username rules", () => {
    expect(validateNewUser("colleague", "A Colleague")).toEqual({})
    expect(validateNewUser("ab", "x").username).toBeDefined()
    expect(validateNewUser("has space", "x").username).toBeDefined()
    expect(validateNewUser("-lead", "x").username).toBeDefined()
    expect(validateNewUser("okay.name", "  ").displayName).toBeDefined()
    expect(validateNewUser("okay.name", "x".repeat(65)).displayName).toBeDefined()
  })
})

describe("validateNewPassword", () => {
  it("checks length, the username and reuse", () => {
    expect(validateNewPassword("short", "colleague")).toMatch(/at least 12/)
    expect(validateNewPassword("x".repeat(257), "colleague")).toMatch(/at most 256/)
    expect(validateNewPassword("My-COLLEAGUE-pass-1", "colleague")).toMatch(/username/)
    expect(validateNewPassword("same-long-password", "colleague", "same-long-password")).toMatch(
      /different/,
    )
    expect(validateNewPassword("a long enough passphrase", "colleague", "old")).toBeNull()
  })
})
