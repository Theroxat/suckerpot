import type { Session } from "./api"
import { describeSession, describeSessionText } from "./describe-session"

function session(overrides: Partial<Session> = {}): Session {
  return {
    session_id: "s1",
    sensor: "ssh",
    src_ip: "203.0.113.9",
    src_port: 51422,
    dst_port: 22,
    started_at: "2026-10-24T18:02:11Z",
    ended_at: "2026-10-24T18:02:19Z",
    last_event_at: "2026-10-24T18:02:19Z",
    event_count: 4,
    login_attempts: 0,
    login_success: false,
    commands: 0,
    downloads: 0,
    http_requests: 0,
    country: null,
    city: null,
    asn: null,
    org: null,
    abuse_score: null,
    known_scanner: null,
    tags: [],
    ...overrides,
  }
}

describe("describeSession", () => {
  it("tells the classic brute force then shell story", () => {
    const s = session({ login_attempts: 37, commands: 5, downloads: 1 })
    expect(describeSessionText(s)).toBe(
      "203.0.113.9 tried 37 SSH passwords, then ran 5 commands and tried to download 1 file",
    )
  })

  it("mentions a successful login", () => {
    const s = session({ login_attempts: 12, login_success: true, commands: 3 })
    expect(describeSession(s).predicate).toBe(
      "tried 12 SSH passwords and got in, then ran 3 commands",
    )
  })

  it("handles a first-try login", () => {
    const s = session({ login_attempts: 1, login_success: true })
    expect(describeSession(s).predicate).toBe("logged in to SSH on the first try")
  })

  it("uses singular forms and thousands separators", () => {
    expect(describeSession(session({ login_attempts: 1 })).predicate).toBe("tried 1 SSH password")
    expect(describeSession(session({ login_attempts: 12_345 })).predicate).toBe(
      "tried 12,345 SSH passwords",
    )
  })

  it("names the payload from tags", () => {
    const s = session({
      login_attempts: 37,
      login_success: true,
      commands: 4,
      tags: ["crypto-miner", "recon"],
    })
    expect(describeSession(s).predicate).toBe(
      "tried 37 SSH passwords and got in, then ran 4 commands to install a crypto-miner",
    )
  })

  it("describes web sessions and exploit tags", () => {
    const s = session({ sensor: "web", dst_port: 80, http_requests: 3, tags: ["php2shell"] })
    expect(describeSession(s).predicate).toBe("sent 3 HTTP requests, including a PHP2Shell exploit")
    expect(describeSession(session({ sensor: "web", http_requests: 1 })).predicate).toBe(
      "sent 1 HTTP request",
    )
  })

  it("uses logins for RDP and passwords for Telnet", () => {
    expect(describeSession(session({ sensor: "rdp", login_attempts: 8 })).predicate).toBe(
      "tried 8 RDP logins",
    )
    expect(describeSession(session({ sensor: "telnet", login_attempts: 2 })).predicate).toBe(
      "tried 2 Telnet passwords",
    )
  })

  it("covers sessions with no activity", () => {
    expect(describeSession(session()).predicate).toBe(
      "connected to SSH and left without logging in",
    )
    expect(describeSession(session({ ended_at: null })).predicate).toBe("is connected to SSH")
    expect(describeSession(session({ sensor: "web" })).predicate).toBe(
      "opened a connection without sending a request",
    )
  })

  it("adds the origin when enrichment is present", () => {
    const s = session({ country: "NL", org: "Example Hosting BV", login_attempts: 2 })
    expect(describeSessionText(s)).toBe(
      "203.0.113.9 (Netherlands, Example Hosting BV) tried 2 SSH passwords",
    )
  })

  it("keeps an unknown country code as is and ignores missing parts", () => {
    expect(describeSession(session({ country: "ZZ" })).origin).toBe("ZZ")
    expect(describeSession(session({ org: "AS-EXAMPLE" })).origin).toBe("AS-EXAMPLE")
    expect(describeSession(session()).origin).toBeNull()
  })

  it("falls back for an unknown sensor", () => {
    expect(describeSession(session({ sensor: "ftp", login_attempts: 2 })).predicate).toBe(
      "tried 2 FTP logins",
    )
  })

  it("tells the Synology NAS stories", () => {
    const syn = (o: Partial<Session>) =>
      describeSession(session({ sensor: "synology", ...o })).predicate
    expect(syn({ login_attempts: 24 })).toBe("tried 24 DSM admin passwords on the Synology NAS")
    expect(syn({ login_attempts: 3, login_success: true })).toBe(
      "tried 3 DSM admin passwords on the Synology NAS and got in",
    )
    expect(syn({ http_requests: 3, tags: ["synology-exploit"] })).toBe(
      "sent a forged DSM session (CVE-2026-13639)",
    )
    expect(syn({ http_requests: 3, tags: ["synology-exploit", "c3rb3r"] })).toBe(
      "sent a forged DSM session (CVE-2026-13639), then dropped a C3RB3R ransom note",
    )
    expect(syn({ http_requests: 2 })).toBe("sent 2 HTTP requests to the Synology NAS")
    expect(syn({})).toBe("probed the Synology NAS and left")
  })

  it("tells the new sensors' stories", () => {
    expect(
      describeSession(session({ sensor: "mysql", login_attempts: 40, login_success: false }))
        .predicate,
    ).toBe("tried 40 MySQL passwords")
    expect(
      describeSession(session({ sensor: "docker", http_requests: 4, tags: ["container-escape"] }))
        .predicate,
    ).toBe("sent 4 Docker API requests, including a container escape")
    expect(describeSession(session({ sensor: "smb", tags: ["eternalblue"] })).predicate).toBe(
      "sent an EternalBlue exploit to SMB",
    )
    expect(describeSession(session({ sensor: "sip" })).predicate).toBe(
      "probed the SIP service and left",
    )
    expect(
      describeSession(
        session({
          sensor: "mssql",
          login_attempts: 1,
          login_success: true,
          commands: 3,
          tags: ["sql-rce"],
        }),
      ).predicate,
    ).toBe(
      "logged in to SQL Server on the first try, then ran 3 commands, trying code execution through SQL",
    )
  })
})

describe("describeSession for RDP clients", () => {
  const rdp = (o: Partial<Session> = {}) => session({ sensor: "rdp", dst_port: 3389, ...o })

  it("names the client tool", () => {
    expect(describeSession(rdp({ login_attempts: 40, client_tool: "FreeRDP" })).predicate).toBe(
      "tried 40 RDP logins with FreeRDP",
    )
    expect(
      describeSession(rdp({ login_attempts: 1, login_success: true, client_tool: "mstsc" }))
        .predicate,
    ).toBe("logged in to RDP on the first try with mstsc")
  })

  it("ignores an unknown or missing tool, and tools on other sensors", () => {
    expect(describeSession(rdp({ login_attempts: 3, client_tool: "unknown" })).predicate).toBe(
      "tried 3 RDP logins",
    )
    expect(describeSession(rdp({ login_attempts: 3, client_tool: null })).predicate).toBe(
      "tried 3 RDP logins",
    )
    expect(describeSession(session({ login_attempts: 3, client_tool: "FreeRDP" })).predicate).toBe(
      "tried 3 SSH passwords",
    )
  })

  it("mentions a BlueKeep probe", () => {
    expect(
      describeSession(rdp({ login_attempts: 2, client_tool: "nmap", tags: ["bluekeep"] }))
        .predicate,
    ).toBe("tried 2 RDP logins with nmap, then probed for BlueKeep")
    expect(describeSession(rdp({ tags: ["bluekeep"] })).predicate).toBe("probed for BlueKeep")
  })
})
