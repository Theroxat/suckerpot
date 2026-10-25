import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import type { SensorEvent } from "@/lib/api"
import { EventRow } from "./event-row"

function rdpLogin(data: Record<string, unknown>): SensorEvent {
  return {
    id: 1,
    ts: "2026-10-24T18:02:11Z",
    sensor: "rdp",
    session_id: "s1",
    type: "login_attempt",
    src_ip: "203.0.113.9",
    src_port: 51422,
    dst_port: 3389,
    country: null,
    city: null,
    asn: null,
    org: null,
    abuse_score: null,
    known_scanner: null,
    tags: [],
    data,
  }
}

function renderRow(event: SensorEvent) {
  return render(
    <MemoryRouter>
      <IpMaskProvider>
        <EventRow event={event} />
      </IpMaskProvider>
    </MemoryRouter>,
  )
}

describe("EventRow for RDP logins", () => {
  it("shows an NTLM login with domain and no password", () => {
    renderRow(
      rdpLogin({ method: "rdp-ntlm", username: "administrator", domain: "OFFICE", password: null }),
    )
    expect(screen.getByText("OFFICE\\administrator")).toBeTruthy()
    expect(screen.getByText("(password hash only)")).toBeTruthy()
  })

  it("shows the decoy password on a match", () => {
    renderRow(
      rdpLogin({ method: "rdp-ntlm", username: "admin", password: "P@ssw0rd", success: true }),
    )
    expect(screen.getByText("P@ssw0rd")).toBeTruthy()
    expect(screen.getByText("Logged in as")).toBeTruthy()
  })

  it("labels a cleartext capture", () => {
    renderRow(rdpLogin({ method: "rdp-nla-off", username: "evil", password: "hunter2" }))
    expect(screen.getByText("Sent in the clear")).toBeTruthy()
    expect(screen.getByText("hunter2")).toBeTruthy()
  })
})
