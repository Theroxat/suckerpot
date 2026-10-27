import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeAll, describe, expect, it } from "vitest"
import { GLOSSARY, TERM_IDS } from "@/lib/glossary"
import { stubResizeObserver } from "@/test/dom-stubs"
import { Explain } from "./explain"

beforeAll(stubResizeObserver)

describe("Explain", () => {
  it("underlines a word and shows its definition on click and on the keyboard", async () => {
    const user = userEvent.setup()
    render(
      <p>
        Robots do <Explain term="brute-force">password guessing</Explain>.
      </p>,
    )
    const trigger = screen.getByRole("button", { name: "password guessing, definition" })
    expect(screen.queryByText(GLOSSARY["brute-force"].short)).not.toBeInTheDocument()
    await user.click(trigger)
    expect(screen.getByText(GLOSSARY["brute-force"].short)).toBeVisible()
    await user.keyboard("{Escape}")
    trigger.focus()
    await user.keyboard("{Enter}")
    expect(screen.getByText(GLOSSARY["brute-force"].short)).toBeVisible()
  })

  it("defines every word the Today story uses", () => {
    const needed = [
      "brute-force",
      "botnet",
      "exploit",
      "cve",
      "malware",
      "scanner",
      "ssh",
      "telnet",
      "rdp",
      "asn",
      "ip-address",
    ]
    for (const id of needed) expect(TERM_IDS).toContain(id)
  })
})
