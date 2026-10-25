import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeAll, describe, expect, it } from "vitest"
import { GLOSSARY } from "@/lib/glossary"
import { stubResizeObserver } from "@/test/dom-stubs"
import { Term, TermText } from "./term"

beforeAll(stubResizeObserver)

describe("Term", () => {
  it("shows its own word and opens the definition on click and on the keyboard", async () => {
    const user = userEvent.setup()
    render(
      <p>
        Your <Term id="asn" /> is shown here.
      </p>,
    )
    const trigger = screen.getByRole("button", { name: "ASN, definition" })
    expect(trigger).toHaveTextContent("ASN")
    expect(screen.queryByText(GLOSSARY.asn.short)).not.toBeInTheDocument()

    await user.click(trigger)
    expect(screen.getByText(GLOSSARY.asn.short)).toBeVisible()
    await user.keyboard("{Escape}")
    expect(screen.queryByText(GLOSSARY.asn.short)).not.toBeInTheDocument()

    trigger.focus()
    await user.keyboard("{Enter}")
    expect(screen.getByText(GLOSSARY.asn.short)).toBeVisible()
  })

  it("keeps the text it is given", () => {
    render(<Term id="research-scanner">research scanners</Term>)
    expect(screen.getByRole("button")).toHaveTextContent("research scanners")
    expect(
      screen.getByRole("button", { name: "research scanners, definition" }),
    ).toBeInTheDocument()
  })
})

describe("TermText", () => {
  it("explains a word inside a sentence written elsewhere", () => {
    render(<TermText text="2 new campaigns formed today." />)
    expect(screen.getByRole("button", { name: "campaigns, definition" })).toBeInTheDocument()
    expect(screen.getByText(/formed today\./)).toBeInTheDocument()
  })
})
