import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { TooltipProvider } from "@/components/ui/tooltip"
import { FetchStatusChip } from "./fetch-status-chip"
import { ChainSteps } from "./chain-steps"
import { StringsList } from "./strings-list"

describe("FetchStatusChip", () => {
  it("shows a word, not just a colour", () => {
    render(<FetchStatusChip status="refused" />)
    expect(screen.getByText("Refused")).toBeInTheDocument()
  })
  it("names TFTP", () => {
    render(<FetchStatusChip status="unsupported" url="tftp://192.0.2.4/a" />)
    expect(screen.getByText("Not fetched (TFTP)")).toBeInTheDocument()
  })
})

describe("ChainSteps", () => {
  it("links the steps to their views and marks the current file", () => {
    const sha = "b".repeat(64)
    render(
      <MemoryRouter>
        <ChainSteps
          current={sha}
          chain={{
            nodes: [
              { id: "s", kind: "session", label: "S1", session_id: "S1" },
              { id: "f", kind: "sample", label: "bbbb", sha256: sha },
            ],
            edges: [{ from: "s", to: "f" }],
          }}
        />
      </MemoryRouter>,
    )
    expect(screen.getByRole("link", { name: "S1" })).toHaveAttribute("href", "/attacks/S1")
    expect(screen.getByText(/this file/)).toBeInTheDocument()
  })
})

describe("StringsList", () => {
  it("is a focusable list", async () => {
    render(
      <TooltipProvider>
        <StringsList strings={["/bin/sh", "wget"]} />
      </TooltipProvider>,
    )
    const list = screen.getByRole("list", { name: "Strings found in the file" })
    await userEvent.tab()
    expect(list).toHaveFocus()
  })
})
