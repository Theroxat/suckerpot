import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { useState } from "react"
import { describe, expect, it } from "vitest"
import { useUnsaved } from "@/hooks/use-unsaved"
import { UnsavedHint } from "./form-parts"

function Harness() {
  const [v, setV] = useState("a")
  const { unsaved, markSaved } = useUnsaved({ v })
  return (
    <>
      <input aria-label="Value" value={v} onChange={(e) => setV(e.target.value)} />
      <button type="button" onClick={() => markSaved({ v })}>
        Save
      </button>
      <UnsavedHint show={unsaved} />
    </>
  )
}

describe("UnsavedHint", () => {
  it("shows after an edit, hides after a save and when the edit is undone", async () => {
    const user = userEvent.setup()
    render(<Harness />)
    expect(screen.queryByText("Unsaved changes")).not.toBeInTheDocument()
    await user.type(screen.getByLabelText("Value"), "b")
    expect(screen.getByText("Unsaved changes")).toBeInTheDocument()
    await user.type(screen.getByLabelText("Value"), "{Backspace}")
    expect(screen.queryByText("Unsaved changes")).not.toBeInTheDocument()
    await user.type(screen.getByLabelText("Value"), "c")
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(screen.queryByText("Unsaved changes")).not.toBeInTheDocument()
  })
})
