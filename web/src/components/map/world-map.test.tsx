import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, describe, expect, it } from "vitest"
import { WorldMap } from "./world-map"

const KEY = "suckerpot.map.preset"

function mount() {
  return render(
    <MemoryRouter>
      <WorldMap
        activity={{ sources: [], events: 0, unlocated: 0 }}
        events={[]}
        home={{ lat: 46.8, lon: 8.2 }}
        homeLabel="Switzerland"
        paused={false}
        now={Date.now()}
      />
    </MemoryRouter>,
  )
}

afterEach(() => localStorage.clear())

describe("WorldMap presets", () => {
  it("opens on the World view by default", () => {
    mount()
    expect(screen.getByRole("button", { name: "World" })).toHaveAttribute("aria-pressed", "true")
    expect(screen.getByRole("button", { name: "Europe" })).toHaveAttribute("aria-pressed", "false")
    expect(screen.getByText("Switzerland")).toBeInTheDocument()
  })

  it("remembers Europe once chosen, and World again after a reset", async () => {
    const user = userEvent.setup()
    const { unmount } = mount()
    await user.click(screen.getByRole("button", { name: "Europe" }))
    expect(localStorage.getItem(KEY)).toBe("europe")
    unmount()
    mount()
    expect(screen.getByRole("button", { name: "Europe" })).toHaveAttribute("aria-pressed", "true")
    // The 0 key (reset) goes back to the world.
    screen.getByRole("group", { name: /Map of attack origins/ }).focus()
    await user.keyboard("0")
    expect(localStorage.getItem(KEY)).toBe("world")
  })
})
