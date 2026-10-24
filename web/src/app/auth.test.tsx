import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { createMemoryRouter, RouterProvider } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { LoginPage } from "@/pages/login"
import { setUnauthorizedHandler } from "@/lib/api"
import { AuthProvider, RequireAuth } from "./auth"
import { ThemeProvider } from "./theme"

function json(status: number, body?: unknown) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status })
}

function setup(initial: string) {
  const router = createMemoryRouter(
    [
      { path: "/login", element: <LoginPage /> },
      {
        element: <RequireAuth />,
        children: [{ path: "/attacks", element: <h1>Attacks page</h1> }],
      },
    ],
    { initialEntries: [initial] },
  )
  render(
    <ThemeProvider>
      <QueryClientProvider client={new QueryClient()}>
        <AuthProvider>
          <RouterProvider router={router} />
        </AuthProvider>
      </QueryClientProvider>
    </ThemeProvider>,
  )
  return router
}

describe("auth flow", () => {
  let signedIn = false
  beforeEach(() => {
    signedIn = false
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        if (url.endsWith("/auth/me"))
          return signedIn ? json(200, { username: "admin" }) : json(401, { detail: "x" })
        if (url.endsWith("/auth/login")) {
          const body = JSON.parse(typeof init?.body === "string" ? init.body : "{}") as {
            password: string
          }
          if (body.password === "good") {
            signedIn = true
            return json(204)
          }
          return json(body.password === "limited" ? 429 : 401, { detail: "no" })
        }
        return json(404)
      }),
    )
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    setUnauthorizedHandler(null)
  })

  it("redirects an anonymous visitor to /login with the page to come back to", async () => {
    const router = setup("/attacks?sensor=ssh")
    await screen.findByRole("heading", { name: "Sign in" })
    expect(router.state.location.pathname).toBe("/login")
    expect(router.state.location.search).toBe("?next=%2Fattacks%3Fsensor%3Dssh")
  })

  it("shows one message for a bad login and keeps the username", async () => {
    const user = userEvent.setup()
    setup("/login")
    await user.type(await screen.findByLabelText("Username"), "admin")
    await user.type(screen.getByLabelText("Password"), "bad")
    await user.click(screen.getByRole("button", { name: "Sign in" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password")
    expect(screen.getByLabelText("Username")).toHaveValue("admin")
    expect(screen.getByLabelText("Password")).toHaveValue("")
  })

  it("explains rate limiting", async () => {
    const user = userEvent.setup()
    setup("/login")
    await user.type(await screen.findByLabelText("Username"), "admin")
    await user.type(screen.getByLabelText("Password"), "limited")
    await user.click(screen.getByRole("button", { name: "Sign in" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("Too many attempts")
  })

  it("goes back to the requested page after signing in", async () => {
    const user = userEvent.setup()
    const router = setup("/attacks")
    await user.type(await screen.findByLabelText("Username"), "admin")
    await user.type(screen.getByLabelText("Password"), "good")
    await user.click(screen.getByRole("button", { name: "Sign in" }))
    await screen.findByRole("heading", { name: "Attacks page" })
    expect(router.state.location.pathname).toBe("/attacks")
  })

  it("shows the page when a session already exists, and sends a 401 back to /login", async () => {
    signedIn = true
    const router = setup("/attacks")
    await screen.findByRole("heading", { name: "Attacks page" })
    const { api } = await import("@/lib/api")
    vi.mocked(fetch).mockResolvedValueOnce(json(401, { detail: "Not authenticated" }))
    await api.summary().catch(() => undefined)
    await waitFor(() => expect(router.state.location.pathname).toBe("/login"))
  })
})
