import "@fontsource-variable/inter"
import "@fontsource-variable/jetbrains-mono"
import "./styles/index.css"

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { RouterProvider } from "react-router"
import { TooltipProvider } from "@/components/ui/tooltip"
import { AuthProvider } from "./app/auth"
import { LiveFeedProvider } from "./app/live-feed"
import { IpMaskProvider } from "./app/ip-mask"
import { ScannerFilterProvider } from "./app/scanner-filter"
import { applyMotionMode } from "./lib/motion"
import { ThemeProvider } from "./app/theme"
import { router } from "./app/router"

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 15_000, refetchOnWindowFocus: false, retry: 1 },
  },
})

async function enableMocks() {
  if (import.meta.env.VITE_MOCK !== "1") return
  const { worker } = await import("./mocks/browser")
  await worker.start({
    onUnhandledFrame: "bypass",
    quiet: true,
    // Under a sub-path (GitHub Pages demo) the worker lives next to index.html.
    serviceWorker: { url: `${import.meta.env.BASE_URL}mockServiceWorker.js` },
  })
}

applyMotionMode()

void enableMocks().then(() => {
  const root = document.getElementById("root")
  if (!root) throw new Error("#root missing")
  createRoot(root).render(
    <StrictMode>
      <ThemeProvider>
        <IpMaskProvider>
          <QueryClientProvider client={queryClient}>
            <TooltipProvider delayDuration={300}>
              <AuthProvider>
                <LiveFeedProvider>
                  <ScannerFilterProvider>
                    <RouterProvider router={router} />
                  </ScannerFilterProvider>
                </LiveFeedProvider>
              </AuthProvider>
            </TooltipProvider>
          </QueryClientProvider>
        </IpMaskProvider>
      </ThemeProvider>
    </StrictMode>,
  )
})
