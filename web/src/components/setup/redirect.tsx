import { useEffect } from "react"
import { useLocation, useNavigate } from "react-router"
import { useWizardProgress } from "@/hooks/use-wizard-progress"
import { takeSetupOffer } from "@/lib/setup-wizard"

/**
 * After sign-in, an administrator whose setup is new or unfinished lands on `/setup`, once per
 * browser session: "Finish later" is respected until the next session.
 */
export function SetupRedirect() {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const { data } = useWizardProgress()
  const show = data?.show === true
  useEffect(() => {
    if (!show || pathname.startsWith("/setup")) return
    if (takeSetupOffer()) void navigate("/setup", { replace: true })
  }, [show, pathname, navigate])
  return null
}
