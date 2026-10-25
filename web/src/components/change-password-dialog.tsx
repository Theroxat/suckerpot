import { ChangePasswordForm } from "@/components/password-form"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"

interface ChangePasswordDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  username: string
  onChanged?: () => void
}

export function ChangePasswordDialog({
  open,
  onOpenChange,
  username,
  onChanged,
}: ChangePasswordDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-popover">
        <DialogHeader className="text-left">
          <DialogTitle>Change your password</DialogTitle>
          <DialogDescription>
            You stay signed in here. Any other browser where you are signed in is signed out.
          </DialogDescription>
        </DialogHeader>
        <ChangePasswordForm
          username={username}
          onCancel={() => onOpenChange(false)}
          onDone={() => {
            onOpenChange(false)
            onChanged?.()
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
