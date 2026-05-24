"use client"

import * as React from "react"
import { HelpCircle } from "lucide-react"

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"

export function SaveEmailHelpSheet({
  triggerLabel = "How do I save my email?",
}: {
  triggerLabel?: string
}) {
  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-foreground gap-1.5 text-sm">
          <HelpCircle className="size-4" aria-hidden />
          {triggerLabel}
        </Button>
      </SheetTrigger>
      <SheetContent className="overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>How to save an email for scanning</SheetTitle>
          <SheetDescription>
            We need the original email: either a .eml file or the raw headers.
            Don&apos;t paste the email body or send a screenshot, since those
            don&apos;t include the hidden routing info we check.
          </SheetDescription>
        </SheetHeader>

        <div className="flex flex-col gap-6 px-4 pb-6 text-sm">
          <Alert variant="warning">
            <AlertTitle>Regular forwarding doesn&apos;t work.</AlertTitle>
            <AlertDescription>
              When you forward an email, your mail program replaces the original
              headers with your own, which destroys the evidence we need. Either
              download the original file, or use the &quot;Show Original&quot; / raw
              headers view and paste those instead. <em>Forward as Attachment</em> (a
              different feature in some clients) is fine because it preserves the
              original intact.
            </AlertDescription>
          </Alert>

          <Section
            title="Gmail (browser)"
            steps={[
              "Open the email.",
              "Click the ⋮ next to the Reply arrow (not the menu at the very top of the page).",
              "Click \"Download message.\"",
              "Drop the .eml file into Message Loupe.",
            ]}
          />

          <Section
            title="Outlook on the web"
            steps={[
              "Open the email at outlook.office.com or outlook.live.com.",
              "Click the ⋯ in the message toolbar.",
              "Choose \"Save as.\"",
              "Drop the .eml file into Message Loupe.",
            ]}
          />

          <Section
            title="Apple Mail (Mac)"
            steps={[
              "Drag the email from your inbox onto your desktop. It saves as a .eml file.",
              "Drop that file into Message Loupe.",
            ]}
          />

          <Section
            title="Outlook desktop (Windows / Mac)"
            steps={[
              "If Outlook can save the message as .eml, use that file.",
              "If Outlook only gives you .msg, switch to \"Paste headers\" instead.",
              "Open the email, choose File → Properties, and copy everything from the \"Internet headers\" box.",
            ]}
          />

          <Section
            title="Thunderbird"
            steps={[
              "Right-click the email in your inbox.",
              "Choose Save As → .eml format.",
              "Drop the saved file into Message Loupe.",
            ]}
          />

          <Section
            title="Anything else"
            steps={[
              'Switch to the "Paste headers" tab.',
              'Open the suspicious email and find a menu option like "Show original," "View source," or "View headers."',
              "Copy everything you see and paste it in.",
            ]}
          />

          <div className="border-border/60 mt-4 border-t pt-6">
            <h3 className="text-foreground mb-3 text-sm font-semibold">On a phone?</h3>
            <p className="text-muted-foreground mb-3 text-sm">
              Phones make this much harder. Two real options:
            </p>
            <ul className="text-muted-foreground space-y-3 text-sm">
              <li>
                <strong className="text-foreground">iPhone Mail:</strong> long-press the
                message → <em>Forward as Attachment</em> (this is different from regular
                Forward, but preserves the original) → send to yourself, then open the
                .eml attachment on a computer.
              </li>
              <li>
                <strong className="text-foreground">Gmail on phone:</strong> open
                gmail.com in your phone&apos;s browser (<em>not</em> the Gmail app), tap
                the three-line menu, choose <em>Desktop site</em>, then use the Gmail
                steps above.
              </li>
              <li>
                If neither works, wait until you&apos;re at a computer. Don&apos;t
                regular-forward the email to yourself, since that breaks the analysis.
              </li>
            </ul>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  )
}

function Section({ title, steps }: { title: string; steps: string[] }) {
  return (
    <div>
      <h3 className="text-foreground mb-2 text-sm font-semibold">{title}</h3>
      <ol className="text-muted-foreground ml-4 list-decimal space-y-1.5 text-sm leading-relaxed marker:text-foreground/40">
        {steps.map((step, i) => (
          <li key={i}>{step}</li>
        ))}
      </ol>
    </div>
  )
}
