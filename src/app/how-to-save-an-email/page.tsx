import type { Metadata } from "next"

import { SiteHeader } from "@/components/site-header"
import { SiteFooter } from "@/components/site-footer"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { TriangleAlert } from "lucide-react"

export const metadata: Metadata = {
  title: "How to save an email for scanning",
  description:
    "Step-by-step instructions for saving an email as a .eml file or copying its raw headers, in Gmail, Outlook, Apple Mail, Thunderbird, and on phones.",
  alternates: { canonical: "/how-to-save-an-email" },
  keywords: [
    "how to save email as eml",
    "download email gmail",
    "save outlook email as file",
    "view original email gmail",
    "show original email",
    "view raw email headers",
    "copy email headers",
  ],
}

export default function HowToSaveAnEmailPage() {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto w-full max-w-2xl flex-1 px-4 py-12 md:px-6 md:py-20">
        <h1 className="text-foreground text-3xl font-semibold tracking-tight md:text-4xl">
          How to save an email for scanning
        </h1>
        <p className="text-muted-foreground mt-3 text-base leading-relaxed">
          Message Loupe needs the original email: either the whole file (
          <code className="font-mono text-sm">.eml</code> or{" "}
          <code className="font-mono text-sm">.msg</code>) or just the raw headers.
          Don&apos;t paste the email body or send a screenshot, since those don&apos;t
          include the hidden routing info we check.
        </p>

        <Alert variant="warning" className="mt-8">
          <TriangleAlert aria-hidden />
          <AlertTitle>Regular forwarding doesn&apos;t work</AlertTitle>
          <AlertDescription>
            When you forward an email, your mail program replaces the original
            headers with your own, which destroys the evidence we need. Either
            download the original file, or use the &quot;Show Original&quot; / raw
            headers view and paste those instead. <em>Forward as Attachment</em> (a
            different feature in some clients, listed below) is fine because it
            preserves the original intact.
          </AlertDescription>
        </Alert>

        <Section
          id="gmail"
          title="Gmail (in a browser)"
          steps={[
            "Open the email.",
            "Click the ⋮ next to the Reply arrow (the one inside the email itself, not the menu at the very top of the page).",
            'Click "Download message."',
            "Drop the saved .eml file into Message Loupe.",
          ]}
          alt="Use the same menu, choose Show original instead, then copy everything from the page that opens and paste it into Message Loupe&apos;s Paste headers tab."
        />

        <Section
          id="outlook-web"
          title="Outlook on the web"
          subtitle="outlook.office.com (work / school) or outlook.live.com (personal)"
          steps={[
            "Open the email.",
            "Click the ⋯ in the message toolbar.",
            'Choose "Save as."',
            "Drop the saved .eml file into Message Loupe.",
          ]}
          alt="Open the email, click ⋯ → View → View message source. Copy the entire window contents and paste into the Paste headers tab."
        />

        <Section
          id="apple-mail"
          title="Apple Mail (Mac)"
          steps={[
            "Drag the email from your inbox onto your desktop. It saves as a .eml file.",
            "Drop that file into Message Loupe.",
          ]}
          alt="Open the email, then View → Message → All Headers. Copy the headers block and paste into the Paste headers tab."
        />

        <Section
          id="outlook-desktop"
          title="Outlook desktop (Windows / Mac)"
          steps={[
            "Drag the email from your inbox onto your desktop. On Windows it saves as .msg; on Mac it saves as .eml.",
            "Drop that file into Message Loupe.",
            'If the file is a .msg and Message Loupe rejects it, switch to "Paste headers" instead.',
          ]}
          alt="Open the email, then File → Properties (Windows) or Message → Internet headers (Mac). Copy the contents of the &apos;Internet headers&apos; box and paste into the Paste headers tab."
          fwdAtt="Outlook desktop also supports Forward as Attachment: Home → More → Forward as Attachment. The forwarded message arrives with the original .eml attached."
        />

        <Section
          id="thunderbird"
          title="Thunderbird"
          steps={[
            "Right-click the email in your inbox.",
            "Choose Save As → .eml.",
            "Drop the saved file into Message Loupe.",
          ]}
          alt="Open the email, then View → Message Source. Copy and paste the full contents."
          fwdAtt="Thunderbird supports Forward As → Attachment via right-click on the message."
        />

        <h2 className="text-foreground mt-16 text-2xl font-semibold tracking-tight">
          On a phone?
        </h2>
        <p className="text-muted-foreground mt-3 leading-relaxed">
          Phones make this much harder. Two real options:
        </p>
        <ul className="text-muted-foreground mt-4 space-y-3">
          <li>
            <strong className="text-foreground">iPhone Mail.</strong> Long-press the
            message, then choose <em>Forward as Attachment</em>. This is{" "}
            <strong>different</strong> from regular Forward, and it preserves the
            original intact. Send to yourself, then open the .eml attachment on a
            computer.
          </li>
          <li>
            <strong className="text-foreground">Gmail on phone.</strong> Open{" "}
            <code>gmail.com</code> in your phone&apos;s web browser (
            <em>not</em> the Gmail app), tap the three-line menu, choose{" "}
            <em>Desktop site</em>, then use the Gmail steps above.
          </li>
          <li>
            If neither works, wait until you&apos;re at a computer. Don&apos;t
            regular-forward the email to yourself, since that breaks the
            analysis.
          </li>
        </ul>

        <p className="text-muted-foreground mt-12 text-sm leading-relaxed">
          Don&apos;t see your email program? Look for a menu option called &quot;Show
          Original,&quot; &quot;View Source,&quot; &quot;View Headers,&quot; or
          &quot;Internet Headers.&quot; Copy what you see and paste it into the{" "}
          <em>Paste headers</em> tab on the home page.
        </p>
      </main>
      <SiteFooter />
    </>
  )
}

function Section({
  id,
  title,
  subtitle,
  steps,
  alt,
  fwdAtt,
}: {
  id: string
  title: string
  subtitle?: string
  steps: string[]
  alt?: string
  fwdAtt?: string
}) {
  return (
    <section id={id} className="mt-12 scroll-mt-20">
      <h2 className="text-foreground text-xl font-semibold tracking-tight md:text-2xl">
        {title}
      </h2>
      {subtitle ? (
        <p className="text-muted-foreground mt-1 font-mono text-xs">{subtitle}</p>
      ) : null}
      <ol className="text-muted-foreground mt-4 ml-6 list-decimal space-y-2 leading-relaxed marker:text-foreground/40">
        {steps.map((step, i) => (
          <li key={i}>{step}</li>
        ))}
      </ol>
      {alt ? (
        <p className="text-muted-foreground mt-3 text-sm leading-relaxed">
          <strong className="text-foreground">Headers-only alternative:</strong>{" "}
          {alt.replace(/&apos;/g, "'")}
        </p>
      ) : null}
      {fwdAtt ? (
        <p className="text-muted-foreground mt-2 text-sm leading-relaxed">
          <strong className="text-foreground">Forward as Attachment:</strong>{" "}
          {fwdAtt}
        </p>
      ) : null}
    </section>
  )
}
