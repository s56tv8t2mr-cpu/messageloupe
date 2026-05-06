import type { Metadata } from "next"

import { SiteHeader } from "@/components/site-header"
import { SiteFooter } from "@/components/site-footer"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { ShieldCheck } from "lucide-react"

export const metadata: Metadata = {
  title: "Privacy",
  description:
    "Message Loupe is a static page that runs entirely in your browser. We don't collect, log, transmit, or store your email — ever.",
  alternates: { canonical: "/privacy" },
}

export default function PrivacyPage() {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto w-full max-w-2xl flex-1 px-4 py-12 md:px-6 md:py-20">
        <h1 className="text-foreground text-3xl font-semibold tracking-tight md:text-4xl">
          Privacy
        </h1>
        <p className="text-muted-foreground mt-3 text-base">
          Short version: nothing leaves your browser. Long version below.
        </p>

        <Alert variant="success" className="mt-8">
          <ShieldCheck aria-hidden />
          <AlertTitle>Your email is never uploaded</AlertTitle>
          <AlertDescription>
            All analysis happens in your browser. There is no server-side processing.
            We can&apos;t see your email even if we wanted to.
          </AlertDescription>
        </Alert>

        <div className="prose prose-zinc dark:prose-invert mt-10 max-w-none text-base leading-relaxed">
          <h2 className="text-foreground text-xl font-semibold">What we collect</h2>
          <p className="text-muted-foreground">
            <strong className="text-foreground">Nothing about your email.</strong>{" "}
            When you drop a file or paste headers, the parser, content classifier, and
            verdict logic all run in JavaScript inside your browser. The contents of
            your email are never transmitted to us, our hosting provider, or any
            third party.
          </p>
          <p className="text-muted-foreground">
            <strong className="text-foreground">No analytics, no cookies, no
            tracking.</strong>{" "}
            We don&apos;t embed Google Analytics, Plausible, Posthog, or any other
            tracker. The site is a static page served from a CDN.
          </p>
          <p className="text-muted-foreground">
            <strong className="text-foreground">Standard server logs.</strong>{" "}
            Our hosting provider (Vercel) keeps short-lived request logs for
            availability and DDoS-mitigation purposes. These contain your IP
            address and the URL you requested, like every other website on the
            internet. They do not contain anything from your email.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            What we don&apos;t do
          </h2>
          <ul className="text-muted-foreground space-y-1.5">
            <li>We do not upload, log, store, or transmit your email.</li>
            <li>We do not call third-party reputation services with your data.</li>
            <li>We do not set cookies (other than what your browser may set automatically — none from us).</li>
            <li>We do not have a database. There is nothing to leak.</li>
          </ul>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            If you contact us
          </h2>
          <p className="text-muted-foreground">
            If you email us at <code>hello@messageloupe.com</code>, we&apos;ll have
            whatever you put in that email and your reply-to address. We use that to
            answer you and nothing else. We don&apos;t add you to a mailing list.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            Verifying our claims
          </h2>
          <p className="text-muted-foreground">
            You don&apos;t have to take our word for it. The full source is available
            on{" "}
            <a
              href="https://github.com/danielbabbitt/messageloupe"
              target="_blank"
              rel="noopener noreferrer"
              className="underline-offset-4 hover:underline"
            >
              GitHub
            </a>
            . Open your browser&apos;s network tab while you analyze a sample
            email — you&apos;ll see no outgoing requests during the scan.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            Changes to this policy
          </h2>
          <p className="text-muted-foreground">
            If this ever changes, the change will be in the git history of the
            site&apos;s repository. We won&apos;t add tracking quietly.
          </p>
        </div>
      </main>
      <SiteFooter />
    </>
  )
}
