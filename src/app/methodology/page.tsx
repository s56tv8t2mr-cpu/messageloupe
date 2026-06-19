import Link from "next/link"

import { SiteHeader } from "@/components/site-header"
import { SiteFooter } from "@/components/site-footer"
import { createPageMetadata } from "@/lib/seo"

export const metadata = createPageMetadata({
  title: "How Message Loupe Analyzes Suspicious Email",
  description:
    "See how Message Loupe checks authentication, sender alignment, routing, domain age, links, attachments, and BEC language, plus what it cannot prove.",
  path: "/methodology",
  keywords: [
    "email header analyzer methodology",
    "SPF DKIM DMARC email check",
    "BEC email detection",
    "email sender alignment",
  ],
})

export default function MethodologyPage() {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto w-full max-w-2xl flex-1 px-4 py-12 md:px-6 md:py-20">
        <h1 className="text-foreground text-3xl font-semibold tracking-tight md:text-4xl">
          Methodology
        </h1>
        <p className="text-muted-foreground mt-3 text-base">
          What Message Loupe actually checks, and what it deliberately doesn&apos;t.
        </p>

        <div className="prose prose-zinc dark:prose-invert mt-10 max-w-none text-base leading-relaxed">
          <h2 className="text-foreground text-xl font-semibold">The signals we read</h2>
          <p className="text-muted-foreground">
            Every email carries a set of routing headers that travel with it from the
            sender&apos;s mail server to yours. They&apos;re invisible by default but
            preserved in the file you save. We read them locally in your browser and
            evaluate four broad categories:
          </p>
          <ul className="text-muted-foreground space-y-1.5">
            <li>
              <strong className="text-foreground">Authentication:</strong> SPF
              (whether the sending server is authorized for the sender domain), DKIM
              (whether the message body and key headers are cryptographically signed),
              and DMARC (whether the sender domain has a published policy and the
              message complies with it).
            </li>
            <li>
              <strong className="text-foreground">Sender alignment:</strong> whether
              the visible <code>From:</code> address matches the technical{" "}
              <code>Return-Path</code>, the DKIM signing domain, and the
              authentication-results domain.
            </li>
            <li>
              <strong className="text-foreground">Routing:</strong> the chain of
              servers (
              <code>Received:</code> headers) that handled the message, working
              backwards to find the originating IP, including stepping past known
              security gateways so the real upstream sender is identified.
            </li>
            <li>
              <strong className="text-foreground">MX records:</strong> for
              non-webmail senders, your browser may ask Google Public DNS which
              provider handles mail for the visible sender domain. We compare that
              inbound provider with the service that delivered the message.
            </li>
            <li>
              <strong className="text-foreground">Domain age:</strong> for
              non-webmail senders, your browser may ask public RDAP when the visible
              sender domain was registered. New domains are treated as advisory unless
              they appear with sensitive business-action language and weak
              authentication.
            </li>
            <li>
              <strong className="text-foreground">Links:</strong> the URLs in the
              message body, checked for visible/actual mismatches, raw IP hosts,
              punycode-encoded lookalikes, .cm typosquats, and known shorteners.
            </li>
          </ul>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            How we get to a verdict
          </h2>
          <p className="text-muted-foreground">
            We don&apos;t score-and-threshold; we apply a small set of rules that mirror
            how an analyst triages a phish:
          </p>
          <ul className="text-muted-foreground space-y-1.5">
            <li>
              <strong className="text-foreground">Danger</strong> if any of the
              high-confidence failures fire: DMARC fails, SPF fails, the sender
              clearly looks spoofed, or a link uses an anchor-vs-href mismatch, raw
              IP host, or punycode.
            </li>
            <li>
              <strong className="text-foreground">Caution</strong> for ambiguous or
              partial signals: SPF soft-fail, DKIM fail, missing authentication, a
              return-path mismatch on a non-ESP message, suspicious shortener links,
              or no source IP at all.
            </li>
            <li>
              <strong className="text-foreground">Safe</strong> when every category
              checks out and there&apos;s no money or credential content present.
            </li>
          </ul>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            The money &amp; credential cap
          </h2>
          <p className="text-muted-foreground">
            If the message body mentions money, banking changes, wires, gift cards,
            credentials, or login info, we never let the verdict rise above
            &quot;Caution: verify by phone.&quot; Even a perfectly-authenticated
            email can be malicious if an attacker has compromised a real account at a
            real vendor. Header analysis is structurally blind to that case. The cap
            is our way of being honest about that blind spot.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            The forwarded-message guard
          </h2>
          <p className="text-muted-foreground">
            Regular forwarding replaces the original headers with the forwarder&apos;s
            own, which destroys the evidence we need. If we detect a forward (by
            subject prefix, by a forward-separator block in the body, or by a
            Received chain that looks like a Sent-Items export), we short-circuit
            with a request to use &quot;Save Original&quot; or &quot;Show
            Original&quot; instead. We&apos;d rather refuse to answer than answer
            wrong on a forwarded phish.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            What we deliberately don&apos;t do
          </h2>
          <ul className="text-muted-foreground space-y-1.5">
            <li>
              <strong className="text-foreground">No spam scoring or
              sender-reputation blocking.</strong>{" "}
              We answer &quot;is this email pretending to be something it
              isn&apos;t?&quot;, not &quot;is this email welcome?&quot; Those are
              different questions, and your email provider&apos;s spam filter
              (imperfect though it is) already handles the second one. Cold sales
              outreach, real newsletters you forgot subscribing to, recruiter
              cold-emails: those are &quot;authentic but unwelcome,&quot; and
              we&apos;ll correctly call them legitimate because they are.
            </li>
            <li>
              <strong className="text-foreground">No general-purpose AI content
              model.</strong>{" "}
              We use explicit, local rules for payment, credential, job, invoice,
              account-change, and fraud-report language. We do not send the message to
              a remote language model to interpret its meaning. That would break the
              privacy promise.
            </li>
            <li>
              <strong className="text-foreground">No reputation lookups.</strong> We
              don&apos;t query VirusTotal, urlscan, abuse.ch, or anything else with
              the contents of your email. Optional DNS and RDAP lookups send only the
              sender domain for MX records and registration age, not the message,
              headers, links, or verdict.
            </li>
            <li>
              <strong className="text-foreground">No tracking.</strong> No analytics,
              no cookies, no application logs. The site is a static page served from a CDN.
            </li>
          </ul>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            Standards and fraud guidance
          </h2>
          <p className="text-muted-foreground">
            Authentication parsing follows the published specifications for{" "}
            <a href="https://www.rfc-editor.org/rfc/rfc7208" target="_blank" rel="noopener noreferrer" className="underline-offset-4 hover:underline">SPF</a>,{" "}
            <a href="https://www.rfc-editor.org/rfc/rfc6376" target="_blank" rel="noopener noreferrer" className="underline-offset-4 hover:underline">DKIM</a>,{" "}
            <a href="https://www.rfc-editor.org/rfc/rfc7489" target="_blank" rel="noopener noreferrer" className="underline-offset-4 hover:underline">DMARC</a>, and{" "}
            <a href="https://www.rfc-editor.org/rfc/rfc8601" target="_blank" rel="noopener noreferrer" className="underline-offset-4 hover:underline">Authentication-Results</a>.
            The recommendation to verify suspicious requests through a known channel
            matches{" "}
            <a href="https://www.cisa.gov/secure-our-world/recognize-and-report-phishing" target="_blank" rel="noopener noreferrer" className="underline-offset-4 hover:underline">CISA guidance</a>.
          </p>
          <p className="text-muted-foreground">
            For payment-redirection and text-only scams, read the{" "}
            <Link href="/business-email-compromise" className="text-foreground underline-offset-4 hover:underline">
              BEC and wire-fraud email guide
            </Link>.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            How we test ourselves
          </h2>
          <p className="text-muted-foreground">
            The rule engine ships with a regression suite: synthetic .eml
            fixtures that exercise each verdict path (authentication failures,
            brand and role impersonation, link flags, the money/credential
            cap, the job-offer-plus-document-request pair, the
            forwarded-message guard, and known-good ESP-routed mail). The
            tests run on every change to make sure refactors don&apos;t
            silently move a verdict from &quot;danger&quot; to
            &quot;caution&quot; on a scenario we&apos;ve already documented.
            The fixtures are constructed, not redacted real samples; they
            prove the engine still produces the documented verdict for each
            rule path.
          </p>
          <p className="text-muted-foreground">
            If you find a real-world email where we get the wrong answer, email
            the saved file (never just the body, since the headers are the
            evidence) to{" "}
            <a
              href="mailto:hello@messageloupe.com"
              className="underline-offset-4 hover:underline"
            >
              hello@messageloupe.com
            </a>{" "}
            and we&apos;ll turn it into a fixture.
          </p>
        </div>
      </main>
      <SiteFooter />
    </>
  )
}
