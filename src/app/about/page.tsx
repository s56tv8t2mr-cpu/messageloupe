import Link from "next/link"

import { SiteHeader } from "@/components/site-header"
import { SiteFooter } from "@/components/site-footer"
import { createPageMetadata } from "@/lib/seo"

export const metadata = createPageMetadata({
  title: "About the Browser-Only Email Checker",
  description:
    "Message Loupe is a free, browser-only second opinion on suspicious email, built from an analyst's triage engine and designed for non-technical users.",
  path: "/about",
})

export default function AboutPage() {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto w-full max-w-2xl flex-1 px-4 py-12 md:px-6 md:py-20">
        <h1 className="text-foreground text-3xl font-semibold tracking-tight md:text-4xl">
          About Message Loupe
        </h1>

        <div className="prose prose-zinc dark:prose-invert mt-8 max-w-none text-base leading-relaxed">
          <p className="text-muted-foreground">
            Message Loupe is a free second-opinion tool for email. Drop a saved
            email, or paste its raw headers, and within a couple of seconds you get
            a plain-English verdict: <strong>no warning signs</strong>,{" "}
            <strong>caution</strong>, or <strong>likely fake</strong>. Each verdict
            explains the evidence and, when needed, the safest next action.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            Why this exists
          </h2>
          <p className="text-muted-foreground">
            Most phishing-detection tools are aimed at security teams and cost five or
            six figures a year. The rest of us (freelancers, small businesses, people
            who handle their parents&apos; bills, anyone who&apos;s ever stared at an
            email and wondered &quot;is this really my bank?&quot;) get a spam folder
            and a hunch. Message Loupe is what happens when an analyst&apos;s triage
            engine is rebuilt for everyone else, with the jargon stripped out.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            What Message Loupe answers (and what it doesn&apos;t)
          </h2>
          <p className="text-muted-foreground">
            Message Loupe answers a narrower question:{" "}
            <strong className="text-foreground">what warning signs are present in
            the evidence it can inspect?</strong> A &quot;No warning signs&quot; result
            means it found no spoofing, sender-alignment, routing, or suspicious-link
            signals. It does not prove who controls the account or that a request is
            trustworthy. It also does not decide whether an email is wanted or
            relevant. Real cold outreach, marketing, and newsletters can pass these
            checks. Spam filtering is a different problem, handled (imperfectly) by
            your email provider.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            What we&apos;re honest about
          </h2>
          <p className="text-muted-foreground">
            The verdict is advisory, not a guarantee. We can read the technical
            evidence in an email&apos;s headers: who really sent it, what server
            relayed it, whether the sender&apos;s domain authorizes that server.
            These checks can catch many common impersonation patterns, including fake
            banks, fake delivery services, lookalike domains, and hijacked login
            pages.
          </p>
          <p className="text-muted-foreground mt-6">
            What we can&apos;t catch is when an attacker has already
            compromised a real account at a real vendor and is sending a real-looking
            request from that real address. Every technical signal passes, because
            from the email&apos;s perspective, nothing is wrong. That&apos;s why a message
            asking for money, banking details, credentials, identity documents, or a
            signed form can never receive &quot;No warning signs&quot; solely because its
            technical signals pass. It is at least Caution, with a verification step
            matched to the request: call a trusted number for money or banking changes,
            open the known site directly for credentials, and use an approved portal
            for documents or signed forms.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            How it&apos;s built
          </h2>
          <p className="text-muted-foreground">
            The email analysis runs in your browser, with no upload or logging of
            your email. For non-webmail senders, the browser may make a domain-only
            MX lookup, and a same-site Cloudflare function may relay the sender
            domain to public RDAP services for its registration age. Message contents,
            headers, links, and verdicts are never sent. The
            engine powering the verdict is
            an open-source port of an internal triage tool originally built for
            phishing analysts; you can read more in our{" "}
            <Link href="/methodology" className="underline-offset-4 hover:underline">
              methodology
            </Link>{" "}
            page. The full source is on{" "}
            <a
              href="https://github.com/s56tv8t2mr-cpu/messageloupe"
              target="_blank"
              rel="noopener noreferrer"
              className="underline-offset-4 hover:underline"
            >
              GitHub
            </a>
            .
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">Get in touch</h2>
          <p className="text-muted-foreground">
            Found a bug, have a question, or want to tell us about a phishing pattern
            we&apos;re missing? Email{" "}
            <a
              href="mailto:hello@messageloupe.com"
              className="underline-offset-4 hover:underline"
            >
              hello@messageloupe.com
            </a>
            .
          </p>
        </div>
      </main>
      <SiteFooter />
    </>
  )
}
