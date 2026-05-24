import type { Metadata } from "next"
import Link from "next/link"

import { SiteHeader } from "@/components/site-header"
import { SiteFooter } from "@/components/site-footer"

export const metadata: Metadata = {
  title: "About",
  description:
    "Message Loupe is a free, browser-only second opinion on whether an email really came from where it claims. Built by an analyst, intended for everyone else.",
  alternates: { canonical: "/about" },
}

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
            a plain-English verdict: <strong>safe</strong>, <strong>caution</strong>,
            or <strong>likely fake</strong>, with a short explanation of how we got
            there.
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
            Message Loupe answers one specific question:{" "}
            <strong className="text-foreground">is the sender who they claim to
            be?</strong> It does not try to decide whether an email is wanted or
            relevant. Real cold outreach, real marketing, real newsletters: those
            can all be &quot;authentic but unwelcome,&quot; and we&apos;ll correctly
            say they look legitimate, because they are. Whether you want them is your
            call. Spam filtering is a different problem, handled (imperfectly) by
            your email provider.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            What we&apos;re honest about
          </h2>
          <p className="text-muted-foreground">
            The verdict is advisory, not a guarantee. We can read the technical
            evidence in an email&apos;s headers: who really sent it, what server
            relayed it, whether the sender&apos;s domain authorizes that server.
            That&apos;s enough to catch the overwhelming majority of impersonation
            scams: fake banks, fake delivery services, lookalike domains, hijacked
            login pages.
          </p>
          <p className="text-muted-foreground">
            What we <em>can&apos;t</em> catch is when an attacker has already
            compromised a real account at a real vendor and is sending a real-looking
            request from that real address. Every technical signal passes, because
            from the email&apos;s perspective, nothing is wrong. That&apos;s why any
            time we see money or credentials in the message, we cap our verdict at
            &quot;Caution: verify by phone.&quot; Use a phone number you already
            trust, not one from the email.
          </p>

          <h2 className="text-foreground mt-10 text-xl font-semibold">
            How it&apos;s built
          </h2>
          <p className="text-muted-foreground">
            The analysis runs in your browser. There&apos;s no server-side processing,
            no upload, and no logging of your email. For non-webmail senders, your
            browser may make one MX-record lookup for the sender domain; the message
            contents and headers are never sent. The engine powering the verdict is
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
