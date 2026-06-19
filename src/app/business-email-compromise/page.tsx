import Link from "next/link"
import { ArrowRight, CheckCircle2, ExternalLink, PhoneCall, ShieldAlert } from "lucide-react"
import type { ReactNode } from "react"

import { JsonLd } from "@/components/json-ld"
import { SiteFooter } from "@/components/site-footer"
import { SiteHeader } from "@/components/site-header"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { createPageMetadata, SITE_URL } from "@/lib/seo"

const DESCRIPTION =
  "Check a suspicious wire, invoice, payroll, or account-change email for BEC warning signs, and learn why authenticated email can still be fraudulent."

export const metadata = createPageMetadata({
  title: "BEC and Wire Fraud Email Checker",
  description: DESCRIPTION,
  path: "/business-email-compromise",
  keywords: [
    "business email compromise checker",
    "BEC email checker",
    "wire fraud email checker",
    "invoice fraud email",
    "payment redirection fraud",
    "text only BEC email",
  ],
})

const FAQS = [
  {
    question: "Can SPF, DKIM, and DMARC pass on a fraudulent email?",
    answer:
      "Yes. Those checks can prove that a domain authorized and signed the message, but they cannot prove the request is honest. A criminal using a compromised real mailbox can send a fully authenticated BEC email.",
  },
  {
    question: "Can Message Loupe prove that an email is safe?",
    answer:
      "No. It can identify technical and content warning signs and explain why a message needs caution. Money, credential, payroll, and account-change requests should be verified through a contact method you already trust.",
  },
  {
    question: "Does Message Loupe upload the email?",
    answer:
      "No. The email is analyzed in the browser. Optional DNS and RDAP lookups may send only the visible sender domain to public lookup services, never the message, headers, links, or verdict.",
  },
  {
    question: "What should I do if money was already wired?",
    answer:
      "Contact the sending bank immediately and ask it to recall or freeze the transfer. Then report the incident to the FBI Internet Crime Complaint Center and your local law enforcement or security team.",
  },
]

const pageJsonLd = [
  {
    "@context": "https://schema.org",
    "@type": "Article",
    headline: "Business email compromise and wire fraud emails: what to check",
    description: DESCRIPTION,
    mainEntityOfPage: `${SITE_URL}/business-email-compromise/`,
    author: { "@type": "Organization", name: "Message Loupe", url: SITE_URL },
    publisher: { "@type": "Organization", name: "Message Loupe", url: SITE_URL },
    datePublished: "2026-06-19",
    dateModified: "2026-06-19",
    inLanguage: "en-US",
  },
  {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: FAQS.map(({ question, answer }) => ({
      "@type": "Question",
      name: question,
      acceptedAnswer: { "@type": "Answer", text: answer },
    })),
  },
  {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Message Loupe", item: SITE_URL },
      {
        "@type": "ListItem",
        position: 2,
        name: "BEC and wire fraud email checker",
        item: `${SITE_URL}/business-email-compromise/`,
      },
    ],
  },
]

export default function BusinessEmailCompromisePage() {
  return (
    <>
      <SiteHeader />
      <JsonLd data={pageJsonLd} />
      <main className="mx-auto w-full max-w-3xl flex-1 px-4 py-12 md:px-6 md:py-20">
        <article>
          <nav aria-label="Breadcrumb" className="text-muted-foreground mb-5 text-sm">
            <Link href="/" className="hover:text-foreground">
              Email checker
            </Link>{" "}
            <span aria-hidden>/</span> BEC and wire fraud
          </nav>

          <h1 className="text-foreground max-w-3xl text-balance text-3xl font-semibold tracking-tight md:text-4xl">
            Business email compromise and wire fraud emails: what to check
          </h1>
          <p className="text-muted-foreground mt-4 max-w-2xl text-lg leading-relaxed">
            A wire or invoice request can be fraudulent even when SPF, DKIM, and DMARC
            pass. Message Loupe checks the original email for impersonation, unusual
            routing, risky links or attachments, and text-only BEC patterns, then tells
            you when to verify the request outside email.
          </p>

          <div className="mt-7 flex flex-wrap gap-3">
            <Button asChild>
              <Link href="/#scanner">
                Check the email
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
            <Button asChild variant="outline">
              <Link href="/how-to-save-an-email">Save the original email</Link>
            </Button>
          </div>

          <Alert variant="warning" className="mt-10">
            <PhoneCall aria-hidden />
            <AlertTitle>Verify payment requests through a known channel</AlertTitle>
            <AlertDescription>
              Do not reply, call a number in the message, or use its signature details.
              Contact the person or company using a number you already had before the
              email arrived. This follows guidance from the{" "}
              <SourceLink href="https://www.cisa.gov/secure-our-world/recognize-and-report-phishing">
                Cybersecurity and Infrastructure Security Agency
              </SourceLink>
              .
            </AlertDescription>
          </Alert>

          <section className="mt-14">
            <h2 className="text-foreground text-2xl font-semibold tracking-tight">
              What is business email compromise?
            </h2>
            <p className="text-muted-foreground mt-3 leading-relaxed">
              Business email compromise (BEC) is fraud that uses a trusted business
              identity to persuade someone to send money, change payment details,
              disclose sensitive information, or enter credentials. The identity may be
              spoofed, registered on a lookalike domain, or taken over through a real
              mailbox. Microsoft&apos;s{" "}
              <SourceLink href="https://www.microsoft.com/en-us/security/business/security-101/what-is-business-email-compromise-bec">
                BEC overview
              </SourceLink>{" "}
              describes the same mix of impersonation and social engineering.
            </p>
          </section>

          <section className="mt-12">
            <h2 className="text-foreground text-2xl font-semibold tracking-tight">
              Can an email scanner detect BEC?
            </h2>
            <p className="text-muted-foreground mt-3 leading-relaxed">
              It can detect many warning signs, but no scanner can prove every request is
              legitimate. Message Loupe is strongest when the attacker spoofs a sender,
              uses a lookalike domain, changes the reply address, fails authentication,
              hides a destination behind misleading link text, or combines payment
              language with a risky delivery pattern.
            </p>
            <p className="text-muted-foreground mt-3 leading-relaxed">
              A compromised real account is the hard case. Its messages can authenticate
              correctly because the real provider sent them. For that reason, Message
              Loupe caps money, credential, payroll, and account-change requests at
              Caution and tells the user to verify by phone.
            </p>
          </section>

          <section className="mt-12">
            <h2 className="text-foreground text-2xl font-semibold tracking-tight">
              Check a wire-transfer email in three steps
            </h2>
            <ol className="mt-5 grid gap-5">
              <CheckStep
                number="1"
                title="Pause the payment"
                text="Do not reply, open an attachment, or use contact details supplied by the message."
              />
              <CheckStep
                number="2"
                title="Analyze the original message"
                text="Save the .eml file or copy the full raw headers. Regular forwarding removes the evidence needed for sender and routing checks."
              />
              <CheckStep
                number="3"
                title="Verify and report"
                text="Call a known contact to confirm the request. If money moved, contact the bank immediately and file a report with IC3."
              />
            </ol>
          </section>

          <section className="mt-12">
            <h2 className="text-foreground text-2xl font-semibold tracking-tight">
              Warning signs Message Loupe checks
            </h2>
            <ul className="text-muted-foreground mt-5 grid gap-3 sm:grid-cols-2">
              {[
                "From, return-path, reply-to, and DKIM domain disagreements",
                "SPF, DKIM, and DMARC failures or missing trusted results",
                "Lookalike, newly registered, unrelated, or raw-IP link hosts",
                "Wire, ACH, routing, remittance, invoice, and bank-change language",
                "Unexpected attachments paired with payment or document requests",
                "Routing and mail-provider inconsistencies",
              ].map((item) => (
                <li key={item} className="flex gap-2 leading-relaxed">
                  <CheckCircle2 className="text-success mt-1 size-4 shrink-0" aria-hidden />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
            <p className="text-muted-foreground mt-5 leading-relaxed">
              See the full{" "}
              <Link href="/methodology" className="text-foreground underline-offset-4 hover:underline">
                email-analysis methodology
              </Link>{" "}
              for how those signals affect a verdict.
            </p>
          </section>

          <section className="mt-12">
            <h2 className="text-foreground text-2xl font-semibold tracking-tight">
              Common BEC and wire-fraud patterns
            </h2>
            <dl className="divide-border mt-5 divide-y border-y">
              <Pattern term="Invoice redirection" detail="A vendor supposedly changed its bank or ACH instructions just before payment." />
              <Pattern term="Executive impersonation" detail="A senior leader requests secrecy, urgency, a wire, gift cards, or sensitive records." />
              <Pattern term="Payroll diversion" detail="An employee or executive supposedly asks to change direct-deposit details." />
              <Pattern term="Credential capture" detail="A familiar sender shares a document or sign-in link that leads to an unrelated domain." />
            </dl>
          </section>

          <section className="mt-12">
            <h2 className="text-foreground text-2xl font-semibold tracking-tight">
              Frequently asked questions
            </h2>
            <div className="divide-border mt-5 divide-y border-y">
              {FAQS.map(({ question, answer }) => (
                <div key={question} className="py-5">
                  <h3 className="text-foreground font-semibold">{question}</h3>
                  <p className="text-muted-foreground mt-2 leading-relaxed">{answer}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="mt-12">
            <div className="flex items-center gap-2">
              <ShieldAlert className="text-primary size-5" aria-hidden />
              <h2 className="text-foreground text-2xl font-semibold tracking-tight">
                Primary sources and standards
              </h2>
            </div>
            <ul className="text-muted-foreground mt-5 space-y-3">
              <Citation href="https://www.fbi.gov/how-we-can-help-you/scams-and-safety/common-frauds-and-scams/business-email-compromise" label="FBI: Business Email Compromise" />
              <Citation href="https://www.cisa.gov/secure-our-world/recognize-and-report-phishing" label="CISA: Recognize and Report Phishing" />
              <Citation href="https://www.microsoft.com/en-us/security/business/security-101/what-is-business-email-compromise-bec" label="Microsoft Security: What is business email compromise?" />
              <Citation href="https://www.ic3.gov/" label="FBI Internet Crime Complaint Center" />
              <Citation href="https://www.rfc-editor.org/rfc/rfc7208" label="IETF RFC 7208: Sender Policy Framework" />
              <Citation href="https://www.rfc-editor.org/rfc/rfc6376" label="IETF RFC 6376: DomainKeys Identified Mail" />
              <Citation href="https://www.rfc-editor.org/rfc/rfc7489" label="IETF RFC 7489: DMARC" />
              <Citation href="https://www.rfc-editor.org/rfc/rfc8601" label="IETF RFC 8601: Authentication-Results" />
            </ul>
          </section>

          <div className="border-border bg-muted/20 mt-14 border-y px-1 py-8">
            <h2 className="text-foreground text-xl font-semibold">Check the original email</h2>
            <p className="text-muted-foreground mt-2 max-w-2xl leading-relaxed">
              Message Loupe runs in the browser and does not upload the message. Use the
              original .eml file or full raw headers for the strongest analysis.
            </p>
            <Button asChild className="mt-5">
              <Link href="/#scanner">
                Scan a suspicious email
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
          </div>
        </article>
      </main>
      <SiteFooter />
    </>
  )
}

function SourceLink({ href, children }: Readonly<{ href: string; children: ReactNode }>) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-foreground underline-offset-4 hover:underline">
      {children}
    </a>
  )
}

function CheckStep({ number, title, text }: Readonly<{ number: string; title: string; text: string }>) {
  return (
    <li className="grid grid-cols-[2rem_1fr] gap-3">
      <span className="bg-primary text-primary-foreground flex size-8 items-center justify-center rounded-full font-mono text-sm" aria-hidden>
        {number}
      </span>
      <div>
        <h3 className="text-foreground font-semibold">{title}</h3>
        <p className="text-muted-foreground mt-1 leading-relaxed">{text}</p>
      </div>
    </li>
  )
}

function Pattern({ term, detail }: Readonly<{ term: string; detail: string }>) {
  return (
    <div className="grid gap-1 py-4 sm:grid-cols-[11rem_1fr] sm:gap-5">
      <dt className="text-foreground font-semibold">{term}</dt>
      <dd className="text-muted-foreground leading-relaxed">{detail}</dd>
    </div>
  )
}

function Citation({ href, label }: Readonly<{ href: string; label: string }>) {
  return (
    <li>
      <a href={href} target="_blank" rel="noopener noreferrer" className="hover:text-foreground inline-flex items-center gap-1.5 underline-offset-4 hover:underline">
        {label}
        <ExternalLink className="size-3.5" aria-hidden />
      </a>
    </li>
  )
}
