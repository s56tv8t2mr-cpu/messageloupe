import Link from "next/link"
import type { Metadata } from "next"
import type { ReactNode } from "react"
import {
  ArrowRight,
  Building2,
  CheckCircle2,
  CircleDollarSign,
  ClipboardCheck,
  Inbox,
  LockKeyhole,
  MailCheck,
  MailWarning,
  ShieldCheck,
  UsersRound,
} from "lucide-react"

import { SiteFooter } from "@/components/site-footer"
import { SiteHeader } from "@/components/site-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"

export const metadata: Metadata = {
  title: "For teams",
  description:
    "Message Loupe for small businesses: browser-only phishing checks today, Gmail and Outlook add-in workflow next, and team-safe verdict metadata without storing email contents.",
  alternates: { canonical: "/business" },
}

const AUDIENCES = [
  "Bookkeepers",
  "Realtors",
  "Law offices",
  "Agencies",
  "Family offices",
]

export default function BusinessPage() {
  return (
    <>
      <SiteHeader />
      <main className="flex flex-1 flex-col">
        <section className="border-border/60 border-b bg-muted/20">
          <div className="mx-auto grid w-full max-w-5xl gap-10 px-4 py-12 md:px-6 md:py-18 lg:grid-cols-[minmax(0,0.95fr)_minmax(360px,1.05fr)] lg:items-center">
            <div className="flex flex-col items-start gap-5">
              <Badge variant="outline" className="h-6 gap-1.5 px-2.5">
                <Building2 data-icon="inline-start" />
                Message Loupe for teams
              </Badge>
              <div className="flex flex-col gap-4">
                <h1 className="text-foreground max-w-3xl text-balance text-4xl font-semibold tracking-tight md:text-5xl">
                  A second opinion before anyone wires money or enters a password.
                </h1>
                <p className="text-muted-foreground max-w-xl text-balance text-base leading-relaxed md:text-lg">
                  Start with the private browser scanner. Build toward Gmail and Outlook
                  add-ins that let employees check suspicious messages from the inbox.
                </p>
              </div>
              <div className="flex flex-wrap gap-2 text-sm">
                {AUDIENCES.map((audience) => (
                  <span
                    key={audience}
                    className="border-border bg-background/70 text-muted-foreground rounded-full border px-3 py-1"
                  >
                    {audience}
                  </span>
                ))}
              </div>
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <Button asChild>
                  <Link href="/#scanner">
                    Try the scanner
                    <ArrowRight data-icon="inline-end" />
                  </Link>
                </Button>
                <Button asChild variant="ghost">
                  <Link href="#add-ins">Add-in roadmap</Link>
                </Button>
              </div>
            </div>

            <InboxConsole />
          </div>
        </section>

        <section className="mx-auto grid w-full max-w-5xl gap-8 px-4 py-14 md:grid-cols-[0.85fr_1.15fr] md:px-6 md:py-18">
          <div className="flex flex-col gap-3">
            <h2 className="text-foreground text-2xl font-semibold tracking-tight">
              The buyer is not a consumer.
            </h2>
            <p className="text-muted-foreground leading-relaxed">
              The wedge is a small company with real invoice risk and no security team.
              They already live in Google Workspace or Microsoft 365.
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            <Signal icon={<CircleDollarSign />} title="Invoice fraud" text="Payment-change and wire requests get escalated before action." />
            <Signal icon={<LockKeyhole />} title="Credential traps" text="Suspicious sign-in and document links get a plain-English verdict." />
            <Signal icon={<UsersRound />} title="Repeatable process" text="Employees have one place to send or scan suspicious emails." />
          </div>
        </section>

        <section id="add-ins" className="border-border/60 border-y">
          <div className="mx-auto grid w-full max-w-5xl gap-10 px-4 py-14 md:px-6 md:py-18 lg:grid-cols-[minmax(0,1fr)_minmax(320px,0.8fr)]">
            <div className="flex flex-col gap-6">
              <div className="flex flex-col gap-3">
                <h2 className="text-foreground text-2xl font-semibold tracking-tight">
                  Gmail and Outlook are the product surface.
                </h2>
                <p className="text-muted-foreground max-w-2xl leading-relaxed">
                  The scanner proves the verdict engine. The add-ins remove the hard
                  part: saving files, finding headers, and leaving the inbox.
                </p>
              </div>
              <div className="grid gap-4">
                <WorkflowStep
                  icon={<Inbox />}
                  title="Inbox add-in"
                  text="Open a suspicious email, click Message Loupe, and see the verdict beside the message."
                />
                <WorkflowStep
                  icon={<MailWarning />}
                  title="Report mailbox"
                  text="Employees can forward questionable mail to a branded address when add-ins are not installed."
                />
                <WorkflowStep
                  icon={<ClipboardCheck />}
                  title="Team dashboard"
                  text="Owners see verdict counts, risky themes, and open follow-ups without storing email contents."
                />
              </div>
            </div>

            <PrivacyModel />
          </div>
        </section>

        <section className="mx-auto grid w-full max-w-5xl gap-8 px-4 py-14 md:grid-cols-[0.8fr_1.2fr] md:px-6 md:py-18">
          <div className="flex flex-col gap-3">
            <h2 className="text-foreground text-2xl font-semibold tracking-tight">
              Pilot pricing hypothesis
            </h2>
            <p className="text-muted-foreground leading-relaxed">
              Keep the public scanner free. Test whether teams will pay for a
              managed workflow before building the full add-in and dashboard product.
            </p>
          </div>
          <div className="divide-border/70 border-border/70 rounded-lg border">
            <PlanRow title="Free" price="$0" text="Public browser scanner for one-off checks." />
            <PlanRow title="Pilot" price="$299/mo" text="Manual suspicious-email intake, setup help, policy templates, and monthly pattern review." />
            <PlanRow title="Roadmap" price="TBD" text="Gmail and Outlook add-ins, verdict metadata history, admin export, and team follow-up states." />
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  )
}

function InboxConsole() {
  return (
    <div className="border-border/70 bg-background/80 rounded-lg border p-4 shadow-sm">
      <div className="flex items-center justify-between border-b border-border/60 pb-3">
        <div className="flex items-center gap-2">
          <MailCheck className="text-primary size-5" aria-hidden />
          <span className="text-sm font-semibold">Suspicious email review</span>
        </div>
        <Badge variant="warning">Caution</Badge>
      </div>
      <div className="grid gap-3 pt-4">
        <ConsoleRow label="From" value="vendor-payments@example-corp.com" />
        <ConsoleRow label="Request" value="Bank details changed before invoice payment" />
        <ConsoleRow label="Authentication" value="Pass, but sender domain differs from known vendor" />
        <ConsoleRow label="Action" value="Verify by known phone number before payment" strong />
      </div>
    </div>
  )
}

function ConsoleRow({
  label,
  value,
  strong,
}: {
  readonly label: string
  readonly value: string
  readonly strong?: boolean
}) {
  return (
    <div className="grid gap-1 rounded-md bg-muted/40 px-3 py-2 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className={strong ? "text-warning font-medium" : "text-foreground"}>{value}</span>
    </div>
  )
}

function Signal({
  icon,
  title,
  text,
}: Readonly<{ icon: ReactNode; title: string; text: string }>) {
  return (
    <div className="border-border/70 rounded-lg border p-4">
      <div className="text-foreground mb-2 flex items-center gap-2 font-semibold">
        <span className="text-primary [&>svg]:size-4" aria-hidden>
          {icon}
        </span>
        {title}
      </div>
      <p className="text-muted-foreground text-sm leading-relaxed">{text}</p>
    </div>
  )
}

function WorkflowStep({
  icon,
  title,
  text,
}: Readonly<{ icon: ReactNode; title: string; text: string }>) {
  return (
    <div className="grid gap-2 border-l border-border/70 pl-4">
      <div className="text-foreground flex items-center gap-2 font-semibold">
        <span className="text-primary [&>svg]:size-4" aria-hidden>
          {icon}
        </span>
        {title}
      </div>
      <p className="text-muted-foreground text-sm leading-relaxed">{text}</p>
    </div>
  )
}

function PrivacyModel() {
  const items = [
    "Email contents stay local in the scanner.",
    "Planned add-ins should request only the message access needed for the opened email.",
    "The planned team dashboard should store verdict metadata, not message bodies.",
  ]

  return (
    <div className="bg-card text-card-foreground rounded-lg border border-border/70 p-4">
      <div className="mb-4 flex items-center gap-2">
        <ShieldCheck className="text-success size-5" aria-hidden />
        <h3 className="font-semibold">Privacy model stays the moat</h3>
      </div>
      <div className="grid gap-3">
        {items.map((item) => (
          <div key={item} className="flex gap-2 text-sm leading-relaxed">
            <CheckCircle2 className="text-success mt-0.5 size-4 shrink-0" aria-hidden />
            <span className="text-muted-foreground">{item}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function PlanRow({
  title,
  price,
  text,
}: Readonly<{ title: string; price: string; text: string }>) {
  return (
    <div className="grid gap-2 p-4 sm:grid-cols-[120px_120px_1fr] sm:items-center">
      <div className="text-foreground font-semibold">{title}</div>
      <div className="font-mono text-sm text-primary">{price}</div>
      <p className="text-muted-foreground text-sm leading-relaxed">{text}</p>
    </div>
  )
}
