import Link from "next/link"
import type { ReactNode } from "react"
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ClipboardCopy,
  Code2,
  Eye,
  LockKeyhole,
  Mail,
  MonitorDown,
  ShieldCheck,
} from "lucide-react"

import { SiteHeader } from "@/components/site-header"
import { SiteFooter } from "@/components/site-footer"
import { Scanner } from "@/components/scanner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"

export default function Home() {
  return (
    <>
      <SiteHeader />
      <main className="flex flex-1 flex-col">
        <section className="mx-auto grid w-full max-w-5xl gap-10 px-4 pt-10 pb-10 md:px-6 md:pt-18 lg:grid-cols-[minmax(0,1fr)_minmax(320px,0.86fr)] lg:items-center">
          <div className="flex flex-col items-start gap-5">
            <Badge variant="outline" className="h-6 gap-1.5 px-2.5">
              <ShieldCheck data-icon="inline-start" />
              Browser-only phishing check
            </Badge>
            <div className="flex flex-col gap-4">
              <h1 className="text-foreground max-w-2xl text-balance text-4xl font-semibold tracking-tight md:text-5xl">
                Is this a fake email?
              </h1>
              <p className="text-muted-foreground max-w-xl text-balance text-base leading-relaxed md:text-lg">
                Drop in the original email or paste its raw headers. Message Loupe
                checks 40+ sender, routing, authentication, and link signals, then gives
                you a plain-English verdict.
              </p>
            </div>
            <div className="flex flex-wrap gap-2 text-sm">
              <TrustPill icon={<LockKeyhole />} text="No upload" />
              <TrustPill icon={<Eye />} text="No tracking" />
              <TrustPill icon={<Code2 />} text="Open source" />
            </div>
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <Button asChild>
                <Link href="#scanner">
                  Scan an email
                  <ArrowRight data-icon="inline-end" />
                </Link>
              </Button>
              <Button asChild variant="ghost">
                <Link href="/how-to-save-an-email">How to save one</Link>
              </Button>
            </div>
          </div>

          <SampleVerdict />
        </section>

        <section className="border-border/60 border-y bg-muted/20">
          <div className="mx-auto grid w-full max-w-5xl gap-5 px-4 py-8 md:grid-cols-[0.9fr_1.1fr] md:px-6 md:py-10">
            <div className="flex flex-col gap-2">
              <h2 className="text-foreground text-2xl font-semibold tracking-tight">
                Start with the original email
              </h2>
              <p className="text-muted-foreground max-w-md leading-relaxed">
                Regular forwarding strips out the evidence. Save the message itself,
                or use the raw-header view if downloading is not available.
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <QuickStep
                icon={<Mail />}
                title="Gmail"
                text="Open the message menu, then choose Download message."
              />
              <QuickStep
                icon={<MonitorDown />}
                title="Outlook"
                text="Use Save as, or copy the Internet headers from the message source."
              />
              <QuickStep
                icon={<ClipboardCopy />}
                title="Headers"
                text="Paste everything from Show original, View source, or View headers."
              />
            </div>
            <div className="md:col-start-2">
              <Button asChild variant="link" className="h-auto px-0">
                <Link href="/how-to-save-an-email">
                  Full Gmail, Outlook, Apple Mail, and phone steps
                  <ArrowRight data-icon="inline-end" />
                </Link>
              </Button>
            </div>
          </div>
        </section>

        <section id="scanner" className="mx-auto flex w-full max-w-3xl scroll-mt-20 flex-col gap-5 px-4 py-12 md:px-6 md:py-16">
          <div className="flex flex-col gap-2">
            <h2 className="text-foreground text-2xl font-semibold tracking-tight">
              Scan the email
            </h2>
            <p className="text-muted-foreground leading-relaxed">
              Your browser reads the file locally. We never receive the email, its
              headers, or the verdict.
            </p>
          </div>
          <Scanner />
        </section>

        <section className="mx-auto grid w-full max-w-5xl gap-4 px-4 pb-16 md:grid-cols-3 md:px-6 md:pb-24">
          <TrustPoint
            icon={<LockKeyhole />}
            title="Private by design"
            text="The parser and verdict logic run in JavaScript on your device. There is no upload step."
          />
          <TrustPoint
            icon={<Eye />}
            title="No analytics"
            text="No cookies, tracking pixels, or third-party reputation calls touch your email data."
          />
          <TrustPoint
            icon={<Code2 />}
            title="Verifiable source"
            text="The methodology and code are public, so the privacy claim can be checked instead of trusted blindly."
          />
        </section>
      </main>
      <SiteFooter />
    </>
  )
}

function SampleVerdict() {
  return (
    <div className="border-border/70 bg-card text-card-foreground rounded-xl border p-4 shadow-sm">
      <div className="flex items-center justify-between gap-3 border-b border-border/60 pb-4">
        <div className="flex items-center gap-2">
          <div className="bg-warning/10 text-warning flex size-9 items-center justify-center rounded-lg">
            <AlertTriangle className="size-5" aria-hidden />
          </div>
          <div>
            <p className="text-sm font-semibold">Caution: verify by phone</p>
            <p className="text-muted-foreground text-xs">Sample result</p>
          </div>
        </div>
        <Badge variant="warning">Money request</Badge>
      </div>

      <div className="flex flex-col gap-4 pt-4">
        <p className="text-muted-foreground text-sm leading-relaxed">
          The sender authentication passes, but the message asks for a wire transfer.
          Message Loupe will not call that safe just because the headers look clean.
        </p>
        <div className="grid gap-2">
          <SignalRow label="SPF / DKIM / DMARC" value="Pass" tone="safe" />
          <SignalRow label="Sender alignment" value="Aligned" tone="safe" />
          <SignalRow label="Link mismatch" value="None found" tone="safe" />
          <SignalRow label="Money or credentials" value="Verify manually" tone="warn" />
        </div>
      </div>
    </div>
  )
}

function SignalRow({
  label,
  value,
  tone,
}: {
  label: string
  value: string
  tone: "safe" | "warn"
}) {
  return (
    <div className="bg-muted/45 flex items-center justify-between gap-3 rounded-lg px-3 py-2 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-foreground inline-flex items-center gap-1.5 font-medium">
        {tone === "safe" ? (
          <CheckCircle2 className="text-success size-4" aria-hidden />
        ) : (
          <AlertTriangle className="text-warning size-4" aria-hidden />
        )}
        {value}
      </span>
    </div>
  )
}

function TrustPill({ icon, text }: { icon: ReactNode; text: string }) {
  return (
    <span className="border-border bg-background/70 text-muted-foreground inline-flex items-center gap-1.5 rounded-full border px-3 py-1">
      <span className="[&>svg]:size-3.5" aria-hidden>
        {icon}
      </span>
      {text}
    </span>
  )
}

function QuickStep({
  icon,
  title,
  text,
}: {
  icon: ReactNode
  title: string
  text: string
}) {
  return (
    <div className="border-border/70 bg-background/70 rounded-lg border p-3">
      <div className="text-foreground mb-2 flex items-center gap-2 text-sm font-semibold">
        <span className="text-primary [&>svg]:size-4" aria-hidden>
          {icon}
        </span>
        {title}
      </div>
      <p className="text-muted-foreground text-sm leading-relaxed">{text}</p>
    </div>
  )
}

function TrustPoint({
  icon,
  title,
  text,
}: {
  icon: ReactNode
  title: string
  text: string
}) {
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
