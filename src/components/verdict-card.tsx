"use client"

import * as React from "react"
import { motion } from "motion/react"
import {
  ShieldCheck,
  TriangleAlert,
  ShieldAlert,
  MailQuestion,
  PhoneCall,
  KeyRound,
  User,
  Network,
  Link2,
  CircleCheck,
  CircleAlert,
  CircleX,
} from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import type {
  Verdict,
  VerdictTier,
  ContentClassification,
  Analysis,
} from "@/lib/email"

type ChipStatus = "ok" | "warn" | "fail" | "unknown"

const TIER_META: Record<
  VerdictTier,
  {
    label: string
    Icon: React.ComponentType<{ className?: string }>
    pill: string
    panel: string
    accent: string
  }
> = {
  safe: {
    label: "Safe",
    Icon: ShieldCheck,
    pill: "bg-success/10 text-success ring-success/25",
    panel: "border-success/25 bg-success/[0.03]",
    accent: "text-success",
  },
  caution: {
    label: "Caution",
    Icon: TriangleAlert,
    pill: "bg-warning/15 text-warning-foreground ring-warning/40",
    panel: "border-warning/35 bg-warning/[0.05]",
    accent: "text-warning",
  },
  danger: {
    label: "Likely fake",
    Icon: ShieldAlert,
    pill: "bg-destructive/10 text-destructive ring-destructive/30",
    panel: "border-destructive/30 bg-destructive/[0.04]",
    accent: "text-destructive",
  },
  forwarded: {
    label: "Can't verdict",
    Icon: MailQuestion,
    pill: "bg-warning/15 text-warning-foreground ring-warning/40",
    panel: "border-warning/35 bg-warning/[0.05]",
    accent: "text-warning",
  },
}

const CHIP_META: Record<
  ChipStatus,
  { Icon: React.ComponentType<{ className?: string }>; cls: string }
> = {
  ok: { Icon: CircleCheck, cls: "text-success" },
  warn: { Icon: CircleAlert, cls: "text-warning" },
  fail: { Icon: CircleX, cls: "text-destructive" },
  unknown: { Icon: CircleAlert, cls: "text-muted-foreground" },
}

interface VerdictCardProps {
  verdict: Verdict
  content: ContentClassification
  analysis: Analysis
}

export function VerdictCard({ verdict, content, analysis }: VerdictCardProps) {
  const meta = TIER_META[verdict.tier]
  const TierIcon = meta.Icon

  const chips = computeChips(analysis)

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, ease: [0.2, 0.8, 0.2, 1] }}
      className="flex flex-col gap-3"
    >
      <section
        className={cn(
          "rounded-xl border p-5 sm:p-6 shadow-sm/2",
          meta.panel,
        )}
        aria-labelledby="verdict-headline"
      >
        <div className="flex items-center justify-between gap-3">
          <span
            className={cn(
              "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold tracking-wide uppercase ring-1 ring-inset",
              meta.pill,
            )}
          >
            <TierIcon className="size-3.5" aria-hidden />
            {meta.label}
          </span>
          {verdict.capped ? (
            <span className="text-muted-foreground text-[11px] font-medium tracking-wide uppercase">
              Capped — verify by phone
            </span>
          ) : null}
        </div>

        <h2
          id="verdict-headline"
          className="text-foreground mt-3 text-xl font-semibold tracking-tight sm:text-2xl"
        >
          {verdict.headline}
        </h2>

        <p className="text-foreground/75 mt-2 text-sm leading-relaxed sm:text-[15px]">
          {verdict.explanation}
        </p>

        <div
          className="border-border/60 mt-4 grid grid-cols-2 gap-2 border-t pt-4 sm:grid-cols-4"
          role="list"
          aria-label="Signal summary"
        >
          <SignalChip
            label="Authentication"
            Icon={KeyRound}
            status={chips.auth}
            detail={chips.authDetail}
          />
          <SignalChip
            label="Sender"
            Icon={User}
            status={chips.sender}
            detail={chips.senderDetail}
          />
          <SignalChip
            label="Routing"
            Icon={Network}
            status={chips.routing}
            detail={chips.routingDetail}
          />
          <SignalChip
            label="Links"
            Icon={Link2}
            status={chips.links}
            detail={chips.linksDetail}
          />
        </div>
      </section>

      {verdict.tier === "safe" ? (
        <p className="text-muted-foreground -mt-1 px-1 text-xs leading-relaxed">
          Safe means <strong className="text-foreground/80">authentic</strong>, not
          welcome. Real cold outreach and marketing pass these checks too — Message
          Loupe answers &quot;is the sender who they claim to be?&quot;, not &quot;is
          this email wanted?&quot;
        </p>
      ) : null}

      {verdict.tier === "caution" && verdict.capped ? (
        <Alert variant="warning" className="bg-warning/[0.06] border-warning/30">
          <PhoneCall aria-hidden />
          <AlertTitle className="text-sm">Verify by phone before acting</AlertTitle>
          <AlertDescription>
            Use a number you already trust — your saved contact, your bank&apos;s
            number on the back of your card, or your accountant&apos;s known line.
            Never call a number from this email.
          </AlertDescription>
        </Alert>
      ) : null}

      {(content.hasMoney ||
        content.hasCredentials ||
        content.hasUrgency ||
        content.hasJobOffer ||
        content.hasDocumentRequest) && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-muted-foreground text-xs">Detected in this message:</span>
          {content.hasMoney ? <Badge variant="warning">Money / banking</Badge> : null}
          {content.hasCredentials ? <Badge variant="warning">Credentials / login</Badge> : null}
          {content.hasJobOffer ? <Badge variant="warning">Job offer</Badge> : null}
          {content.hasDocumentRequest ? <Badge variant="warning">Documents requested</Badge> : null}
          {content.hasUrgency ? <Badge variant="outline">Urgency language</Badge> : null}
        </div>
      )}

      {verdict.reasons.length > 0 ? (
        <div className="text-muted-foreground border-border/60 mt-1 rounded-lg border p-3">
          <p className="text-foreground mb-2 text-xs font-medium">Why we said that:</p>
          <ul className="space-y-1.5 text-xs">
            {verdict.reasons.map((r) => (
              <li key={r.signal} className="flex gap-2 leading-relaxed">
                <span
                  aria-hidden
                  className={
                    r.weight === "high"
                      ? "text-destructive mt-1.5 size-1.5 shrink-0 rounded-full bg-current"
                      : r.weight === "medium"
                        ? "text-warning mt-1.5 size-1.5 shrink-0 rounded-full bg-current"
                        : "text-muted-foreground mt-1.5 size-1.5 shrink-0 rounded-full bg-current"
                  }
                />
                <span>{r.detail}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </motion.div>
  )
}

function SignalChip({
  label,
  Icon,
  status,
  detail,
}: {
  label: string
  Icon: React.ComponentType<{ className?: string }>
  status: ChipStatus
  detail: string
}) {
  const m = CHIP_META[status]
  const StatusIcon = m.Icon
  return (
    <div
      role="listitem"
      className="bg-background/60 border-border/60 flex items-center gap-2.5 rounded-lg border px-3 py-2"
      title={detail}
    >
      <Icon className="text-muted-foreground size-4 shrink-0" aria-hidden />
      <div className="flex min-w-0 flex-col leading-tight">
        <span className="text-muted-foreground text-[10px] font-medium tracking-wide uppercase">
          {label}
        </span>
        <span className="text-foreground/90 truncate text-xs font-medium">
          {detail}
        </span>
      </div>
      <StatusIcon className={cn("ml-auto size-4 shrink-0", m.cls)} aria-hidden />
    </div>
  )
}

interface ChipState {
  auth: ChipStatus
  authDetail: string
  sender: ChipStatus
  senderDetail: string
  routing: ChipStatus
  routingDetail: string
  links: ChipStatus
  linksDetail: string
}

function computeChips(a: Analysis): ChipState {
  const { parser, links, trust } = a

  // Authentication: worst of SPF / DKIM / DMARC
  const authResults = [parser.spfResult, parser.dkimResult, parser.dmarcResult]
  const authStatuses = authResults.map(authToStatus)
  const authStatus = worst(authStatuses)
  const authDetail =
    authStatus === "ok"
      ? "SPF, DKIM, DMARC pass"
      : authStatus === "fail"
        ? "Authentication failed"
        : authStatus === "warn"
          ? "Partial / soft failures"
          : "No auth headers"

  // Sender: spoofing, role/brand impersonation, return-path or reply-to drift
  let senderStatus: ChipStatus = "ok"
  let senderDetail = "Aligned"
  if (parser.spoofingLikely) {
    senderStatus = "fail"
    senderDetail = "Looks spoofed"
  } else if (trust.brandImpersonation) {
    senderStatus = "fail"
    senderDetail = `Impersonates ${trust.brandImpersonation.brand}`
  } else if (trust.roleImpersonation && trust.domainHasTyposquatShape) {
    senderStatus = "fail"
    senderDetail = "Role + lookalike domain"
  } else if (trust.roleImpersonation && trust.fromPublicWebmail) {
    senderStatus = "fail"
    senderDetail = "Role from webmail"
  } else if (trust.roleImpersonation) {
    senderStatus = "warn"
    senderDetail = "Role display name"
  } else if (
    parser.replyToDomain &&
    parser.sendingDomain &&
    !sameRegistrable(parser.replyToDomain, parser.sendingDomain) &&
    !parser.listId
  ) {
    senderStatus = "warn"
    senderDetail = "Reply-To differs"
  } else if (
    parser.returnPathDomain &&
    parser.sendingDomain &&
    !sameRegistrable(parser.returnPathDomain, parser.sendingDomain) &&
    !parser.serviceIdentified
  ) {
    senderStatus = "warn"
    senderDetail = "Return-Path differs"
  } else if (parser.serviceIdentified) {
    senderDetail = `Sent via ${parser.sendingService}`
  }

  // Routing: source IP found?
  let routingStatus: ChipStatus = "ok"
  let routingDetail = parser.sourceHostname || parser.sourceIp || "Identified"
  if (!parser.sourceIp) {
    routingStatus = "warn"
    routingDetail = "No source IP"
  } else if (parser.sourceHostname) {
    routingDetail = parser.sourceHostname
  }

  // Links: worst flag across all links
  let linksStatus: ChipStatus = "ok"
  let linksDetail = links.length === 0 ? "No links" : `${links.length} clean`
  if (links.length > 0) {
    let hasHigh = false
    let hasMed = false
    for (const l of links) {
      for (const f of l.flags) {
        if (f === "mismatch" || f === "ipHost" || f === "punycode") hasHigh = true
        else if (f === "cmTld" || f === "shortener") hasMed = true
      }
    }
    if (hasHigh) {
      linksStatus = "fail"
      linksDetail = "Suspicious links"
    } else if (hasMed) {
      linksStatus = "warn"
      linksDetail = "Watch links"
    } else {
      linksDetail = `${links.length} link${links.length === 1 ? "" : "s"}, clean`
    }
  } else if (!parser.bodyText) {
    linksStatus = "unknown"
    linksDetail = "Headers only"
  }

  return {
    auth: authStatus,
    authDetail,
    sender: senderStatus,
    senderDetail,
    routing: routingStatus,
    routingDetail,
    links: linksStatus,
    linksDetail,
  }
}

function authToStatus(v: string | null): ChipStatus {
  if (!v) return "unknown"
  const lower = v.toLowerCase()
  if (lower === "pass") return "ok"
  if (lower === "fail" || lower === "permerror") return "fail"
  if (
    lower === "softfail" ||
    lower === "neutral" ||
    lower === "temperror" ||
    lower === "none"
  )
    return "warn"
  return "unknown"
}

function worst(s: ChipStatus[]): ChipStatus {
  if (s.includes("fail")) return "fail"
  if (s.includes("warn")) return "warn"
  if (s.includes("unknown")) return "warn"
  return "ok"
}

const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk",
  "com.au",
  "com.co",
  "co.nz",
  "co.za",
  "co.jp",
  "com.br",
  "com.mx",
  "com.sg",
])

function sameRegistrable(a: string, b: string): boolean {
  return registrable(a) === registrable(b)
}

function registrable(domain: string): string {
  const d = domain.toLowerCase().replace(/\.$/, "")
  const parts = d.split(".")
  if (parts.length <= 2) return d
  const last2 = parts.slice(-2).join(".")
  const last3 = parts.slice(-3).join(".")
  if (MULTI_LABEL_SUFFIXES.has(last2)) return last3
  return last2
}
