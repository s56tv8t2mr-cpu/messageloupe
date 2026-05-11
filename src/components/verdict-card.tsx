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
import {
  authResultStatus,
  sameRegistrable,
  type Analysis,
  type AuthStatus,
  type LinkFlag,
  type VerdictTier,
} from "@/lib/email"

type ChipStatus = AuthStatus

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

// Chip presentation buckets a subset of high-risk flags as "fail" and
// medium-risk as "warn". This is intentionally less aggressive than the
// verdict engine's HIGH_RISK_LINK_FLAGS — for the chip we want a glance-
// readable status, not the full escalation rule.
const FAIL_LINK_FLAGS: readonly LinkFlag[] = ["mismatch", "ipHost", "punycode"]
const WARN_LINK_FLAGS: readonly LinkFlag[] = ["cmTld", "shortener"]

const REASON_DOT_COLOR = {
  high: "text-destructive",
  medium: "text-warning",
  low: "text-muted-foreground",
} as const

interface VerdictCardProps {
  analysis: Analysis
}

export function VerdictCard({ analysis }: VerdictCardProps) {
  const { verdict, content } = analysis
  const meta = TIER_META[verdict.tier]
  const TierIcon = meta.Icon

  const chips = React.useMemo(() => computeChips(analysis), [analysis])

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
              "inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold tracking-wide uppercase ring-1 ring-inset",
              meta.pill,
            )}
          >
            <TierIcon className="size-4" aria-hidden />
            {meta.label}
          </span>
          {verdict.capped ? (
            <span className="text-muted-foreground text-xs font-medium tracking-wide uppercase">
              Capped: verify by phone
            </span>
          ) : null}
        </div>

        <h2
          id="verdict-headline"
          className="text-foreground mt-3 text-2xl font-semibold tracking-tight sm:text-3xl"
        >
          {verdict.headline}
        </h2>

        <p className="text-foreground/80 mt-2.5 text-base leading-relaxed sm:text-[17px]">
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
          welcome. Real cold outreach and marketing pass these checks too, so Message
          Loupe answers &quot;is the sender who they claim to be?&quot;, not &quot;is
          this email wanted?&quot;
        </p>
      ) : null}

      {verdict.tier === "caution" && verdict.capped ? (
        <Alert variant="warning" className="bg-warning/[0.06] border-warning/30">
          <PhoneCall aria-hidden />
          <AlertTitle className="text-sm">Verify by phone before acting</AlertTitle>
          <AlertDescription>
            Use a number you already trust: your saved contact, your bank&apos;s
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
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-muted-foreground text-sm">Detected in this message:</span>
          {content.hasMoney ? <Badge variant="warning">Money / banking</Badge> : null}
          {content.hasCredentials ? <Badge variant="warning">Credentials / login</Badge> : null}
          {content.hasJobOffer ? <Badge variant="warning">Job offer</Badge> : null}
          {content.hasDocumentRequest ? <Badge variant="warning">Documents requested</Badge> : null}
          {content.hasUrgency ? <Badge variant="outline">Urgency language</Badge> : null}
        </div>
      )}

      {verdict.reasons.length > 0 ? (
        <div className="text-muted-foreground border-border/60 mt-1 rounded-lg border p-4">
          <p className="text-foreground mb-2.5 text-sm font-medium">Why we said that:</p>
          <ul className="space-y-2 text-sm">
            {verdict.reasons.map((r) => (
              <li key={r.signal} className="flex gap-2.5 leading-relaxed">
                <span
                  aria-hidden
                  className={cn(
                    "mt-[7px] size-2 shrink-0 rounded-full bg-current",
                    REASON_DOT_COLOR[r.weight],
                  )}
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
      className="bg-background/60 border-border/60 flex items-center gap-2.5 rounded-lg border px-3 py-2.5"
      title={detail}
    >
      <Icon className="text-muted-foreground size-4 shrink-0" aria-hidden />
      <div className="flex min-w-0 flex-col leading-tight">
        <span className="text-muted-foreground text-[11px] font-medium tracking-wide uppercase">
          {label}
        </span>
        <span className="text-foreground/90 mt-0.5 truncate text-sm font-medium">
          {detail}
        </span>
      </div>
      <StatusIcon className={cn("ml-auto size-[18px] shrink-0", m.cls)} aria-hidden />
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
  const auth = computeAuthChip(a)
  const sender = computeSenderChip(a)
  const routing = computeRoutingChip(a)
  const links = computeLinksChip(a)

  return {
    auth: auth.status,
    authDetail: auth.detail,
    sender: sender.status,
    senderDetail: sender.detail,
    routing: routing.status,
    routingDetail: routing.detail,
    links: links.status,
    linksDetail: links.detail,
  }
}

interface ChipResult {
  status: ChipStatus
  detail: string
}

function computeAuthChip({ parser }: Analysis): ChipResult {
  const statuses = [parser.spfResult, parser.dkimResult, parser.dmarcResult].map(
    authResultStatus,
  )
  const status = worstStatus(statuses)
  const detail =
    status === "ok"
      ? "SPF, DKIM, DMARC pass"
      : status === "fail"
        ? "Authentication failed"
        : status === "warn"
          ? "Partial / soft failures"
          : "No auth headers"
  return { status, detail }
}

// Sender-chip rules in priority order — first match wins. Reads as data,
// not branching control flow, so adding a new rule is one entry.
type SenderRule = {
  match: (a: Analysis) => ChipResult | null
}

const SENDER_RULES: SenderRule[] = [
  {
    match: ({ parser }) =>
      parser.spoofingLikely ? { status: "fail", detail: "Looks spoofed" } : null,
  },
  {
    match: ({ trust }) =>
      trust.brandImpersonation
        ? { status: "fail", detail: `Impersonates ${trust.brandImpersonation.brand}` }
        : null,
  },
  {
    match: ({ trust }) =>
      trust.roleImpersonation && trust.domainHasTyposquatShape
        ? { status: "fail", detail: "Role + lookalike domain" }
        : null,
  },
  {
    match: ({ trust }) =>
      trust.roleImpersonation && trust.fromPublicWebmail
        ? { status: "fail", detail: "Role from webmail" }
        : null,
  },
  {
    match: ({ trust }) =>
      trust.roleImpersonation
        ? { status: "warn", detail: "Role display name" }
        : null,
  },
  {
    match: ({ replyTo }) =>
      replyTo.assessment === "strong"
        ? { status: "fail", detail: "Reply-To impersonation" }
        : null,
  },
  {
    match: ({ replyTo }) =>
      replyTo.assessment === "mismatch"
        ? { status: "fail", detail: "Reply-To differs" }
        : null,
  },
  {
    match: ({ parser }) => {
      const cross =
        parser.returnPathDomain &&
        parser.sendingDomain &&
        !sameRegistrable(parser.returnPathDomain, parser.sendingDomain) &&
        !parser.serviceIdentified
      return cross ? { status: "warn", detail: "Return-Path differs" } : null
    },
  },
]

function computeSenderChip(a: Analysis): ChipResult {
  for (const rule of SENDER_RULES) {
    const hit = rule.match(a)
    if (hit) return hit
  }
  if (a.parser.serviceIdentified) {
    return { status: "ok", detail: `Sent via ${a.parser.sendingService}` }
  }
  return { status: "ok", detail: "Aligned" }
}

function computeRoutingChip({ parser }: Analysis): ChipResult {
  if (!parser.sourceIp) {
    return { status: "warn", detail: "No source IP" }
  }
  return {
    status: "ok",
    detail: parser.sourceHostname || parser.sourceIp,
  }
}

function computeLinksChip({ links, parser }: Analysis): ChipResult {
  if (links.length === 0) {
    if (!parser.bodyText) return { status: "unknown", detail: "Headers only" }
    return { status: "ok", detail: "No links" }
  }

  let hasFail = false
  let hasWarn = false
  for (const l of links) {
    for (const f of l.flags) {
      if (FAIL_LINK_FLAGS.includes(f)) hasFail = true
      else if (WARN_LINK_FLAGS.includes(f)) hasWarn = true
    }
  }

  if (hasFail) return { status: "fail", detail: "Suspicious links" }
  if (hasWarn) return { status: "warn", detail: "Watch links" }
  return { status: "ok", detail: `${links.length} link${links.length === 1 ? "" : "s"}, clean` }
}

function worstStatus(s: ChipStatus[]): ChipStatus {
  if (s.includes("fail")) return "fail"
  if (s.includes("warn")) return "warn"
  if (s.includes("unknown")) return "warn"
  return "ok"
}
