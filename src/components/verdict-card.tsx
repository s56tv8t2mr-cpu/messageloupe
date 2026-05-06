"use client"

import * as React from "react"
import { motion } from "motion/react"
import {
  ShieldCheck,
  TriangleAlert,
  ShieldAlert,
  MailQuestion,
  PhoneCall,
} from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import type { Verdict, VerdictTier, ContentClassification } from "@/lib/email"

const VARIANT_FOR_TIER: Record<VerdictTier, "success" | "warning" | "destructive" | "default"> = {
  safe: "success",
  caution: "warning",
  danger: "destructive",
  forwarded: "warning",
}

const ICON_FOR_TIER: Record<VerdictTier, React.ComponentType<{ className?: string }>> = {
  safe: ShieldCheck,
  caution: TriangleAlert,
  danger: ShieldAlert,
  forwarded: MailQuestion,
}

interface VerdictCardProps {
  verdict: Verdict
  content: ContentClassification
}

export function VerdictCard({ verdict, content }: VerdictCardProps) {
  const variant = VARIANT_FOR_TIER[verdict.tier]
  const Icon = ICON_FOR_TIER[verdict.tier]

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: [0.2, 0.8, 0.2, 1] }}
      className="flex flex-col gap-3"
    >
      <Alert variant={variant} className="px-4 py-3.5 [&>svg]:size-5">
        <Icon aria-hidden />
        <AlertTitle className="text-base font-semibold tracking-tight">
          {verdict.headline}
        </AlertTitle>
        <AlertDescription className="leading-relaxed">
          {verdict.explanation}
        </AlertDescription>
      </Alert>

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
