"use client"

import * as React from "react"
import {
  ShieldCheck,
  User,
  Network,
  Link2,
  CircleCheck,
  CircleX,
  CircleHelp,
  Info,
  Paperclip,
} from "lucide-react"

import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  FLAG_LABELS,
  authResultStatus,
  type Analysis,
  type LinkFlag,
} from "@/lib/email"

const FLAG_VARIANT: Record<LinkFlag, "destructive" | "warning" | "outline"> = {
  mismatch: "destructive",
  ipHost: "destructive",
  punycode: "destructive",
  cmTld: "warning",
  shortener: "warning",
  thirdParty: "outline",
}

interface UnderTheHoodProps {
  analysis: Analysis
}

export function UnderTheHood({ analysis }: UnderTheHoodProps) {
  const { parser, links, attachments } = analysis
  const hasLinks = links.length > 0

  return (
    <Accordion type="multiple" className="w-full">
      <AccordionItem value="auth">
        <AccordionTrigger className="gap-3">
          <span className="flex items-center gap-2.5">
            <ShieldCheck className="text-muted-foreground size-4" aria-hidden />
            Authentication
          </span>
        </AccordionTrigger>
        <AccordionContent className="flex flex-col gap-4 pt-2">
          <div className="flex flex-wrap items-center gap-2">
            <AuthBadge label="SPF" result={parser.spfResult} />
            <AuthBadge label="DKIM" result={parser.dkimResult} />
            <AuthBadge label="DMARC" result={parser.dmarcResult} />
          </div>
          <p className="text-muted-foreground text-sm leading-relaxed">
            {parser.senderDomainNote}
          </p>
        </AccordionContent>
      </AccordionItem>

      <AccordionItem value="sender">
        <AccordionTrigger className="gap-3">
          <span className="flex items-center gap-2.5">
            <User className="text-muted-foreground size-4" aria-hidden />
            Sender
          </span>
        </AccordionTrigger>
        <AccordionContent className="flex flex-col gap-3 pt-2 text-sm">
          <Field
            label="Display name"
            value={
              parser.sendingName && parser.sendingName !== parser.sendingEmail && parser.sendingName.toLowerCase() !== "unknown"
                ? parser.sendingName
                : null
            }
            fallback="(none — only an address)"
          />
          <Field label="Actual sender" value={parser.sendingEmail} mono />
          <Field
            label="Reply-To"
            value={parser.replyTo}
            fallback="(none — replies go to sender)"
            mono
          />
          <Field label="Return-Path" value={parser.returnPath} mono />
          <Field label="Sending domain" value={parser.sendingDomain} mono />
          <Field label="Sent via" value={parser.serviceIdentified ? parser.sendingService : null} fallback="No clear email service identified" />
        </AccordionContent>
      </AccordionItem>

      {attachments.length > 0 ? (
        <AccordionItem value="attachments">
          <AccordionTrigger className="gap-3">
            <span className="flex items-center gap-2.5">
              <Paperclip className="text-muted-foreground size-4" aria-hidden />
              Attachments{" "}
              <Badge variant="outline" className="ml-1">
                {attachments.length}
              </Badge>
            </span>
          </AccordionTrigger>
          <AccordionContent className="flex flex-col gap-2 pt-2 text-sm">
            <p className="text-muted-foreground text-xs leading-relaxed">
              We don&apos;t open or scan attachment contents — only the names and types
              are shown. Don&apos;t open an attachment from a message you can&apos;t verify.
            </p>
            <ul className="flex flex-col gap-1.5">
              {attachments.map((a, i) => (
                <li
                  key={`${a.filename}-${i}`}
                  className="border-border/60 flex items-center justify-between gap-3 rounded-md border p-2.5"
                >
                  <span className="font-mono text-xs break-all">{a.filename}</span>
                  <Badge variant="outline" className="shrink-0 font-mono">
                    {a.contentType}
                  </Badge>
                </li>
              ))}
            </ul>
          </AccordionContent>
        </AccordionItem>
      ) : null}

      <AccordionItem value="routing">
        <AccordionTrigger className="gap-3">
          <span className="flex items-center gap-2.5">
            <Network className="text-muted-foreground size-4" aria-hidden />
            Routing
          </span>
        </AccordionTrigger>
        <AccordionContent className="flex flex-col gap-4 pt-2 text-sm">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Source IP" value={parser.sourceIp} mono />
            <Field label="Source hostname" value={parser.sourceHostname} mono />
          </div>
          {parser.sourceIpEvidence ? (
            <p className="text-muted-foreground flex items-start gap-2 text-xs leading-relaxed">
              <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
              {parser.sourceIpEvidence}
            </p>
          ) : null}

          {parser.receivedChain.length > 0 ? (
            <>
              <Separator />
              <div className="flex flex-col gap-2">
                <p className="text-foreground text-xs font-medium">
                  Received chain ({parser.receivedChain.length} hop
                  {parser.receivedChain.length === 1 ? "" : "s"})
                </p>
                <ol className="flex flex-col gap-1.5">
                  {parser.receivedChain.map((hop) => (
                    <li
                      key={hop.hop}
                      className={
                        hop.selected
                          ? "border-primary/50 bg-primary/[0.04] rounded-md border p-2"
                          : "rounded-md p-2"
                      }
                    >
                      <div className="flex items-baseline gap-2">
                        <Badge
                          variant={hop.selected ? "default" : "outline"}
                          className="shrink-0"
                        >
                          hop {hop.hop}
                        </Badge>
                        <code className="text-muted-foreground font-mono text-[11px] leading-relaxed break-all whitespace-pre-wrap">
                          {hop.header}
                        </code>
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            </>
          ) : null}

          {parser.relayIndicators.length > 0 ? (
            <>
              <Separator />
              <div className="flex flex-col gap-2">
                <p className="text-foreground text-xs font-medium">Relay notes</p>
                <ul className="text-muted-foreground space-y-1.5 text-xs">
                  {parser.relayIndicators.map((ri) => (
                    <li key={ri.label} className="leading-relaxed">
                      <span className="text-foreground font-medium">{ri.label}.</span>{" "}
                      {ri.detail}
                    </li>
                  ))}
                </ul>
              </div>
            </>
          ) : null}
        </AccordionContent>
      </AccordionItem>

      <AccordionItem value="links">
        <AccordionTrigger className="gap-3">
          <span className="flex items-center gap-2.5">
            <Link2 className="text-muted-foreground size-4" aria-hidden />
            Links{" "}
            <Badge variant="outline" className="ml-1">
              {links.length}
            </Badge>
          </span>
        </AccordionTrigger>
        <AccordionContent className="pt-2">
          {hasLinks ? (
            <div className="overflow-hidden rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-1/2">Link</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead className="text-right">Flags</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {links.map((link) => (
                    <TableRow key={link.url}>
                      <TableCell className="max-w-0 align-top">
                        <div className="flex flex-col gap-1">
                          <a
                            href="#"
                            onClick={(e) => e.preventDefault()}
                            className="text-foreground/90 truncate font-mono text-xs"
                            title={link.url}
                          >
                            {link.url}
                          </a>
                          {link.displayText && link.displayText !== link.url ? (
                            <span className="text-muted-foreground truncate text-xs">
                              shown as: {link.displayText}
                            </span>
                          ) : null}
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground align-top font-mono text-xs">
                        {link.host}
                      </TableCell>
                      <TableCell className="align-top text-right">
                        <div className="inline-flex flex-wrap justify-end gap-1">
                          {link.flags.length === 0 ? (
                            <span className="text-muted-foreground text-xs">—</span>
                          ) : (
                            link.flags.map((flag) => (
                              <Badge key={flag} variant={FLAG_VARIANT[flag]}>
                                {FLAG_LABELS[flag]?.text ?? flag}
                              </Badge>
                            ))
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">
              {parser.bodyText
                ? "No links found in the message body."
                : "Links can't be analyzed in headers-only mode. Upload the original .eml file to include link analysis."}
            </p>
          )}
        </AccordionContent>
      </AccordionItem>
    </Accordion>
  )
}

const AUTH_BADGE_META: Record<
  ReturnType<typeof authResultStatus>,
  { Icon: typeof CircleHelp; variant: "success" | "warning" | "destructive" | "outline" }
> = {
  ok: { Icon: CircleCheck, variant: "success" },
  fail: { Icon: CircleX, variant: "destructive" },
  warn: { Icon: CircleHelp, variant: "warning" },
  unknown: { Icon: CircleHelp, variant: "outline" },
}

function AuthBadge({ label, result }: { label: string; result: string | null }) {
  const value = result ?? "unknown"
  // "present" is an engine-only signal meaning a DKIM-Signature header
  // exists but the verifier never reported a result — neutral, not warning.
  const status = value.toLowerCase() === "present" ? "unknown" : authResultStatus(value)
  const { Icon, variant } = AUTH_BADGE_META[status]
  const DisplayIcon = value.toLowerCase() === "present" ? Info : Icon

  return (
    <Badge variant={variant} className="gap-1">
      <DisplayIcon aria-hidden />
      <span className="font-mono">{label}</span>
      <span className="text-muted-foreground/80 font-mono lowercase">: {value}</span>
    </Badge>
  )
}

function Field({
  label,
  value,
  muted,
  fallback = "—",
  mono,
}: {
  label: string
  value: string | null | undefined
  muted?: string | null
  fallback?: string
  mono?: boolean
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-muted-foreground text-xs">{label}</span>
      {value ? (
        <span className={mono ? "font-mono text-sm break-all" : "text-sm break-all"}>
          {value}
          {muted ? (
            <span className="text-muted-foreground ml-2 text-xs">({muted})</span>
          ) : null}
        </span>
      ) : (
        <span className="text-muted-foreground text-sm">{fallback}</span>
      )}
    </div>
  )
}
