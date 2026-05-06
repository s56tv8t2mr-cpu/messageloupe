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
import { FLAG_LABELS, type Analysis, type LinkFlag } from "@/lib/email"

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
  const { parser, links } = analysis
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
          <Field label="From" value={parser.sendingEmail} muted={parser.sendingName} />
          <Field label="Return-Path" value={parser.returnPath} />
          <Field label="Sending domain" value={parser.sendingDomain} />
          <Field label="Sent via" value={parser.serviceIdentified ? parser.sendingService : null} fallback="No clear email service identified" />
        </AccordionContent>
      </AccordionItem>

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

function AuthBadge({ label, result }: { label: string; result: string | null }) {
  const value = result ?? "unknown"
  const lower = value.toLowerCase()

  let Icon = CircleHelp
  let variant: "success" | "warning" | "destructive" | "outline" = "outline"

  if (lower === "pass") {
    Icon = CircleCheck
    variant = "success"
  } else if (lower === "fail" || lower === "permerror") {
    Icon = CircleX
    variant = "destructive"
  } else if (lower === "softfail" || lower === "neutral" || lower === "temperror") {
    Icon = CircleHelp
    variant = "warning"
  } else if (lower === "present") {
    Icon = Info
    variant = "outline"
  }

  return (
    <Badge variant={variant} className="gap-1">
      <Icon aria-hidden />
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
