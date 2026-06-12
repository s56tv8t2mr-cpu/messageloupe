import type { Analysis, VerdictTier } from "@/lib/email/types"

export type TeamReportChannel =
  | "web-scanner"
  | "gmail-add-on"
  | "outlook-add-in"
  | "forwarded-mailbox"

export interface TeamReportMetadataInput {
  channel: TeamReportChannel
  reportId?: string
  reporterId?: string
  organizationId?: string
  createdAt?: Date
}

export interface TeamReportMetadata {
  schemaVersion: 1
  reportId: string
  createdAt: string
  channel: TeamReportChannel
  reporterId: string | null
  organizationId: string | null
  verdictTier: VerdictTier
  verdictHeadline: string
  verdictCapped: boolean
  reasonSignals: string[]
  senderDomain: string | null
  sendingService: string | null
  auth: {
    spf: string | null
    dkim: string | null
    dmarc: string | null
  }
  riskFlags: {
    hasMoneyLanguage: boolean
    hasCredentialLanguage: boolean
    hasUrgencyLanguage: boolean
    hasDocumentRequest: boolean
    hasSubscriptionRefundScam: boolean
    hasWireTransferLure: boolean
    hasOpaqueEncryptedBody: boolean
    hasTransactionNoticeLure: boolean
    linkCount: number
    suspiciousLinkCount: number
    attachmentCount: number
  }
  linkHosts: string[]
  mxProvider: string | null
}

const FORBIDDEN_FIELD_NAMES = new Set([
  "allHeaders",
  "body",
  "bodyHtml",
  "bodyText",
  "displayText",
  "headers",
  "messageId",
  "raw",
  "replyTo",
  "returnPath",
  "sendingEmail",
  "subject",
  "url",
])

const URL_PATTERN = /\bhttps?:\/\//i

export function createTeamReportMetadata(
  analysis: Analysis,
  input: TeamReportMetadataInput,
): TeamReportMetadata {
  const linkHosts = Array.from(
    new Set(analysis.links.map((link) => normalizeHost(link.host)).filter(isPresent)),
  ).slice(0, 20)

  const metadata: TeamReportMetadata = {
    schemaVersion: 1,
    reportId: input.reportId ?? crypto.randomUUID(),
    createdAt: (input.createdAt ?? new Date()).toISOString(),
    channel: input.channel,
    reporterId: input.reporterId ?? null,
    organizationId: input.organizationId ?? null,
    verdictTier: analysis.verdict.tier,
    verdictHeadline: analysis.verdict.headline,
    verdictCapped: analysis.verdict.capped,
    reasonSignals: analysis.verdict.reasons.map((reason) => reason.signal),
    senderDomain: normalizeHost(analysis.parser.sendingDomain),
    sendingService: analysis.parser.serviceIdentified ? analysis.parser.sendingService : null,
    auth: {
      spf: analysis.parser.spfResult,
      dkim: analysis.parser.dkimResult,
      dmarc: analysis.parser.dmarcResult,
    },
    riskFlags: {
      hasMoneyLanguage: analysis.content.hasMoney,
      hasCredentialLanguage: analysis.content.hasCredentials,
      hasUrgencyLanguage: analysis.content.hasUrgency,
      hasDocumentRequest: analysis.content.hasDocumentRequest,
      hasSubscriptionRefundScam: analysis.content.hasSubscriptionRefundScam,
      hasWireTransferLure: analysis.content.hasWireTransferLure,
      hasOpaqueEncryptedBody: analysis.content.hasOpaqueEncryptedBody,
      hasTransactionNoticeLure: analysis.content.hasTransactionNoticeLure,
      linkCount: analysis.links.length,
      suspiciousLinkCount: analysis.links.filter((link) => link.flags.length > 0).length,
      attachmentCount: analysis.attachments.length,
    },
    linkHosts,
    mxProvider: analysis.mx?.provider ?? null,
  }

  assertTeamReportMetadataOnly(metadata)
  return metadata
}

export function assertTeamReportMetadataOnly(value: unknown): void {
  walkMetadata(value, [])
}

function walkMetadata(value: unknown, path: string[]): void {
  if (value === null || value === undefined) return

  if (typeof value === "string") {
    if (URL_PATTERN.test(value)) {
      throw new Error(`Team report metadata must not include full URLs at ${formatPath(path)}`)
    }
    return
  }

  if (typeof value !== "object") return

  if (Array.isArray(value)) {
    value.forEach((item, index) => walkMetadata(item, [...path, String(index)]))
    return
  }

  for (const [key, nested] of Object.entries(value)) {
    if (FORBIDDEN_FIELD_NAMES.has(key)) {
      throw new Error(`Team report metadata must not include ${key} at ${formatPath(path)}`)
    }
    walkMetadata(nested, [...path, key])
  }
}

function normalizeHost(value: string | null | undefined): string | null {
  const normalized = value?.trim().toLowerCase().replace(/\.$/, "")
  return normalized || null
}

function isPresent(value: string | null): value is string {
  return value !== null
}

function formatPath(path: string[]): string {
  return path.length ? path.join(".") : "root"
}
