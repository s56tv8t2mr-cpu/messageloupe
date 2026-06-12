// Public TypeScript surface for the Message Loupe analysis pipeline.
// Mirrors the actual shape returned by parser.js — keep in sync if the
// underlying engine evolves.

export type AuthValue =
  | "pass"
  | "fail"
  | "softfail"
  | "neutral"
  | "none"
  | "temperror"
  | "permerror"
  | "present"
  | "unknown"
  | string
  | null

export interface ReceivedHopRow {
  hop: number
  header: string
  selected: boolean
}

export interface RelayIndicatorHeader {
  name: string
  value: string
}

export interface RelayIndicator {
  label: string
  detail: string
  headers: RelayIndicatorHeader[]
}

export interface ProviderInfo {
  name: string
}

export interface ParserResult {
  subject: string | null
  sendingEmail: string | null
  sendingName: string
  sendingDomain: string | null
  recipientEmail: string | null
  recipientDomain: string | null
  contentClass: string | null
  returnPath: string | null
  returnPathDomain: string | null
  replyTo: string | null
  replyToDomain: string | null
  listId: string | null
  messageId: string
  bodyText: string
  bodyHtml: string
  hasImageContent: boolean
  hasBodyContent: boolean
  duplicateCriticalHeaders: string[]
  allHeaders: string
  sendingService: string
  serviceIdentified: boolean
  abuseReport: unknown
  sourceHostname: string
  sourceIp: string | null
  sourceIpEvidence: string | null
  sourceReceivedHeader: string | null
  receivedChain: ReceivedHopRow[]
  relayIndicators: RelayIndicator[]
  heloIdentity: string | null
  spfResult: string | null
  spfMailFromDomain: string | null
  dkimResult: string | null
  dkimHeaderDomain: string | null
  dmarcResult: string | null
  authSummary: string
  authResultsTrusted: boolean
  ignoredAuthResultsCount: number
  recipientSpamVerdict: "spam" | null
  recipientSpamScore: number | null
  recipientSpamSource: string | null
  spoofingLikely: boolean
  senderDomainNote: string
  authHeaderFromDomain: string | null
  version: string
}

export type LinkFlag =
  | "mismatch"
  | "ipHost"
  | "punycode"
  | "cmTld"
  | "shortener"
  | "thirdParty"

export interface AnalyzedLink {
  url: string
  host: string
  displayText: string | null
  flags: LinkFlag[]
}

export type FlagSeverity = "high" | "medium" | "info"

export interface FlagLabel {
  text: string
  severity: FlagSeverity
}

export type VerdictTier = "safe" | "caution" | "danger" | "forwarded"

export type VerdictReasonWeight = "high" | "medium" | "low"

export interface VerdictReason {
  signal: string
  detail: string
  weight: VerdictReasonWeight
}

export interface ContentClassification {
  hasMoney: boolean
  hasCredentials: boolean
  hasUrgency: boolean
  hasJobOffer: boolean
  hasDocumentRequest: boolean
  hasBecOpener: boolean
  hasSecureDocumentLure: boolean
  hasSubscriptionRefundScam: boolean
  hasWireTransferLure: boolean
  hasInvoicePaymentRequest: boolean
  hasCoercivePaymentThreat: boolean
  hasFraudReportContext: boolean
  hasBankNoticeLure: boolean
  mentionsPolarisPartners: boolean
  hasRiskyWorkFromHomeJobLure: boolean
  hasOpaqueEncryptedBody: boolean
  hasTransactionNoticeLure: boolean
}

export interface SenderTrustSignals {
  roleImpersonation: boolean
  brandImpersonation: { brand: string } | null
  domainHasTyposquatShape: boolean
  fromPublicWebmail: boolean
  hasDisplayName: boolean
}

export interface ForwardDetection {
  isForwarded: boolean
  reason?: "subject-prefix" | "body-separator" | "from-self"
  suspectedReason?: "subject-prefix" | "body-separator"
}

export type ReplyToAssessment = "strong" | "mismatch" | null

export interface ReplyToCheck {
  email: string | null
  domain: string | null
  assessment: ReplyToAssessment
  note: string | null
}

export interface MxRecord {
  priority: number | null
  host: string
}

export interface MxLookup {
  domain: string
  hosts: string[]
  records: MxRecord[]
  provider: string | null
  status: "pending" | "done" | "error"
  error?: string
}

export interface RdapLookup {
  domain: string
  registeredAt: string | null
  ageDays: number | null
  status: "done" | "no-date" | "error"
  error?: string
}

export interface Verdict {
  tier: VerdictTier
  headline: string
  explanation: string
  reasons: VerdictReason[]
  capped: boolean
  capReason?: string
}

export interface AttachmentInfo {
  filename: string
  contentType: string
}

export interface Analysis {
  parser: ParserResult
  links: AnalyzedLink[]
  attachments: AttachmentInfo[]
  content: ContentClassification
  forward: ForwardDetection
  trust: SenderTrustSignals
  replyTo: ReplyToCheck
  mx: MxLookup | null
  rdap: RdapLookup | null
  verdict: Verdict
}
