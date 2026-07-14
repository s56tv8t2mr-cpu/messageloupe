// Verdict synthesis: take parser output + link analysis + content
// classification + forward detection, return a 3-tier verdict (Safe /
// Caution / Danger) plus a plain-English explanation, with the money/
// credential cap rule applied.
//
// Tier semantics:
//   safe      → authentication and routing all check out; no high-risk
//               link flags; no money/credential content present.
//   caution   → ambiguous or low-confidence signals; reply-to mismatch;
//               low-risk link flags; or a content-cap forced the tier up.
//   danger    → at least one high-confidence failure (DMARC fail, SPF fail,
//               anchor-href mismatch on links, IP-host link, punycode host).
//   forwarded → input is a regular forward; engine is structurally blind.

import type {
  AnalyzedLink,
  AttachmentInfo,
  ContentClassification,
  ForwardDetection,
  MxLookup,
  ParserResult,
  RdapLookup,
  ReplyToCheck,
  SenderTrustSignals,
  Verdict,
  VerdictReason,
  VerdictTier,
} from "./types"
import { shouldCapVerdict } from "./classify-content"
import { sameRegistrable } from "./domain"

const HIGH_RISK_LINK_FLAGS = new Set([
  "mismatch",
  "ipHost",
  "punycode",
  "cmTld",
])

const HIGH_RISK_ATTACHMENT_EXTENSIONS = new Set([
  "htm",
  "html",
  "svg",
  "iso",
  "img",
  "lnk",
  "one",
  "js",
  "vbs",
])

const DECEPTIVE_INNER_ATTACHMENT_EXTENSIONS = new Set([
  "doc",
  "docx",
  "pdf",
  "xls",
  "xlsx",
  "ppt",
  "pptx",
  "txt",
])

const EXECUTABLE_ATTACHMENT_EXTENSIONS = new Set([
  "bat",
  "cmd",
  "com",
  "exe",
  "js",
  "lnk",
  "msi",
  "ps1",
  "scr",
  "vbs",
])

const escalate = (current: VerdictTier, target: VerdictTier): VerdictTier => {
  const order: VerdictTier[] = ["safe", "caution", "danger"]
  if (current === "forwarded" || target === "forwarded") return current
  return order.indexOf(target) > order.indexOf(current) ? target : current
}

function filenameExtensions(filename: string): string[] {
  return filename
    .toLowerCase()
    .split(/[\\/]/)
    .pop()
    ?.split(".")
    .slice(1)
    .filter(Boolean) ?? []
}

function isHighRiskAttachment(attachment: AttachmentInfo): boolean {
  const extensions = filenameExtensions(attachment.filename)
  const lastExtension = extensions.at(-1) ?? ""
  if (HIGH_RISK_ATTACHMENT_EXTENSIONS.has(lastExtension)) return true
  if (extensions.length < 2) return false

  const innerExtension = extensions.at(-2) ?? ""
  return (
    DECEPTIVE_INNER_ATTACHMENT_EXTENSIONS.has(innerExtension) &&
    EXECUTABLE_ATTACHMENT_EXTENSIONS.has(lastExtension)
  )
}

function hasFinancialFilename(attachment: AttachmentInfo): boolean {
  const normalizedFilename = attachment.filename.replace(/[_-]+/g, " ")
  return /\b(?:invoices?|payments?)\b/i.test(normalizedFilename)
}

interface VerdictInputs {
  parser: ParserResult
  links: AnalyzedLink[]
  attachments: AttachmentInfo[]
  content: ContentClassification
  forward: ForwardDetection
  trust: SenderTrustSignals
  replyTo: ReplyToCheck
  mx: MxLookup | null
  rdap: RdapLookup | null
}

// True iff the visible sender domain is authenticated by SPF, DKIM, or
// DMARC pass aligned to the sender domain. Used to gate the MX-based
// brand-impersonation reasons: a legitimate sender can host inbound mail
// at Google and authorize SendGrid in SPF for outbound — that split is
// normal and not impersonation. The auth gate is what converts an MX
// mismatch from "suspicious" to "the domain is being spoofed."
function senderAuthenticates(parser: ParserResult): boolean {
  if (parser.dmarcResult === "pass") return true
  if (
    parser.spfResult === "pass" &&
    sameRegistrable(parser.spfMailFromDomain, parser.sendingDomain)
  )
    return true
  if (
    parser.dkimResult === "pass" &&
    sameRegistrable(parser.dkimHeaderDomain, parser.sendingDomain)
  )
    return true
  return false
}

function visibleSenderAuthenticates(parser: ParserResult): boolean {
  if (
    parser.dmarcResult === "pass" &&
    sameRegistrable(parser.authHeaderFromDomain, parser.sendingDomain)
  )
    return true
  if (
    parser.spfResult === "pass" &&
    sameRegistrable(parser.spfMailFromDomain, parser.sendingDomain)
  )
    return true
  if (
    parser.dkimResult === "pass" &&
    sameRegistrable(parser.dkimHeaderDomain, parser.sendingDomain)
  )
    return true
  return false
}

function decodeHtmlCodePoint(value: string, radix: number): string {
  const codePoint = parseInt(value, radix)
  if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > 0x10FFFF) return ""
  try {
    return String.fromCodePoint(codePoint)
  } catch {
    return ""
  }
}

function readableBodyLength(parser: ParserResult): number {
  const htmlText = (parser.bodyHtml || "")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_match, hex: string) => decodeHtmlCodePoint(hex, 16))
    .replace(/&#(\d+);/g, (_match, code: string) => decodeHtmlCodePoint(code, 10))
  return `${parser.bodyText || ""}\n${htmlText}`
    .replace(/[^a-z0-9]/gi, "")
    .length
}

export function computeVerdict({
  parser,
  links,
  attachments,
  content,
  forward,
  trust,
  replyTo,
  mx,
  rdap,
}: VerdictInputs): Verdict {
  if (forward.isForwarded) {
    return {
      tier: "forwarded",
      headline: "This looks like a forward",
      explanation:
        "The original headers (the only thing that proves who really sent the email) appear to have been replaced by your own when the message was forwarded. Save the original message instead, or open the suspicious email and use \"Show Original\" / \"View Source\" to copy the raw headers, then paste them in here.",
      reasons: [
        {
          signal: forward.reason ?? "forwarded",
          detail:
            forward.reason === "subject-prefix"
              ? "Subject begins with a forward prefix (Fwd:/Fw:)."
              : forward.reason === "body-separator"
                ? "Message body contains a forwarded-message separator block."
                : "No upstream Received chain detected; likely sent or forwarded by you.",
          weight: "high",
        },
      ],
      capped: false,
    }
  }

  let tier: VerdictTier = "safe"
  const reasons: VerdictReason[] = []
  const hasThirdPartyLink = links.some((link) => link.flags.includes("thirdParty"))
  const hasHighRiskBusinessContent =
    content.hasMoney ||
    content.hasCredentials ||
    content.hasJobOffer ||
    content.hasDocumentRequest ||
    content.hasWireTransferLure ||
    content.hasInvoicePaymentRequest ||
    content.hasBankNoticeLure ||
    content.hasSubscriptionRefundScam

  if (forward.suspectedReason) {
    reasons.push({
      signal: "possible-forward-marker",
      detail:
        forward.suspectedReason === "subject-prefix"
          ? "The subject begins with a forward prefix, but the message still contains enough original header structure to analyze instead of stopping as a forward."
          : "The body contains a forwarded-message separator, but the message still contains enough original header structure to analyze instead of stopping as a forward.",
      weight: "low",
    })
  }

  if (parser.duplicateCriticalHeaders.length > 0) {
    reasons.push({
      signal: "duplicate-critical-headers",
      detail: `This message contains duplicate ${parser.duplicateCriticalHeaders.join(", ")} header${parser.duplicateCriticalHeaders.length === 1 ? "" : "s"}. Duplicate sender or subject headers can make filters and mail apps disagree about what the message really says.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  if (parser.ignoredAuthResultsCount > 0 && !parser.authResultsTrusted) {
    reasons.push({
      signal: "untrusted-auth-results",
      detail:
        "This message includes Authentication-Results headers, but they do not appear to come from the recipient-side mail system. Message Loupe ignored them instead of trusting sender-supplied authentication claims.",
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  }

  // ---- Recipient-side spam verdicts ----
  // When a trusted recipient-side filter (for example Proton/Rspamd) has
  // already marked the message as spam, do not let clean-looking auth make
  // the result appear safe. This is especially important for header-only
  // exports where the readable scam body may be encrypted or unavailable.
  if (parser.recipientSpamVerdict === "spam") {
    let detail = "The recipient-side spam filter marked this message as spam."
    if (parser.recipientSpamScore !== null) {
      detail = `The recipient-side spam filter marked this message as spam with score ${parser.recipientSpamScore}.`
    }
    reasons.push({
      signal: "recipient-spam-verdict",
      detail,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Authentication signals ----
  if (parser.dmarcResult === "fail") {
    reasons.push({
      signal: "dmarc-fail",
      detail: `DMARC explicitly failed for ${parser.sendingDomain ?? "the sending domain"}. The visible sender is not authorized to send from this domain.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  if (parser.spfResult === "fail" || parser.spfResult === "permerror") {
    reasons.push({
      signal: "spf-fail",
      detail: `SPF check ${parser.spfResult === "fail" ? "explicitly failed" : "had a permanent error"}. The server that sent this email is not in the sender's authorized list.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  if (parser.spoofingLikely && tier !== "danger") {
    reasons.push({
      signal: "spoofing-likely",
      detail: parser.senderDomainNote,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  if (parser.spfResult === "softfail") {
    reasons.push({
      signal: "spf-softfail",
      detail: "SPF soft-failed. The sender's domain says messages from this server are probably not authorized, but didn't reject outright.",
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  }

  if (parser.dkimResult === "fail") {
    reasons.push({
      signal: "dkim-fail",
      detail: "The DKIM signature did not verify. The message may have been altered in transit, or the signing was forged.",
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  }

  if (
    !parser.dmarcResult &&
    parser.spfResult !== "pass" &&
    parser.dkimResult !== "pass"
  ) {
    reasons.push({
      signal: "no-auth",
      detail: "No clear authentication results. The sender domain doesn't enforce DMARC, and SPF/DKIM didn't return a pass.",
      weight: "low",
    })
    tier = escalate(tier, "caution")
  }

  if (
    parser.spfResult === "pass" &&
    parser.dkimResult !== "pass" &&
    (!parser.dmarcResult || parser.dmarcResult === "none")
  ) {
    reasons.push({
      signal: "spf-only-auth",
      detail:
        "Only SPF passed. DKIM and DMARC did not provide a passing sender-domain check, so the sender is not strongly authenticated.",
      weight: "low",
    })
    tier = escalate(tier, "caution")
  }

  // ---- Sender trust: display-name impersonation + sketchy domain ----
  // These catch the case where a message authenticates correctly *for its
  // own domain* but the visible identity (display name) doesn't match what
  // any legitimate sender of that identity would use.

  if (trust.brandImpersonation) {
    reasons.push({
      signal: "brand-impersonation",
      detail: `The display name claims to be ${trust.brandImpersonation.brand}, but the email comes from ${parser.sendingDomain ?? "an unrelated domain"}, not a domain ${trust.brandImpersonation.brand} actually sends from.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  if (trust.roleImpersonation) {
    if (trust.domainHasTyposquatShape) {
      reasons.push({
        signal: "role-impersonation-sketchy-domain",
        detail: `The display name claims a department or role (“${parser.sendingName}”), but the actual email comes from ${parser.sendingDomain ?? "an unusual domain"}: a domain shape (digits mixed with letters, leading numbers, or punycode) commonly used by attackers, and unlikely to be any real employer.`,
        weight: "high",
      })
      tier = escalate(tier, "danger")
    } else if (trust.fromPublicWebmail) {
      reasons.push({
        signal: "role-impersonation-webmail",
        detail: `The display name claims a department or role (“${parser.sendingName}”), but the actual email comes from a personal/public email account at ${parser.sendingDomain}. Real employers don't send HR/IT/Accounting emails from gmail or outlook.`,
        weight: "high",
      })
      tier = escalate(tier, "danger")
    } else {
      reasons.push({
        signal: "role-impersonation",
        detail: `The display name says “${parser.sendingName}” but the actual email is from ${parser.sendingDomain}. If this is supposed to be from your own employer's HR/IT/Accounting, double-check the domain matches your company's real domain.`,
        weight: "medium",
      })
      tier = escalate(tier, "caution")
    }
  } else if (trust.domainHasTyposquatShape && !trust.brandImpersonation) {
    // Typosquat shape on its own is a soft signal — many legitimate small
    // businesses have hyphenated or numeric labels. Caution, not danger.
    reasons.push({
      signal: "domain-typosquat-shape",
      detail: `The sending domain (${parser.sendingDomain}) has a shape associated with throwaway or typosquat domains: letters mixed with digits, a leading number, or punycode. Legitimate businesses usually have cleaner domain names.`,
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  }

  // ---- Executive / role BEC with financial action ----
  if (trust.executiveImpersonation && content.hasMoney && !visibleSenderAuthenticates(parser)) {
    reasons.push({
      signal: "executive-impersonation-with-money",
      detail: `The display name claims an executive role (“${parser.sendingName}”) and the message asks for money, payment, banking, or receivables action. That pairing is a common BEC pattern.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Payroll / banking-change request from public webmail ----
  if (
    !content.hasFraudReportContext &&
    content.hasBankingChangeRequest &&
    trust.fromPublicWebmail
  ) {
    reasons.push({
      signal: "public-webmail-banking-change",
      detail:
        `This message asks to change banking, payment, payroll, or direct-deposit details, but it comes from a public webmail domain (${parser.sendingDomain}). Payroll-diversion BEC commonly uses this shape.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Consumer mailbox person-name mismatch ----
  if (
    !content.hasFraudReportContext &&
    trust.personNameMailboxMismatch &&
    content.hasBecOpener
  ) {
    reasons.push({
      signal: "consumer-mailbox-person-mismatch",
      detail:
        `The display name looks like a person's name (“${parser.sendingName}”), but the consumer mailbox address (${parser.sendingEmail ?? "unknown"}) does not match that name, and the body uses a BEC-style opener.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Return-Path mismatch (sender vs envelope-bounce) ----
  if (
    parser.sendingDomain &&
    parser.returnPathDomain &&
    parser.returnPathDomain !== parser.sendingDomain &&
    !parser.serviceIdentified
  ) {
    reasons.push({
      signal: "returnpath-mismatch",
      detail: `Return-Path domain (${parser.returnPathDomain}) doesn't match the visible sender domain (${parser.sendingDomain}), and the message wasn't sent through a recognized email service.`,
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  }

  // ---- Encrypted self-send (compromised-mailbox RMS phish) ----
  // Pattern: an attacker who has popped a real Microsoft 365 mailbox sends
  // an RMS-rights-protected message from that mailbox to itself, then routes
  // it onward. The encryption hides the payload (typically a fake "click to
  // read" Microsoft login form) from any content scanner. Because the
  // message originates in the real tenant, SPF/DKIM/DMARC all check out.
  //
  // Either signal alone is benign: people email themselves notes; orgs use
  // RMS for legitimate internal traffic. The combination is the tell —
  // legitimate users do not send themselves encrypted email as a workflow.
  const fromMailbox = parser.sendingEmail?.toLowerCase().trim() ?? null
  const toMailbox = parser.recipientEmail?.toLowerCase().trim() ?? null
  const isSelfSend = Boolean(fromMailbox && toMailbox && fromMailbox === toMailbox)
  const isRmsEncrypted = parser.contentClass === "rpmsg.message"
  if (isSelfSend && isRmsEncrypted) {
    reasons.push({
      signal: "rms-self-send",
      detail:
        `This message was sent from ${parser.sendingEmail} to the same mailbox and is encrypted with Microsoft Rights Management (Content-Class: rpmsg.message). Legitimate users don't send themselves rights-protected mail as a workflow. This pattern is associated with compromised-mailbox phishing: an attacker who controls the real account uses encryption to hide a fake "click to read message" login prompt from content scanners.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Early-stage BEC opener ----
  // Many real BECs start as a cleanly-authenticated, link-free "quick chat"
  // message so the money request happens in the next reply, outside scanners.
  // Keep this at caution by default, but escalate if the same message already
  // contains money/payment movement.
  if (content.hasBecOpener) {
    reasons.push({
      signal: content.hasMoney ? "bec-opener-with-money" : "bec-opener",
      detail: content.hasMoney
        ? "This message uses a common executive-impersonation opener and includes money or payment language. That pairing is a high-risk business email compromise pattern."
        : "This message uses a common executive-impersonation opener: a vague request for a quick chat or help with a small situation. Treat it as suspicious until you verify the sender through a channel you already trust.",
      weight: content.hasMoney ? "high" : "medium",
    })
    tier = escalate(tier, content.hasMoney ? "danger" : "caution")
  }

  // ---- Secure document / message lure to an unrelated host ----
  // Legitimate secure-message systems exist, so the content alone is not
  // enough. The dangerous shape is document-portal wording plus a link whose
  // registrable domain does not match the sender.
  if (content.hasSecureDocumentLure && hasThirdPartyLink) {
    reasons.push({
      signal: "off-brand-document-link",
      detail:
        "This email says a secure message or document is waiting, but the link points to a different third-party site. Fake document portals are commonly used to steal credentials.",
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Fake antivirus / subscription renewal refund scams ----
  // Text-only refund scams often contain no malware and no link. The hook is
  // an alarming renewal/order/charge notice plus a phone number to cancel.
  if (content.hasSubscriptionRefundScam) {
    reasons.push({
      signal: "subscription-refund-scam",
      detail:
        "This message matches a fake antivirus/subscription renewal pattern: an unexpected order or charge, a security-product brand, and a phone-number/cancel hook. These are commonly used to push victims into refund or remote-support scams.",
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Opaque encrypted invoice / transaction lures ----
  // Proton exports and some secure-mail flows can leave the message body as
  // a PGP armored blob. When the visible subject looks transactional and the
  // sender is public webmail, do not let clean Hotmail/Gmail auth become a
  // "Safe" verdict; the actual invoice/refund content is hidden from us.
  if (
    content.hasOpaqueEncryptedBody &&
    content.hasTransactionNoticeLure &&
    trust.fromPublicWebmail
  ) {
    reasons.push({
      signal: "encrypted-transaction-lure",
      detail:
        "The readable content is hidden inside an encrypted body, while the visible subject looks like a transaction, invoice, order, or billing notice from a public webmail sender. Fake invoice and refund scams can use this shape to bypass content filters.",
      weight: "high",
    })
    tier = escalate(tier, "danger")
  } else if (content.hasOpaqueEncryptedBody && tier === "safe") {
    reasons.push({
      signal: "opaque-encrypted-body",
      detail:
        "The message body is encrypted or otherwise opaque, so Message Loupe cannot inspect the actual content. Treat it as unverified unless you expected an encrypted message from this sender.",
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  }

  // ---- Wire / ACH payment lure ----
  // Plain invoice language is common and should stay at caution. The stronger
  // signal is wire/ACH/routing/remittance language paired with another risky
  // delivery shape: an attachment, an unrelated link, or an auth failure.
  const hasAuthFailure =
    parser.dkimResult === "fail" ||
    parser.dmarcResult === "fail" ||
    parser.spfResult === "fail" ||
    parser.spfResult === "softfail" ||
    parser.spfResult === "permerror"
  if (
    !content.hasFraudReportContext &&
    content.hasWireTransferLure &&
    (attachments.length > 0 || hasThirdPartyLink || hasAuthFailure)
  ) {
    reasons.push({
      signal: "wire-transfer-lure",
      detail:
        "This message combines wire, ACH, routing, or remittance language with a risky delivery shape such as an attachment, unrelated link, or authentication failure. That combination is a common wire-fraud and invoice-redirection pattern.",
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Fake invoice / payment request ----
  // A bare invoice attachment is too common to call fake. A payment-request
  // invoice plus a missing/non-passing DMARC result is a stronger BEC shape.
  if (
    !content.hasFraudReportContext &&
    content.hasInvoicePaymentRequest &&
    attachments.length > 0 &&
    !senderAuthenticates(parser)
  ) {
    reasons.push({
      signal: "invoice-payment-request",
      detail:
        "This message asks for invoice payment and includes an attachment, while the sender is not strongly authenticated. That combination is a common fake-invoice and payment-redirection pattern.",
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Coercive invoice / payment threat ----
  if (!content.hasFraudReportContext && content.hasCoercivePaymentThreat) {
    reasons.push({
      signal: "coercive-payment-threat",
      detail:
        "This message combines payment or invoice language with coercive threats such as final notice, legal action, exposure, or public disclosure. That is a high-risk pressure tactic.",
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Fake bank notice / account-opening lure ----
  if (
    !content.hasFraudReportContext &&
    content.hasBankNoticeLure &&
    !senderAuthenticates(parser)
  ) {
    reasons.push({
      signal: "bank-notice-lure",
      detail:
        "This looks like a bank notice or account-opening message, but the sender is not strongly authenticated. Treat bank-account notices as high risk unless verified through the bank's official site or phone number.",
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Fake reply thread marker ----
  if (
    !content.hasFraudReportContext &&
    /^re\s*:/i.test(parser.subject ?? "") &&
    !parser.hasThreadReferences &&
    content.hasMoney
  ) {
    reasons.push({
      signal: "fake-reply-thread",
      detail:
        "The subject begins with Re:, but the message has no In-Reply-To or References header tying it to a real prior conversation. Fake reply threads are commonly used to make payment requests feel familiar.",
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Newly registered sender domain ----
  // Domain age is not proof by itself: new companies and campaigns use new
  // domains. It becomes high-risk when paired with business-action language
  // and weak sender authentication.
  if (rdap?.status === "done" && rdap.ageDays !== null && rdap.ageDays <= 30) {
    if (
      rdap.ageDays <= 14 &&
      hasHighRiskBusinessContent &&
      !senderAuthenticates(parser)
    ) {
      reasons.push({
        signal: "new-sender-domain-high-risk",
        detail: `${rdap.domain} appears to have been registered about ${rdap.ageDays} day${rdap.ageDays === 1 ? "" : "s"} ago, and this message asks for a sensitive business action without strong sender authentication. Newly registered domains are common in BEC and invoice-redirection attempts.`,
        weight: "high",
      })
      tier = escalate(tier, "danger")
    } else {
      reasons.push({
        signal: "new-sender-domain",
        detail: `${rdap.domain} appears to have been registered about ${rdap.ageDays} day${rdap.ageDays === 1 ? "" : "s"} ago. New sender domains deserve extra scrutiny, especially for money, login, or document requests.`,
        weight: "medium",
      })
      tier = escalate(tier, "caution")
    }
  }

  // ---- Job offer signed as a known firm but sent from another domain ----
  if (
    !content.hasFraudReportContext &&
    content.hasJobOffer &&
    content.mentionsPolarisPartners &&
    content.hasRiskyWorkFromHomeJobLure &&
    !sameRegistrable(parser.sendingDomain, "polarispartners.com")
  ) {
    reasons.push({
      signal: "job-brand-signature-impersonation",
      detail:
        "This job-offer message references Polaris Partners, but the sender domain is not a Polaris Partners domain. Fake job offers often impersonate real firms in the email body or signature rather than the From name.",
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Brand claimed in body/signature rather than From display name ----
  if (
    !content.hasFraudReportContext &&
    content.bodyBrandClaim &&
    (content.hasJobOffer || content.hasMoney || content.hasCredentials || content.hasDocumentRequest) &&
    !content.bodyBrandClaim.legitimateDomains.some((domain) =>
      sameRegistrable(parser.sendingDomain, domain),
    )
  ) {
    reasons.push({
      signal: "body-brand-claim-impersonation",
      detail:
        `The message body claims to represent ${content.bodyBrandClaim.brand}, but the sender domain (${parser.sendingDomain ?? "unknown"}) is not a known ${content.bodyBrandClaim.brand} domain. Scams often impersonate brands in the body or signature instead of the From display name.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Reply-To mismatch (two-tier: strong / mismatch) ----
  // Phishers commonly send via one infrastructure (often a hijacked or
  // lookalike sending domain) while routing victim replies to a separate
  // attacker-owned address. `assessReplyTo` applies the ESP/notification
  // skip list and distinguishes:
  //   strong   — same local-part, different domain (andrew@a.com vs
  //              andrew@b.com): hallmark of compromised-account /
  //              brand-impersonation abuse.
  //   mismatch — domains differ, local-parts don't match.
  // Both are high-severity per the validated playbook (~100% / ~89%
  // precision on 250 real phishing samples after skip list).
  if (replyTo.assessment && replyTo.note) {
    reasons.push({
      signal: replyTo.assessment === "strong" ? "replyto-strong-mismatch" : "replyto-mismatch",
      detail: replyTo.note,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- MX-based brand-impersonation detection ----
  // Discriminator: the visible sender domain's *inbound* MX records resolve
  // to one provider (e.g. Google), but the *outbound* delivery came from an
  // unrelated third-party ESP (e.g. SendGrid). Combined with no domain
  // authentication, this is the signature of a forged-sender attack where
  // the domain owner is the victim, not the source.
  //
  // Auth gate: if SPF/DKIM/DMARC pass aligned to the sender domain, the
  // ESP is authorized — that's a normal split-inbound/outbound setup, not
  // impersonation. Without the gate, every legitimately-authorized
  // marketing email through SendGrid would flag.
  const senderDomain = parser.sendingDomain
  const service = parser.sendingService
  if (
    !senderAuthenticates(parser) &&
    senderDomain &&
    service &&
    parser.serviceIdentified
  ) {
    if (mx?.status === "done" && mx.provider && mx.provider.toLowerCase() !== service.toLowerCase()) {
      reasons.push({
        signal: "brand-impersonation-confirmed",
        detail: `${senderDomain}'s MX records point to ${mx.provider}, but this message was delivered by ${service}. The visible sender domain is being spoofed by a third party.`,
        weight: "high",
      })
      tier = escalate(tier, "danger")
    } else if (replyTo.assessment === "strong") {
      reasons.push({
        signal: "brand-impersonation-likely",
        detail: `${service} delivered this message, but ${senderDomain} has no authentication tying it to ${service}. Combined with the Reply-To redirect, this looks like third-party brand impersonation.`,
        weight: "medium",
      })
      tier = escalate(tier, "caution")
    }
  }

  // ---- Link flags ----
  const allLinkFlags = new Set<string>()
  for (const link of links) {
    for (const flag of link.flags) allLinkFlags.add(flag)
  }
  const highRisk = [...allLinkFlags].filter((f) => HIGH_RISK_LINK_FLAGS.has(f))
  if (highRisk.length > 0) {
    const labels = highRisk
      .map((f) => {
        switch (f) {
          case "mismatch":
            return "the visible link text doesn't match where the link actually goes"
          case "ipHost":
            return "a link points to a raw IP address instead of a domain"
          case "punycode":
            return "a link uses punycode, which can hide a fake domain"
          case "cmTld":
            return "a link ends in .cm, a common typo trap for .com"
          default:
            return f
        }
      })
      .join("; ")
    reasons.push({
      signal: "suspicious-links",
      detail: `Links in this message carry high-risk signals: ${labels}.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  } else if (allLinkFlags.has("shortener")) {
    reasons.push({
      signal: "shortener-link",
      detail: "Message contains shortened links (bit.ly, t.co, etc). They hide the real destination.",
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  }

  // ---- Dangerous attachment types ----
  const highRiskAttachments = attachments.filter(isHighRiskAttachment)
  if (highRiskAttachments.length > 0) {
    const fileList = highRiskAttachments
      .slice(0, 3)
      .map((a) => a.filename)
      .join(", ")
    reasons.push({
      signal: "dangerous-attachment-type",
      detail: `This email includes a high-risk attachment type (${fileList}${highRiskAttachments.length > 3 ? ", ..." : ""}). HTML, script, disk-image, shortcut, OneNote, SVG, and double-extension attachments are commonly used to hide malware or fake login pages.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // A fully authenticated consumer mailbox can still be disposable or
  // compromised. A mismatched personal identity sending an image-only
  // invoice is a strong scam shape because the financial pitch is hidden
  // from text scanning inside the image.
  const hasImageAttachment = attachments.some((attachment) =>
    attachment.contentType.startsWith("image/"),
  )
  const hasFinancialImageAttachment = attachments.some(
    (attachment) =>
      attachment.contentType.startsWith("image/") && hasFinancialFilename(attachment),
  )
  if (
    !content.hasFraudReportContext &&
    trust.fromPublicWebmail &&
    trust.personNameMailboxMismatch &&
    ((content.hasMoney && hasImageAttachment) || hasFinancialImageAttachment) &&
    readableBodyLength(parser) < 20
  ) {
    reasons.push({
      signal: "image-invoice-from-mismatched-webmail",
      detail:
        "This invoice or payment message comes from a public email account whose address does not match the sender's name, and the actual pitch is hidden in an image attachment. That combination is a strong fake-invoice pattern even when Outlook or Gmail authentication passes.",
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  // ---- Source IP missing ----
  if (!parser.sourceIp && tier === "safe") {
    reasons.push({
      signal: "no-source-ip",
      detail: "The originating server's IP address could not be determined from the headers.",
      weight: "low",
    })
    tier = escalate(tier, "caution")
  }

  // ---- Image-only / no-readable-text bodies ----
  if (
    tier === "safe" &&
    readableBodyLength(parser) < 20 &&
    (parser.hasImageContent || links.length > 0 || attachments.length > 0)
  ) {
    reasons.push({
      signal: "low-readable-content",
      detail:
        "This message has almost no readable text but contains an image, link, or attachment. Image-only and QR-style emails can hide scam content from text-based checks.",
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  }

  // ---- Job-offer + document-request scams ----
  // A distinct phish family from money/credential phish. The dangerous
  // combination is offer language + document/PII request: real employers
  // use secure portals (Lever, BambooHR, DocuSign) and don't ask candidates
  // to email scans of their passport. Pair fires danger; single fires
  // caution.
  if (content.hasJobOffer && content.hasDocumentRequest) {
    reasons.push({
      signal: "job-offer-with-document-request",
      detail: jobDocumentRequestDetail(content),
      weight: "high",
    })
    tier = escalate(tier, "danger")
  } else if (content.hasJobOffer) {
    reasons.push({
      signal: "job-offer-content",
      detail:
        "This email reads like a job offer, interview invitation, or onboarding message. If you didn't apply for this role through a recruiter or the company's official site, treat it as a scam. Verify any offer through the company's official careers page before acting.",
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  } else if (content.hasDocumentRequest) {
    reasons.push({
      signal: "document-request-content",
      detail: documentRequestDetail(content),
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  }

  // ---- Money/credential cap ----
  let capped = false
  let capReason: string | undefined
  if (shouldCapVerdict(content) && tier === "safe") {
    capped = true
    let capSignal = "document-request-content"
    capReason = documentRequestCapReason(content)
    if (content.hasMoney) {
      capSignal = "financial-action-content"
      capReason = "This message mentions money, payment, or banking changes."
    } else if (content.hasCredentials) {
      capSignal = "credential-request-content"
      capReason = "This message asks about credentials or login info."
    }
    reasons.push({
      signal: capSignal,
      detail: capReason,
      weight: "medium",
    })
    tier = "caution"
  }

  // ---- Attachment + offer/money combination ----
  // Attachments alone are normal. Attachments combined with job-offer or
  // money-transfer language are how a lot of malware-bearing phish lands.
  if (
    attachments.length > 0 &&
    (content.hasJobOffer || content.hasMoney) &&
    tier !== "danger"
  ) {
    const fileList = attachments
      .slice(0, 3)
      .map((a) => a.filename)
      .join(", ")
    reasons.push({
      signal: "attachment-with-suspicious-content",
      detail: `This email carries ${attachments.length} attachment${attachments.length === 1 ? "" : "s"} (${fileList}${attachments.length > 3 ? ", …" : ""}) alongside ${content.hasJobOffer ? "job-offer" : "money-transfer"} language. Don't open the attachment unless you can confirm the sender by phone first; phishing attachments often contain malware or fake login pages.`,
      weight: content.hasJobOffer && content.hasDocumentRequest ? "high" : "medium",
    })
    tier = escalate(tier, "caution")
  }

  return {
    tier,
    headline: headlineFor(tier),
    explanation: explanationFor(tier, { capped, capReason, content, parser }),
    reasons,
    capped,
    capReason,
  }
}

function headlineFor(tier: VerdictTier): string {
  switch (tier) {
    case "safe":
      return "No obvious warning signs"
    case "caution":
      return "Be careful"
    case "danger":
      return "Likely fake"
    case "forwarded":
      return "This looks like a forward"
  }
}

function explanationFor(
  tier: VerdictTier,
  ctx: {
    capped: boolean
    capReason?: string
    content: ContentClassification
    parser: ParserResult
  },
): string {
  if (tier === "danger") {
    return "Multiple signals say this email is not what it claims to be. Don't click any links, don't reply, don't act on it. Delete it and report it as phishing."
  }
  if (tier === "caution") {
    if (ctx.capped) {
      if (ctx.content.hasMoney) {
        return `${ctx.capReason} Even though the technical signals look fine on the surface, verify any payment or banking change by phone using a number you already trust, not one from this email.`
      }
      if (ctx.content.hasCredentials) {
        return `${ctx.capReason} Don't use a sign-in or password link from this email. Open the service from a saved bookmark or type its known address yourself.`
      }
      return `${ctx.capReason} Confirm the request through a channel you already trust before sharing documents or signed forms.`
    }
    return "Some signals don't add up. Treat this email with skepticism. Verify any requested action through a channel you already trust before responding."
  }
  if (tier === "safe") {
    return "No spoofing, sender-alignment, routing, or suspicious-link signals were found. This does not prove the person or request is trustworthy."
  }
  return ""
}

function jobDocumentRequestDetail(content: ContentClassification): string {
  if (content.hasIdentityDocumentRequest) {
    return "This email reads like a job offer and asks for identity documents such as a passport, ID, or certificate. Legitimate employers use approved hiring portals for this; they don't ask candidates to email scans. This is a common recruitment-scam pattern."
  }
  if (content.hasBankStatementRequest) {
    return "This email reads like a job offer and asks for a bank statement. Confirm the employer through its official careers site and use only an approved hiring portal before sharing financial documents."
  }
  return "This email reads like a job offer and asks you to sign and return a form. Confirm the employer and the role through its official careers site before returning onboarding paperwork."
}

function documentRequestDetail(content: ContentClassification): string {
  if (content.hasIdentityDocumentRequest) {
    return "This email asks for identity documents such as a passport, ID, certificate, or license. Confirm the request through a channel you already trust and use the organization's approved portal instead of replying with scans."
  }
  if (content.hasBankStatementRequest) {
    return "This email asks for a bank statement. Confirm the request through a channel you already trust before sharing financial documents, and use the organization's approved portal."
  }
  return "This email asks you to return a signed form. Confirm the request through a channel you already trust before sending signed paperwork."
}

function documentRequestCapReason(content: ContentClassification): string {
  if (content.hasIdentityDocumentRequest) {
    return "This message asks for identity documents."
  }
  if (content.hasBankStatementRequest) {
    return "This message asks for a bank statement."
  }
  return "This message asks you to sign and return a form."
}
