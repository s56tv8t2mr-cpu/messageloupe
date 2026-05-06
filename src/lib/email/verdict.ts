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
  ParserResult,
  SenderTrustSignals,
  Verdict,
  VerdictReason,
  VerdictTier,
} from "./types"
import { shouldCapVerdict } from "./classify-content"

const HIGH_RISK_LINK_FLAGS = new Set([
  "mismatch",
  "ipHost",
  "punycode",
  "cmTld",
])

// Multi-label TLDs that legitimately use a "<label>.<sld>.<cc>" form.
// Used to extract the registrable domain so subdomains and multi-label
// country TLDs don't cause false-positive Reply-To-mismatch flags.
const KNOWN_MULTI_LABEL_SUFFIXES = [
  "com.au", "com.br", "com.cn", "com.co", "com.hk", "com.mx", "com.my",
  "com.ng", "com.sg", "com.tr", "com.vn",
  "co.jp", "co.kr", "co.nz", "co.uk", "co.za",
  "net.au", "org.au", "org.uk", "ac.uk", "gov.uk",
]

function registrableDomain(domain: string | null): string | null {
  if (!domain) return null
  const lower = domain.toLowerCase()
  for (const suffix of KNOWN_MULTI_LABEL_SUFFIXES) {
    if (lower.endsWith(`.${suffix}`)) {
      const before = lower.slice(0, -suffix.length - 1)
      const lastLabel = before.split(".").pop()
      return lastLabel ? `${lastLabel}.${suffix}` : lower
    }
  }
  return lower.split(".").slice(-2).join(".")
}

const escalate = (current: VerdictTier, target: VerdictTier): VerdictTier => {
  const order: VerdictTier[] = ["safe", "caution", "danger"]
  if (current === "forwarded" || target === "forwarded") return current
  return order.indexOf(target) > order.indexOf(current) ? target : current
}

interface VerdictInputs {
  parser: ParserResult
  links: AnalyzedLink[]
  attachments: AttachmentInfo[]
  content: ContentClassification
  forward: ForwardDetection
  trust: SenderTrustSignals
}

export function computeVerdict({
  parser,
  links,
  attachments,
  content,
  forward,
  trust,
}: VerdictInputs): Verdict {
  if (forward.isForwarded) {
    return {
      tier: "forwarded",
      headline: "This looks like a forward",
      explanation:
        "The original headers — the only thing that proves who really sent the email — appear to have been replaced by your own when the message was forwarded. Save the original message instead, or open the suspicious email and use \"Show Original\" / \"View Source\" to copy the raw headers, then paste them in here.",
      reasons: [
        {
          signal: forward.reason ?? "forwarded",
          detail:
            forward.reason === "subject-prefix"
              ? "Subject begins with a forward prefix (Fwd:/Fw:)."
              : forward.reason === "body-separator"
                ? "Message body contains a forwarded-message separator block."
                : "No upstream Received chain detected — likely sent or forwarded by you.",
          weight: "high",
        },
      ],
      capped: false,
    }
  }

  let tier: VerdictTier = "safe"
  const reasons: VerdictReason[] = []

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

  // ---- Sender trust: display-name impersonation + sketchy domain ----
  // These catch the case where a message authenticates correctly *for its
  // own domain* but the visible identity (display name) doesn't match what
  // any legitimate sender of that identity would use.

  if (trust.brandImpersonation) {
    reasons.push({
      signal: "brand-impersonation",
      detail: `The display name claims to be ${trust.brandImpersonation.brand}, but the email comes from ${parser.sendingDomain ?? "an unrelated domain"} — not a domain ${trust.brandImpersonation.brand} actually sends from.`,
      weight: "high",
    })
    tier = escalate(tier, "danger")
  }

  if (trust.roleImpersonation) {
    if (trust.domainHasTyposquatShape) {
      reasons.push({
        signal: "role-impersonation-sketchy-domain",
        detail: `The display name claims a department or role (“${parser.sendingName}”), but the actual email comes from ${parser.sendingDomain ?? "an unusual domain"} — a domain shape (digits mixed with letters, leading numbers, or punycode) commonly used by attackers, and unlikely to be any real employer.`,
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
      detail: `The sending domain (${parser.sendingDomain}) has a shape associated with throwaway or typosquat domains — letters mixed with digits, a leading number, or punycode. Legitimate businesses usually have cleaner domain names.`,
      weight: "medium",
    })
    tier = escalate(tier, "caution")
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

  // ---- Reply-To routing across distinct registrable domains ----
  // Phishers commonly send via one infrastructure (e.g., MailerLite-routed
  // domain A) while routing victim replies to a separate attacker-owned
  // domain B. Legitimate newsletters keep Reply-To inside the same
  // registrable as the sender. We carve out actual mailing lists via
  // List-Id and the very common ESP "noreply / replies@<esp>" pattern.
  if (parser.sendingDomain && parser.replyToDomain) {
    const fromReg = registrableDomain(parser.sendingDomain)
    const replyReg = registrableDomain(parser.replyToDomain)
    if (fromReg && replyReg && fromReg !== replyReg && !parser.listId) {
      reasons.push({
        signal: "replyto-cross-domain",
        detail: `Replies would go to ${parser.replyToDomain} — a different domain than the visible sender (${parser.sendingDomain}). Phishing campaigns frequently split sending and receiving across multiple attacker-controlled domains; legitimate businesses rarely do this. If both domains share a brand-like name on different TLDs, that's a strong signal of a coordinated impersonation campaign.`,
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
            return "a link ends in .cm — a common typo trap for .com"
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

  // ---- Source IP missing ----
  if (!parser.sourceIp && tier === "safe") {
    reasons.push({
      signal: "no-source-ip",
      detail: "The originating server's IP address could not be determined from the headers.",
      weight: "low",
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
      detail:
        "This email reads like a job offer and asks for personal documents (passport, ID, certificates, photos). Legitimate employers use secure portals for this — they don't ask candidates to email scans. This is a classic recruitment-scam pattern.",
      weight: "high",
    })
    tier = escalate(tier, "danger")
  } else if (content.hasJobOffer && tier === "safe") {
    reasons.push({
      signal: "job-offer-content",
      detail:
        "This email reads like a job offer or onboarding message. If you didn't apply for this role through a recruiter or company website, treat it as a scam. Verify any offer through the company's official careers page before acting.",
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  } else if (content.hasDocumentRequest && tier === "safe") {
    reasons.push({
      signal: "document-request-content",
      detail:
        "This email asks for copies of personal documents (passport, ID, certificates, photos). Legitimate organizations use secure upload portals or in-person verification — never email attachments. Verify the request through a channel you already trust.",
      weight: "medium",
    })
    tier = escalate(tier, "caution")
  }

  // ---- Money/credential cap ----
  let capped = false
  let capReason: string | undefined
  if (shouldCapVerdict(content) && tier === "safe") {
    capped = true
    capReason = content.hasMoney
      ? "This message mentions money, payment, or banking changes."
      : content.hasCredentials
        ? "This message asks about credentials or login info."
        : "This message asks for copies of personal documents."
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
      detail: `This email carries ${attachments.length} attachment${attachments.length === 1 ? "" : "s"} (${fileList}${attachments.length > 3 ? ", …" : ""}) alongside ${content.hasJobOffer ? "job-offer" : "money-transfer"} language. Don't open the attachment unless you can confirm the sender by phone first — phishing attachments often contain malware or fake login pages.`,
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
      return "Looks legitimate"
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
      return `${ctx.capReason} Even though the technical signals look fine on the surface, anything involving money or credentials should be verified by phone using a number you already trust — not one from this email.`
    }
    return "Some signals don't add up. Treat this email with skepticism. Verify any requested action through a channel you already trust before responding."
  }
  if (tier === "safe") {
    return "Authentication, sender alignment, and routing all check out. The email appears to come from where it claims."
  }
  return ""
}
