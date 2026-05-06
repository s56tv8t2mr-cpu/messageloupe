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
  ContentClassification,
  ForwardDetection,
  ParserResult,
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

const escalate = (current: VerdictTier, target: VerdictTier): VerdictTier => {
  const order: VerdictTier[] = ["safe", "caution", "danger"]
  if (current === "forwarded" || target === "forwarded") return current
  return order.indexOf(target) > order.indexOf(current) ? target : current
}

interface VerdictInputs {
  parser: ParserResult
  links: AnalyzedLink[]
  content: ContentClassification
  forward: ForwardDetection
}

export function computeVerdict({
  parser,
  links,
  content,
  forward,
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

  // ---- Reply-To / Return-Path mismatch ----
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

  // ---- Money/credential cap ----
  let capped = false
  let capReason: string | undefined
  if (shouldCapVerdict(content) && tier === "safe") {
    capped = true
    capReason = content.hasMoney
      ? "This message mentions money, payment, or banking changes."
      : "This message asks about credentials or login info."
    tier = "caution"
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
