// Forwarded-message detector.
//
// Critical correctness guard: a regular forward replaces the original
// authentication-relevant headers with the user's own. Analyzing such a
// message gives a verdict on the user's own infrastructure, not the
// suspected sender — which is the worst possible failure mode for a phishing
// triage tool. We short-circuit before issuing any verdict.
//
// Forward-as-Attachment (a different feature in some mail clients) preserves
// the original .eml intact; those are normal inputs and should not trigger.

import type { ForwardDetection, ParserResult } from "./types"

const SUBJECT_PATTERNS: RegExp[] = [
  /^\s*fwd?:\s/i,
  /^\s*fw:\s/i,
  /^\s*\[\s*fwd?\s*\]\s/i,
  /^\s*\[\s*fw\s*\]\s/i,
]

const BODY_PATTERNS: RegExp[] = [
  /-{3,}\s*forwarded message\s*-{3,}/i,
  /-{3,}\s*original message\s*-{3,}/i,
  /\bbegin forwarded message:\s*$/im,
  /^\s*from:\s*.+\bsent:\s*.+\bto:\s*.+\bsubject:/im, // Outlook-style forward block
]

export function detectForward(parser: ParserResult): ForwardDetection {
  const subject = parser.subject ?? ""
  const body = parser.bodyText ?? ""
  const hasSubjectMarker = SUBJECT_PATTERNS.some((p) => p.test(subject))
  const hasBodyMarker = BODY_PATTERNS.some((p) => p.test(body))

  if (hasBodyMarker) {
    return { isForwarded: true, reason: "body-separator" }
  }

  if (hasSubjectMarker) {
    const hasUpstreamChain = parser.receivedChain.length > 1
    const hasAuthEvidence = Boolean(
      parser.spfResult ||
      parser.dkimResult ||
      parser.dmarcResult ||
      /^Authentication-Results:/im.test(parser.allHeaders) ||
      /^Received-SPF:/im.test(parser.allHeaders) ||
      /^DKIM-Signature:/im.test(parser.allHeaders),
    )

    if (!hasUpstreamChain || !hasAuthEvidence) {
      return { isForwarded: true, reason: "subject-prefix" }
    }

    return { isForwarded: false, suspectedReason: "subject-prefix" }
  }

  // Heuristic: if the only Received hop is the recipient's own delivery hop
  // (no upstream chain), it's likely a save-from-Sent-Items export of a
  // forward. Combined with the absence of a meaningful source IP, this is
  // reasonable to flag — but we keep it conservative: only when there's no
  // sourceIp AND only one Received header in the chain.
  if (!parser.sourceIp && parser.receivedChain.length <= 1) {
    return { isForwarded: true, reason: "from-self" }
  }

  return { isForwarded: false }
}
