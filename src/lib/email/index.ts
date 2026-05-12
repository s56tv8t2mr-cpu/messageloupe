// Public analysis API for Message Loupe.
//
// Single entry point: pass raw RFC-822 text (a .eml file's contents OR raw
// headers + body OR just headers), receive a complete Analysis. Parsing,
// link analysis, content classification, and verdict synthesis all run
// client-side — the message contents, headers, and body never leave the
// browser. The one exception is the MX lookup: when the visible sender
// is a non-webmail domain, this module issues a single DNS-over-HTTPS
// query to https://dns.google/resolve carrying only the sender domain
// name (no headers, no body, no recipient, no message-id). The request
// goes from the user's browser directly to Google; no Message Loupe
// server is in the path.

import { parseEmlLocally } from "./parser.js"
import { extractLinks, FLAG_LABELS as RAW_FLAG_LABELS } from "./linkAnalyzer.js"

import { classifyContent } from "./classify-content"
import { detectForward } from "./detect-forward"
import { evaluateSenderTrust } from "./sender-trust"
import { extractAttachments } from "./attachments"
import { assessReplyTo } from "./reply-to"
import { lookupMx } from "./mx-lookup"
import { computeVerdict } from "./verdict"

export { sameRegistrable } from "./domain"
export { authResultStatus, type AuthStatus } from "./auth-status"

import type {
  AnalyzedLink,
  Analysis,
  FlagLabel,
  LinkFlag,
  ParserResult,
} from "./types"

export const FLAG_LABELS = RAW_FLAG_LABELS as Record<LinkFlag, FlagLabel>

/**
 * Analyze a raw email source string.
 *
 * Accepts:
 *   - The full contents of a .eml file
 *   - Raw RFC-822 headers + body
 *   - Headers-only (e.g. from "Show Original" / "View Source")
 *
 * Issues one DNS-over-HTTPS MX lookup for the visible sender domain
 * (skipped for public webmail). Throws if `source` is empty.
 */
export async function analyze(source: string): Promise<Analysis> {
  if (!source || !source.trim()) {
    throw new Error("Empty source: paste headers or upload a .eml file.")
  }

  const parser = parseEmlLocally(source) as ParserResult
  const links = extractLinks(parser) as AnalyzedLink[]
  const attachments = extractAttachments(source)
  const content = classifyContent(`${parser.bodyText ?? ""}\n${parser.subject ?? ""}`)
  const forward = detectForward(parser)
  const trust = evaluateSenderTrust(parser)
  const replyTo = assessReplyTo(parser)
  // Skip the MX lookup for public webmail — billions of gmail.com /
  // outlook.com senders all share inbound MX with no signal value.
  const mx = trust.fromPublicWebmail ? null : await lookupMx(parser.sendingDomain)
  const verdict = computeVerdict({
    parser,
    links,
    attachments,
    content,
    forward,
    trust,
    replyTo,
    mx,
  })

  return { parser, links, attachments, content, forward, trust, replyTo, mx, verdict }
}

export type {
  Analysis,
  ParserResult,
  AnalyzedLink,
  AttachmentInfo,
  LinkFlag,
  FlagLabel,
  Verdict,
  VerdictTier,
  VerdictReason,
  ContentClassification,
  ForwardDetection,
  SenderTrustSignals,
  ReplyToCheck,
  ReplyToAssessment,
  MxLookup,
  MxRecord,
} from "./types"
