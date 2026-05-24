// Public analysis API for Message Loupe.
//
// Single entry point: pass raw RFC-822 text (a .eml file's contents OR raw
// headers + body OR just headers), receive a complete Analysis. All work
// happens client-side except the optional sender-domain MX lookup.

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

function stripHtmlForClassification(html: string): string {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim()
}

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
  const content = classifyContent(
    [
      parser.bodyText,
      stripHtmlForClassification(parser.bodyHtml ?? ""),
      parser.subject,
    ].join("\n"),
  )
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
