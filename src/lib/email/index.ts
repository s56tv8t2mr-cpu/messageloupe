// Public analysis API for Message Loupe.
//
// Single entry point: pass raw RFC-822 text (a .eml file's contents OR raw
// headers + body OR just headers), receive a complete Analysis. All work
// happens client-side except optional sender-domain DNS/RDAP lookups.

import { parseEmlLocally } from "./parser.js"
import { extractLinks, FLAG_LABELS as RAW_FLAG_LABELS } from "./linkAnalyzer.js"

import { classifyContent } from "./classify-content"
import { detectForward } from "./detect-forward"
import { evaluateSenderTrust } from "./sender-trust"
import { extractAttachments } from "./attachments"
import { assessReplyTo } from "./reply-to"
import { lookupMx } from "./mx-lookup"
import { lookupRdapDomainAge } from "./rdap-lookup"
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

const CONFUSABLES: Record<string, string> = {
  "\u0430": "a",
  "\u0410": "A",
  "\u0435": "e",
  "\u0415": "E",
  "\u043E": "o",
  "\u041E": "O",
  "\u0440": "p",
  "\u0420": "P",
  "\u0441": "c",
  "\u0421": "C",
  "\u0445": "x",
  "\u0425": "X",
  "\u0443": "y",
  "\u0423": "Y",
  "\u0456": "i",
  "\u0406": "I",
  "\u0455": "s",
  "\u0405": "S",
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

function decodeHtmlEntities(text: string): string {
  return text
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_match, hex: string) => decodeHtmlCodePoint(hex, 16))
    .replace(/&#(\d+);/g, (_match, code: string) => decodeHtmlCodePoint(code, 10))
}

function normalizeForClassification(text: string): string {
  return decodeHtmlEntities(text)
    .replace(/[\u00AD\u200B-\u200D\u2060\uFEFF]/g, "")
    .replace(/[\u0430\u0410\u0435\u0415\u043E\u041E\u0440\u0420\u0441\u0421\u0445\u0425\u0443\u0423\u0456\u0406\u0455\u0405]/g, (char) =>
      CONFUSABLES[char] ?? char,
    )
    .normalize("NFKC")
}

function stripHtmlForClassification(html: string, separator = " "): string {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, separator)
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
 * Issues optional DNS-over-HTTPS MX and RDAP domain-age lookups for the
 * visible sender domain (skipped for public webmail). Throws if `source`
 * is empty.
 */
export async function analyze(source: string): Promise<Analysis> {
  if (!source || !source.trim()) {
    throw new Error("Empty source: paste headers or upload a .eml file.")
  }

  const parser = parseEmlLocally(source) as ParserResult
  const links = extractLinks(parser) as AnalyzedLink[]
  const attachments = extractAttachments(source)
  const content = classifyContent(
    normalizeForClassification(
    [
      parser.bodyText,
      stripHtmlForClassification(parser.bodyHtml ?? ""),
      stripHtmlForClassification(parser.bodyHtml ?? "", ""),
      parser.subject,
      parser.contentClass,
    ].join("\n"),
    ),
  )
  const forward = detectForward(parser)
  const trust = evaluateSenderTrust(parser)
  const replyTo = assessReplyTo(parser)
  // Skip the MX lookup for public webmail — billions of gmail.com /
  // outlook.com senders all share inbound MX with no signal value.
  const [mx, rdap] = trust.fromPublicWebmail
    ? [null, null]
    : await Promise.all([
        lookupMx(parser.sendingDomain),
        lookupRdapDomainAge(parser.sendingDomain),
      ])
  const verdict = computeVerdict({
    parser,
    links,
    attachments,
    content,
    forward,
    trust,
    replyTo,
    mx,
    rdap,
  })

  return { parser, links, attachments, content, forward, trust, replyTo, mx, rdap, verdict }
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
  RdapLookup,
} from "./types"
