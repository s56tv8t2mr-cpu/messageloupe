// Public analysis API for Message Loupe.
//
// Single entry point: pass raw RFC-822 text (a .eml file's contents OR raw
// headers + body OR just headers), receive a complete Analysis. All work
// happens client-side; nothing leaves the browser.

import { parseEmlLocally } from "./parser.js"
import { extractLinks, FLAG_LABELS as RAW_FLAG_LABELS } from "./linkAnalyzer.js"

import { classifyContent } from "./classify-content"
import { detectForward } from "./detect-forward"
import { evaluateSenderTrust } from "./sender-trust"
import { extractAttachments } from "./attachments"
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
 * Throws if `source` is empty.
 */
export function analyze(source: string): Analysis {
  if (!source || !source.trim()) {
    throw new Error("Empty source — paste headers or upload a .eml file.")
  }

  const parser = parseEmlLocally(source) as ParserResult
  const links = extractLinks(parser) as AnalyzedLink[]
  const attachments = extractAttachments(source)
  const content = classifyContent(`${parser.bodyText ?? ""}\n${parser.subject ?? ""}`)
  const forward = detectForward(parser)
  const trust = evaluateSenderTrust(parser)
  const verdict = computeVerdict({ parser, links, attachments, content, forward, trust })

  return { parser, links, attachments, content, forward, trust, verdict }
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
} from "./types"
